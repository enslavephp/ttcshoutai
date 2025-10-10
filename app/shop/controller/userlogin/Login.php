<?php
namespace app\shop\controller\userlogin;

use app\BaseController;
use app\shop\model\Users;
use think\facade\Request;
use think\facade\Validate;
use think\facade\Db;
use think\facade\Cache;
use think\facade\Log;
use think\facade\Cookie;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;
use app\common\service\WeChatClientInterface; // 实现见下文示例
use think\facade\Config;

class Login extends BaseController
{
    private int $maxAttempts = 5;
    private int $baseLockoutTime = 300;
    private int $lockoutMultiplier = 2;

    private TokenService $tokenService;
    private WeChatClientInterface $wechat;

    public function __construct(WeChatClientInterface $wechat = null)
    {
        $cache = new CacheFacadeAdapter();
        $clock = new SystemClock();
        $cfg   = config('jwt') ?: [];
        $this->tokenService = new TokenService($cache, $clock, $cfg);

        if ($wechat) {
            $this->wechat = $wechat;
        } else {
            $this->wechat = new class(config('wechat')) implements WeChatClientInterface {
                private array $cfg;
                public function __construct(array $cfg){ $this->cfg=$cfg; }
                public function code2Session(string $code): array {
                    $url = $this->cfg['api_url'] . "?appid={$this->cfg['app_id']}&secret={$this->cfg['secret']}&js_code={$code}&grant_type=authorization_code";
                    $ch = curl_init($url);
                    curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER=>true, CURLOPT_CONNECTTIMEOUT=>3, CURLOPT_TIMEOUT=>5]);
                    $resp = curl_exec($ch);
                    if ($resp === false) throw new \RuntimeException('wechat_network_error');
                    $http = curl_getinfo($ch, CURLINFO_HTTP_CODE); curl_close($ch);
                    if ($http!==200) throw new \RuntimeException('wechat_http_'.$http);
                    $data = json_decode($resp, true) ?: [];
                    if (empty($data['session_key']) || empty($data['openid'])) throw new \RuntimeException('wechat_bad_response');
                    return ['session_key'=>$data['session_key'],'openid'=>$data['openid']];
                }
            };
        }
    }

    // —— 注册 ——
    public function register()
    {
        $data = Request::post();
        $shopId = $data['shop_id'] ?? env('DEFAULT_SHOP_ID');

        $validate = new \app\shop\validate\UsersValidate();
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        $telephone = $data['telephone'];
        $password  = $data['password'];

        Db::startTrans();
        try {
            $user = new Users();
            $user->save([
                'username'  => '用户'.$telephone,
                'password'  => password_hash($password, PASSWORD_BCRYPT),
                'telephone' => $telephone,
            ]);

            $roleId = Db::name('shop_roles')->where(['shop_id'=>$shopId,'is_default'=>1])->value('role_id') ?: env('DEFAULT_ROLE_ID');
            Db::name('user_role_mapping')->insert([
                'user_id'=>$user->id,'shop_id'=>$shopId,'role_id'=>$roleId,
                'created_at'=>date('Y-m-d H:i:s'),'updated_at'=>date('Y-m-d H:i:s'),
            ]);

            Db::commit();

            $claims = [
                'user_id'=>$user->id, 'username'=>$user->username, 'telephone'=>$user->telephone,
                'is_admin'=>false, 'role_id'=>$roleId,
            ];
            $issued = $this->tokenService->issue($claims, (int)config('jwt.expire'), 7*24*3600);

            return $this->jsonResponse('注册成功并登录', 200, 'success', [
                'token'=>$issued['access'], 'refresh_token'=>$issued['refresh'],
                'user_id'=>$user->id, 'username'=>$user->username, 'is_admin'=>false,
                'role_id'=>$roleId, 'telephone'=>$user->telephone,
            ]);
        } catch (\Throwable $e) {
            Db::rollback();
            return $this->jsonResponse('注册失败: '.$e->getMessage(), 500, 'error');
        }
    }

    // —— 登录 ——
    public function login()
    {
        $data = Request::post();
        $rules = ['telephone'=>'require|regex:/^\+?[1-9]\d{7,14}$/', 'password'=>'require'];
        $validate = Validate::rule($rules);
        $shopId = $data['shop_id'] ?? env('DEFAULT_SHOP_ID');
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 400, 'error');

        $telephone = $data['telephone'];
        $keyAttempts = "login_attempts:{$telephone}"; $keyLock = "lock_time:{$telephone}";

        $lockTime = Cache::get($keyLock);
        if ($lockTime && time() < $lockTime) return $this->jsonResponse("登录过于频繁，请 ".($lockTime-time())." 秒后再试", 429, 'error');

        $user = Users::where('telephone', $telephone)->find();
        if (!$user || !password_verify($data['password'], $user->password)) {
            $this->incrementLoginAttempts($keyAttempts, $keyLock, $telephone);
            return $this->jsonResponse('手机号或密码错误', 400, 'error');
        }

        $this->resetLoginAttempts($keyAttempts, $keyLock);

        // 失效旧对：拉黑旧 access/refresh 的 JTI
        $prevA = Cache::get("active_access_jti:{$user->id}");
        $prevR = Cache::get("active_refresh_jti:{$user->id}");
        if ($prevA) {
            $ttlA = Cache::ttl("active_access_jti:{$user->id}");
            $this->tokenService->blacklist($prevA, ($ttlA && $ttlA > 0) ? $ttlA : (int)config('jwt.expire'));
        }
        if ($prevR) {
            $ttlR = Cache::ttl("active_refresh_jti:{$user->id}");
            $this->tokenService->blacklist($prevR, ($ttlR && $ttlR > 0) ? $ttlR : 7*24*3600);
        }

        $sf = $this->user_sf($user->id, $shopId);
        $claims = [
            'user_id'=>$user->id, 'username'=>$user->username, 'telephone'=>$user->telephone,
            'is_admin'=>$sf['is_admin'], 'role_id'=>$sf['role_id'],
        ];
        $issued = $this->tokenService->issue($claims, (int)config('jwt.expire'), 7*24*3600);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'=>$issued['access'], 'refresh_token'=>$issued['refresh'],
            'user_id'=>$user->id, 'username'=>$user->username,
            'is_admin'=>$sf['is_admin'], 'role_id'=>$sf['role_id'], 'telephone'=>$user->telephone,
        ]);
    }

    public function refresh()
    {
        try {
            // 只从 Header 读取，并去掉 Bearer 前缀（也兼容直接传完整 Authorization）
            $header = Request::header('Authorization') ?? '';
            $refreshToken = preg_replace('/^\s*Bearer\s+/i', '', (string)$header);

            if (!$refreshToken) {
                return $this->jsonResponse('缺少 Refresh Token', 401, 'error');
            }

            // 轮换新对（claimsResolver 里补齐业务字段）
            $issued = $this->tokenService->rotateFromRefresh($refreshToken, function (array $seed) {
                $uid = (int)$seed['user_id'];
                $firstAt = (int)($seed['iat0'] ?? ($seed['iat'] ?? time()));

                // 👉 按你的老登录逻辑查业务信息
                $user   = \app\shop\model\Users::where('id', $uid)->find();
                $admin  = \think\facade\Db::name('admin_users')->where(['user_id' => $uid, 'status' => 1])->find();
                $roleId = (int)\think\facade\Db::name('user_role_mapping')->where(['user_id' => $uid, 'shop_id' => 1])->value('role_id');

                return [
                    'user_id'   => $uid,
                    'telephone' => $user['telephone'] ?? null,
                    'is_admin'  => $admin ? 1 : 0,
                    'role_id'   => $roleId,
                    'iat0'      => $firstAt, // 保持同一会话起点
                ];
            });

            // 如果你已经决定全部走 Header，可以注释掉下面这行，或将 config('jwt.cookie.enable') 设为 false
            // $this->setRefreshCookie($issued['refresh'], (int)config('jwt.refresh_ttl', 7 * 24 * 3600));

            return $this->jsonResponse('Token 刷新成功', 200, 'success', [
                'token'         => $issued['access'],
                'refresh_token' => $issued['refresh'],
                'access_exp'    => $issued['access_exp'],
                'refresh_exp'   => $issued['refresh_exp'],
            ]);

        } catch (\Firebase\JWT\ExpiredException $e) {
            return $this->jsonResponse('会话已失效，请重新登录', 401, 'error');
        } catch (\Throwable $e) {
            // 建议打日志，避免 var_dump / die 破坏输出
            \think\facade\Log::warning('refresh_failed: '.$e->getMessage());
            return $this->jsonResponse('无效的 Refresh Token，请重新登录', 401, 'error');
        }
    }

    /** 统一设置 refresh Cookie（ThinkPHP6） */
    private function setRefreshCookie(string $token, int $ttl): void
    {
        $cfg = config('jwt.cookie');
        if (!($cfg['enable'] ?? false)) return;

        // 规范化、兜底
        $name     = $cfg['name_refresh'] ?? 'rt';
        $path     = $cfg['path'] ?? '/';
        $domain   = isset($cfg['domain']) && $cfg['domain'] !== null ? (string)$cfg['domain'] : '';
        $secure   = (bool)($cfg['secure']   ?? false);
        $httponly = (bool)($cfg['httponly'] ?? true);
        $samesite = $cfg['samesite'] ?? 'Lax';
        if (!in_array($samesite, ['Lax','Strict','None'], true)) {
            $samesite = 'Lax';
        }
        // Chrome 规则：SameSite=None 必须 secure
        if ($samesite === 'None' && $secure === false) {
            $secure = true;
        }

        $options = [
            'expire'   => max(0, (int)$ttl),
            'path'     => $path,
            // 仅当有值时再传 domain，避免 PHP 8 报类型错误
            // 'domain' => $domain,
            'secure'   => $secure,
            'httponly' => $httponly,
            'samesite' => $samesite,
        ];
        if ($domain !== '') {
            $options['domain'] = $domain;
        }

        try {
            \think\facade\Cookie::set($name, $token, $options);
        } catch (\Throwable $e) {
            // 打日志方便定位（比如 TypeError: setcookie(): Argument #5 ($domain) must be of type string, null given）
            \think\facade\Log::error('setRefreshCookie_failed: '.$e->getMessage(), ['options' => $options]);
            // 不让它把接口整个打爆 —— 按需返回也行
            // throw $e;
        }
    }


    // —— 登出 ——
    public function loginOut()
    {
        $auth = Request::header('Authorization');
        if (!$auth || !str_starts_with($auth, 'Bearer ')) return $this->jsonResponse('缺少 Token，请先登录', 401, 'error');
        $token = substr($auth, 7);
        try {
            $decoded = $this->tokenService->parse($token); // parse 内含黑名单校验
            $jti = (string)($decoded->jti ?? ''); $exp = (int)($decoded->exp ?? time());
            $uid = (int)($decoded->user_id ?? 0);
            $ttl = max(0, $exp - time());
            if ($jti && $ttl>0) $this->tokenService->blacklist($jti, $ttl);

            $acc = Cache::pull("active_access_jti:{$uid}");
            $ref = Cache::pull("active_refresh_jti:{$uid}");
            if ($acc) $this->tokenService->blacklist($acc, (int)config('jwt.expire'));
            if ($ref) $this->tokenService->blacklist($ref, 7*24*3600);

            return $this->jsonResponse('登出成功', 200, 'success');
        } catch (\Firebase\JWT\ExpiredException $e) {
            return $this->jsonResponse('Token 已过期，请重新登录', 401, 'error');
        } catch (\Throwable $e) {
            return $this->jsonResponse('无效的 Token，请重新登录', 401, 'error');
        }
    }

    // —— 小程序：手机号注册 ——
    public function phoneRegister()
    {
        $code = Request::post('code');
        $encryptedData = Request::post('encryptedData');
        $iv = Request::post('iv');
        $shopId = Request::post('shop_id');
        if (!$code || !$encryptedData || !$iv) return $this->jsonResponse('参数不完整', 400, 'error');

        try {
            $wx = $this->wechat->code2Session($code);
            $sessionKey = $wx['session_key']; $openid = $wx['openid'];
        } catch (\Throwable $e) {
            return $this->jsonResponse('微信登录失败', 500, 'error');
        }

        $user = Users::where('open_id', $openid)->find();
        $is_admin = false; $role_id = env('DEFAULT_ROLE_ID');

        if (!$user) {
            try {
                $phoneData = $this->decryptPhoneNumber($sessionKey, $encryptedData, $iv);
            } catch (\Throwable $e) {
                return $this->jsonResponse('手机号解密失败', 500, 'error');
            }
            $telephone = $phoneData['phoneNumber'] ?? '';
            if (!preg_match('/^\+?[1-9]\d{7,14}$/', $telephone)) return $this->jsonResponse('手机号格式错误', 400, 'error');

            Db::startTrans();
            try {
                $user = Users::where('telephone',$telephone)->find();
                if (!$user) {
                    $user = new Users();
                    $user->save([
                        'username'=>'用户'.$telephone,
                        'password'=> password_hash(time().$telephone, PASSWORD_BCRYPT),
                        'telephone'=>$telephone,
                        'open_id'=>$openid,
                    ]);
                } else {
                    $user->open_id = $openid; $user->save();
                }

                $role_id = Db::name('shop_roles')->where(['shop_id'=>$shopId,'is_default'=>1])->value('role_id') ?: env('DEFAULT_ROLE_ID');
                Db::name('user_role_mapping')->insert([
                    'user_id'=>$user->id,'shop_id'=>$shopId,'role_id'=>$role_id,
                    'created_at'=>date('Y-m-d H:i:s'),'updated_at'=>date('Y-m-d H:i:s'),
                ]);

                Db::commit();
            } catch (\Throwable $e) {
                Db::rollback();
                return $this->jsonResponse('注册失败: '.$e->getMessage(), 500, 'error');
            }
        } else {
            $user->open_id = $openid; $user->save();
            $sf = $this->user_sf($user->id, $shopId); $is_admin=$sf['is_admin']; $role_id=$sf['role_id'];
        }

        // 失效旧对
        $prevA = Cache::get("active_access_jti:{$user->id}");
        $prevR = Cache::get("active_refresh_jti:{$user->id}");
        if ($prevA) {
            $ttlA = Cache::ttl("active_access_jti:{$user->id}");
            $this->tokenService->blacklist($prevA, ($ttlA && $ttlA > 0) ? $ttlA : (int)config('jwt.expire'));
        }
        if ($prevR) {
            $ttlR = Cache::ttl("active_refresh_jti:{$user->id}");
            $this->tokenService->blacklist($prevR, ($ttlR && $ttlR > 0) ? $ttlR : 7*24*3600);
        }

        $claims = [
            'user_id'=>$user->id, 'username'=>$user->username, 'telephone'=>$user->telephone,
            'is_admin'=>$is_admin, 'role_id'=>$role_id,
        ];
        $issued = $this->tokenService->issue($claims, (int)config('jwt.expire'), 7*24*3600);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'=>$issued['access'], 'refresh_token'=>$issued['refresh'],
            'user_id'=>$user->id, 'username'=>$user->username,
            'is_admin'=>$is_admin, 'role_id'=>$role_id, 'telephone'=>$user->telephone,
        ]);
    }

    // —— 小程序：手机号登录（存在即登录） ——
    public function phoneLogin()
    {
        $code = Request::post('code');
        $shopId = Request::post('shop_id', env('DEFAULT_SHOP_ID'));
        if (!$code) return $this->jsonResponse('参数不完整', 400, 'error');
        try {
            $wx = $this->wechat->code2Session($code);
            $openid = $wx['openid'];
        } catch (\Throwable $e) {
            return $this->jsonResponse('微信登录失败', 500, 'error');
        }
        $user = Users::where('open_id', $openid)->find();
        if (!$user) return $this->jsonResponse('用户微信小程序未注册', 901, 'success');

        $sf = $this->user_sf($user->id,$shopId);
        $prevA = Cache::get("active_access_jti:{$user->id}");
        $prevR = Cache::get("active_refresh_jti:{$user->id}");
        if ($prevA) {
            $ttlA = Cache::ttl("active_access_jti:{$user->id}");
            $this->tokenService->blacklist($prevA, ($ttlA && $ttlA > 0) ? $ttlA : (int)config('jwt.expire'));
        }
        if ($prevR) {
            $ttlR = Cache::ttl("active_refresh_jti:{$user->id}");
            $this->tokenService->blacklist($prevR, ($ttlR && $ttlR > 0) ? $ttlR : 7*24*3600);
        }

        $claims = [
            'user_id'=>$user->id,'username'=>$user->username,'telephone'=>$user->telephone,
            'is_admin'=>$sf['is_admin'],'role_id'=>$sf['role_id'],
        ];
        $issued = $this->tokenService->issue($claims, (int)config('jwt.expire'), 7*24*3600);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'=>$issued['access'], 'refresh_token'=>$issued['refresh'],
            'user_id'=>$user->id,'username'=>$user->username,'is_admin'=>$sf['is_admin'],
            'role_id'=>$sf['role_id'],'telephone'=>$user->telephone,
        ]);
    }

    // —— 工具：角色/管理员 ——
    public function user_sf($user_id, $shopId)
    {
        $is_admin = Db::name('admin_users')->where(['user_id'=>$user_id,'status'=>1])->find() ? true : false;
        $role_id = Db::name('user_role_mapping')->where(['user_id'=>$user_id,'shop_id'=>$shopId])->value('role_id') ?: env('DEFAULT_ROLE_ID');
        return ['is_admin'=>$is_admin,'role_id'=>$role_id];
    }

    // —— 工具：登录防爆破 ——
    private function incrementLoginAttempts($keyAttempts, $keyLock, $telephone)
    {
        $attempts = (int)Cache::inc($keyAttempts);
        if ($attempts === 1) Cache::set($keyAttempts, $attempts, $this->baseLockoutTime);
        if ($attempts >= $this->maxAttempts) {
            $lock = $this->baseLockoutTime * (int)pow($this->lockoutMultiplier, floor($attempts / $this->maxAttempts));
            Cache::set($keyLock, time()+$lock, $lock);
            Cache::delete($keyAttempts);
        }
    }
    private function resetLoginAttempts($keyAttempts, $keyLock)
    {
        Cache::delete($keyAttempts); Cache::delete($keyLock);
    }

    // —— 工具：解密微信手机号（含 appid 水印校验） ——
    private function decryptPhoneNumber(string $sessionKey, string $encryptedData, string $iv)
    {
        $data = openssl_decrypt(base64_decode($encryptedData), 'AES-128-CBC', base64_decode($sessionKey), OPENSSL_RAW_DATA, base64_decode($iv));
        $arr = json_decode($data, true);
        $cfg = config('wechat');
        if (!isset($arr['watermark']['appid']) || $arr['watermark']['appid'] !== ($cfg['app_id'] ?? '')) {
            throw new \RuntimeException('wechat_watermark_mismatch');
        }
        return $arr;
    }

    // —— 获取用户信息 ——
    public function getUserInfo(\think\Request $request)
    {
        try {
            $user = $request->user ?? null;
            if (!$user || !isset($user['id'])) return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
            $userInfo = Users::with('roles')->where('id', $user['id'])->find();
            if (!$userInfo) return $this->jsonResponse('用户信息不存在', 404, 'error');
            return $this->jsonResponse('获取用户信息成功', 200, 'success', ['user'=>$userInfo]);
        } catch (\Throwable $e) {
            Log::error('获取用户信息失败', ['error'=>$e->getMessage(), 'trace'=>$e->getTrace()]);
            return $this->jsonResponse('获取用户信息失败: '.$e->getMessage(), 500, 'error');
        }
    }
    // —— 获取用户信息 ——
    public function checkUnique()
    {
        $tel = Request::post('telephone');
        if (!$tel) {
            return $this->jsonResponse('缺少 telephone', 400, 'error');
        }
        $exists = \app\shop\model\Users::where('telephone', $tel)->value('id') ? 1 : 0;
        return $this->jsonResponse('OK', 200, 'success', ['exists' => $exists]);
    }

}
