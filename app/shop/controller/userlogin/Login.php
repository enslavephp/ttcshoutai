<?php
// File: app/shop/controller/userlogin/Login.php  （去商户依赖，适配新表结构 users/roles/user_roles/user_identities）
namespace app\shop\controller\userlogin;

use app\BaseController;
use app\shop\model\Users;
use app\shop\model\Roles;
use app\shop\model\UserIdentities;
use think\facade\Request;
use think\facade\Validate;
use think\facade\Db;
use think\facade\Cache;
use think\facade\Log;
use think\facade\Cookie;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;
use app\common\service\WeChatClientInterface;

class Login extends BaseController
{
    private int $maxAttempts = 5;          // 连续失败阈值
    private int $baseLockoutTime = 300;    // 初始锁定秒数
    private int $lockoutMultiplier = 2;    // 锁定倍增

    private TokenService $tokenService;
    private WeChatClientInterface $wechat;

    public function __construct(WeChatClientInterface $wechat = null)
    {
        // 初始化 TokenService 用于生成和验证 JWT token
        $jwtSecret = (string)(\app\common\Helper::getValue('jwt.secret') ?? 'PLEASE_CHANGE_ME');
        $jwtCfg['secret'] = $jwtSecret;

        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            $jwtCfg
        );

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

    // —— 注册（仅手机号 + 密码），无商户 ——
    public function register()
    {
        $data = Request::post();

        $validate = new \app\shop\validate\UsersValidate();
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        $telephone = (string)($data['telephone'] ?? '');
        $password  = (string)($data['password']  ?? '');

        // 中国大陆手机号（无国家码，11 位，以 1 开头）
        if (!preg_match('/^1\d{10}$/', $telephone)) {
            return $this->jsonResponse('手机号格式错误（需 11 位中国大陆手机号, 无国家码）', 400, 'error');
        }

        Db::startTrans();
        try {
            $exists = Users::where('telephone', $telephone)->value('id');
            if ($exists) {
                Db::rollback();
                return $this->jsonResponse('手机号已注册', 409, 'error');
            }

            $user = new Users();
            $user->save([
                'username'      => '用户'.$telephone,
                'password_hash' => password_hash($password, PASSWORD_BCRYPT),
                'telephone'     => $telephone,
                'status'        => Users::STATUS_NORMAL,
            ]);

            // 绑定默认角色（按名称，默认 user；若找不到则跳过）
            $defaultRoleName = (string)(\app\common\Helper::getValue('auth.default_role_name') ?? 'user');
            $roleId = (int)Roles::where('name', $defaultRoleName)->value('id');
            if ($roleId) {
                Db::name('user_roles')->insert([
                    'user_id'    => $user->id,
                    'role_id'    => $roleId,
                    'created_at' => date('Y-m-d H:i:s'),
                ]);
            }

            Db::commit();

            $auth = $this->buildAuthSnapshot($user->id);
            $claims = [
                'user_id'   => $user->id,
                'username'  => $user->username,
                'telephone' => $user->telephone,
                'is_admin'  => $auth['is_admin'],
                'role_ids'  => $auth['role_ids'],
            ];
            $issued = $this->tokenService->issue($claims, (int)\app\common\Helper::getValue('jwt.expire'), 7*24*3600);

            return $this->jsonResponse('注册成功并登录', 200, 'success', [
                'token'         => $issued['access'],
                'refresh_token' => $issued['refresh'],
                'user_id'       => $user->id,
                'username'      => $user->username,
                'telephone'     => $user->telephone,
                'is_admin'      => $auth['is_admin'],
                'role_ids'      => $auth['role_ids'],
            ]);
        } catch (\Throwable $e) {
            Db::rollback();
            return $this->jsonResponse('注册失败: '.$e->getMessage(), 500, 'error');
        }
    }

    // —— 登录（手机号 + 密码），无商户 ——
    public function login()
    {
        $data = Request::post();
        $rules = ['telephone'=>'require|regex:/^1\\d{10}$/', 'password'=>'require'];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 400, 'error');

        $telephone = $data['telephone'];
        $keyAttempts = "login_attempts:{$telephone}"; $keyLock = "lock_time:{$telephone}";

        $lockTime = Cache::get($keyLock);
        if ($lockTime && time() < $lockTime) return $this->jsonResponse("登录过于频繁，请 ".($lockTime-time())." 秒后再试", 429, 'error');

        $user = Users::where('telephone', $telephone)->find();
        if (!$user) {
            $this->incrementLoginAttempts($keyAttempts, $keyLock, $telephone);
            return $this->jsonResponse('手机号或密码错误', 400, 'error');
        }

        // 账号状态
        if ((int)$user->status === Users::STATUS_DISABLED) {
            return $this->jsonResponse('账号已被禁用', 403, 'error');
        }
        if (!empty($user->locked_until) && strtotime((string)$user->locked_until) > time()) {
            return $this->jsonResponse('账号暂时锁定，请稍后再试', 423, 'error');
        }

        if (!password_verify($data['password'], $user->password_hash)) {
            $this->incrementLoginAttempts($keyAttempts, $keyLock, $telephone);
            // 同步更新 users 里的失败计数（按自然日）
            Db::name('users')->where('id',$user->id)->update([
                'login_fail_count' => Db::raw("IF(login_fail_date = CURDATE(), login_fail_count + 1, 1)"),
                'login_fail_date'  => Db::raw('CURDATE()'),
            ]);
            return $this->jsonResponse('手机号或密码错误', 400, 'error');
        }

        $this->resetLoginAttempts($keyAttempts, $keyLock);

        // 登录成功：更新最近登录
        try {
            Db::name('users')->where('id',$user->id)->update([
                'last_login_at' => date('Y-m-d H:i:s'),
                'last_login_ip' => (string)request()->ip(),
                'login_fail_count' => 0,
                'login_fail_date'  => null,
                'locked_until'     => null,
            ]);
        } catch (\Throwable $e) {
            Log::warning('update_last_login_failed: '.$e->getMessage());
        }

        // 失效旧对：拉黑旧 access/refresh 的 JTI
        $prevA = Cache::get("active_access_jti:{$user->id}");
        $prevR = Cache::get("active_refresh_jti:{$user->id}");
        if ($prevA) {
            $ttlA = Cache::ttl("active_access_jti:{$user->id}");
            $this->tokenService->blacklist($prevA, ($ttlA && $ttlA > 0) ? $ttlA : (int)\app\common\Helper::getValue('jwt.expire'));
        }
        if ($prevR) {
            $ttlR = Cache::ttl("active_refresh_jti:{$user->id}");
            $this->tokenService->blacklist($prevR, ($ttlR && $ttlR > 0) ? $ttlR : 7*24*3600);
        }

        $auth = $this->buildAuthSnapshot($user->id);
        $claims = [
            'user_id'   => $user->id,
            'username'  => $user->username,
            'telephone' => $user->telephone,
            'is_admin'  => $auth['is_admin'],
            'role_ids'  => $auth['role_ids'],
        ];
        $issued = $this->tokenService->issue($claims, (int)\app\common\Helper::getValue('jwt.expire'), 7*24*3600);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'         => $issued['access'],
            'refresh_token' => $issued['refresh'],
            'user_id'       => $user->id,
            'username'      => $user->username,
            'telephone'     => $user->telephone,
            'is_admin'      => $auth['is_admin'],
            'role_ids'      => $auth['role_ids'],
        ]);
    }

    public function refresh()
    {
        try {
            $header = Request::header('Authorization') ?? '';
            $refreshToken = preg_replace('/^\s*Bearer\s+/i', '', (string)$header);
            if (!$refreshToken) return $this->jsonResponse('缺少 Refresh Token', 401, 'error');

            $issued = $this->tokenService->rotateFromRefresh($refreshToken, function (array $seed) {
                $uid = (int)$seed['user_id'];
                $firstAt = (int)($seed['iat0'] ?? ($seed['iat'] ?? time()));

                $user = Users::where('id', $uid)->find();
                $auth = $this->buildAuthSnapshot($uid);

                return [
                    'user_id'   => $uid,
                    'telephone' => $user['telephone'] ?? null,
                    'is_admin'  => $auth['is_admin'],
                    'role_ids'  => $auth['role_ids'],
                    'iat0'      => $firstAt,
                ];
            });

            return $this->jsonResponse('Token 刷新成功', 200, 'success', [
                'token'         => $issued['access'],
                'refresh_token' => $issued['refresh'],
                'access_exp'    => $issued['access_exp'],
                'refresh_exp'   => $issued['refresh_exp'],
            ]);
        } catch (\Firebase\JWT\ExpiredException $e) {
            return $this->jsonResponse('会话已失效，请重新登录', 401, 'error');
        } catch (\Throwable $e) {
            Log::warning('refresh_failed: '.$e->getMessage());
            return $this->jsonResponse('无效的 Refresh Token，请重新登录', 401, 'error');
        }
    }

    /** 统一设置 refresh Cookie（按需启用） */
    private function setRefreshCookie(string $token, int $ttl): void
    {
        $cfg = \app\common\Helper::getValue('jwt.cookie');
        if (!($cfg['enable'] ?? false)) return;

        $name     = $cfg['name_refresh'] ?? 'rt';
        $path     = $cfg['path'] ?? '/';
        $domain   = isset($cfg['domain']) && $cfg['domain'] !== null ? (string)$cfg['domain'] : '';
        $secure   = (bool)($cfg['secure']   ?? false);
        $httponly = (bool)($cfg['httponly'] ?? true);
        $samesite = $cfg['samesite'] ?? 'Lax';
        if (!in_array($samesite, ['Lax','Strict','None'], true)) $samesite = 'Lax';
        if ($samesite === 'None' && $secure === false) $secure = true;

        $options = [
            'expire'   => max(0, (int)$ttl),
            'path'     => $path,
            'secure'   => $secure,
            'httponly' => $httponly,
            'samesite' => $samesite,
        ];
        if ($domain !== '') $options['domain'] = $domain;

        try { Cookie::set($name, $token, $options); }
        catch (\Throwable $e) { Log::error('setRefreshCookie_failed: '.$e->getMessage(), ['options'=>$options]); }
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
            if ($acc) $this->tokenService->blacklist($acc, (int)\app\common\Helper::getValue('jwt.expire'));
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
        if (!$code || !$encryptedData || !$iv) return $this->jsonResponse('参数不完整', 400, 'error');

        try {
            $wx = $this->wechat->code2Session($code);
            $sessionKey = $wx['session_key']; $openid = $wx['openid'];
        } catch (\Throwable $e) {
            return $this->jsonResponse('微信登录失败', 500, 'error');
        }

        // 先看 openid 是否已有绑定
        $bind = UserIdentities::where(['provider'=>'wechat','provider_user_id'=>$openid])->find();
        $user = null;

        if ($bind) {
            $user = Users::where('id', (int)$bind->user_id)->find();
            if (!$user) return $this->jsonResponse('用户记录不存在', 404, 'error');
        } else {
            try {
                $phoneData = $this->decryptPhoneNumber($sessionKey, $encryptedData, $iv);
            } catch (\Throwable $e) {
                return $this->jsonResponse('手机号解密失败', 500, 'error');
            }
            $telephone = (string)($phoneData['phoneNumber'] ?? '');
            if (!preg_match('/^1\d{10}$/', $telephone)) return $this->jsonResponse('手机号格式错误', 400, 'error');

            Db::startTrans();
            try {
                $user = Users::where('telephone',$telephone)->find();
                if (!$user) {
                    $user = new Users();
                    $user->save([
                        'username'      => '用户'.$telephone,
                        'password_hash' => password_hash(time().$telephone, PASSWORD_BCRYPT),
                        'telephone'     => $telephone,
                        'status'        => Users::STATUS_NORMAL,
                    ]);

                    // 默认角色
                    $defaultRoleName = (string)(\app\common\Helper::getValue('app.default_role_name') ?? 'user');
                    $roleId = (int)Roles::where('name', $defaultRoleName)->value('id');
                    if ($roleId) {
                        Db::name('user_roles')->insert([
                            'user_id'=>$user->id,'role_id'=>$roleId,'created_at'=>date('Y-m-d H:i:s'),
                        ]);
                    }
                }

                // 绑定 openid -> user_id
                UserIdentities::create([
                    'user_id' => $user->id,
                    'provider' => 'wechat',
                    'provider_user_id' => $openid,
                    'meta' => json_encode(['bound_at'=>date('c')], JSON_UNESCAPED_UNICODE),
                ]);

                Db::commit();
            } catch (\Throwable $e) {
                Db::rollback();
                return $this->jsonResponse('注册失败: '.$e->getMessage(), 500, 'error');
            }
        }

        // 失效旧对
        $prevA = Cache::get("active_access_jti:{$user->id}");
        $prevR = Cache::get("active_refresh_jti:{$user->id}");
        if ($prevA) {
            $ttlA = Cache::ttl("active_access_jti:{$user->id}");
            $this->tokenService->blacklist($prevA, ($ttlA && $ttlA > 0) ? $ttlA : (int)\app\common\Helper::getValue('jwt.expire'));
        }
        if ($prevR) {
            $ttlR = Cache::ttl("active_refresh_jti:{$user->id}");
            $this->tokenService->blacklist($prevR, ($ttlR && $ttlR > 0) ? $ttlR : 7*24*3600);
        }

        $auth = $this->buildAuthSnapshot($user->id);
        $claims = [
            'user_id'=>$user->id, 'username'=>$user->username, 'telephone'=>$user->telephone,
            'is_admin'=>$auth['is_admin'], 'role_ids'=>$auth['role_ids'],
        ];
        $issued = $this->tokenService->issue($claims, (int)\app\common\Helper::getValue('jwt.expire'), 7*24*3600);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'=>$issued['access'], 'refresh_token'=>$issued['refresh'],
            'user_id'=>$user->id, 'username'=>$user->username,
            'is_admin'=>$auth['is_admin'], 'role_ids'=>$auth['role_ids'], 'telephone'=>$user->telephone,
        ]);
    }

    // —— 小程序：手机号登录（存在即登录） ——
    public function phoneLogin()
    {
        $code = Request::post('code');
        if (!$code) return $this->jsonResponse('参数不完整', 400, 'error');
        try {
            $wx = $this->wechat->code2Session($code);
            $openid = $wx['openid'];
        } catch (\Throwable $e) {
            return $this->jsonResponse('微信登录失败', 500, 'error');
        }

        $bind = UserIdentities::where(['provider'=>'wechat','provider_user_id'=>$openid])->find();
        if (!$bind) return $this->jsonResponse('用户微信小程序未注册', 901, 'success');
        $user = Users::where('id', (int)$bind->user_id)->find();
        if (!$user) return $this->jsonResponse('用户记录不存在', 404, 'error');

        $prevA = Cache::get("active_access_jti:{$user->id}");
        $prevR = Cache::get("active_refresh_jti:{$user->id}");
        if ($prevA) {
            $ttlA = Cache::ttl("active_access_jti:{$user->id}");
            $this->tokenService->blacklist($prevA, ($ttlA && $ttlA > 0) ? $ttlA : (int)\app\common\Helper::getValue('jwt.expire'));
        }
        if ($prevR) {
            $ttlR = Cache::ttl("active_refresh_jti:{$user->id}");
            $this->tokenService->blacklist($prevR, ($ttlR && $ttlR > 0) ? $ttlR : 7*24*3600);
        }

        $auth = $this->buildAuthSnapshot($user->id);
        $claims = [
            'user_id'=>$user->id,'username'=>$user->username,'telephone'=>$user->telephone,
            'is_admin'=>$auth['is_admin'],'role_ids'=>$auth['role_ids'],
        ];
        $issued = $this->tokenService->issue($claims, (int)\app\common\Helper::getValue('jwt.expire'), 7*24*3600);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'=>$issued['access'], 'refresh_token'=>$issued['refresh'],
            'user_id'=>$user->id,'username'=>$user->username,'is_admin'=>$auth['is_admin'],
            'role_ids'=>$auth['role_ids'],'telephone'=>$user->telephone,
        ]);
    }

    // —— 工具：基于角色的权限快照 ——
    private function buildAuthSnapshot(int $userId): array
    {
        $rows = Db::name('roles')->alias('r')
            ->join('user_roles ur','ur.role_id = r.id')
            ->where('ur.user_id',$userId)
            ->field('r.id,r.name')
            ->select();
        $roleIds = []; $roleNames = [];
        foreach ($rows as $row) { $roleIds[] = (int)$row['id']; $roleNames[] = (string)$row['name']; }
        $isAdmin = in_array('admin', $roleNames, true) || in_array('superadmin', $roleNames, true);
        return ['role_ids'=>$roleIds, 'role_names'=>$roleNames, 'is_admin'=>$isAdmin];
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

    // —— 检查手机号唯一 ——
    public function checkUnique()
    {
        $tel = Request::post('telephone');
        if (!$tel) return $this->jsonResponse('缺少 telephone', 400, 'error');
        $exists = Users::where('telephone', $tel)->value('id') ? 1 : 0;
        return $this->jsonResponse('OK', 200, 'success', ['exists' => $exists]);
    }
}