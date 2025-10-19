<?php
declare(strict_types=1);

namespace app\shopadmin\controller\auth;

use app\BaseController;
use think\facade\Request;
use think\facade\Db;
use think\facade\Cache;
use think\facade\Cookie;
use think\facade\Log;


use app\shopadmin\validate\ShopAdminLoginValidate;
use app\shopadmin\validate\ShopAdminRegisterValidate;
use app\shopadmin\validate\ShopAdminChangePasswordValidate;

use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;

use app\common\service\PermissionCacheService;
use app\shopadmin\model\ShopAdminUser;
use app\shopadmin\model\ShopAdminUserRole;
use app\shopadmin\model\ShopAdminRole;
use app\shopadmin\model\ShopAdminUserPasswordHistory;
use app\shopadmin\model\ShopAdminUserLoginAudit;
use app\shopadmin\service\ShopAdminSensitiveOperationService;

// 权限相关模型
use app\shopadmin\model\ShopAdminPermission;
use app\shopadmin\model\ShopAdminRolePermission;

// ✅ 商户模型改用后台命名空间（ORM）
use app\admin\model\ShopAdminMerchant;

class ShopAdminAuth extends BaseController
{
    private TokenService $tokenService;

    private int $maxAttempts = 5;
    private int $baseLockoutTime = 300;
    private float $lockoutMultiplier = 2.0;

    private int $accessTtlSeconds = 21600; // 6h

    private string $SUPER_CODE = 'super_shopadmin'; // 租户侧超管角色代码

    public function __construct()
    {
        // 初始化 TokenService 用于生成和验证 JWT token
        $jwtSecret = (string)(\app\common\Helper::getValue('jwt.secret') ?? 'PLEASE_CHANGE_ME');
        $jwtCfg['secret'] = $jwtSecret;

        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            $jwtCfg
        );
    }

    // ========================= 工具函数 =========================

    private function ipToBin(?string $ip): ?string
    {
        if (!$ip) return null;
        $packed = @inet_pton($ip);
        return $packed === false ? null : $packed;
    }

    private function binToIp($bin): ?string
    {
        if (empty($bin)) return null;
        $ip = @inet_ntop(is_string($bin) ? $bin : (string)$bin);
        return $ip === false ? null : $ip;
    }

    private function hashPassword(string $plain): array
    {
        $cost = (int)(\app\common\Helper::getValue('security.admin_bcrypt_cost') ?? 12);
        $hash = password_hash($plain, PASSWORD_BCRYPT, ['cost' => $cost]);
        return [
            'password'      => $hash,
            'password_algo' => 'bcrypt',
            'password_meta' => json_encode(['cost' => $cost], JSON_UNESCAPED_UNICODE),
        ];
    }

    /** 登录节流：加入 merchant 维度 */
    private function throttle(string $merchantKey, string $username, string $ip): ?\think\Response
    {
        $bucket = sprintf('salogin:%s:%s:%s', $merchantKey, strtolower($username), $ip);
        $lockK  = "lock:{$bucket}";
        $attK   = "attempts:{$bucket}";

        $lockUntil = Cache::get($lockK);
        if ($lockUntil && time() < (int)$lockUntil) {
            $ttl = ((int)$lockUntil) - time();
            return $this->jsonResponse("操作过于频繁，请 {$ttl} 秒后再试", 429, 'error');
        }

        $attempts = (int)Cache::inc($attK);
        if ($attempts === 1) {
            Cache::set($attK, $attempts, $this->baseLockoutTime);
        }
        if ($attempts >= $this->maxAttempts) {
            $lock = (int)($this->baseLockoutTime * pow($this->lockoutMultiplier, floor($attempts / $this->maxAttempts)));
            Cache::set($lockK, time() + $lock, $lock);
            Cache::delete($attK);
            return $this->jsonResponse("操作已锁定，请 {$lock} 秒后再试", 429, 'error');
        }
        return null;
    }

    /** 解析商户标识：支持 merchant_id / merchant_code / merchant_name（ORM版本） */
    private function resolveMerchantId(array $in): ?int
    {
        if (!empty($in['merchant_id'])) return (int)$in['merchant_id'];
        if (!empty($in['merchant_code'])) {
            $id = ShopAdminMerchant::where('merchant_code', $in['merchant_code'])->value('id');
            return $id ? (int)$id : null;
        }
        if (!empty($in['merchant_name'])) {
            $id = ShopAdminMerchant::where('merchant_name', $in['merchant_name'])->value('id');
            return $id ? (int)$id : null;
        }
        return null;
    }

    /** 找到本租户“首位超管”的 admin_id（按创建时间/ID最早；ORM） */
    private function primarySuperAdminId(int $merchantId): ?int
    {
        $row = ShopAdminUser::alias('u')
            ->join(['shopadmin_user_role'=>'ur'],'ur.admin_id = u.id AND ur.merchant_id = u.merchant_id')
            ->join(['shopadmin_role'=>'r'],'r.id = ur.role_id AND r.merchant_id = u.merchant_id')
            ->where('u.merchant_id',$merchantId)
            ->whereNull('u.deleted_at')
            ->where('r.code',$this->SUPER_CODE)
            ->order('u.created_at','asc')
            ->order('u.id','asc')
            ->field('u.id')
            ->find();
        return $row ? (int)$row->getAttr('id') : null;
    }

    /** 是否本租户“首位超管” */
    private function isPrimarySuperAdmin(int $merchantId, int $adminId): bool
    {
        $pid = $this->primarySuperAdminId($merchantId);
        if (!$pid) return false;
        return $pid === $adminId;
    }

    /** 统计本租户“子账号”数量（不含首位超管；仅未软删；ORM） */
    private function countSubAccounts(int $merchantId): int
    {
        $primaryId = $this->primarySuperAdminId($merchantId);
        $q = ShopAdminUser::where('merchant_id',$merchantId)->whereNull('deleted_at');
        if ($primaryId) {
            $q->where('id','<>',$primaryId);
        }
        return (int)$q->count();
    }

    /** 本租户下账号的“最高权限等级”（无则 99，数值越小权限越高） */
    private function bestRoleLevel(int $merchantId, int $adminId): int
    {
        $now = date('Y-m-d H:i:s');
        $levels = ShopAdminUserRole::alias('ur')
            ->join(['shopadmin_role' => 'r'],'r.id = ur.role_id')
            ->where('ur.admin_id', $adminId)
            ->where('ur.merchant_id', $merchantId)
            ->where('r.merchant_id', $merchantId)
            ->where('r.status', 1)
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            ->column('r.level');

        if (empty($levels)) return 99;
        $levels = array_map('intval',$levels);
        return (int)min($levels);
    }

    /** 本租户下账号的有效角色代码 */
    private function activeRoleCodes(int $merchantId, int $adminId): array
    {
        $now = date('Y-m-d H:i:s');
        $codes = ShopAdminUserRole::alias('ur')
            ->join(['shopadmin_role' => 'r'],'ur.role_id = r.id')
            ->where('ur.admin_id', $adminId)
            ->where('ur.merchant_id', $merchantId)
            ->where('r.merchant_id', $merchantId)
            ->where('r.status', 1)
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            ->column('r.code');
        $codes = array_values(array_unique(array_map('strval',$codes)));
        sort($codes, SORT_STRING);
        return $codes;
    }

    private function writeLoginAudit(int $merchantId, ?int $adminId, ?string $username, string $result, ?string $reason = null): void
    {
        try {
            ShopAdminUserLoginAudit::create([
                'merchant_id' => $merchantId,
                'admin_id'    => $adminId,
                'username'    => $username,
                'occurred_at' => date('Y-m-d H:i:s'),
                'ip'          => $this->ipToBin(Request::ip() ?? ''),
                'user_agent'  => substr(Request::server('HTTP_USER_AGENT') ?? '', 0, 255),
                'device_fingerprint' => substr(Request::header('X-Device-Fingerprint') ?? '', 0, 128),
                'result'      => $result,   // SUCCESS | FAIL | LOCKED
                'reason'      => $reason,
            ]);
        } catch (\Throwable $e) {
            Log::warning('shopadmin login audit write failed: ' . $e->getMessage());
        }
    }

    /** 解析并校验 shopadmin 会话（返回 [merchant_id, admin_id, errorResponse|null]） */
    private function requireShopAdminSession(): array
    {
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return [0, 0, $this->jsonResponse('未登录', 401, 'error')];

        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return [0, 0, $this->jsonResponse('会话无效', 401, 'error')];
        }
        if (($claims->realm ?? '') !== 'shopadmin') {
            return [0, 0, $this->jsonResponse('非法领域', 403, 'error')];
        }
        $merchantId = (int)($claims->merchant_id ?? 0);
        $adminId    = (int)($claims->user_id ?? 0);
        if ($merchantId <= 0 || $adminId <= 0) {
            return [0, 0, $this->jsonResponse('会话缺少租户标识', 401, 'error')];
        }
        return [$merchantId, $adminId, null];
    }

    /** 解析角色（支持 role_id 或 role_code），并校验租户一致 */
    private function resolveRoleRow(int $merchantId, $roleId, $roleCode): ?ShopAdminRole
    {
        if ($roleId) {
            /** @var ShopAdminRole|null $row */
            $row = ShopAdminRole::where('id',(int)$roleId)->where('merchant_id',$merchantId)->find();
            return $row ?: null;
        }
        if ($roleCode) {
            /** @var ShopAdminRole|null $row */
            $row = ShopAdminRole::where('code',(string)$roleCode)->where('merchant_id',$merchantId)->find();
            return $row ?: null;
        }
        return null;
    }

    /**
     * 严格按租户获取权限代码列表（ORM 联查）
     * 注意：shopadmin_permission 为全局表（无 merchant_id）。
     */
    private function getTenantPermCodesStrict(int $merchantId, int $adminId): array
    {
        try {
            if (is_callable([PermissionCacheService::class, 'getAdminPermCodesForTenant'])) {
                /** @phpstan-ignore-next-line */
                $codes = PermissionCacheService::getAdminPermCodesForTenant($merchantId, $adminId);
                if (is_array($codes)) {
                    $codes = array_values(array_unique(array_map('strval',$codes)));
                    sort($codes, SORT_STRING);
                    return $codes;
                }
            }
        } catch (\Throwable $e) {
            Log::warning('PermissionCacheService::getAdminPermCodesForTenant failed: '.$e->getMessage());
        }

        $codes = ShopAdminUserRole::alias('ur')
            ->join(['shopadmin_role' => 'r'],  'r.id = ur.role_id AND r.merchant_id = ur.merchant_id')
            ->join(['shopadmin_role_permission' => 'rp'], 'rp.role_id = ur.role_id AND rp.merchant_id = ur.merchant_id')
            ->join(['shopadmin_permission' => 'p'], 'p.id = rp.permission_id')
            ->where('ur.admin_id', $adminId)
            ->where('ur.merchant_id', $merchantId)
            ->distinct(true)
            ->column('p.code');

        $codes = array_values(array_unique(array_map('strval',$codes)));
        sort($codes, SORT_STRING);
        return $codes;
    }

    /** 失效权限缓存（优先租户维度；无则回退全局） */
    private function invalidatePermCache(int $merchantId, int $adminId): void
    {
        try {
            if (is_callable([PermissionCacheService::class, 'invalidateAdminForTenant'])) {
                /** @phpstan-ignore-next-line */
                PermissionCacheService::invalidateAdminForTenant($merchantId, $adminId);
                return;
            }
        } catch (\Throwable $e) {
            Log::warning('PermissionCacheService::invalidateAdminForTenant failed: '.$e->getMessage());
        }
        try {
            PermissionCacheService::invalidateAdmin($adminId);
        } catch (\Throwable $e) {
            Log::warning('PermissionCacheService::invalidateAdmin failed: '.$e->getMessage());
        }
    }

    // ========================= 业务接口 =========================

    /** 注册（同租户创建账号）—— 含“子账号配额”校验 + 唯一性友好报错（ORM版） */
    public function register()
    {
        $in = Request::post();
        $v = new ShopAdminRegisterValidate();
        if (!$v->check($in)) {
            return $this->jsonResponse($v->getError(), 422, 'error');
        }

        $merchantId = $this->resolveMerchantId($in);
        if (!$merchantId) return $this->jsonResponse('缺少或无法解析商户标识', 422, 'error');

        $username = strtolower(trim((string)$in['username']));
        $phone    = trim((string)($in['phone'] ?? ''));
        $email    = strtolower(trim((string)($in['email'] ?? '')));

        try {
            Db::transaction(function () use ($merchantId, $username, $phone, $email, $in) {
                // 锁商户行，校验可用与配额（ORM）
                /** @var ShopAdminMerchant|null $m */
                $m = ShopAdminMerchant::where('id',$merchantId)->lock(true)->find();
                if (!$m)                  throw new \RuntimeException('商户不存在', 404);
                if ((int)$m->getAttr('status')!==1) throw new \RuntimeException('商户已禁用', 403);

                // 子账号配额（不含首位超管）
                $subCnt = $this->countSubAccounts($merchantId);
                $maxSub = (int)$m->getAttr('max_sub_accounts');
                if ($subCnt >= $maxSub)  throw new \RuntimeException('子账号已达上限，无法新增', 409);

                // 唯一性预检
                if (ShopAdminUser::where('merchant_id',$merchantId)->where('username',$username)->find()) {
                    throw new \RuntimeException('用户名已存在（当前商户）', 409);
                }
                if ($phone !== '' && ShopAdminUser::where('merchant_id',$merchantId)->where('phone',$phone)->find()) {
                    throw new \RuntimeException('手机号已存在（当前商户）', 409);
                }
                if ($email !== '' && ShopAdminUser::where('merchant_id',$merchantId)->where('email',$email)->find()) {
                    throw new \RuntimeException('邮箱已存在（当前商户）', 409);
                }

                // 创建账号
                $hp = $this->hashPassword((string)$in['password']);
                /** @var ShopAdminUser $user */
                $user = ShopAdminUser::create([
                    'merchant_id'           => $merchantId,
                    'username'              => $username,
                    'password'              => $hp['password'],
                    'password_algo'         => $hp['password_algo'],
                    'password_meta'         => $hp['password_meta'],
                    'email'                 => ($email !== '' ? $email : null),
                    'phone'                 => ($phone !== '' ? $phone : null),
                    'status'                => 1,
                    'login_failed_attempts' => 0,
                    'mfa_enabled'           => 0,
                    'created_by'            => (int)($in['operator_id'] ?? 0) ?: null,
                    'updated_by'            => null,
                    'version'               => 0,
                ]);

                // 密码历史
                ShopAdminUserPasswordHistory::create([
                    'merchant_id'  => $merchantId,
                    'admin_id'     => (int)$user->id,
                    'password'     => $hp['password'],
                    'password_algo'=> $hp['password_algo'],
                    'password_meta'=> $hp['password_meta'],
                    'changed_at'   => date('Y-m-d H:i:s'),
                    'changed_by'   => (int)$user->id,
                    'reason'       => 'active',
                    'client_info'  => sprintf('ip=%s; ua=%s', Request::ip() ?? '', substr(Request::server('HTTP_USER_AGENT') ?? '',0,180)),
                ]);

                // 增加当前子账号计数（ORM）
                ShopAdminMerchant::where('id',$merchantId)->inc('current_sub_accounts',1)->update();
            });

            // 回查新建用户ID（按用户名/商户）
            $userId = (int)ShopAdminUser::where('merchant_id',$merchantId)->where('username',$username)->value('id');

            return $this->jsonResponse('创建成功', 200, 'success', [
                'admin_id'    => $userId,
                'merchant_id' => $merchantId
            ]);
        } catch (\RuntimeException $e) {
            $code = $e->getCode() ?: 400;
            return $this->jsonResponse($e->getMessage(), $code, 'error');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            if (stripos($msg, 'Duplicate entry') !== false) {
                if (stripos($msg, 'uk_user_merchant_phone') !== false) {
                    return $this->jsonResponse('手机号已存在（当前商户）', 409, 'error');
                }
                if (stripos($msg, 'uk_user_merchant_username') !== false || stripos($msg, 'uk_user_merchant_uname') !== false) {
                    return $this->jsonResponse('用户名已存在（当前商户）', 409, 'error');
                }
                if (stripos($msg, 'uk_user_merchant_email') !== false) {
                    return $this->jsonResponse('邮箱已存在（当前商户）', 409, 'error');
                }
            }
            Log::error('ShopAdminAuth::register failed: ' . $e->getMessage());
            return $this->jsonResponse('服务器忙，请稍后重试', 500, 'error');
        }
    }

    /** 登录（仅 access；有效 6 小时） */
    public function login()
    {
        var_dump(123);
        die();
        $in = Request::post();
        $v = new ShopAdminLoginValidate();
        if (!$v->check($in)) {
            return $this->jsonResponse($v->getError(), 422, 'error');
        }

        $merchantId = $this->resolveMerchantId($in);
        if (!$merchantId) return $this->jsonResponse('缺少或无法解析商户标识', 422, 'error');

        /** @var ShopAdminMerchant|null $m */
        $m = ShopAdminMerchant::where('id',$merchantId)->find();
        if (!$m || (int)$m->getAttr('status') !== 1) {
            return $this->jsonResponse('商户不可用或不存在', 403, 'error');
        }

        $username = strtolower(trim((string)$in['username']));
        $ip = Request::ip() ?? '';
        if ($resp = $this->throttle((string)$merchantId, $username, $ip)) {
            $this->writeLoginAudit($merchantId, null, $username, 'LOCKED', 'throttled');
            return $resp;
        }

        /** @var ShopAdminUser|null $user */
        $user = ShopAdminUser::whereNull('deleted_at')
            ->where('merchant_id',$merchantId)
            ->where('username',$username)->find();
        if (!$user) {
            $this->writeLoginAudit($merchantId, null, $username, 'FAIL', 'not_found');
            return $this->jsonResponse('账号或密码错误', 401, 'error');
        }
        if ((int)$user->getAttr('status') === 0) {
            $this->writeLoginAudit($merchantId, (int)$user->id, $username, 'FAIL', 'disabled');
            return $this->jsonResponse('账号已被禁用', 403, 'error');
        }
        if (!password_verify((string)$in['password'], (string)$user->getAttr('password'))) {
            ShopAdminUser::where('id', (int)$user->id)->inc('login_failed_attempts')->update();
            $this->writeLoginAudit($merchantId, (int)$user->id, $username, 'FAIL', 'bad_password');
            return $this->jsonResponse('账号或密码错误', 401, 'error');
        }

        // 可选 rehash
        $needRehash = password_needs_rehash(
            (string)$user->getAttr('password'),
            PASSWORD_BCRYPT,
            ['cost' => (int)(\app\common\Helper::getValue('security.admin_bcrypt_cost') ?? 12)]
        );
        if ($needRehash) {
            $hp = $this->hashPassword((string)$in['password']);
            ShopAdminUser::where('id', (int)$user->id)->update([
                'password'      => $hp['password'],
                'password_algo' => $hp['password_algo'],
                'password_meta' => $hp['password_meta'],
                'updated_at'    => date('Y-m-d H:i:s'),
                'updated_by'    => (int)$user->id,
            ]);
            ShopAdminUserPasswordHistory::create([
                'merchant_id'  => $merchantId,
                'admin_id'     => (int)$user->id,
                'password'     => $hp['password'],
                'password_algo'=> $hp['password_algo'],
                'password_meta'=> $hp['password_meta'],
                'changed_at'   => date('Y-m-d H:i:s'),
                'changed_by'   => (int)$user->id,
                'reason'       => 'security',
                'client_info'  => sprintf('ip=%s; ua=%s', $ip, substr(Request::server('HTTP_USER_AGENT') ?? '',0,180)),
            ]);
        }

        $adminId   = (int)$user->id;
        $roleCodes = $this->activeRoleCodes($merchantId, $adminId);
        $isPrimary = $this->isPrimarySuperAdmin($merchantId, $adminId);
        $roleLevel = $isPrimary ? 0 : $this->bestRoleLevel($merchantId, $adminId);
        $permCodes = $this->getTenantPermCodesStrict($merchantId, $adminId);

        // 颁发 token
        $payload = [
            'user_id'     => $adminId,
            'merchant_id' => $merchantId,
            'realm'       => 'shopadmin',
            'roles'       => $roleCodes,
            'perms'       => $permCodes,
        ];
        $tokens = $this->tokenService->issue($payload, $this->accessTtlSeconds, $this->accessTtlSeconds);
        $access = $tokens['access'] ?? ($tokens['access_token'] ?? '');

        // 状态更新
        ShopAdminUser::where('id', $adminId)
            ->inc('version')
            ->update([
                'login_failed_attempts' => 0,
                'locked_until'          => null,
                'last_login_at'         => date('Y-m-d H:i:s'),
                'last_login_ip'         => $this->ipToBin($ip),
            ]);

        // 清除节流计数桶（登录成功后）
        try {
            $bucket = sprintf('salogin:%s:%s:%s', (string)$merchantId, strtolower($username), $ip);
            Cache::delete("attempts:{$bucket}");
            Cache::delete("lock:{$bucket}");
        } catch (\Throwable $e) {
            Log::warning('clear throttle bucket failed: '.$e->getMessage());
        }

        $this->writeLoginAudit($merchantId, $adminId, $username, 'SUCCESS', null);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'            => $access,
            'expires_in'       => $this->accessTtlSeconds,
            'merchant_id'      => $merchantId,
            'roles'            => $roleCodes,
            'perms'            => $permCodes,
            'role_level'       => $roleLevel,      // int：0=首位超管；越小权限越高
            'is_primary_super' => $isPrimary ? 1 : 0,
        ]);
    }

    /** 退出 */
    public function logout()
    {
        try {
            $auth = Request::header('Authorization') ?: '';
            $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
            if ($raw) { try { $this->tokenService->revoke($raw); } catch (\Throwable $e) {} }
            Cookie::delete('refresh_token');
        } catch (\Throwable $e) {
            Log::warning('shopadmin logout error: ' . $e->getMessage());
        }
        return $this->jsonResponse('已退出', 200, 'success');
    }

    /** 本人修改密码（近 N 次不可复用；租户隔离） */
    public function changePassword()
    {
        [$merchantId, $adminId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        $in = Request::post();
        $v = new ShopAdminChangePasswordValidate();
        if (!$v->check($in)) {
            return $this->jsonResponse($v->getError(), 422, 'error');
        }

        /** @var ShopAdminUser|null $user */
        $user = ShopAdminUser::whereNull('deleted_at')
            ->where('merchant_id',$merchantId)
            ->where('id',$adminId)->find();
        if (!$user) return $this->jsonResponse('账号不存在', 404, 'error');

        if (!password_verify($in['old_password'], (string)$user->getAttr('password'))) {
            return $this->jsonResponse('旧密码不正确', 400, 'error');
        }

        $N = (int)(\app\common\Helper::getValue('security.pwd_history_depth') ?? 5);
        $history = ShopAdminUserPasswordHistory::where('merchant_id',$merchantId)
            ->where('admin_id',$adminId)->order('changed_at','desc')->limit($N)->select();
        foreach ($history as $row) {
            if (password_verify($in['new_password'], (string)$row->getAttr('password'))) {
                return $this->jsonResponse("新密码不能与最近 {$N} 次使用的密码相同", 400, 'error');
            }
        }

        $hp = $this->hashPassword($in['new_password']);

        try {
            Db::transaction(function () use ($merchantId, $adminId, $hp) {
                ShopAdminUser::where('id',$adminId)
                    ->where('merchant_id',$merchantId)
                    ->inc('version')
                    ->update([
                        'password'      => $hp['password'],
                        'password_algo' => $hp['password_algo'],
                        'password_meta' => $hp['password_meta'],
                        'updated_at'    => date('Y-m-d H:i:s'),
                        'updated_by'    => $adminId,
                    ]);

                ShopAdminUserPasswordHistory::create([
                    'merchant_id'  => $merchantId,
                    'admin_id'     => $adminId,
                    'password'     => $hp['password'],
                    'password_algo'=> $hp['password_algo'],
                    'password_meta'=> $hp['password_meta'],
                    'changed_at'   => date('Y-m-d H:i:s'),
                    'changed_by'   => $adminId,
                    'reason'       => 'active',
                    'client_info'  => sprintf('ip=%s; ua=%s', Request::ip() ?? '', substr(Request::server('HTTP_USER_AGENT') ?? '',0,180)),
                ]);
            });

            return $this->jsonResponse('密码已更新', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('ShopAdminAuth::changePassword failed: ' . $e->getMessage());
            return $this->jsonResponse('服务器忙，请稍后重试', 500, 'error');
        }
    }

    /**
     * 是否为“本商户超管”（启用且在有效期内；按租户隔离）
     */
    private function isSuperAdminInTenant(int $merchantId, int $adminId): bool
    {
        $now = date('Y-m-d H:i:s');
        return ShopAdminUserRole::alias('ur')
                ->join(['shopadmin_role' => 'r'], 'r.id = ur.role_id AND r.merchant_id = ur.merchant_id')
                ->where('ur.merchant_id', $merchantId)
                ->where('ur.admin_id', $adminId)
                ->where('r.code', $this->SUPER_CODE)
                ->where('r.status', 1)
                // 角色有效期 [from, to)
                ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                // 分配有效期 [from, to)
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
                ->count() > 0;
    }

    /**
     * 修改子账号信息（仅“商户超管”可操作；不可修改首位超管）
     * 可修改字段（可选）：username/email/phone/status(0|1)
     */
    public function updateSubAccount()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        if (!$this->isSuperAdminInTenant($merchantId, $callerId)) {
            return $this->jsonResponse('无权限：仅商户超管可操作', 403, 'error');
        }

        $in = Request::post();
        $targetId = (int)($in['target_admin_id'] ?? 0);
        if ($targetId <= 0) return $this->jsonResponse('缺少 target_admin_id', 422, 'error');

        /** @var ShopAdminUser|null $u */
        $u = ShopAdminUser::where('merchant_id',$merchantId)->where('id',$targetId)->whereNull('deleted_at')->find();
        if (!$u) return $this->jsonResponse('目标账号不存在', 404, 'error');
        if ($this->isPrimarySuperAdmin($merchantId, $targetId)) {
            return $this->jsonResponse('禁止修改首位超管信息', 403, 'error');
        }

        $sets = [];
        $usernameProvided = array_key_exists('username', $in);
        $emailProvided    = array_key_exists('email',    $in);
        $phoneProvided    = array_key_exists('phone',    $in);
        $statusProvided   = array_key_exists('status',   $in);

        if (!$usernameProvided && !$emailProvided && !$phoneProvided && !$statusProvided) {
            return $this->jsonResponse('无可更新字段（可传：username/email/phone/status）', 400, 'error');
        }

        if ($usernameProvided) {
            $newUsername = strtolower(trim((string)$in['username']));
            if ($newUsername === '') return $this->jsonResponse('username 不能为空', 422, 'error');
            if ($newUsername !== (string)$u->getAttr('username')) {
                $dup = ShopAdminUser::where('merchant_id',$merchantId)
                    ->where('username',$newUsername)->where('id','<>',$targetId)->find();
                if ($dup) return $this->jsonResponse('用户名已存在（当前商户）', 409, 'error');
                $sets['username'] = $newUsername;
            }
        }

        if ($emailProvided) {
            $newEmail = strtolower(trim((string)$in['email']));
            $newEmail = ($newEmail === '') ? null : $newEmail;
            if ($newEmail !== (string)$u->getAttr('email')) {
                if ($newEmail !== null) {
                    $dup = ShopAdminUser::where('merchant_id',$merchantId)
                        ->where('email',$newEmail)->where('id','<>',$targetId)->find();
                    if ($dup) return $this->jsonResponse('邮箱已存在（当前商户）', 409, 'error');
                }
                $sets['email'] = $newEmail;
            }
        }

        if ($phoneProvided) {
            $newPhone = trim((string)$in['phone']);
            $newPhone = ($newPhone === '') ? null : $newPhone;
            if ($newPhone !== (string)$u->getAttr('phone')) {
                if ($newPhone !== null) {
                    $dup = ShopAdminUser::where('merchant_id',$merchantId)
                        ->where('phone',$newPhone)->where('id','<>',$targetId)->find();
                    if ($dup) return $this->jsonResponse('手机号已存在（当前商户）', 409, 'error');
                }
                $sets['phone'] = $newPhone;
            }
        }

        if ($statusProvided) {
            $sv = (int)$in['status'];
            if (!in_array($sv, [0,1], true)) return $this->jsonResponse('status 仅允许 0 或 1', 422, 'error');
            if ($sv !== (int)$u->getAttr('status')) {
                $sets['status'] = $sv;
            }
        }

        if (!$sets) return $this->jsonResponse('没有需要更新的内容', 400, 'error');

        try {
            $sets['updated_at'] = date('Y-m-d H:i:s');
            $sets['updated_by'] = $callerId;
            ShopAdminUser::where('id',$targetId)->where('merchant_id',$merchantId)
                ->inc('version')->update($sets);

            return $this->jsonResponse('更新成功', 200, 'success');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            if (stripos($msg, 'Duplicate entry') !== false) {
                if (stripos($msg, 'uk_user_merchant_username') !== false || stripos($msg, 'uk_user_merchant_uname') !== false) {
                    return $this->jsonResponse('用户名已存在（当前商户）', 409, 'error');
                }
                if (stripos($msg, 'uk_user_merchant_email') !== false) {
                    return $this->jsonResponse('邮箱已存在（当前商户）', 409, 'error');
                }
                if (stripos($msg, 'uk_user_merchant_phone') !== false) {
                    return $this->jsonResponse('手机号已存在（当前商户）', 409, 'error');
                }
            }
            Log::error('updateSubAccount error: ' . $e->getMessage());
            return $this->jsonResponse('更新失败，请稍后重试', 500, 'error');
        }
    }

    /**
     * 删除子账号（软删 + 回收子账号配额；仅“商户超管”可操作；禁止删除首位超管与自己）
     * 入参：target_admin_id
     */
    /**
     * 删除子账号（物理删除 + 回收子账号配额；仅“商户超管”可操作；禁止删除首位超管与自己）
     * 入参：target_admin_id
     */
    public function deleteSubAccount()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        // 仅“商户超管”可操作
        if (!$this->isSuperAdminInTenant($merchantId, $callerId)) {
            return $this->jsonResponse('无权限：仅商户超管可操作', 403, 'error');
        }

        $targetId = (int)(Request::post('target_admin_id') ?? 0);
        if ($targetId <= 0) return $this->jsonResponse('缺少 target_admin_id', 422, 'error');

        $primaryId = $this->primarySuperAdminId($merchantId);
        if ($targetId === $callerId)  return $this->jsonResponse('禁止删除自己', 400, 'error');
        if ($targetId === $primaryId) return $this->jsonResponse('禁止删除首位超管', 403, 'error');

        try {
            Db::transaction(function () use ($merchantId, $targetId) {
                // 锁定目标用户
                $u = ShopAdminUser::where('id', $targetId)
                    ->where('merchant_id', $merchantId)
                    ->lock(true)
                    ->find();
                if (!$u) {
                    throw new \RuntimeException('NOT_FOUND');
                }

                // 清理关联（避免残留/外键约束）
                ShopAdminUserRole::where([
                    'merchant_id' => $merchantId,
                    'admin_id'    => $targetId,
                ])->delete();

                ShopAdminUserPasswordHistory::where([
                    'merchant_id' => $merchantId,
                    'admin_id'    => $targetId,
                ])->delete();

                // 如有其它绑定表（设备指纹、MFA、会话、通知偏好等），在此追加清理

                // 物理删除账号
                ShopAdminUser::where('id', $targetId)
                    ->where('merchant_id', $merchantId)
                    ->delete();

                // 回收配额（原子表达式防止负数）
                ShopAdminMerchant::where('id', $merchantId)->update([
                    'current_sub_accounts' => Db::raw('CASE WHEN current_sub_accounts>0 THEN current_sub_accounts-1 ELSE 0 END')
                ]);
            });

            // 失效被删用户的权限缓存
            $this->invalidatePermCache($merchantId, $targetId);

            return $this->jsonResponse('账号已删除', 200, 'success');
        } catch (\RuntimeException $e) {
            if ($e->getMessage() === 'NOT_FOUND') {
                return $this->jsonResponse('目标账号不存在或已删除', 404, 'error');
            }
            Log::error('deleteSubAccount runtime error: ' . $e->getMessage());
            return $this->jsonResponse('删除失败，请稍后重试', 500, 'error');
        } catch (\Throwable $e) {
            Log::error('deleteSubAccount failed: ' . $e->getMessage());
            return $this->jsonResponse('删除失败，请稍后重试', 500, 'error');
        }
    }


    /**
     * 重置他人密码（仅初始超管）
     * 入参：target_admin_id, new_password
     */
    public function resetOtherPassword()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        $targetId = (int)(Request::post('target_admin_id') ?? 0);
        $newPwd   = (string)(Request::post('new_password') ?? '');
        $token    = (string)(Request::post('confirmation_token') ?? '');
        if ($targetId <= 0 || $newPwd === '') return $this->jsonResponse('缺少必要参数', 422, 'error');

        if (!$this->isPrimarySuperAdmin($merchantId, $callerId)) {
            return $this->jsonResponse('无权限：仅初始超管可执行', 403, 'error');
        }

        // 二次确认
        $svc = new ShopAdminSensitiveOperationService();
        if (!$svc->verifyConfirmed($merchantId, $callerId, 'user.reset_password', $token)) {
            return $this->jsonResponse('敏感操作未确认或已过期', 400, 'error');
        }

        $primaryId = $this->primarySuperAdminId($merchantId);
        if ($targetId === $primaryId) {
            return $this->jsonResponse('禁止重置初始超管自身密码，请走“本人改密”', 400, 'error');
        }

        /** @var ShopAdminUser|null $u */
        $u = ShopAdminUser::whereNull('deleted_at')->where('merchant_id',$merchantId)->where('id',$targetId)->find();
        if (!$u) return $this->jsonResponse('目标账号不存在', 404, 'error');

        // 近 N 次不可复用
        $N = (int)(\app\common\Helper::getValue('security.pwd_history_depth') ?? 5);
        $history = ShopAdminUserPasswordHistory::where('merchant_id',$merchantId)
            ->where('admin_id',$targetId)->order('changed_at','desc')->limit($N)->select();
        foreach ($history as $row) {
            if (password_verify($newPwd, (string)$row->getAttr('password'))) {
                return $this->jsonResponse("新密码不能与该账号最近 {$N} 次使用的密码相同", 400, 'error');
            }
        }

        $hp = $this->hashPassword($newPwd);

        try {
            Db::transaction(function () use ($merchantId, $callerId, $targetId, $hp) {
                ShopAdminUser::where('id',$targetId)->where('merchant_id',$merchantId)
                    ->inc('version')->update([
                        'password'      => $hp['password'],
                        'password_algo' => $hp['password_algo'],
                        'password_meta' => $hp['password_meta'],
                        'updated_at'    => date('Y-m-d H:i:s'),
                        'updated_by'    => $callerId,
                    ]);

                ShopAdminUserPasswordHistory::create([
                    'merchant_id'  => $merchantId,
                    'admin_id'     => $targetId,
                    'password'     => $hp['password'],
                    'password_algo'=> $hp['password_algo'],
                    'password_meta'=> $hp['password_meta'],
                    'changed_at'   => date('Y-m-d H:i:s'),
                    'changed_by'   => $callerId,
                    'reason'       => 'reset',
                    'client_info'  => sprintf('ip=%s; ua=%s', Request::ip() ?? '', substr(Request::server('HTTP_USER_AGENT') ?? '',0,180)),
                ]);
            });

            return $this->jsonResponse('密码已重置', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('ShopAdminAuth::resetOtherPassword failed: ' . $e->getMessage());
            return $this->jsonResponse('重置失败，请稍后重试', 500, 'error');
        }
    }

    /**
     * 角色分配（仅首位超管 + 二次确认）
     * 入参：admin_id, role_id|role_code, valid_from?, valid_to?, confirmation_token
     */
    public function assignRoleToUser()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        if (!$this->isPrimarySuperAdmin($merchantId, $callerId)) {
            return $this->jsonResponse('无权限：仅初始超管可分配角色', 403, 'error');
        }

        $adminId = (int)(Request::post('admin_id') ?? 0);
        $roleId  = (int)(Request::post('role_id') ?? 0);
        $roleCode= (string)(Request::post('role_code') ?? '');
        $vfRaw = Request::post('valid_from', null);
        $vtRaw = Request::post('valid_to', null);
        if (is_string($vfRaw) && trim($vfRaw) === '') $vfRaw = null;
        if (is_string($vtRaw) && trim($vtRaw) === '') $vtRaw = null;

        $vf = $this->normalizeDT($vfRaw);
        $vt = $this->normalizeDT($vtRaw);
        $token   = (string)(Request::post('confirmation_token') ?? '');

        if ($adminId<=0 || ($roleId<=0 && $roleCode==='')) {
            return $this->jsonResponse('缺少 admin_id 或 role_id/role_code', 422, 'error');
        }
        if ($vf === '__INVALID__' || $vt === '__INVALID__') {
            return $this->jsonResponse('valid_from/valid_to 时间格式不正确', 422, 'error');
        }
        if ($vf && $vt && strtotime($vf) >= strtotime($vt)) {
            return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
        }

        // 二次确认校验
        $svc = new ShopAdminSensitiveOperationService();
        if (!$svc->verifyConfirmed($merchantId, $callerId, 'role.assign', $token)) {
            return $this->jsonResponse('敏感操作未确认或已过期', 400, 'error');
        }

        // 目标用户校验
        $user = ShopAdminUser::whereNull('deleted_at')->where('merchant_id',$merchantId)->where('id',$adminId)->find();
        if (!$user) return $this->jsonResponse('目标账号不存在', 404, 'error');

        // 角色解析 + 租户校验
        $role = $this->resolveRoleRow($merchantId, $roleId, $roleCode);
        if (!$role) return $this->jsonResponse('角色不存在（或不属于当前商户）', 404, 'error');

        try {
            Db::transaction(function () use ($merchantId, $callerId, $adminId, $role, $vf, $vt) {
                // 存在则更新有效期；不存在则创建
                $map = [
                    'merchant_id' => $merchantId,
                    'admin_id'    => $adminId,
                    'role_id'     => (int)$role->id,
                ];
                $exist = ShopAdminUserRole::where($map)->find();
                $now = date('Y-m-d H:i:s');

                if ($exist) {
                    ShopAdminUserRole::where($map)->update([
                        'valid_from'  => $vf,
                        'valid_to'    => $vt,
                        'assigned_at' => $now,
                        'assigned_by' => $callerId,
                    ]);
                } else {
                    ShopAdminUserRole::create([
                        'merchant_id' => $merchantId,
                        'admin_id'    => $adminId,
                        'role_id'     => (int)$role->id,
                        'valid_from'  => $vf,
                        'valid_to'    => $vt,
                        'assigned_at' => $now,
                        'assigned_by' => $callerId,
                    ]);
                }
            });

            // 失效权限缓存（目标账号）
            $this->invalidatePermCache($merchantId, $adminId);

            return $this->jsonResponse('分配成功', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('ShopAdminAuth::assignRoleToUser failed: '.$e->getMessage());
            return $this->jsonResponse('分配失败，请稍后重试', 500, 'error');
        }
    }

    /**
     * 角色撤销（仅首位超管 + 二次确认）
     * 入参：admin_id, role_id|role_code, confirmation_token
     */
    public function revokeRoleFromUser()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        if (!$this->isPrimarySuperAdmin($merchantId, $callerId)) {
            return $this->jsonResponse('无权限：仅初始超管可撤销角色', 403, 'error');
        }

        $adminId = (int)(Request::post('admin_id') ?? 0);
        $roleId  = (int)(Request::post('role_id') ?? 0);
        $roleCode= (string)(Request::post('role_code') ?? '');
        $token   = (string)(Request::post('confirmation_token') ?? '');

        if ($adminId<=0 || ($roleId<=0 && $roleCode==='')) {
            return $this->jsonResponse('缺少 admin_id 或 role_id/role_code', 422, 'error');
        }

        // 二次确认校验
        $svc = new ShopAdminSensitiveOperationService();
        if (!$svc->verifyConfirmed($merchantId, $callerId, 'role.revoke', $token)) {
            return $this->jsonResponse('敏感操作未确认或已过期', 400, 'error');
        }

        // 目标用户校验
        $user = ShopAdminUser::whereNull('deleted_at')->where('merchant_id',$merchantId)->where('id',$adminId)->find();
        if (!$user) return $this->jsonResponse('目标账号不存在', 404, 'error');

        // 角色解析 + 租户校验
        $role = $this->resolveRoleRow($merchantId, $roleId, $roleCode);
        if (!$role) return $this->jsonResponse('角色不存在（或不属于当前商户）', 404, 'error');

        try {
            $affected = 0;
            Db::transaction(function () use ($merchantId, $adminId, $role, &$affected) {
                $affected = ShopAdminUserRole::where([
                    'merchant_id' => $merchantId,
                    'admin_id'    => $adminId,
                    'role_id'     => (int)$role->id,
                ])->delete();
            });

            // 失效权限缓存（目标账号）
            if ($affected) $this->invalidatePermCache($merchantId, $adminId);

            return $this->jsonResponse('撤销成功', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('ShopAdminAuth::revokeRoleFromUser failed: '.$e->getMessage());
            return $this->jsonResponse('撤销失败，请稍后重试', 500, 'error');
        }
    }

    /**
     * 管理员列表（本租户）
     */
    public function listAdmins()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        $in = Request::post();
        $page      = max(1, (int)($in['page'] ?? 1));
        $pageSize  = min(200, max(1, (int)($in['page_size'] ?? 20)));
        $keyword   = trim((string)($in['keyword'] ?? ''));
        $roleCode  = trim((string)($in['role_code'] ?? ''));
        $statusStr = $in['status'] ?? null;
        $status    = ($statusStr === '' || $statusStr === null) ? null : (int)$statusStr;

        $allowSort = [
            'id'            => 'u.id',
            'username'      => 'u.username',
            'status'        => 'u.status',
            'created_at'    => 'u.created_at',
            'updated_at'    => 'u.updated_at',
            'last_login_at' => 'u.last_login_at',
        ];
        $sortField = (string)($in['sort_field'] ?? 'id');
        $sortOrder = strtolower((string)($in['sort_order'] ?? 'desc'));
        $sortCol   = $allowSort[$sortField] ?? 'u.id';
        $sortOrd   = in_array($sortOrder, ['asc','desc'], true) ? $sortOrder : 'desc';

        $q = ShopAdminUser::alias('u')
            ->whereNull('u.deleted_at')
            ->where('u.merchant_id',$merchantId);

        if ($status !== null) $q->where('u.status',$status);
        if ($keyword !== '') {
            $kw = '%' . str_replace(['%','_'], ['\%','\_'], $keyword) . '%';
            $q->where(function($w) use ($kw) {
                $w->whereLike('u.username', $kw)
                    ->whereOr('u.email', 'like', $kw)
                    ->whereOr('u.phone', 'like', $kw);
            });
        }

        if ($roleCode !== '') {
            $now = date('Y-m-d H:i:s');
            $q->join(['shopadmin_user_role' => 'ur'], 'ur.admin_id = u.id AND ur.merchant_id = u.merchant_id')
                ->join(['shopadmin_role' => 'r'], 'r.id = ur.role_id AND r.merchant_id = u.merchant_id')
                ->where('r.code', $roleCode)
                ->where('r.status', 1)
                ->where(function($w) use ($now){ $w->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($w) use ($now){ $w->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                ->where(function($w) use ($now){ $w->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
                ->where(function($w) use ($now){ $w->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
                ->group('u.id');
        }

        try {
            $total = $q->count();
            $rows = $q->field('u.id,u.username,u.email,u.phone,u.status,u.created_at,u.updated_at,u.last_login_at,u.last_login_ip')
                ->order($sortCol, $sortOrd)
                ->page($page, $pageSize)
                ->select();
        } catch (\Throwable $e) {
            Log::error('查询管理员列表失败：' . $e->getMessage());
            return $this->jsonResponse('查询失败，请稍后重试', 500, 'error');
        }

        $items = [];
        $primaryId = $this->primarySuperAdminId($merchantId);
        foreach ($rows as $r) {
            /** @var ShopAdminUser $r */
            $adminId   = (int)$r->getAttr('id');
            $roleCodes = $this->activeRoleCodes($merchantId, $adminId);
            $isPrimary = ($adminId === $primaryId);
            $roleLevel = $isPrimary ? 0 : $this->bestRoleLevel($merchantId, $adminId);

            $items[] = [
                'id'              => $adminId,
                'username'        => (string)$r->getAttr('username'),
                'email'           => (string)$r->getAttr('email'),
                'phone'           => (string)$r->getAttr('phone'),
                'status'          => (int)$r->getAttr('status'),
                'created_at'      => (string)$r->getAttr('created_at'),
                'updated_at'      => (string)$r->getAttr('updated_at'),
                'last_login_at'   => (string)$r->getAttr('last_login_at'),
                'last_login_ip'   => $this->binToIp($r->getAttr('last_login_ip')),
                'roles'           => $roleCodes,
                'is_primary_super'=> $isPrimary ? 1 : 0,
                'role_level'      => $roleLevel,
            ];
        }

        return $this->jsonResponse('ok', 200, 'success', [
            'list'       => $items,
            'page'       => $page,
            'page_size'  => $pageSize,
            'total'      => $total,
            'sort'       => ['field' => $sortField, 'order' => $sortOrd],
            'filters'    => ['keyword' => $keyword, 'status' => $status, 'role_code' => $roleCode],
        ]);
    }



    // ========================= /业务接口 =========================
}
