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

// 如你项目中已有同名模型，保持引用即可
use app\shopadmin\model\ShopAdminPermission;
use app\shopadmin\model\ShopAdminRolePermission;

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
        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            config('jwt') ?: []
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
        $cost = (int)(config('security.admin_bcrypt_cost') ?? 12);
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

    /** 解析商户标识：支持 merchant_id / merchant_code / merchant_name */
    private function resolveMerchantId(array $in): ?int
    {
        if (!empty($in['merchant_id'])) return (int)$in['merchant_id'];
        if (!empty($in['merchant_code'])) {
            $id = Db::name('shopadmin_merchant')->where('merchant_code', $in['merchant_code'])->value('id');
            return $id ? (int)$id : null;
        }
        if (!empty($in['merchant_name'])) {
            $id = Db::name('shopadmin_merchant')->where('merchant_name', $in['merchant_name'])->value('id');
            return $id ? (int)$id : null;
        }
        return null;
    }

    /** 找到本租户“首位超管”的 admin_id（按创建时间/ID最早） */
    private function primarySuperAdminId(int $merchantId): ?int
    {
        $row = Db::table('shopadmin_user')->alias('u')
            ->join(['shopadmin_user_role'=>'ur'],'ur.admin_id = u.id AND ur.merchant_id = u.merchant_id')
            ->join(['shopadmin_role'=>'r'],'r.id = ur.role_id AND r.merchant_id = u.merchant_id')
            ->where('u.merchant_id',$merchantId)
            ->whereNull('u.deleted_at')
            ->where('r.code',$this->SUPER_CODE)
            ->order('u.created_at','asc')
            ->order('u.id','asc')
            ->field('u.id')
            ->limit(1)->find();
        return $row ? (int)$row['id'] : null;
    }

    /** 是否本租户“首位超管” */
    private function isPrimarySuperAdmin(int $merchantId, int $adminId): bool
    {
        $pid = $this->primarySuperAdminId($merchantId);
        if (!$pid) return false;
        return $pid === $adminId;
    }

    /** 统计本租户“子账号”数量（不含首位超管；仅未软删） */
    private function countSubAccounts(int $merchantId): int
    {
        $primaryId = $this->primarySuperAdminId($merchantId);
        $q = Db::name('shopadmin_user')
            ->where('merchant_id',$merchantId)
            ->whereNull('deleted_at');
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

    /** 规范化时间字段：空串->NULL；合法->标准化到秒；非法返回 '__INVALID__' */
    private function normalizeDT($v)
    {
        if (!isset($v)) return null;
        $v = trim((string)$v);
        if ($v === '') return null;
        $ts = strtotime($v);
        if ($ts === false) return '__INVALID__';
        return date('Y-m-d H:i:s', $ts);
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

    /** ✅ 严格按租户获取权限（纯 ORM；与现有表结构精确匹配） */
    private function getTenantPermCodesStrict(int $merchantId, int $adminId): array
    {
        // 优先尝试租户维度缓存接口
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

        // 纯 ORM 联查：ur ➜ r ➜ rp ➜ p，全程强制 merchant_id 一致，避免串租户
        $codes = ShopAdminUserRole::alias('ur')
            ->join(['shopadmin_role' => 'r'], 'r.id = ur.role_id AND r.merchant_id = ur.merchant_id')
            ->join(['shopadmin_role_permission' => 'rp'], 'rp.role_id = ur.role_id AND rp.merchant_id = ur.merchant_id')
            ->join(['shopadmin_permission' => 'p'], 'p.id = rp.permission_id AND p.merchant_id = ur.merchant_id')
            ->where('ur.admin_id', $adminId)
            ->where('ur.merchant_id', $merchantId)
            ->distinct(true)
            ->column('p.code');

        $codes = array_values(array_unique(array_map('strval',$codes)));
        sort($codes, SORT_STRING);
        return $codes;
    }

    /** ✅ 失效权限缓存（优先租户维度；无则回退全局） */
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

    /** 注册（同租户创建账号）—— 含“子账号配额”校验 */
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

        try {
            Db::startTrans();

            // 锁商户行
            $m = Db::name('shopadmin_merchant')->where('id',$merchantId)->lock(true)->find();
            if (!$m) throw new \RuntimeException('商户不存在');
            if ((int)$m['status'] !== 1) throw new \RuntimeException('商户已禁用');

            // 计算当前子账号数（不含首位超管）
            $subCnt = $this->countSubAccounts($merchantId);
            $maxSub = (int)$m['max_sub_accounts'];
            if ($subCnt >= $maxSub) {
                Db::rollback();
                return $this->jsonResponse('子账号已达上限，无法新增', 409, 'error');
            }

            // 同租户用户名唯一
            $exists = ShopAdminUser::whereNull('deleted_at')
                ->where('merchant_id',$merchantId)
                ->where('username',$username)->find();
            if ($exists) {
                Db::rollback();
                return $this->jsonResponse('用户名已存在（当前商户）', 409, 'error');
            }

            $hp = $this->hashPassword((string)$in['password']);

            /** @var ShopAdminUser $user */
            $user = ShopAdminUser::create([
                'merchant_id'           => $merchantId,
                'username'              => $username,
                'password'              => $hp['password'],
                'password_algo'         => $hp['password_algo'],
                'password_meta'         => $hp['password_meta'],
                'email'                 => $in['email'] ?? null,
                'phone'                 => $in['phone'] ?? null,
                'status'                => 1,
                'login_failed_attempts' => 0,
                'mfa_enabled'           => 0,
                'created_by'            => (int)($in['operator_id'] ?? 0) ?: null,
                'updated_by'            => null,
                'version'               => 0,
            ]);

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

            // 原子更新商户当前子账号数（不含首位超管）
            Db::name('shopadmin_merchant')->where('id',$merchantId)->inc('current_sub_accounts',1)->update();

            Db::commit();
            return $this->jsonResponse('创建成功', 200, 'success', [
                'admin_id'    => (int)$user->id,
                'merchant_id' => $merchantId
            ]);
        } catch (\Throwable $e) {
            if (Db::isTransaction()) Db::rollback();
            Log::error('ShopAdminAuth::register failed: ' . $e->getMessage());
            return $this->jsonResponse('服务器忙，请稍后重试', 500, 'error');
        }
    }

    /** 登录（仅 access；有效 6 小时） */
    public function login()
    {
        $in = Request::post();
        $v = new ShopAdminLoginValidate();
        if (!$v->check($in)) {
            return $this->jsonResponse($v->getError(), 422, 'error');
        }

        $merchantId = $this->resolveMerchantId($in);
        if (!$merchantId) return $this->jsonResponse('缺少或无法解析商户标识', 422, 'error');

        $m = Db::name('shopadmin_merchant')->where('id',$merchantId)->find();
        if (!$m || (int)$m['status'] !== 1) {
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
            ['cost' => (int)(config('security.admin_bcrypt_cost') ?? 12)]
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
        $roleLevel = $isPrimary ? $this->SUPER_CODE : $this->bestRoleLevel($merchantId, $adminId);

        // ✅ 严格租户隔离的权限集
        $permCodes = $this->getTenantPermCodesStrict($merchantId, $adminId);

        $payload = [
            'user_id'     => $adminId,
            'merchant_id' => $merchantId,
            'realm'       => 'shopadmin',
            'roles'       => $roleCodes,
            'perms'       => $permCodes,
        ];
        $tokens = $this->tokenService->issue($payload, $this->accessTtlSeconds, $this->accessTtlSeconds);
        $access = $tokens['access'] ?? ($tokens['access_token'] ?? '');

        ShopAdminUser::where('id', $adminId)
            ->inc('version')
            ->update([
                'login_failed_attempts' => 0,
                'locked_until'          => null,
                'last_login_at'         => date('Y-m-d H:i:s'),
                'last_login_ip'         => $this->ipToBin($ip),
            ]);

        $this->writeLoginAudit($merchantId, $adminId, $username, 'SUCCESS', null);

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'            => $access,
            'expires_in'       => $this->accessTtlSeconds,
            'merchant_id'      => $merchantId,
            'roles'            => $roleCodes,
            'perms'            => $permCodes,
            'role_level'       => $roleLevel,
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

        $N = (int)(config('security.pwd_history_depth') ?? 5);
        $history = ShopAdminUserPasswordHistory::where('merchant_id',$merchantId)
            ->where('admin_id',$adminId)->order('changed_at','desc')->limit($N)->select();
        foreach ($history as $row) {
            if (password_verify($in['new_password'], (string)$row->getAttr('password'))) {
                return $this->jsonResponse("新密码不能与最近 {$N} 次使用的密码相同", 400, 'error');
            }
        }

        $hp = $this->hashPassword($in['new_password']);

        try {
            Db::startTrans();

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

            Db::commit();
            return $this->jsonResponse('密码已更新', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('ShopAdminAuth::changePassword failed: ' . $e->getMessage());
            return $this->jsonResponse('服务器忙，请稍后重试', 500, 'error');
        }
    }

    /**
     * 删除管理员（软删 + 回收配额）
     * 约束：仅本租户“首位 super_shopadmin”可操作；不可删除自己与首位超管本身
     * 入参：target_admin_id
     */
    public function deleteAdmin()
    {
        [$merchantId, $callerId, $err] = $this->requireShopAdminSession();
        if ($err) return $err;

        $targetId = (int)(Request::post('target_admin_id') ?? 0);
        if ($targetId <= 0) return $this->jsonResponse('缺少目标账号ID', 422, 'error');

        // 权限校验：必须为首位超管
        if (!$this->isPrimarySuperAdmin($merchantId, $callerId)) {
            return $this->jsonResponse('无权限：仅初始超管可执行', 403, 'error');
        }

        // 不能删除自己；不能删除首位超管
        $primaryId = $this->primarySuperAdminId($merchantId);
        if ($targetId === $callerId || $targetId === $primaryId) {
            return $this->jsonResponse('禁止删除自身或初始超管', 400, 'error');
        }

        try {
            Db::startTrans();

            $u = ShopAdminUser::where('id',$targetId)->where('merchant_id',$merchantId)->whereNull('deleted_at')->find();
            if (!$u) {
                Db::rollback();
                return $this->jsonResponse('目标账号不存在或已删除', 404, 'error');
            }

            // 软删 + 停用
            ShopAdminUser::where('id',$targetId)->where('merchant_id',$merchantId)->update([
                'status'     => 0,
                'deleted_at' => date('Y-m-d H:i:s'),
                'updated_at' => date('Y-m-d H:i:s'),
                'updated_by' => $callerId,
            ]);

            // 回收配额（原子自减，不低于0）
            Db::name('shopadmin_merchant')->where('id',$merchantId)->lock(true)->update([
                'current_sub_accounts' => Db::raw('GREATEST(current_sub_accounts - 1, 0)')
            ]);

            Db::commit();
            return $this->jsonResponse('账号已删除', 200, 'success');
        } catch (\Throwable $e) {
            if (Db::isTransaction()) Db::rollback();
            Log::error('ShopAdminAuth::deleteAdmin failed: ' . $e->getMessage());
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
        $N = (int)(config('security.pwd_history_depth') ?? 5);
        $history = ShopAdminUserPasswordHistory::where('merchant_id',$merchantId)
            ->where('admin_id',$targetId)->order('changed_at','desc')->limit($N)->select();
        foreach ($history as $row) {
            if (password_verify($newPwd, (string)$row->getAttr('password'))) {
                return $this->jsonResponse("新密码不能与该账号最近 {$N} 次使用的密码相同", 400, 'error');
            }
        }

        $hp = $this->hashPassword($newPwd);

        try {
            Db::startTrans();

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

            Db::commit();
            return $this->jsonResponse('密码已重置', 200, 'success');
        } catch (\Throwable $e) {
            if (Db::isTransaction()) Db::rollback();
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
        $vf      = $this->normalizeDT(Request::post('valid_from'));
        $vt      = $this->normalizeDT(Request::post('valid_to'));
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
            Db::startTrans();

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

            Db::commit();

            // 失效权限缓存（目标账号）—— 优先租户维度
            $this->invalidatePermCache($merchantId, $adminId);

            return $this->jsonResponse('分配成功', 200, 'success');
        } catch (\Throwable $e) {
            if (Db::isTransaction()) Db::rollback();
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
            Db::startTrans();

            $affected = ShopAdminUserRole::where([
                'merchant_id' => $merchantId,
                'admin_id'    => $adminId,
                'role_id'     => (int)$role->id,
            ])->delete();

            Db::commit();

            // 失效权限缓存（目标账号）—— 优先租户维度
            if ($affected) $this->invalidatePermCache($merchantId, $adminId);

            return $this->jsonResponse('撤销成功', 200, 'success');
        } catch (\Throwable $e) {
            if (Db::isTransaction()) Db::rollback();
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
            $roleLevel = $isPrimary ? $this->SUPER_CODE : $this->bestRoleLevel($merchantId, $adminId);

            $items[] = [
                'id'             => $adminId,
                'username'       => (string)$r->getAttr('username'),
                'email'          => (string)$r->getAttr('email'),
                'phone'          => (string)$r->getAttr('phone'),
                'status'         => (int)$r->getAttr('status'),
                'created_at'     => (string)$r->getAttr('created_at'),
                'updated_at'     => (string)$r->getAttr('updated_at'),
                'last_login_at'  => (string)$r->getAttr('last_login_at'),
                'last_login_ip'  => $this->binToIp($r->getAttr('last_login_ip')),
                'roles'          => $roleCodes,
                'is_primary_super'=> $isPrimary ? 1 : 0,
                'role_level'     => $roleLevel,
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
}
