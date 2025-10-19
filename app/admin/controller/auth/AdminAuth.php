<?php
declare(strict_types=1);

namespace app\admin\controller\auth;

use app\BaseController;
use think\facade\Request;
use think\facade\Db;
use think\facade\Cache;
use think\facade\Cookie;
use think\facade\Log;

use app\admin\validate\AdminLoginValidate;
use app\admin\validate\AdminRegisterValidate;
use app\admin\validate\AdminChangePasswordValidate;

use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;

use app\common\service\PermissionCacheService;     // 基于缓存的权限读写层
use app\admin\model\AdminUser;                     // ORM：管理员
use app\admin\model\AdminUserRole;                 // ORM：用户-角色
use app\admin\model\AdminRole;                     // ORM：角色
use app\admin\model\AdminUserPasswordHistory;      // ORM：密码历史
use app\admin\model\AdminUserLoginAudit;           // ORM：登录审计

/**
 * Admin 认证控制器（去掉 refresh；access 统一有效 6 小时）
 *
 * 变更要点：
 * 1) 登录成功响应新增字段：role_level
 *    - 超级管理员 → 返回字符串 "超级管理员"
 *    - 否则 → 返回该账号当前“最高权限”的角色等级（int）
 * 2) 登录、注册、改密均切到 ORM（事务仍用 Db::transaction）
 * 3) 权限列表走 PermissionCacheService，角色代码基于 ORM 实时计算
 */
class AdminAuth extends BaseController
{
    private TokenService $tokenService;

    // 登录节流参数（指数退避）
    private int $maxAttempts = 5; // 最大尝试次数
    private int $baseLockoutTime = 300; // 秒，锁定时间的基数
    private float $lockoutMultiplier = 2.0; // 锁定时间的指数倍数

    // 统一 access TTL：6 小时（21600 秒）
    private int $accessTtlSeconds = 21600;

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

    /** IP 转二进制（兼容 IPv4/IPv6；适合 BLOB/VARBINARY 存） */
    private function ipToBin(?string $ip): ?string
    {
        if (!$ip) return null;
        $packed = @inet_pton($ip);
        return $packed === false ? null : $packed;
    }

    /** 指数退避节流（用户名 + IP 桶） */
    private function throttle(string $username, string $ip): ?\think\Response
    {
        $bucket = sprintf('admlogin:%s:%s', strtolower($username), $ip); // 创建唯一的锁定桶
        $lockK  = "lock:{$bucket}";
        $attK   = "attempts:{$bucket}";

        // 获取锁定时间，若存在并且还未过期，则返回限流信息
        $lockUntil = Cache::get($lockK);
        if ($lockUntil && time() < (int)$lockUntil) {
            $ttl = ((int)$lockUntil) - time();
            return $this->jsonResponse("操作过于频繁，请 {$ttl} 秒后再试", 429, 'error');
        }

        // 记录尝试次数
        $attempts = (int)Cache::inc($attK);
        if ($attempts === 1) {
            Cache::set($attK, $attempts, $this->baseLockoutTime); // 第一次失败设定超时
        }
        if ($attempts >= $this->maxAttempts) {
            // 超过最大尝试次数，计算锁定时间
            $lock = (int)($this->baseLockoutTime * pow($this->lockoutMultiplier, floor($attempts / $this->maxAttempts)));
            Cache::set($lockK, time() + $lock, $lock);
            Cache::delete($attK);
            return $this->jsonResponse("操作已锁定，请 {$lock} 秒后再试", 429, 'error');
        }
        return null;
    }

    /** hash 密码（记录算法参数，便于后续 needs_rehash） */
    private function hashPassword(string $plain): array
    {
        $cost = (int)(\app\common\Helper::getValue('security.admin_bcrypt_cost') ?? 12); // 获取 bcrypt 算法的 cost 参数
        $hash = password_hash($plain, PASSWORD_BCRYPT, ['cost' => $cost]); // 使用 bcrypt 加密密码
        return [
            'password'      => $hash,
            'password_algo' => 'bcrypt',
            'password_meta' => json_encode(['cost' => $cost], JSON_UNESCAPED_UNICODE),
        ];
    }

    /** 登录审计（ORM 写入） */
    private function auditLogin(?int $adminId, ?string $username, string $result, ?string $reason = null): void
    {
        try {
            AdminUserLoginAudit::create([ // 创建登录审计记录
                'admin_id'   => $adminId,
                'username'   => $username,
                'occurred_at'=> date('Y-m-d H:i:s'),
                'ip'         => $this->ipToBin(Request::ip() ?? ''),
                'user_agent' => substr(Request::server('HTTP_USER_AGENT') ?? '', 0, 255),
                'device_fingerprint' => substr(Request::header('X-Device-Fingerprint') ?? '', 0, 128),
                'result'     => $result,
                'reason'     => $reason,
            ]);
        } catch (\Throwable $e) {
            Log::warning('admin login audit write failed: ' . $e->getMessage());
        }
    }

    /** 等级排序方向：'asc'（默认）/ 'desc' */
    private function levelOrder(): string
    {
        $order = (string)(\app\common\Helper::getValue('permission.level_order') ?? 'asc');
        return ($order === 'desc') ? 'desc' : 'asc';
    }

    /** 是否超级管理员（启用且在有效期内；分配关系有效） */
    private function isSuperAdmin(int $adminId): bool
    {
        $now   = date('Y-m-d H:i:s');
        $super = (string)(\app\common\Helper::getValue('permission.super_admin_code') ?? 'super_admin');
        return AdminUserRole::alias('ur')
                ->join(['admin_role'=>'r'],'r.id = ur.role_id')
                ->where('ur.admin_id', $adminId)
                ->where('r.code', $super)
                ->where('r.status', 1)
                // 角色有效期
                ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                // 分配有效期
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
                ->count() > 0;
    }

    /**
     * 取账号“最高权限”的角色等级（int）
     * - asc：数字越小权限越高 → 取 min(level)
     * - desc：数字越大权限越高 → 取 max(level)
     * - 无任何有效角色：asc→99；desc→0
     */
    private function bestRoleLevelOfAdmin(int $adminId): int
    {
        $now = date('Y-m-d H:i:s');
        $levels = AdminUserRole::alias('ur')
            ->join(['admin_role'=>'r'],'r.id = ur.role_id')
            ->where('ur.admin_id', $adminId)
            ->where('r.status', 1)
            // 角色有效期
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            // 分配有效期
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            ->column('r.level');

        if (empty($levels)) {
            return $this->levelOrder()==='desc' ? 0 : 99;
        }
        $levels = array_map('intval', $levels);
        return $this->levelOrder()==='desc' ? (int)max($levels) : (int)min($levels);
    }

    /** 当前账号有效的“角色代码”数组（仅 status=1 且有效期命中的角色） */
    private function activeRoleCodesOfAdmin(int $adminId): array
    {
        $now = date('Y-m-d H:i:s');
        $codes = AdminUserRole::alias('ur')
            ->join(['admin_role'=>'r'],'ur.role_id = r.id')
            ->where('ur.admin_id', $adminId)
            ->where('r.status', 1)
            // 角色有效期
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            // 分配有效期
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            ->column('r.code');

        $codes = array_values(array_unique(array_map('strval',$codes)));
        sort($codes, SORT_STRING);
        return $codes;
    }

    // ========================= 业务接口 =========================

    /** 注册管理员（需要已有管理员调用或安装引导）—— 完全 ORM */
    public function register()
    {
        $data = Request::post(); // 获取请求的数据
        $validate = new AdminRegisterValidate(); // 验证数据
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        $username = strtolower(trim($data['username']));
        $exists = AdminUser::where('username', $username)->find();
        if ($exists) {
            return $this->jsonResponse('用户名已存在', 400, 'error');
        }

        $hp = $this->hashPassword($data['password']); // 对密码进行哈希加密

        try {
            Db::startTrans(); // 开启事务

            /** @var AdminUser $user */
            $user = AdminUser::create([ // 创建新用户
                'username'               => $username,
                'password'               => $hp['password'],
                'password_algo'          => $hp['password_algo'],
                'password_meta'          => $hp['password_meta'],
                'email'                  => $data['email'] ?? null,
                'phone'                  => $data['phone'] ?? null,
                'status'                 => 1,
                'login_failed_attempts'  => 0,
                'locked_until'           => null,
                'mfa_enabled'            => 0,
                'created_by'             => (int)(Request::post('operator_id') ?? 0) ?: null,
                'updated_by'             => null,
                'version'                => 0,
            ]);

            AdminUserPasswordHistory::create([ // 记录密码历史
                'admin_id'     => (int)$user->id,
                'password'     => $hp['password'],
                'password_algo'=> $hp['password_algo'],
                'password_meta'=> $hp['password_meta'],
                'changed_at'   => date('Y-m-d H:i:s'),
                'changed_by'   => (int)$user->id,
                'reason'       => 'active',
                'client_info'  => sprintf('ip=%s; ua=%s', Request::ip() ?? '', substr(Request::server('HTTP_USER_AGENT') ?? '',0,180)),
            ]);

            Db::commit(); // 提交事务
            return $this->jsonResponse('创建成功', 200, 'success', ['admin_id' => (int)$user->id]);
        } catch (\Throwable $e) {
            Db::rollback(); // 回滚事务
            Log::error('AdminAuth::register failed: ' . $e->getMessage());
            return $this->jsonResponse('服务器忙，请稍后重试', 500, 'error');
        }
    }

    /**
     * 登录（仅发 access；有效 6 小时）
     * 响应新增字段：role_level（最高等级 or "超级管理员"）
     */
    public function login()
    {
        $data = Request::post(); // 获取请求的数据
        $validate = new AdminLoginValidate(); // 校验登录数据
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        $username = strtolower(trim($data['username']));
        $ip       = Request::ip() ?? '';

        // 登录节流（指数退避）
        if ($resp = $this->throttle($username, $ip)) {
            $this->auditLogin(null, $username, 'LOCKED', 'throttled');
            return $resp;
        }

        /** @var AdminUser|null $user */
        $user = AdminUser::whereNull('deleted_at')->where('username', $username)->find();
        if (!$user) {
            $this->auditLogin(null, $username, 'FAIL', 'not_found');
            return $this->jsonResponse('账号或密码错误', 401, 'error');
        }

        // 状态与锁定
        if ((int)$user->getAttr('status') === 0) {
            $this->auditLogin((int)$user->id, $username, 'FAIL', 'disabled');
            return $this->jsonResponse('账号已被禁用', 403, 'error');
        }
        if ((int)$user->getAttr('status') === 2 && $user->getAttr('locked_until')) {
            $remain = strtotime((string)$user->getAttr('locked_until')) - time();
            if ($remain > 0) {
                $this->auditLogin((int)$user->id, $username, 'LOCKED', 'locked_until');
                return $this->jsonResponse("账号临时锁定，请 {$remain} 秒后再试", 429, 'error');
            }
        }

        // 校验密码
        if (!password_verify($data['password'], (string)$user->getAttr('password'))) {
            // 失败计数 +1（使用 ORM 的 Query Builder）
            AdminUser::where('id', (int)$user->id)->inc('login_failed_attempts')->update();
            $this->auditLogin((int)$user->id, $username, 'FAIL', 'bad_password');
            return $this->jsonResponse('账号或密码错误', 401, 'error');
        }

        // 需要时升级哈希参数
        $needRehash = password_needs_rehash(
            (string)$user->getAttr('password'),
            PASSWORD_BCRYPT,
            ['cost' => (int)(\app\common\Helper::getValue('security.admin_bcrypt_cost') ?? 12)]
        );
        if ($needRehash) {
            $hp = $this->hashPassword($data['password']);

            AdminUser::where('id', (int)$user->id)->update([ // 更新密码
                'password'      => $hp['password'],
                'password_algo' => $hp['password_algo'],
                'password_meta' => $hp['password_meta'],
                'updated_at'    => date('Y-m-d H:i:s'),
                'updated_by'    => (int)$user->id,
            ]);

            AdminUserPasswordHistory::create([ // 记录密码变更历史
                'admin_id'     => (int)$user->id,
                'password'     => $hp['password'],
                'password_algo'=> $hp['password_algo'],
                'password_meta'=> $hp['password_meta'],
                'changed_at'   => date('Y-m-d H:i:s'),
                'changed_by'   => (int)$user->id,
                'reason'       => 'security',
                'client_info'  => sprintf('ip=%s; ua=%s', Request::ip() ?? '', substr(Request::server('HTTP_USER_AGENT') ?? '',0,180)),
            ]);
        }

        $adminId = (int)$user->id;

        // 有效角色代码（status=1，且角色有效期 & 分配有效期命中）
        $roleCodes = $this->activeRoleCodesOfAdmin($adminId);

        // 权限代码：从缓存服务读取（未命中会自动回源并缓存）
        $permCodes = PermissionCacheService::getAdminPermCodes($adminId);

        $super = (string)(\app\common\Helper::getValue('permission.super_admin_code') ?? 'super_admin');

        // 最高等级 or 超级管理员
        $roleLevelReturn = $this->isSuperAdmin($adminId) ? $super : $this->bestRoleLevelOfAdmin($adminId);

        // 组装 JWT 自定义负载（不改变 TokenService 的签发方式）
        $payload = [
            'user_id' => $adminId,
            'realm'   => 'admin',
            'roles'   => $roleCodes,
            'perms'   => $permCodes,
        ];
        $tokens = $this->tokenService->issue($payload, $this->accessTtlSeconds, $this->accessTtlSeconds);

        // 成功：重置失败计数、写登录时间/IP（inc 版本号）
        AdminUser::where('id', $adminId)
            ->inc('version')
            ->update([
                'login_failed_attempts' => 0,
                'locked_until'          => null,
                'last_login_at'         => date('Y-m-d H:i:s'),
                'last_login_ip'         => $this->ipToBin($ip),
            ]);

        $this->auditLogin($adminId, $username, 'SUCCESS', null);

        // 只返回 access；不设置 refresh Cookie
        $access = $tokens['access'] ?? ($tokens['access_token'] ?? '');

        return $this->jsonResponse('登录成功', 200, 'success', [
            'token'       => $access,
            'expires_in'  => $this->accessTtlSeconds,
            'roles'       => $roleCodes,
            'perms'       => $permCodes,
            // 新增：角色等级（若超管 → "超级管理员"，否则为最高等级的整数）
            'role_level'  => $roleLevelReturn,
        ]);
    }

    /** 退出（可选：拉黑当前 access） */
    public function logout()
    {
        try {
            $auth = Request::header('Authorization') ?: '';
            $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
            if ($raw) {
                try { $this->tokenService->revoke($raw); } catch (\Throwable $e) {}
            }
            // 不再使用 refresh，这里删不删 Cookie 都无所谓；留一行兼容。
            Cookie::delete('refresh_token');
        } catch (\Throwable $e) {
            Log::warning('admin logout error: ' . $e->getMessage());
        }
        return $this->jsonResponse('已退出', 200, 'success');
    }

    /** 本人修改密码（近 N 次不可复用）—— 完全 ORM */
    public function changePassword()
    {
        // 解析 access token
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return $this->jsonResponse('未登录', 401, 'error');
        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return $this->jsonResponse('会话无效', 401, 'error');
        }
        if (($claims->realm ?? '') !== 'admin') {
            return $this->jsonResponse('非法领域', 403, 'error');
        }
        $adminId = (int)($claims->user_id ?? 0);
        if ($adminId <= 0) return $this->jsonResponse('会话异常', 401, 'error');

        $data = Request::post();
        $validate = new AdminChangePasswordValidate();
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        /** @var AdminUser|null $user */
        $user = AdminUser::whereNull('deleted_at')->where('id', $adminId)->find();
        if (!$user) return $this->jsonResponse('账号不存在', 404, 'error');

        if (!password_verify($data['old_password'], (string)$user->getAttr('password'))) {
            return $this->jsonResponse('旧密码不正确', 400, 'error');
        }

        // 禁止近 N 次复用
        $N = (int)(\app\common\Helper::getValue('security.pwd_history_depth') ?? 5);
        $history = AdminUserPasswordHistory::where('admin_id', $adminId)
            ->order('changed_at', 'desc')->limit($N)->select();
        foreach ($history as $row) {
            if (password_verify($data['new_password'], (string)$row->getAttr('password'))) {
                return $this->jsonResponse("新密码不能与最近 {$N} 次使用的密码相同", 400, 'error');
            }
        }

        $hp = $this->hashPassword($data['new_password']);

        try {
            Db::startTrans();

            // 更新主表 + 版本号
            AdminUser::where('id', $adminId)
                ->inc('version')
                ->update([
                    'password'      => $hp['password'],
                    'password_algo' => $hp['password_algo'],
                    'password_meta' => $hp['password_meta'],
                    'updated_at'    => date('Y-m-d H:i:s'),
                    'updated_by'    => $adminId,
                ]);

            // 记录密码历史
            AdminUserPasswordHistory::create([
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
            Log::error('AdminAuth::changePassword failed: ' . $e->getMessage());
            return $this->jsonResponse('服务器忙，请稍后重试', 500, 'error');
        }
    }

    /** 二进制 IP -> 文本（兼容 IPv4/IPv6） */
    private function binToIp($bin): ?string
    {
        if (empty($bin)) return null;
        $ip = @inet_ntop(is_string($bin) ? $bin : (string)$bin);
        return $ip === false ? null : $ip;
    }
    /**
     * 管理员列表（POST）
     * - 鉴权：admin realm 的 Bearer Token（权限点建议：admin.auth.list）
     * - 过滤：keyword（模糊匹配 username/email/phone）、status、role_code（命中有效期且启用的角色）
     * - 排序：id/username/status/created_at/updated_at/last_login_at（asc/desc）
     * - 分页：page（>=1）、page_size（1~200）
     * - 角色：仅返回“当前有效”的角色代码；同时返回 is_super_admin 与 role_level（与 login 保持一致）
     *
     * 请求示例：
     * {
     *   "page":1,"page_size":20,
     *   "keyword":"adm","status":1,"role_code":"auditor",
     *   "sort_field":"id","sort_order":"desc"
     * }
     */
    public function listAdmins()
    {
        // 1) 解析并校验会话（与 changePassword 同一风格）
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return $this->jsonResponse('未登录或Token无效', 401, 'error');

        try {
            $claims = $this->tokenService->parse($raw); // 解析 token
        } catch (\Throwable $e) {
            Log::error('Token解析失败：' . $e->getMessage());
            return $this->jsonResponse('会话无效，请重新登录', 401, 'error');
        }
        if (($claims->realm ?? '') !== 'admin') { // 校验权限领域
            return $this->jsonResponse('非法领域，必须为管理员权限', 403, 'error');
        }

        // 2) 接收与标准化入参
        $in = Request::post();
        $page      = max(1, (int)($in['page'] ?? 1)); // 页码
        $pageSize  = min(200, max(1, (int)($in['page_size'] ?? 20))); // 每页大小
        $keyword   = trim((string)($in['keyword'] ?? '')); // 关键字
        $roleCode  = trim((string)($in['role_code'] ?? '')); // 角色代码
        $statusStr = $in['status'] ?? null; // 账号状态
        $status    = ($statusStr === '' || $statusStr === null) ? null : (int)$statusStr;

        // 允许的排序字段
        $allowSort = [
            'id'            => 'u.id',
            'username'      => 'u.username',
            'status'        => 'u.status',
            'created_at'    => 'u.created_at',
            'updated_at'    => 'u.updated_at',
            'last_login_at' => 'u.last_login_at',
        ];
        $sortField = (string)($in['sort_field'] ?? 'id'); // 排序字段
        $sortOrder = strtolower((string)($in['sort_order'] ?? 'desc')); // 排序顺序
        $sortCol   = $allowSort[$sortField] ?? 'u.id'; // 默认排序字段
        $sortOrd   = in_array($sortOrder, ['asc','desc'], true) ? $sortOrder : 'desc'; // 默认排序顺序

        // 3) 构建查询（主表）—— 保持 ORM 风格
        $q = AdminUser::alias('u')->whereNull('u.deleted_at');
        if ($status !== null) {
            $q->where('u.status', $status); // 过滤状态
        }
        if ($keyword !== '') {
            $kw = '%' . str_replace(['%','_'], ['\%','\_'], $keyword) . '%'; // 防止 SQL 注入
            $q->where(function($w) use ($kw) {
                $w->whereLike('u.username', $kw)
                    ->whereOr('u.email', 'like', $kw)
                    ->whereOr('u.phone', 'like', $kw);
            });
        }

        // 4) 角色过滤（仅命中启用且在有效期内的角色/分配）
        if ($roleCode !== '') {
            $now = date('Y-m-d H:i:s');
            $q->join(['admin_user_role' => 'ur'], 'ur.admin_id = u.id')
                ->join(['admin_role' => 'r'], 'r.id = ur.role_id')
                ->where('r.code', $roleCode)
                ->where('r.status', 1)
                // 角色有效期
                ->where(function($w) use ($now){ $w->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($w) use ($now){ $w->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                // 分配有效期
                ->where(function($w) use ($now){ $w->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
                ->where(function($w) use ($now){ $w->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
                ->group('u.id');
        }

        // 5) 统计 + 分页拉取（避免使用 DISTINCT）
        try {
            // 获取总记录数
            $total = $q->count();  // 不使用 DISTINCT

            // 分页查询数据
            $rows = $q->field('u.id,u.username,u.email,u.phone,u.status,u.created_at,u.updated_at,u.last_login_at,u.last_login_ip')
                ->order($sortCol, $sortOrd)
                ->page($page, $pageSize)
                ->select();
        } catch (\Throwable $e) {
            Log::error('查询管理员列表失败：' . $e->getMessage());
            return $this->jsonResponse('查询失败，请稍后重试', 500, 'error');
        }

        // 6) 装配视图模型（最小暴露 + 角色聚合 + 超管/最高等级）
        $items = [];
        foreach ($rows as $r) {
            /** @var AdminUser $r */
            $adminId     = (int)$r->getAttr('id');
            $roleCodes   = $this->activeRoleCodesOfAdmin($adminId);
            $isSuper     = $this->isSuperAdmin($adminId);
            $roleLevel   = $isSuper
                ? (string)(\app\common\Helper::getValue('permission.super_admin_code') ?? 'super_admin')
                : $this->bestRoleLevelOfAdmin($adminId);

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
                'roles'          => $roleCodes,      // 仅返回“有效角色代码”
                'is_super_admin' => $isSuper ? 1 : 0,
                'role_level'     => $roleLevel,      // 超管返回 super_admin 代码，否则返回 int 等级
            ];
        }

        // 7) 标准响应（与现有控制器风格一致）
        return $this->jsonResponse('ok', 200, 'success', [
            'list'       => $items,
            'page'       => $page,
            'page_size'  => $pageSize,
            'total'      => $total,
            'sort'       => ['field' => $sortField, 'order' => $sortOrd],
            'filters'    => ['keyword' => $keyword, 'status' => $status, 'role_code' => $roleCode],
        ]);
    }

    /**
     * 删除管理员（物理删除 + 解除角色绑定）
     * - 鉴权：admin realm 的 Bearer Token
     * - 限制：不能删除自己；超级管理员不可删除
     *
     * 请求示例：
     * { "admin_id": 123 }
     */
    public function deleteAdmin()
    {
        // 1) 解析并校验会话
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return $this->jsonResponse('未登录', 401, 'error');

        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return $this->jsonResponse('会话无效', 401, 'error');
        }
        if (($claims->realm ?? '') !== 'admin') {
            return $this->jsonResponse('非法领域', 403, 'error');
        }
        $operatorId = (int)($claims->user_id ?? 0);
        if ($operatorId <= 0) {
            return $this->jsonResponse('会话异常', 401, 'error');
        }

        // 2) 入参
        $in       = Request::post();
        $targetId = (int)($in['admin_id'] ?? 0);
        if ($targetId <= 0) {
            return $this->jsonResponse('参数错误：admin_id', 422, 'error');
        }

        // 3) 读取目标账号（存在性检查）
        /** @var AdminUser|null $target */
        $target = AdminUser::where('id', $targetId)->find(); // 不加 whereNull('deleted_at')，兼容已软删场景
        if (!$target) {
            return $this->jsonResponse('账号不存在', 404, 'error');
        }

        // 4) 业务限制
        if ($operatorId === $targetId) {
            return $this->jsonResponse('不能删除自己', 400, 'error');
        }
        if ($this->isSuperAdmin($targetId)) {
            return $this->jsonResponse('超级管理员不可删除', 403, 'error');
        }

        // 5) 执行删除（事务）：先解绑角色，再物理删用户
        try {
            Db::startTrans();

            // 解除角色绑定
            AdminUserRole::where('admin_id', $targetId)->delete();

            // （可选但推荐）清理口令历史与登录审计，避免外键/脏数据
            // 如无外键也可保留审计数据，按需开启：
             AdminUserPasswordHistory::where('admin_id', $targetId)->delete();
            // AdminUserLoginAudit::where('admin_id', $targetId)->delete();

            // 物理删除用户记录：使用 Db 层以规避软删除特性
            Db::name('admin_user')->where('id', $targetId)->delete();

            // （可选）清理与权限相关的缓存，如有对应方法可在此调用：
            try {
                PermissionCacheService::invalidateAdmin($targetId);
            } catch (\Throwable $e) {
                Log::warning("清理权限缓存失败: {$e->getMessage()}");
            }

            Db::commit();
            return $this->jsonResponse('删除成功', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('AdminAuth::deleteAdmin failed: ' . $e->getMessage());
            return $this->jsonResponse('删除失败，请稍后重试', 500, 'error');
        }
    }

}
