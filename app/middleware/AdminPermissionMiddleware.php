<?php
declare(strict_types=1);

namespace app\middleware;

use Closure;
use think\facade\Cache;
use app\common\service\TokenService;
use app\common\infra\CacheFacadeAdapter;
use app\common\util\SystemClock;
use app\common\service\PermissionCacheService;
use app\admin\model\AdminPermission;
use app\admin\model\AdminUserRole;

/**
 * AdminPermissionMiddleware
 *
 * 基于“管理员 → 权限代码集合”的缓存进行接口权限校验。
 *
 * 设计要点：
 * 1) 路由权限声明可选。如果未显式传入权限码且配置 `permission.enforce_all=true`，
 *    则自动把当前请求路径点号化为权限码（例如 /admin/role/create → admin.role.create）进行校验；
 *    若该自动推导的权限码在白名单 `permission.allow_routes` 中则放行。
 * 2) 超管（`permission.super_admin_code` 指定的角色 code）直通。
 * 3) 权限集合优先走缓存（key 前缀取自 `permission.prefix`，与 PermissionCacheService 一致），
 *    未命中则由 PermissionCacheService 回源并写入缓存。
 * 4) 校验模式为 ALL：需要的权限码必须全部具备。保留“双检”逻辑（缓存命中但边界失效时再强刷一次）。
 * 5) 全面使用 ORM（不使用 Db::name），与既有 Model/Service 保持一致。
 */
class AdminPermissionMiddleware
{
    /** JWT 解析服务 */
    private TokenService $tokenService;

    public function __construct()
    {
        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            config('jwt') ?: []
        );
    }

    /**
     * 中间件入口
     *
     * @param \think\Request $request
     * @param Closure $next
     * @param mixed ...$requiredCodes  可变参数：路由上声明的权限码列表（ALL 模式）
     */
    public function handle($request, Closure $next, ...$requiredCodes)
    {
        // 预检请求（CORS）直接放行
        if (strtoupper($request->method()) === 'OPTIONS') {
            return $next($request);
        }

        // 行为开关
        $enforceAll  = (bool)(config('permission.enforce_all') ?? true);
        $allowRoutes = (array)(config('permission.allow_routes') ?? []);
        $superCode   = (string)(config('permission.super_admin_code') ?? 'super_admin');

        // 1) 解析 Token（要求 realm=admin）
        $auth = (string)($request->header('Authorization') ?? '');
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if ($raw === '') {
            return $this->deny('未登录', 401);
        }
        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return $this->deny('会话无效', 401);
        }
        if (($claims->realm ?? 'admin') !== 'admin') {
            return $this->deny('非法领域', 403);
        }
        $adminId = (int)($claims->user_id ?? 0);
        if ($adminId <= 0) {
            return $this->deny('会话异常', 401);
        }

        // 2) 超管直通
        if ($this->isSuperAdmin($adminId, $superCode)) {
            return $next($request);
        }

        // 3) 计算需要的权限码（ALL 模式）
        $required = array_values(array_filter(array_map('strval', $requiredCodes)));
        if (empty($required)) {
            if (!$enforceAll) {
                // 未开启全局强制，且没传 codes：直接放行（兼容旧路由）
                return $next($request);
            }
            $auto = $this->calcPermissionCode($request); // 例：admin.role.create
            if (in_array($auto, $allowRoutes, true)) {
                return $next($request);
            }
            $required = [$auto];
        }

        // 4) 这些权限码必须在权限表中存在（避免路由写错/未配置）
        $invalid = $this->nonexistentPermCodes($required);
        if (!empty($invalid)) {
            if ((bool)(config('permission.auto_register_missing') ?? false)) {
                // （如需：可开启自动注册缺失的权限；建议上线环境关闭）
                // foreach ($invalid as $code) {
                //     AdminPermission::create([
                //         'code'          => $code,
                //         'name'          => $code,
                //         'description'   => 'auto-registered',
                //         'resource_type' => 'api',
                //         'resource_id'   => '/'.str_replace('.', '/', $code),
                //         'action'        => strtoupper($request->method()),
                //         'created_at'    => date('Y-m-d H:i:s'),
                //     ]);
                // }
            } else {
                return $this->deny(
                    '权限未配置: ' . implode(',', $invalid),
                    403,
                    ['invalid' => $invalid]
                );
            }
        }

        // 5) 从缓存（或回源）获取当前管理员的权限集合
        [$permSet, $cacheHit] = $this->loadAdminPermSet($adminId);

        // 6) ALL 模式：必须全部具备；若缓存命中仍缺，则强刷再校验一次（避免边界失效）
        $missing = array_values(array_diff($required, $permSet));
        if (!empty($missing) && $cacheHit) {
            [$permSet] = $this->loadAdminPermSet($adminId, true); // 强制刷新
            $missing = array_values(array_diff($required, $permSet));
        }
        if (!empty($missing)) {
            return $this->deny(
                '缺少权限: ' . implode(',', $missing),
                403,
                ['need' => $required, 'missing' => $missing]
            );
        }

        return $next($request);
    }

    /**
     * 把请求路径点号化为权限码：
     *   /admin/role/create → admin.role.create
     */
    private function calcPermissionCode($request): string
    {
        $path = $request->pathinfo();           // 例：admin/role/create
        $path = preg_replace('#/+#', '/', $path ?? '');
        $path = strtolower(trim((string)$path, '/'));
        return str_replace('/', '.', $path);
    }

    /**
     * 校验权限码是否都存在于权限表
     * @return string[] 不存在的 code 列表
     */
    private function nonexistentPermCodes(array $codes): array
    {
        if (!$codes) return [];
        $found = AdminPermission::whereIn('code', $codes)->column('code');
        $found = array_map('strval', $found);
        return array_values(array_diff($codes, $found));
    }

    /**
     * 是否超管（启用且在有效期内）
     * 使用 ORM：AdminUserRole ⇄ AdminRole
     */
    private function isSuperAdmin(int $adminId, string $superCode): bool
    {
        $now = date('Y-m-d H:i:s');
        return AdminUserRole::alias('ur')
                ->join(['admin_role' => 'r'], 'r.id = ur.role_id')
                ->where('ur.admin_id', $adminId)
                ->where('r.code', $superCode)
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
     * 读取管理员权限集合
     * 返回 [codes[], 是否命中缓存]
     *
     * 策略：
     *  - 先尝试直接读缓存（key 规则与 PermissionCacheService 一致：permission.prefix + adminId）
     *  - 未命中则调用 PermissionCacheService::getAdminPermCodes() 回源（内部会 remember 到缓存）
     *  - forceRefresh=true 时，先删除缓存再回源
     */
    private function loadAdminPermSet(int $adminId, bool $forceRefresh = false): array
    {
        $key = (string)(config('permission.prefix') ?? 'admin:perms:') . $adminId;

        if ($forceRefresh) {
            Cache::delete($key);
            $codes = PermissionCacheService::getAdminPermCodes($adminId);
            return [$codes, false];
        }

        $cached = Cache::get($key);
        if (is_array($cached)) {
            $codes = array_values(array_unique(array_map('strval', $cached)));
            sort($codes, SORT_STRING);
            return [$codes, true];
        }

        $codes = PermissionCacheService::getAdminPermCodes($adminId);
        return [$codes, false];
    }

    /**
     * 统一拒绝响应（JSON）
     */
    private function deny(string $msg, int $code = 403, ?array $data = null)
    {
        return json(['msg' => $msg, 'code' => $code, 'status' => 'error', 'data' => $data], $code);
    }
}
