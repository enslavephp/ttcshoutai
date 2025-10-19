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
 */
class AdminPermissionMiddleware
{
    /** JWT 解析服务 */
    private TokenService $tokenService;

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

    /**
     * 中间件入口
     *
     * @param \think\Request $request
     * @param Closure $next
     * @param mixed ...$requiredCodes  可变参数：路由声明的权限码列表（ALL 模式）
     */
    public function handle($request, Closure $next, ...$requiredCodes)
    {
        // 预检请求（CORS）直接放行
        if (strtoupper($request->method()) === 'OPTIONS') {
            return $next($request);
        }

        // 读取配置
        $enforceAll  = (bool)(\app\common\Helper::getValue('permission.enforce_all') ?? true);
        $allowRoutes = (array)(\app\common\Helper::getValue('permission.allow_routes') ?? []);
        $superCode   = (string)(\app\common\Helper::getValue('permission.super_admin_code') ?? 'super_admin');
        $prefix      = (string)(\app\common\Helper::getValue('permission.prefix') ?? 'admin:perms:');

        // 1) 优先复用 AdminTokenMiddleware 注入的 claims；若没有就自行解析
        $claims  = null;
        $adminId = null;

        if (app()->has('admin.jwt_claims') && app()->has('admin.id')) {
            $claims  = app()->get('admin.jwt_claims');
            $adminId = (int)app()->get('admin.id');
        } else {
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
            // 也注入容器，方便后续链路使用
            app()->instance('admin.jwt_claims', $claims);
            app()->instance('admin.id', $adminId);
        }

        // 2) 超管直通
        if ($this->isSuperAdmin($adminId, $superCode)) {
            return $next($request);
        }

        // 3) 计算需要的权限码（ALL 模式）
        $required = array_values(array_filter(array_map('strval', $requiredCodes)));
        if (empty($required)) {
            if (!$enforceAll) {
                // 未开启强制 & 路由未显式声明：直接放行（兼容老路由）
                return $next($request);
            }
            $auto = $this->calcPermissionCode($request); // 例：admin/permission/create → admin.permission.create 或 permission.create
            $codePrefix = (string)(\app\common\Helper::getValue('permission.auto_code_prefix') ?? '');
            $auto = $codePrefix . ltrim($auto, $codePrefix); // 如果已存在前缀，则不重复添加
            if (in_array($auto, $allowRoutes, true)) {
                return $next($request);
            }
            $required = [$auto];
        }

        // 4) 校验这些权限码是否都存在（避免路由/配置写错）
        $invalid = $this->nonexistentPermCodes($required);
        if (!empty($invalid)) {
            if ((bool)(\app\common\Helper::getValue('permission.auto_register_missing') ?? false)) {
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

        // 5) 读取当前管理员的权限集合（缓存 → 回源）
        [$permSet, $cacheHit] = $this->loadAdminPermSet($adminId, $prefix);

        // 6) ALL 模式：必须全部具备；若缓存命中仍缺，则强刷一次再校验
        $missing = array_values(array_diff($required, $permSet));
        if (!empty($missing) && $cacheHit) {
            [$permSet] = $this->loadAdminPermSet($adminId, $prefix, true);
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
     */
    private function loadAdminPermSet(int $adminId, string $prefix, bool $forceRefresh = false): array
    {
        $key = $prefix . $adminId;

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
