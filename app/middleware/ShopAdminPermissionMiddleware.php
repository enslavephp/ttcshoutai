<?php
declare(strict_types=1);

namespace app\middleware;


use Closure;
use think\facade\Cache;
use app\common\service\TokenService;
use app\common\infra\CacheFacadeAdapter;
use app\common\util\SystemClock;
use app\common\service\PermissionCacheService;

use app\shopadmin\model\ShopAdminPermission;
use app\shopadmin\model\ShopAdminUserRole;

/**
 * ShopAdminPermissionMiddleware
 *
 * 商户侧（shopadmin）接口权限校验，中间件基于“管理员 → 权限代码集合”的缓存进行校验。
 *
 * 要点：
 * 1) 路由权限声明可选；若未声明且 `permission.enforce_all=true`，则将当前路径点号化为权限码
 *    （/shopadmin/role/assign → shopadmin.role.assign）并校验；若在白名单 `permission.allow_routes` 则放行。
 * 2) 超管直通：本商户内拥有 `permission.super_shop_admin_code`（默认 super_shopadmin）的账号。
 * 3) 权限集合优先缓存（key 前缀取自 `permission.prefix`，与 PermissionCacheService 一致），未命中回源。
 * 4) ALL 模式：声明的权限码必须全部具备；命中缓存仍缺时会强刷一次再判定（双检）。
 */
class ShopAdminPermissionMiddleware
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
     * @param mixed ...$requiredCodes 路由上声明的权限码列表（ALL 模式）
     */
    public function handle($request, Closure $next, ...$requiredCodes)
    {
        // 预检请求（CORS）直接放行
        if (strtoupper($request->method()) === 'OPTIONS') {
            return $next($request);
        }

        // 行为开关
        $enforceAll  = (bool)(\app\common\Helper::getValue('permission.enforce_all') ?? true);
        $allowRoutes = (array)(\app\common\Helper::getValue('permission.allow_routes') ?? []);
        $superCode   = (string)(\app\common\Helper::getValue('permission.super_shop_admin_code') ?? 'super_shopadmin');

        // 1) 解析 Token（要求 realm=shopadmin，且带 merchant_id / user_id）
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
        if (($claims->realm ?? '') !== 'shopadmin') {
            return $this->deny('非法领域', 403);
        }
        $adminId    = (int)($claims->user_id ?? 0);
        $merchantId = (int)($claims->merchant_id ?? 0);

        if ($adminId <= 0 || $merchantId <= 0) {
            return $this->deny('会话异常（缺少租户/用户标识）', 401);
        }

        // 2) 本商户超管直通
        if ($this->isSuperAdminInTenant($merchantId, $adminId, $superCode)) {
            return $next($request);
        }

        // 3) 计算需要的权限码（ALL 模式）
        $required = array_values(array_filter(array_map('strval', $requiredCodes)));
        if (empty($required)) {
            if (!$enforceAll) {
                // 未开启全局强制，且没传 codes：直接放行（兼容旧路由）
                return $next($request);
            }
            $auto = $this->calcPermissionCode($request); // 例：shopadmin.role.assign
            if (in_array($auto, $allowRoutes, true)) {
                return $next($request);
            }
            $required = [$auto];
        }

        // 4) 这些权限码必须在权限表中存在（避免路由写错/未配置）
        $invalid = $this->nonexistentPermCodes($required);
        if (!empty($invalid)) {
            if ((bool)(\app\common\Helper::getValue('permission.auto_register_missing') ?? false)) {
                // 如果你确实要自动注册缺失权限，可在这里放开（注意 shopadmin_permission 的字段约束）
                // foreach ($invalid as $code) {
                //     ShopAdminPermission::create([
                //         'code'          => $code,
                //         'name'          => $code,
                //         'description'   => 'auto-registered',
                //         'resource_type' => 'api',
                //         'resource_id'   => null,
                //         'action'        => strtoupper($request->method()),
                //         'created_at'    => date('Y-m-d H:i:s'),
                //     ]);
                // }
            } else {
                return $this->deny('权限未配置: ' . implode(',', $invalid), 403, ['invalid' => $invalid]);
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
            return $this->deny('缺少权限: ' . implode(',', $missing), 403, [
                'need'    => $required,
                'missing' => $missing,
            ]);
        }

        return $next($request);
    }

    /**
     * 把请求路径点号化为权限码：
     *   /shopadmin/role/assign → shopadmin.role.assign
     */
    private function calcPermissionCode($request): string
    {
        $path = $request->pathinfo();           // 例：shopadmin/role/assign
        $path = preg_replace('#/+#', '/', $path ?? '');
        $path = strtolower(trim((string)$path, '/'));
        return str_replace('/', '.', $path);
    }

    /**
     * 校验权限码是否都存在于商户侧权限表
     * @return string[] 不存在的 code 列表
     */
    private function nonexistentPermCodes(array $codes): array
    {
        if (!$codes) return [];
        $found = ShopAdminPermission::whereIn('code', $codes)->column('code');
        $found = array_map('strval', $found);
        return array_values(array_diff($codes, $found));
    }

    /**
     * 是否为“本商户超管”（启用且在有效期内；按租户隔离）
     */
    private function isSuperAdminInTenant(int $merchantId, int $adminId, string $superCode): bool
    {
        $now = date('Y-m-d H:i:s');
        return ShopAdminUserRole::alias('ur')
                ->join(['shopadmin_role' => 'r'], 'r.id = ur.role_id AND r.merchant_id = ur.merchant_id')
                ->where('ur.merchant_id', $merchantId)
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
        $key = (string)(\app\common\Helper::getValue('permission.prefix') ?? 'admin:perms:') . $adminId;

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

    /** 统一拒绝响应（JSON） */
    private function deny(string $msg, int $code = 403, ?array $data = null)
    {
        return json(['msg' => $msg, 'code' => $code, 'status' => 'error', 'data' => $data], $code);
    }
}
