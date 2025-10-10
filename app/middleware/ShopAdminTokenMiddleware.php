<?php
declare(strict_types=1);

namespace app\middleware;

use Closure;
use think\facade\Request;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;

/**
 * 仅校验 shopadmin 领域 access token 的中间件。
 * - 商户侧业务接口统一挂这个；认证接口（登录/注册）不挂。
 * - 要求：JWT realm=shopadmin，且包含 merchant_id 与 user_id。
 */
class ShopAdminTokenMiddleware
{
    private TokenService $tokenService;

    public function __construct()
    {
        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            config('jwt') ?: []
        );
    }

    public function handle($request, Closure $next)
    {
        // 预检请求直接放行（避免阻断 CORS）
        if (strtoupper($request->method()) === 'OPTIONS') {
            return $next($request);
        }

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

        // 仅允许 shopadmin 领域
        if (($claims->realm ?? '') !== 'shopadmin') {
            return $this->deny('非法领域', 403);
        }

        // 必须携带租户与用户标识
        $merchantId = (int)($claims->merchant_id ?? 0);
        $adminId    = (int)($claims->user_id ?? 0);
        if ($merchantId <= 0 || $adminId <= 0) {
            return $this->deny('会话异常（缺少租户/用户标识）', 401);
        }

        // 如需在后续控制器中使用，可注入少量上下文（可选）
        // $request->shopadmin = ['merchant_id' => $merchantId, 'admin_id' => $adminId, 'claims' => $claims];

        return $next($request);
    }

    private function deny(string $msg, int $code)
    {
        return json(['msg' => $msg, 'code' => $code, 'status' => 'error', 'data' => null], $code);
    }
}
