<?php
declare(strict_types=1);

namespace app\middleware;

use Closure;
use think\facade\Request;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\admin\service\AdminSensitiveOperationService;

/**
 * 敏感操作二次确认中间件
 *
 * 路由用法：
 *   ->middleware(\app\middleware\AdminSensitiveOperationMiddleware::class . ':OPERATION_TYPE')
 *
 * 调用流程：
 *   1) 首次调用未携带确认 token：
 *        - 从配置读取 TTL（security.sensitive_ttl，默认 300s）
 *        - 创建 pending_token，返回 HTTP 409（Conflict），告知 token 和有效期
 *   2) 客户端调用 /admin/secure/confirm/verify 完成确认（把 pending_token 置 confirmed=true）
 *   3) 再次调用目标接口，并在 Header 中携带 X-Confirm-Token: <pending_token>（或参数 confirmation_token）
 */
class AdminSensitiveOperationMiddleware
{
    private TokenService $tokenService;
    private AdminSensitiveOperationService $svc;

    public function __construct()
    {
        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new \app\common\util\SystemClock(),
            config('jwt') ?: []
        );
        $this->svc = new AdminSensitiveOperationService();
    }

    public function handle($request, Closure $next, string $operationType = 'GENERIC')
    {
        // 1) 解析 admin access
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return json(['msg'=>'未登录','code'=>401,'status'=>'error','data'=>null], 401);

        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return json(['msg'=>'会话无效','code'=>401,'status'=>'error','data'=>null], 401);
        }
        if (($claims->realm ?? '') !== 'admin') {
            return json(['msg'=>'非法领域','code'=>403,'status'=>'error','data'=>null], 403);
        }
        $adminId = (int)($claims->user_id ?? 0);
        if ($adminId <= 0) {
            return json(['msg'=>'会话异常','code'=>401,'status'=>'error','data'=>null], 401);
        }

        // 2) 读取确认 token（Header 优先，其次参数）
        $token = (string)(Request::header('X-Confirm-Token') ?? Request::param('confirmation_token', ''));
        if ($token === '') {
            // 未提供，则生成一个待确认 token，返回 409
            $ttl  = (int)(config('security.sensitive_ttl') ?? 300);
            $opData = [
                'path' => Request::baseUrl(),
                'method' => Request::method(),
                'ip' => Request::ip(),
                'ua' => substr(Request::server('HTTP_USER_AGENT') ?? '', 0, 180),
                'confirmed' => false,
            ];
            $pending = $this->svc->initiate($adminId, $operationType, $opData, $ttl);
            return json([
                'msg'   => '需要二次确认',
                'code'  => 409,
                'status'=> 'error',
                'data'  => [
                    'pending_token'  => $pending,
                    'operation_type' => $operationType,
                    'expires_in'     => $ttl,
                    'how_to'         => '请先调用 /admin/secure/confirm/verify 完成确认，再在 Header 中携带 X-Confirm-Token 重试本操作',
                ],
            ], 409);
        }

        // 3) 校验 token 是否已确认且未过期
        $ok = $this->svc->verifyConfirmed($adminId, $operationType, $token);
        if (!$ok) {
            return json(['msg'=>'二次确认未通过或已过期','code'=>403,'status'=>'error','data'=>null], 403);
        }

        return $next($request);
    }
}
