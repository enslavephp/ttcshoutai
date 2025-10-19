<?php
declare(strict_types=1);

namespace app\middleware;

use Closure;
use think\facade\Request;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;
use app\shopadmin\service\ShopAdminSensitiveOperationService;

/**
 * 敏感操作二次确认中间件（商户侧）
 *
 * 用法（示例）：
 *   ->middleware(\app\middleware\ShopAdminSensitiveOperationMiddleware::class . ':ROLE_ASSIGN')
 *
 * 流程：
 *  1) 首次调用未携带确认 token：
 *       - 读取 TTL（security.sensitive_ttl 或 security.sensitive_ttl_shopadmin，默认 300s）
 *       - 生成 pending_token，返回 HTTP 409（Conflict）
 *       - 前端去调用 /shopadmin/secure/confirm/verify 完成确认
 *  2) 再次调用目标接口，并在 Header 中携带：
 *       X-Confirm-Token: <pending_token>
 *     （或使用参数 confirmation_token 传入）
 *
 * 说明：
 *  - 强制要求 JWT 为 realm=shopadmin，并携带 merchant_id、user_id。
 *  - 兼容旧版 Service 签名（不含 merchant_id）。如已升级为租户化签名，优先使用新签名。
 */
class ShopAdminSensitiveOperationMiddleware
{
    private TokenService $tokenService;
    private ShopAdminSensitiveOperationService $svc;

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
     * @param \think\Request $request
     * @param Closure        $next
     * @param string         $operationType 路由上声明的操作类型标识（自定义字符串）
     */
    public function handle($request, Closure $next, string $operationType = 'GENERIC')
    {
        // 1) 解析 shopadmin access
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if ($raw === '') {
            return $this->jsonError('未登录', 401);
        }

        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return $this->jsonError('会话无效', 401);
        }
        if (($claims->realm ?? '') !== 'shopadmin') {
            return $this->jsonError('非法领域', 403);
        }

        $merchantId = (int)($claims->merchant_id ?? 0);
        $adminId    = (int)($claims->user_id ?? 0);
        if ($merchantId <= 0 || $adminId <= 0) {
            return $this->jsonError('会话异常（缺少租户/用户标识）', 401);
        }

        // 2) 读取确认 token（Header 优先，其次参数）
        $token = (string)(Request::header('X-Confirm-Token') ?? Request::param('confirmation_token', ''));
        if ($token === '') {
            // 未提供 token：生成待确认 token，返回 409
            $ttl = (int)(\app\common\Helper::getValue('security.sensitive_ttl_shopadmin')
                ?? \app\common\Helper::getValue('security.sensitive_ttl')
                ?? 300);

            $opData = [
                'merchant_id' => $merchantId,
                'path'        => Request::baseUrl(),
                'method'      => Request::method(),
                'ip'          => Request::ip(),
                'ua'          => substr((string)(Request::server('HTTP_USER_AGENT') ?? ''), 0, 180),
                'confirmed'   => false,
            ];

            // 兼容新旧 Service 签名：优先调用“含租户”的新签名，失败则退回旧签名
            try {
                // 新签名：initiate(int $merchantId, int $adminId, string $operationType, array $opData, int $ttlSeconds)
                $pending = $this->svc->initiate($merchantId, $adminId, $operationType, $opData, $ttl);
            } catch (\ArgumentCountError|\TypeError $e) {
                // 旧签名：initiate(int $adminId, string $operationType, array $opData, int $ttlSeconds)
                $pending = $this->svc->initiate($adminId, $operationType, $opData, $ttl);
            }

            return json([
                'msg'    => '需要二次确认',
                'code'   => 409,
                'status' => 'error',
                'data'   => [
                    'pending_token'  => $pending,
                    'operation_type' => $operationType,
                    'expires_in'     => $ttl,
                    'how_to'         => '请先调用 /shopadmin/secure/confirm/verify 完成确认，再在 Header 中携带 X-Confirm-Token 重试本操作',
                ],
            ], 409);
        }

        // 3) 校验 token 是否已确认且未过期（同样兼容新旧签名）
        try {
            // 新签名：verifyConfirmed(int $merchantId, int $adminId, string $operationType, string $token)
            $ok = $this->svc->verifyConfirmed($merchantId, $adminId, $operationType, $token);
        } catch (\ArgumentCountError|\TypeError $e) {
            // 旧签名：verifyConfirmed(int $adminId, string $operationType, string $token)
            $ok = $this->svc->verifyConfirmed($adminId, $operationType, $token);
        }

        if (!$ok) {
            return $this->jsonError('二次确认未通过或已过期', 403);
        }

        return $next($request);
    }

    private function jsonError(string $msg, int $code)
    {
        return json([
            'msg'    => $msg,
            'code'   => $code,
            'status' => 'error',
            'data'   => null,
        ], $code);
    }
}
