<?php
declare(strict_types=1);

namespace app\middleware;

use Closure;
use think\facade\Request;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;


/**
 * AdminTokenMiddleware
 *
 * 只校验 admin 领域 access token 是否有效。
 * 成功后把解析出的 claims 写入容器，供后续链路复用（避免重复解析）。
 *
 * 容器键：
 *  - 'admin.jwt_claims'  : 解析后的 JWT claims（对象/数组）
 *  - 'admin.id'         : 管理员ID（int）
 */
class AdminTokenMiddleware
{
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

    public function handle($request, Closure $next)
    {
        // CORS 预检直接通过
        if (strtoupper($request->method()) === 'OPTIONS') {
            return $next($request);
        }

        $auth = (string)(Request::header('Authorization') ?? '');
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if ($raw === '') {
            return json(['msg' => '未登录', 'code' => 401, 'status' => 'error', 'data' => null], 401);
        }

        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return json(['msg' => '会话无效', 'code' => 401, 'status' => 'error', 'data' => null], 401);
        }

        if (($claims->realm ?? '') !== 'admin') {
            return json(['msg' => '非法领域', 'code' => 403, 'status' => 'error', 'data' => null], 403);
        }

        $adminId = (int)($claims->user_id ?? 0);
        if ($adminId <= 0) {
            return json(['msg' => '会话异常', 'code' => 401, 'status' => 'error', 'data' => null], 401);
        }

        // 把 claims 与 adminId 注入容器，供后续中间件/控制器复用，避免重复解析。
        app()->instance('admin.jwt_claims', $claims);
        app()->instance('admin.id', $adminId);

        return $next($request);
    }
}
