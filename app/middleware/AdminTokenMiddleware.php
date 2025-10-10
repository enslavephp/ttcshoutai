<?php
declare(strict_types=1);

namespace app\middleware;

use Closure;
use think\facade\Request;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;

/**
 * 仅校验 admin 领域 access token 的中间件。
 * - 业务接口统一挂这个；认证接口（登录/注册/刷新）不挂。
 */
class AdminTokenMiddleware
{
    private TokenService $tokenService;

    public function __construct()
    {
        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new \app\common\util\SystemClock(),
            config('jwt') ?: []
        );
    }

    public function handle($request, Closure $next)
    {
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) {
            return json(['msg'=>'未登录','code'=>401,'status'=>'error','data'=>null], 401);
        }
        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            return json(['msg'=>'会话无效','code'=>401,'status'=>'error','data'=>null], 401);
        }
        if (($claims->realm ?? '') !== 'admin') {
            return json(['msg'=>'非法领域','code'=>403,'status'=>'error','data'=>null], 403);
        }
        // 通过即可；如需注入上下文，可：Request::macro(...) 或容器绑定
        return $next($request);
    }
}
