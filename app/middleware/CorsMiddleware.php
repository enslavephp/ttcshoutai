<?php
declare(strict_types=1);

namespace app\middleware;

//跨域文件处理
class CorsMiddleware
{
    public function handle($request, \Closure $next)
    {
        $origin = $request->header('origin');
        // 强烈建议使用白名单治理，而非 '*'
        $allow = [
            'http://localhost:5173',
            'http://localhost:5174',
            'http://127.0.0.1:5173',
            // 'https://dev.yourdomain.com',
        ];

        $headers = [
            'Access-Control-Allow-Methods'  => 'GET,POST,PUT,PATCH,DELETE,OPTIONS',
            'Access-Control-Allow-Headers'  => 'X-Confirm-Token,Authorization,Content-Type,X-Requested-With,Accept,Origin',
            'Access-Control-Expose-Headers' => 'X-Confirm-Token,Authorization,X-Request-Id',
            'Access-Control-Max-Age'        => '86400',
        ];

        if ($origin && in_array($origin, $allow, true)) {
            $headers['Access-Control-Allow-Origin'] = $origin;
            // 若使用 Cookie/Session 时需要；JWT 场景可不返回此项
            $headers['Access-Control-Allow-Credentials'] = 'true';
        }

        // 预检请求：直接 204 返回，避免进入业务栈
        if (strtoupper($request->method()) === 'OPTIONS') {
            return response('', 204)->header($headers);
        }

        $response = $next($request);
        foreach ($headers as $k => $v) {
            $response->header([$k => $v]);
        }
        return $response;
    }
}
