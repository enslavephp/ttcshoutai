<?php
namespace app\middleware;

use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;
use think\facade\Cache;
use think\facade\Cookie;
use think\facade\Log;

class TokenMiddleware
{
    private TokenService $tokens;

    public function __construct()
    {
        $cache = new CacheFacadeAdapter();
        $clock = new SystemClock();
        $cfg   = config('jwt') ?: [];
        $this->tokens = new TokenService($cache, $clock, $cfg);
    }

    public function handle($request, \Closure $next)
    {
        // ===== 路由白名单：不需要 access 参与校验的接口 =====
        $path = ltrim(strtolower($request->pathinfo() ?? ''), '/');
        $whitelist = [
            'shop/user/login',
            'shop/user/register',
            'shop/user/phonelogin',
            'shop/user/phoneregister',
            'shop/user/refresh', // 刷新接口走控制器内校验 refresh
        ];
        if (in_array($path, $whitelist, true)) {
            return $next($request);
        }
        // ================================================

        // 1) 取 access token：优先 Authorization，其次 Cookie(at)
        $auth = $request->header('Authorization');
        $cookieAtName = config('jwt.cookie.name_access', 'at');
        $cookieAt = Cookie::get($cookieAtName);

        $rawToken = null;
        if ($auth && stripos($auth, 'Bearer ') === 0) {
            $rawToken = substr($auth, 7);
        } elseif (!empty($cookieAt)) {
            $rawToken = $cookieAt;
        }

        if (!$rawToken) {
            return $this->unauthorized('未登录，请先登录');
        }

        // 2) 解析 + 黑名单/iss/aud 校验
        try {
            $decoded = $this->tokens->parse($rawToken);
        } catch (\Firebase\JWT\ExpiredException $e) {
            return $this->unauthorized('会话已过期，请重新登录');
        } catch (\Throwable $e) {
            Log::warning('JWT 解析失败: '.$e->getMessage());
            return $this->unauthorized('会话已失效，请重新登录');
        }

        // 3) 只允许 access 访问业务接口
        $typ = (string)($decoded->typ ?? '');
        if ($typ !== 'access') {
            return $this->unauthorized('令牌类型错误');
        }

        $uid = (int)($decoded->user_id ?? 0);
        $jti = (string)($decoded->jti ?? '');
        $exp = (int)($decoded->exp ?? 0);
        if ($uid <= 0 || $jti === '' || $exp <= 0) {
            return $this->unauthorized('令牌无效');
        }

        // 4) 活跃态校验（新键优先，失败再检查旧键并一次性迁移）
        if (!$this->isSessionValidAndMigrate($uid, $jti, $exp)) {
            return $this->unauthorized('会话已失效，请重新登录');
        }

        // 5) 注入上下文
        $request->user = [
            'id'        => $uid,
            'username'  => (string)($decoded->username ?? ''),
            'telephone' => (string)($decoded->telephone ?? ''),
            'is_admin'  => (bool)  ($decoded->is_admin ?? false),
            'role_id'   => (int)   ($decoded->role_id ?? 0),
        ];

        return $next($request);
    }

    protected function isSessionValidAndMigrate(int $userId, string $jti, int $exp): bool
    {
        $newKey = "active_access_jti:{$userId}";
        $oldKey = "active_token_jti:{$userId}"; // 兼容历史

        $active = Cache::get($newKey);
        if (is_string($active) && hash_equals($active, $jti)) {
            return true;
        }

        $legacy = Cache::get($oldKey);
        if (is_string($legacy) && hash_equals($legacy, $jti)) {
            $ttl = max(1, $exp - time());
            Cache::set($newKey, $jti, $ttl);
            Log::info("迁移活跃态: {$oldKey} -> {$newKey}, uid={$userId}, ttl={$ttl}");
            return true;
        }

        Log::warning("会话无效：user_id={$userId}, req_jti={$jti}, cache_new={$active}, cache_old={$legacy}");
        return false;
    }

    private function unauthorized(string $msg)
    {
        return json(['msg' => $msg, 'code' => 401], 401);
    }
}
