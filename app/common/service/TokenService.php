<?php
namespace app\common\service;

use app\common\contracts\SimpleCacheInterface;
use app\common\contracts\ClockInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;


class TokenService
{
    private SimpleCacheInterface $cache;
    private ClockInterface $clock;
    private string $secret;
    private string $algo;
    private int $leeway;
    private ?string $issuer;
    private ?string $audience;

    private const BL_PREFIX          = 'jwt_blacklist:';          // 黑名单 key 前缀
    private const ACT_ACCESS_PREFIX  = 'active_access_jti:';      // 与 Login.php 保持一致
    private const ACT_REFRESH_PREFIX = 'active_refresh_jti:';     // 与 Login.php 保持一致

    public function __construct(SimpleCacheInterface $cache, ClockInterface $clock, array $cfg)
    {
        $this->cache    = $cache;
        $this->clock    = $clock;
        $this->secret   = (string)($cfg['secret'] ?? env('JWT_SECRET'));
        $this->algo     = (string)($cfg['algo']   ?? 'HS256');
        $this->leeway   = (int)   ($cfg['leeway'] ?? 0);
        $this->issuer   = $cfg['iss'] ?? ($cfg['issuer'] ?? null);
        $this->audience = $cfg['aud'] ?? ($cfg['audience'] ?? null);

        if (!$this->secret) {
            throw new \RuntimeException('JWT secret not configured');
        }

        // 为 Firebase/JWT 设置 leeway
        if ($this->leeway > 0) {
            JWT::$leeway = $this->leeway;
        }
    }

    /**
     * 签发一对 access/refresh。
     * - 为二者生成不同 JTI
     * - 写入 active_access_jti / active_refresh_jti
     */
    public function issue(array $claims, int $accessTtl, int $refreshTtl): array
    {
        $now = $this->clock->now();
        $uid = (int)($claims['user_id'] ?? 0);

        $accessJti  = $this->genJti();
        $refreshJti = $this->genJti();

        $accessExp  = $now + max(1, (int)$accessTtl);
        $refreshExp = $now + max(1, (int)$refreshTtl);

        // 会话起点 iat0（给后续 refresh 继承）
        $baseIat0 = (int)($claims['iat0'] ?? $now);

        $accessPayload = array_merge($claims, [
            'jti'  => $accessJti,
            'typ'  => 'access',
            'iat'  => $now,
            'nbf'  => $now,
            'exp'  => $accessExp,
            'iat0' => $baseIat0,
        ]);

        $refreshPayload = array_merge($claims, [
            'jti'  => $refreshJti,
            'typ'  => 'refresh',
            'iat'  => $now,
            'nbf'  => $now,
            'exp'  => $refreshExp,
            'iat0' => $baseIat0,
        ]);

        // 标准注册声明（可选）
        if ($this->issuer)   { $accessPayload['iss'] = $this->issuer;   $refreshPayload['iss'] = $this->issuer; }
        if ($this->audience) { $accessPayload['aud'] = $this->audience; $refreshPayload['aud'] = $this->audience; }

        $access  = JWT::encode($accessPayload,  $this->secret, $this->algo);
        $refresh = JWT::encode($refreshPayload, $this->secret, $this->algo);

        // 记录当前活跃 JTI
        if ($uid > 0) {
            $this->cache->set(self::ACT_ACCESS_PREFIX.$uid,  $accessJti,  $accessTtl);
            $this->cache->set(self::ACT_REFRESH_PREFIX.$uid, $refreshJti, $refreshTtl);
        }

        return [
            'access'      => $access,
            'refresh'     => $refresh,
            'access_exp'  => $accessExp,
            'refresh_exp' => $refreshExp,
        ];
    }

    /**
     * 解析并校验 token（签名/exp/nbf/iat），并做黑名单/iss/aud 校验。
     * 返回 payload（object）。
     */
    public function parse(string $token): object
    {
        // 兜底清理 “Bearer ” 前缀（避免上层漏处理）
        $token = trim($token);
        if (stripos($token, 'Bearer ') === 0) {
            $token = trim(substr($token, 7));
        }

        $payload = JWT::decode($token, new Key($this->secret, $this->algo)); // 自动校验 exp/nbf/iat

        // 黑名单
        $jti = (string)($payload->jti ?? '');
        if ($jti && $this->isBlacklisted($jti)) {
            throw new \UnexpectedValueException('Token has been revoked');
        }

        // 可选：严格校验 iss/aud（若配置存在）
        if ($this->issuer !== null && (($payload->iss ?? null) !== $this->issuer)) {
            throw new \UnexpectedValueException('Issuer mismatch');
        }
        if ($this->audience !== null && (($payload->aud ?? null) !== $this->audience)) {
            throw new \UnexpectedValueException('Audience mismatch');
        }

        return $payload;
    }

    /**
     * 用 refresh 轮换新的一对 token。
     * - 校验 refresh（签名/过期/黑名单）
     * - typ == refresh
     * - 强制匹配 active_refresh_jti:{uid}
     * - 拉黑旧 refresh JTI
     * - 由 $claimsResolver 生成业务 claims（务必包含 user_id）
     */
    public function rotateFromRefresh(string $refreshToken, callable $claimsResolver): array
    {
        // 兜底清理 “Bearer ” 前缀（防止上层传原样 Authorization）
        $refreshToken = trim($refreshToken);
        if (stripos($refreshToken, 'Bearer ') === 0) {
            $refreshToken = trim(substr($refreshToken, 7));
        }

        $payload = $this->parse($refreshToken); // 内含黑名单/iss/aud 校验
        $typ = (string)($payload->typ ?? '');
        if ($typ !== 'refresh') {
            throw new \UnexpectedValueException('Not a refresh token');
        }

        $uid = (int)($payload->user_id ?? 0);
        if ($uid <= 0) {
            throw new \UnexpectedValueException('Bad refresh token claims');
        }

        // 必须与当前活跃 refresh JTI 匹配（单活会话）
        $activeR = (string)($this->cache->get(self::ACT_REFRESH_PREFIX.$uid) ?? '');
        $curJti  = (string)($payload->jti ?? '');
        if (!$activeR || !hash_equals($activeR, $curJti)) {
            throw new \UnexpectedValueException('Refresh token not active');
        }


        // 拉黑旧 refresh（避免重复使用）
        $ttlLeft = max(0, (int)($payload->exp ?? 0) - $this->clock->now());
        if ($curJti && $ttlLeft > 0) {
            $this->blacklist($curJti, $ttlLeft);
        }

        // 生成新的业务 claims
        $seed   = (array)$payload;
        $claims = $claimsResolver($seed);
        if (!is_array($claims) || !isset($claims['user_id'])) {
            throw new \UnexpectedValueException('claimsResolver must return array with user_id');
        }

        // 继承 iat0
        if (!isset($claims['iat0'])) {
            $claims['iat0'] = (int)($payload->iat0 ?? ($payload->iat ?? $this->clock->now()));
        }

        // 读取配置 TTL
        $accessTtl  = (int)(\app\common\Helper::getValue('jwt.expire')      ?? 3600);
        $refreshTtl = (int)(\app\common\Helper::getValue('jwt.refresh_ttl') ?? 7*24*3600);

        return $this->issue($claims, $accessTtl, $refreshTtl);
    }

    /** 将某个 JTI 加入黑名单（ttl 秒） */
    public function blacklist(string $jti, int $ttl): void
    {
        if (!$jti) return;
        $ttl = max(1, (int)$ttl);
        $this->cache->set(self::BL_PREFIX.$jti, 1, $ttl);
    }

    /** 查询 JTI 是否在黑名单 */
    public function isBlacklisted(string $jti): bool
    {
        if (!$jti) return false;
        return (bool)$this->cache->get(self::BL_PREFIX.$jti);
    }

    private function genJti(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (\Throwable $e) {
            return md5(uniqid((string)mt_rand(), true));
        }
    }
}
