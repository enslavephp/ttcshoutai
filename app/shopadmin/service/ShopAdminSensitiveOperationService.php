<?php
declare(strict_types=1);

namespace app\shopadmin\service;

use think\facade\Db;
use think\facade\Cache;

/**
 * 商户侧敏感操作确认服务（统一签名版）
 * 存储表：shopadmin_sensitive_operation_confirmation
 * 关键点：
 *  - 严格校验 merchant_id + admin_id + token
 *  - Cache 分片包含 merchant_id，防止跨租户串扰
 *  - verifyConfirmed() 供中间件或二次检查使用
 */
class ShopAdminSensitiveOperationService
{
    /** 64位hex token */
    private function genToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    private function metaKey(int $merchantId, string $token): string
    {
        return "shop:soc:meta:{$merchantId}:{$token}";
    }

    private function confirmedKey(int $merchantId, string $token): string
    {
        return "shop:soc:confirmed:{$merchantId}:{$token}";
    }

    /**
     * 发起一次敏感操作确认
     * @param int $merchantId 商户ID（租户隔离）
     * @param int $adminId    发起人ID
     * @param string $operationType 操作类型（业务自定义）
     * @param array $opData   操作上下文数据（将入库为 JSON）
     * @param int $ttlSeconds Token 有效期（秒）
     * @return string confirmation_token
     */
    public function initiate(int $merchantId, int $adminId, string $operationType, array $opData, int $ttlSeconds): string
    {
        $ttlSeconds = max(1, (int)$ttlSeconds);
        $token      = $this->genToken();
        $now        = time();
        $expiresAt  = date('Y-m-d H:i:s', $now + $ttlSeconds);

        // 审计入库（严格带上 merchant_id）
        Db::name('shopadmin_sensitive_operation_confirmation')->insert([
            'merchant_id'        => $merchantId,
            'admin_id'           => $adminId,
            'operation_type'     => $operationType,
            'operation_data'     => json_encode($opData, JSON_UNESCAPED_UNICODE),
            'confirmation_token' => $token,
            'expires_at'         => $expiresAt,
            'created_at'         => date('Y-m-d H:i:s', $now),
        ]);

        // Cache：meta + pending 状态（与 DB 过期保持一致）
        Cache::set($this->metaKey($merchantId, $token), [
            'merchant_id'    => $merchantId,
            'admin_id'       => $adminId,
            'operation_type' => $operationType,
            'expires_at'     => $expiresAt,
        ], $ttlSeconds);

        Cache::set($this->confirmedKey($merchantId, $token), false, $ttlSeconds);

        return $token;
    }

    /**
     * 用户确认（统一签名）
     * @return bool 是否确认成功（校验租户、账号、有效期）
     */
    public function confirm(int $merchantId, int $adminId, string $token): bool
    {
        if ($token === '') return false;

        $row = Db::name('shopadmin_sensitive_operation_confirmation')
            ->where('confirmation_token', $token)
            ->where('merchant_id', $merchantId)
            ->where('admin_id', $adminId)
            ->find();

        if (!$row) return false;

        $remain = strtotime((string)$row['expires_at']) - time();
        if ($remain <= 0) return false;

        // 确认标记只对本租户本令牌生效
        Cache::set($this->confirmedKey($merchantId, $token), true, $remain);
        return true;
    }

    /**
     * 二次校验：必须是同一租户&同一管理员&同一操作类型&未过期&已确认
     */
    public function verifyConfirmed(int $merchantId, int $adminId, string $operationType, string $token): bool
    {
        if ($token === '') return false;

        $row = Db::name('shopadmin_sensitive_operation_confirmation')
            ->where('confirmation_token', $token)
            ->where('merchant_id', $merchantId)
            ->where('admin_id', $adminId)
            ->find();

        if (!$row) return false;
        if ($operationType !== '' && (string)$row['operation_type'] !== $operationType) return false;
        if (strtotime((string)$row['expires_at']) <= time()) return false;

        return Cache::get($this->confirmedKey($merchantId, $token)) === true;
    }
}
