<?php
declare(strict_types=1);

namespace app\admin\service;

use think\facade\Db;
use think\facade\Cache;

/**
 * 敏感操作确认服务（最小实现）
 * - 创建待确认记录（落库审计 + 缓存状态）
 * - 确认（将 token 置为 confirmed=true，直到过期）
 * - 校验（供中间件使用）
 *
 * 说明：表结构使用 admin_sensitive_operation_confirmation（你已提供的第7张表）。
 * 我们用 Cache 记录“是否已确认”，避免改表结构。
 */
class AdminSensitiveOperationService
{
    /** 生成随机 token（64 hex） */
    private function genToken(): string
    {
        return bin2hex(random_bytes(32));
    }

    /**
     * 发起一次敏感操作确认
     */
    public function initiate(int $adminId, string $operationType, array $opData, int $ttlSeconds): string
    {
        $ttlSeconds = max(1, (int)$ttlSeconds);
        $token      = $this->genToken();
        $now        = time();
        $expiresAt  = date('Y-m-d H:i:s', $now + $ttlSeconds);

        // 审计入库
        Db::name('admin_sensitive_operation_confirmation')->insert([
            'admin_id'           => $adminId,
            'operation_type'     => $operationType,
            'operation_data'     => json_encode($opData, JSON_UNESCAPED_UNICODE),
            'confirmation_token' => $token,
            'expires_at'         => $expiresAt,
            'created_at'         => date('Y-m-d H:i:s', $now),
        ]);

        // 缓存 meta + pending 状态
        Cache::set("soc:meta:{$token}", [
            'admin_id'       => $adminId,
            'operation_type' => $operationType,
            'expires_at'     => $expiresAt,
        ], $ttlSeconds);

        Cache::set("soc:confirmed:{$token}", false, $ttlSeconds);

        return $token;
    }

    /**
     * 用户确认（/admin/secure/confirm/verify 调用）
     * - 仅允许拥有该 token 的 admin 确认
     */
    public function confirm(int $adminId, string $token): bool
    {
        if ($token === '') return false;

        $row = Db::name('admin_sensitive_operation_confirmation')
            ->where('confirmation_token', $token)
            ->find();

        if (!$row) return false;
        if ((int)$row['admin_id'] !== $adminId) return false;

        $remain = strtotime((string)$row['expires_at']) - time();
        if ($remain <= 0) return false;

        Cache::set("soc:confirmed:{$token}", true, $remain);
        return true;
    }

    /**
     * 中间件校验：token 属于本人 + 类型一致 + 未过期 + 已确认
     */
    public function verifyConfirmed(int $adminId, string $operationType, string $token): bool
    {
        if ($token === '') return false;

        $row = Db::name('admin_sensitive_operation_confirmation')
            ->where('confirmation_token', $token)
            ->find();

        if (!$row) return false;
        if ((int)$row['admin_id'] !== $adminId) return false;
        if ($operationType !== '' && (string)$row['operation_type'] !== $operationType) return false;
        if (strtotime((string)$row['expires_at']) <= time()) return false;

        return Cache::get("soc:confirmed:{$token}") === true;
    }
}
