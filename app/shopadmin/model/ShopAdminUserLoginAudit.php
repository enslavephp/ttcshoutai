<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 管理员登录审计（ORM）
 *
 * 字段：
 *  - id, merchant_id, admin_id, username, occurred_at, ip, user_agent, device_fingerprint, result, reason
 *
 * 说明：
 *  - occurred_at 由业务控制，不启用自动时间戳
 *  - ip 存二进制（BLOB/VARBINARY），此处不做类型转换
 */
class ShopAdminUserLoginAudit extends Model
{
    protected $name = 'shopadmin_user_login_audit';
    protected $pk   = 'id';

    /** 不自动维护时间戳（occurred_at 由业务写入） */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'id',
        'merchant_id',
        'admin_id',
        'username',
        'occurred_at',
        'ip',
        'user_agent',
        'device_fingerprint',
        'result',
        'reason',
    ];

    /** 类型转换 */
    protected $type = [
        'id'           => 'integer',
        'merchant_id'  => 'integer',
        'admin_id'     => 'integer',
        'occurred_at'  => 'datetime',
        // ip 为二进制，不做类型转换
    ];

    /* ==== 可选的查询范围（若后续有列表/检索需求可用） ==== */

    /** 按商户过滤 */
    public function scopeByMerchant($query, int $merchantId)
    {
        return $query->where('merchant_id', $merchantId);
    }

    /** 按管理员过滤 */
    public function scopeByAdmin($query, int $adminId)
    {
        return $query->where('admin_id', $adminId);
    }

    /** 最近 N 条 */
    public function scopeRecent($query, int $limit = 50)
    {
        return $query->order('occurred_at', 'desc')->limit(max(1, $limit));
    }
}
