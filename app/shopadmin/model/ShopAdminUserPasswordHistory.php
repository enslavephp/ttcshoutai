<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 管理员密码历史（ORM）
 *
 * 字段：
 *  - id, merchant_id, admin_id, password, password_algo, password_meta
 *  - changed_at, changed_by, reason, client_info
 *
 * 说明：
 *  - 表内只有 changed_at，不走自动时间戳
 */
class ShopAdminUserPasswordHistory extends Model
{
    protected $name = 'shopadmin_user_password_history';
    protected $pk   = 'id';

    /** 不自动维护时间戳 */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'id',
        'merchant_id',
        'admin_id',
        'password',
        'password_algo',
        'password_meta',
        'changed_at',
        'changed_by',
        'reason',
        'client_info',
    ];

    /** 类型转换 */
    protected $type = [
        'id'           => 'integer',
        'merchant_id'  => 'integer',
        'admin_id'     => 'integer',
        'changed_by'   => 'integer',
        'changed_at'   => 'datetime',
    ];

    /* ==== 可选查询范围 ==== */

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
        return $query->order('changed_at', 'desc')->limit(max(1, $limit));
    }
}
