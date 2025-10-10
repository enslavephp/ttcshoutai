<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 角色-权限映射（租户隔离）
 *
 * 表: shopadmin_role_permission
 * 关键键: (role_id, permission_id) + merchant_id
 */
class ShopAdminRolePermission extends Model
{
    protected $name = 'shopadmin_role_permission';
    protected $pk   = null; // ✅ 复合主键，不使用单列主键

    protected $autoWriteTimestamp = false;

    protected $field = [
        'merchant_id','role_id','permission_id',
        'assigned_at','assigned_by',
    ];

    protected $type = [
        'merchant_id'   => 'integer',
        'role_id'       => 'integer',
        'permission_id' => 'integer',
        'assigned_by'   => 'integer',
        'assigned_at'   => 'datetime',
    ];

    // ---------- 关联（附带租户条件） ----------
    public function role()
    {
        return $this->belongsTo(ShopAdminRole::class, 'role_id', 'id')
            ->where('merchant_id', $this->getAttr('merchant_id'));
    }

    public function permission()
    {
        return $this->belongsTo(ShopAdminPermission::class, 'permission_id', 'id')
            ->where('merchant_id', $this->getAttr('merchant_id'));
    }

    // ---------- 查询范围 ----------
    public function scopeOfMerchant($query, int $merchantId)
    {
        $query->where('merchant_id', $merchantId);
    }

    public function scopeOfRole($query, int $roleId)
    {
        $query->where('role_id', $roleId);
    }

    public function scopeOfPermission($query, int $permissionId)
    {
        $query->where('permission_id', $permissionId);
    }

    public function scopePageAndSort($query, int $page, int $limit, string $sortField = 'assigned_at', string $sortOrder = 'desc')
    {
        return $query->order($sortField, $sortOrder)->page(max(1,$page), max(1,$limit));
    }
}
