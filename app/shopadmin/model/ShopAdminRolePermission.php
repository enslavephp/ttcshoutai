<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 角色-权限映射（租户隔离）
 *
 * 表: shopadmin_role_permission
 * 复合主键: (merchant_id, role_id, permission_id) —— TP 不原生支持复合主键，按 where 条件操作
 *
 * @property int         $merchant_id
 * @property int         $role_id
 * @property int         $permission_id
 * @property string      $assigned_at
 * @property int|null    $assigned_by
 */
class ShopAdminRolePermission extends Model
{
    /** 物理表名 */
    protected $name = 'shopadmin_role_permission';

    /** 复合主键，不设置单列主键 */
    protected $pk   = null;

    /** 时间交给 DB DEFAULT/ON UPDATE 处理 */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'merchant_id',
        'role_id',
        'permission_id',
        'assigned_at',
        'assigned_by',
    ];

    /** 类型转换 */
    protected $type = [
        'merchant_id'   => 'integer',
        'role_id'       => 'integer',
        'permission_id' => 'integer',
        'assigned_by'   => 'integer',
        'assigned_at'   => 'datetime',
    ];

    /* -------- 关联（带租户隔离） -------- */

    /** 关联角色（限定同一 merchant_id） */
    public function role()
    {
        return $this->belongsTo(ShopAdminRole::class, 'role_id', 'id')
            ->where('merchant_id', $this->getAttr('merchant_id'));
    }

    /** 关联全局权限（无 merchant 维度） */
    public function permission()
    {
        return $this->belongsTo(\app\admin\model\ShopAdminPermission::class, 'permission_id', 'id');
    }

    /* -------- 常用作用域（含兼容别名） -------- */

    /** 按商户 */
    public function scopeMerchant($query, int $merchantId)
    {
        return $query->where('merchant_id', $merchantId);
    }
    public function scopeOfMerchant($query, int $merchantId)
    {
        return $this->scopeMerchant($query, $merchantId);
    }

    /** 按角色 */
    public function scopeRole($query, int $roleId)
    {
        return $query->where('role_id', $roleId);
    }
    public function scopeOfRole($query, int $roleId)
    {
        return $this->scopeRole($query, $roleId);
    }

    /** 按权限 */
    public function scopePermission($query, int $permissionId)
    {
        return $query->where('permission_id', $permissionId);
    }
    public function scopeOfPermission($query, int $permissionId)
    {
        return $this->scopePermission($query, $permissionId);
    }

    /** 分页+排序便捷 */
    public function scopePageAndSort($query, int $page, int $limit, string $sortField = 'assigned_at', string $sortOrder = 'desc')
    {
        return $query->order($sortField, $sortOrder)->page(max(1, $page), max(1, $limit));
    }
}
