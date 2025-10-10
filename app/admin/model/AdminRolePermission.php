<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;

/**
 * 角色-权限映射表（ORM）
 *
 * 典型字段：
 *  - id, role_id, permission_id
 *  - assigned_at, assigned_by
 *
 * 说明：
 *  - 若你的表还有 created_at/updated_at，可把 $autoWriteTimestamp 改为 true 并映射字段名。
 */
class AdminRolePermission extends Model
{
    protected $name = 'admin_role_permission';
    protected $pk   = 'id';

    /** 默认关闭自动时间戳（按你的表结构调整） */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'id','role_id','permission_id',
        'assigned_at','assigned_by',
    ];

    /** 类型转换 */
    protected $type = [
        'id'            => 'integer',
        'role_id'       => 'integer',
        'permission_id' => 'integer',
        'assigned_by'   => 'integer',
        'assigned_at'   => 'datetime',
    ];
}
