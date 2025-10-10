<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;

/**
 * 角色模型（ORM）
 *
 * 字段：
 *  - id, code, name, description
 *  - status, valid_from, valid_to, level
 *  - created_at, updated_at
 *
 * 说明：
 *  - 采用 created_at/updated_at 时间戳字段。
 */
class AdminRole extends Model
{
    protected $name = 'admin_role';
    protected $pk   = 'id';

    /** 自动时间戳映射（created_at/updated_at） */
    protected $autoWriteTimestamp = true;
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';

    /** 字段白名单 */
    protected $field = [
        'id','code','name','description',
        'status','valid_from','valid_to','level',
        'created_at','updated_at',
    ];

    /** 类型转换 */
    protected $type = [
        'id'         => 'integer',
        'status'     => 'integer',
        'level'      => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /**
     * 反向多对多：角色 → 管理员
     * - 中间表字段随同返回（可选）
     */
    public function admins()
    {
        return $this->belongsToMany(
            AdminUser::class,
            'admin_user_role', // 中间表
            'admin_id',        // 中间表指向 AdminUser 的键
            'role_id'          // 中间表指向 AdminRole 的键
        )->withPivot(['assigned_at','assigned_by','valid_from','valid_to']);
    }
}
