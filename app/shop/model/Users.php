<?php
// File: app/shop/model/Users.php
namespace app\shop\model;


use think\Model;


class Users extends Model
{
// 绑定表
    protected $table = 'users';


// 时间戳（与 DDL 对齐）
    protected $autoWriteTimestamp = 'datetime';
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';


// 状态常量（DDL：0=正常,1=禁用,2=锁定）
    public const STATUS_NORMAL = 0;
    public const STATUS_DISABLED = 1;
    public const STATUS_LOCKED = 2;


// 多对多：用户-角色
    public function roles()
    {
// pivot 表名与 DDL 一致：user_roles（非 user_role_mapping）
        return $this->belongsToMany(Roles::class, 'user_roles', 'role_id', 'user_id');
    }


// 一对多：地址
    public function addresses()
    {
        return $this->hasMany(UserAddresses::class, 'user_id', 'id');
    }


// 一对多：第三方身份
    public function identities()
    {
        return $this->hasMany(UserIdentities::class, 'user_id', 'id');
    }
}