<?php
namespace app\shop\model;

use think\Model;

class UserRoleMapping extends Model
{
    // 设置当前模型对应的表名
    protected $name = 'user_role_mapping';

    // 开启自动写入时间戳
    protected $autoWriteTimestamp = true;

    // 指定时间戳字段名
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 设置字段类型转换
    protected $type = [
        'id'       => 'integer',
        'user_id'  => 'integer',
        'role_id'  => 'integer',
        'level'    => 'integer',
    ];

    // 允许写入的字段
    protected $field = [
        'user_id',
        'role_id',
        'level',
    ];

    // 关联 tag
    public function userRoleMapping()
    {
        return $this->belongsToMany(Users::class, 'user', 'role_id', 'user_id');
    }
}
