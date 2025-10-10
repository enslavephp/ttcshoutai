<?php
namespace app\shop\model;

use think\Model;

class Users extends Model
{
    // 设置表名
    protected $table = 'users';

    // 设置自动写入时间戳
    protected $autoWriteTimestamp = 'datetime';


    // 关联 tag
    public function roles()
    {
        return $this->belongsToMany(Roles::class, 'user_role_mapping', 'role_id', 'user_id');
    }
}
