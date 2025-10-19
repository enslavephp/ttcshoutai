<?php
//------------------------------------------------------------
// File: app/shop/model/Roles.php
namespace app\shop\model;


use think\Model;


class Roles extends Model
{
    protected $table = 'roles';


    protected $autoWriteTimestamp = 'datetime';
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';


// 多对多：角色-用户
    public function users()
    {
        return $this->belongsToMany(Users::class, 'user_roles', 'user_id', 'role_id');
    }
}