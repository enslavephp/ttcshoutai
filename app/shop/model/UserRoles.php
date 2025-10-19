<?php
//------------------------------------------------------------
// File: app/shop/model/UserRoles.php （可选：直接操作 pivot 用）
namespace app\shop\model;


use think\Model;


class UserRoles extends Model
{
    protected $table = 'user_roles';


// pivot 只有 created_at，没有 updated_at
    protected $autoWriteTimestamp = 'datetime';
    protected $createTime = 'created_at';
    protected $updateTime = false; // 关闭 update_time
    protected $dateFormat = 'Y-m-d H:i:s';


// 复合主键：无单一自增主键
    protected $pk = null;
}