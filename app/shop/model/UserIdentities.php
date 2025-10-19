<?php
//------------------------------------------------------------
// File: app/shop/model/UserIdentities.php
namespace app\shop\model;


use think\Model;


class UserIdentities extends Model
{
    protected $table = 'user_identities';


    protected $autoWriteTimestamp = 'datetime';
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';


    public function user()
    {
        return $this->belongsTo(Users::class, 'user_id', 'id');
    }
}