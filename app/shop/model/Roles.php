<?php
namespace app\shop\model;

use think\Model;

class Roles extends Model
{
    // 设置表名
    protected $table = 'roles';

    // 设置自动写入时间戳
    protected $autoWriteTimestamp = 'datetime';
}
