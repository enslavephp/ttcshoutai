<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;
use think\model\concern\SoftDelete;

class ShopAdminMerchant extends Model
{
    use SoftDelete;

    // 表名 & 主键
    protected $name = 'shopadmin_merchant';
    protected $pk   = 'id';

    // 自动时间
    protected $autoWriteTimestamp = 'datetime'; // 使用 create_time / update_time

    // 软删字段
    protected $deleteTime = 'deleted_at'; // 对应你的表结构
    protected $defaultSoftDelete = null; // 未删除时的默认值

    // 建议：如需隐藏字段可在此定义
    // protected $hidden = ['deleted_at'];
}
