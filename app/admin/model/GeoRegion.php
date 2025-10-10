<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;
use think\model\concern\SoftDelete;

class GeoRegion extends Model
{
    use SoftDelete;

    protected $name = 'geo_region';
    protected $pk   = 'id';
    protected $autoWriteTimestamp = 'datetime';

    protected $deleteTime = 'deleted_at';
    protected $defaultSoftDelete = null;

    // 建议隐藏无关字段（按需）
    // protected $hidden = ['deleted_at'];
}
