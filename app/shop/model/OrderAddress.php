<?php

namespace app\shop\model;

use think\Model;

class OrderAddress extends Model
{
    // 自动隐藏的字段
    protected $hidden = ['location'];
    // 表名
    protected $table = 'order_address';

    // 主键
    protected $pk = 'id';

    // 自动写入时间戳字段
    protected $autoWriteTimestamp = true;

    // 时间戳字段
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 数据类型转换
    protected $type = [
        'location' => 'point',
    ];

    // 关联 Order 表
    public function order()
    {
        return $this->belongsTo(Order::class, 'order_id', 'order_id');
    }
}
