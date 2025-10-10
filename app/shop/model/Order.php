<?php

namespace app\shop\model;

use think\Model;

class Order extends Model
{
    // 定义表名
    protected $table = 'orders';

    // 设置主键字段
    protected $pk = 'order_id';

    // 自动写入时间戳
    protected $autoWriteTimestamp = true;

    // 时间字段的类型
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 关联订单项表
    public function items()
    {
        return $this->hasMany(OrderItem::class, 'order_id', 'order_id');
    }
    // 关联 OrderAddress 表
    public function orderAddress()
    {
        return $this->hasOne(OrderAddress::class, 'order_id', 'order_id');
    }
}
