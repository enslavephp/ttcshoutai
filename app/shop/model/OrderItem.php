<?php

namespace app\shop\model;

use think\Model;

class OrderItem extends Model
{
    // 定义表名
    protected $table = 'order_items';

    // 设置主键字段
    protected $pk = 'order_item_id';

    // 自动写入时间戳
    protected $autoWriteTimestamp = true;

    // 时间字段的类型
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 关联订单表
    public function order()
    {
        return $this->belongsTo(Order::class, 'order_id', 'order_id');
    }
    // 关联订单项表
    public function productItems()
    {
        return $this->hasMany(Product::class, 'id', 'product_id');
    }
}
