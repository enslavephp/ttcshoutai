<?php
namespace app\shop\model;

use think\Model;

class ProductDiscount extends Model
{
    // 定义表名（可选，默认会使用类名小写作为表名）
    protected $name = 'product_discounts';

    // 设置主键
    protected $pk = 'id';

    // 自动写入时间戳字段
    protected $autoWriteTimestamp = 'timestamp';

    // 定义时间戳字段
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 允许批量赋值的字段
    protected $fillable = [
        'product_id',
        'shop_id',
        'discount_before_amount',
        'discount_after_amount',
        'discount_rate',
        'fixed_amount',
    ];

    // 定义与 Product 表的关联关系
    public function product()
    {
        return $this->belongsTo('app\shop\model\Product', 'product_id', 'id');
    }

    // 定义与 Shop 表的关联关系
    public function shop()
    {
        return $this->belongsTo('app\shop\model\Shop', 'shop_id', 'shop_id');
    }

    // 自定义操作：例如折扣金额计算
    public function calculateDiscount($originalPrice)
    {
        // 按折扣比例或者固定金额折扣来计算折后价格
        if ($this->fixed_amount > 0) {
            // 如果是固定金额折扣
            return max(0, $originalPrice - $this->fixed_amount);
        } else if ($this->discount_rate > 0) {
            // 计算打折后的价格
            return ($originalPrice-$this->discount_before_amount) * (1 - $this->discount_rate / 100) - $this->discount_before_amount;
        }
        // 如果没有折扣，返回原价
        return $originalPrice;
    }
}
