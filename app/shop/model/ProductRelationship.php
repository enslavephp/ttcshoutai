<?php

namespace app\shop\model;

use think\Model;
use app\shop\model\Product as ProductModel;

class ProductRelationship extends Model
{
    // 设置表名
    protected $name = 'product_relationships';

    // 定义关联主商品
    public function product()
    {
        return $this->belongsTo(ProductModel::class, 'product_id', 'id');
    }

    // 定义关联的关联商品
    public function relatedProduct()
    {
        return $this->belongsTo(ProductModel::class, 'related_product_id', 'id');
    }

    // 自动时间戳
    protected $autoWriteTimestamp = true;

    // 定义可用字段
    protected $fillable = [
        'product_id',
        'related_product_id',
        'conversion_rate',
    ];
}
