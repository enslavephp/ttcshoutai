<?php

namespace app\shop\model;

use think\Model;

class Cart extends Model
{
    protected $name = 'cart';
    protected $autoWriteTimestamp = true;
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    public function product()
    {
        return $this->belongsTo(Product::class, 'product_id', 'id');
    }
}
