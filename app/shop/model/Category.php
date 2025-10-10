<?php
namespace app\shop\model;

use think\Model;

class Category extends Model
{
    protected $autoWriteTimestamp = true;
    protected $fillable = ['name', 'image'];
    protected $table = 'categories';
    // 关联商品
    public function products()
    {
        return $this->belongsToMany(Product::class, 'product_category', 'product_id', 'category_id');
    }
    // 定义字段的类型转换
    protected $type = [
        'id' => 'integer',
        'name' => 'string',
        'image' => 'string',
    ];
}
