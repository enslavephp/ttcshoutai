<?php
namespace app\shop\model;

use think\Db;
use think\Model;
class Product extends Model
{
    // 定义表名
    protected $table = 'products'; // 默认表名
    protected $autoWriteTimestamp = true; // 自动维护时间戳
    protected $fillable = ['name', 'sku', 'price', 'stock', 'description']; // 可批量填充字段

    // 关联分类
    public function categories()
    {
        return $this->belongsToMany(Category::class, 'product_category', 'category_id', 'product_id');
    }

    // 关联 tag
    public function tags()
    {
        return $this->belongsToMany(Tag::class, 'product_tag', 'tag_id', 'product_id');
    }
}
