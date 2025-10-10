<?php

namespace app\shop\model;

use think\Model;

class Tag extends Model
{
    // 指定数据表
    protected $table = 'tags';

    // 设置自动写入时间戳
    protected $autoWriteTimestamp = 'datetime';
    /**
     * 根据关键字搜索商户
     */
    public static function searchTags($keyword = null)
    {
        $query = self::order(['updated_at' => 'desc', 'weight' => 'asc']);
        if ($keyword) {
            $query->whereLike('name', "%$keyword%");
        }
        return $query->select()->toArray();
    }
    // 定义与 Category 模型的关联
    public function category()
    {
        return $this->belongsTo(Category::class, 'categorie_id', 'id');
    }
    public function products()
    {
        return $this->belongsToMany(Product::class, 'product_tag', 'product_id', 'tag_id');
    }
}