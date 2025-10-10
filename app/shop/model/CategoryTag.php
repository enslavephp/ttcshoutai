<?php
namespace app\shop\model;

use think\Model;

class CategoryTag extends Model
{
    protected $autoWriteTimestamp = true;
    protected $table = 'category_tag';

    // 定义与 Category 和 Tag 的关联关系
    public function category()
    {
        return $this->belongsTo('app\shop\model\Category', 'category_id','id');
    }

    public function tag()
    {
        return $this->belongsTo('app\shop\model\Tag', 'tag_id','id');
    }
}