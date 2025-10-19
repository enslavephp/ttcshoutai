<?php
// app/shopadmin/model/SkuCategory.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * 关系表：SKU-类目
 */
class SkuCategory extends BaseModel
{
    protected $table = 'shop_sku_category';

    protected $type = [
        'id'           => 'integer',
        'merchant_id'  => 'integer',
        'sku_id'       => 'integer',
        'category_id'  => 'integer',
    ];

    public function sku()
    {
        return $this->belongsTo(Sku::class, 'sku_id', 'id');
    }

    public function category()
    {
        return $this->belongsTo(Category::class, 'category_id', 'id');
    }
}
