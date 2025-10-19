<?php
// app/shopadmin/model/SkuTag.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * 关系表：SKU-标签
 */
class SkuTag extends BaseModel
{
    protected $table = 'shop_sku_tag';

    protected $type = [
        'id'           => 'integer',
        'merchant_id'  => 'integer',
        'sku_id'       => 'integer',
        'tag_id'       => 'integer',
    ];

    public function sku()
    {
        return $this->belongsTo(Sku::class, 'sku_id', 'id');
    }

    public function tag()
    {
        return $this->belongsTo(Tag::class, 'tag_id', 'id');
    }
}
