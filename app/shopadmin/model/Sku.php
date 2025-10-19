<?php
// app/shopadmin/model/Sku.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * SKU（销售项）
 * - 必须绑定 SPU
 * - 独立定价；必须有图片 image
 * - conversion_base_qty：1 个该 SKU 消耗的 SPU 基础单位数量（>=1）
 * - 条码 barcode 在商户内唯一
 */
class Sku extends BaseModel
{
    protected $table = 'shop_sku';

    protected $type = [
        'id'                  => 'integer',
        'merchant_id'         => 'integer',
        'spu_id'              => 'integer',
        'unit_id'             => 'integer',
        'sale_price'          => 'float',
        'market_price'        => 'float',
        'conversion_base_qty' => 'integer',
        'status'              => 'integer',
        'sort'                => 'integer',
    ];

    /* 关联 */

    public function spu()
    {
        return $this->belongsTo(Spu::class, 'spu_id', 'id');
    }

    public function unit()
    {
        return $this->belongsTo(Unit::class, 'unit_id', 'id');
    }

    // 多对多：SKU -> 类目
    public function categories()
    {
        return $this->belongsToMany(Category::class, 'shop_sku_category', 'category_id', 'sku_id');
    }

    // 多对多：SKU -> 标签
    public function tags()
    {
        return $this->belongsToMany(Tag::class, 'shop_sku_tag', 'tag_id', 'sku_id');
    }

    public function skuCategoryPivots()
    {
        return $this->hasMany(SkuCategory::class, 'sku_id', 'id');
    }

    public function skuTagPivots()
    {
        return $this->hasMany(SkuTag::class, 'sku_id', 'id');
    }

    /* 便捷：库存换算 */

    /** 对应 SPU 的可用库存（基础单位） */
    public function getSpuAvailableBaseAttr()
    {
        $spu = $this->spu;
        if (!$spu) return 0;
        return (int) ($spu->available_base ?? 0);
    }

    /** 可售数量（以本 SKU 单位）= floor( SPU可用基础单位 / conversion_base_qty ) */
    public function getAvailableAttr()
    {
        $base = (int) ($this->getAttr('spu_available_base') ?? $this->getSpuAvailableBaseAttr());
        $conv = max(1, (int) $this->getAttr('conversion_base_qty') ?: 1);
        return intdiv(max(0, $base), $conv);
    }
}
