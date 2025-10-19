<?php
// app/shopadmin/model/Tag.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * 商品标签（含有效期；sort 越小越靠前）
 */
class Tag extends BaseModel
{
    protected $table = 'shop_tag';

    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'status'      => 'integer',
        'valid_from'  => 'datetime',
        'valid_to'    => 'datetime',
        'sort'        => 'integer',
    ];

    /* ===== 生效期&排序作用域 ===== */

    public function scopeEffective($query, ?string $now = null)
    {
        $nowExp = $now ?? date('Y-m-d H:i:s');
        return $query->where('status', 1)
            ->where(function ($q) use ($nowExp) {
                $q->whereNull('valid_from')->whereOr('valid_from', '<=', $nowExp);
            })->where(function ($q) use ($nowExp) {
                $q->whereNull('valid_to')->whereOr('valid_to', '>', $nowExp);
            });
    }

    public function scopeOrdered($query)
    {
        return $query->order('sort', 'asc')->order('id', 'asc');
    }

    /* ===== 关联 ===== */

    // 多对多：标签 -> SKU（经 shop_sku_tag）
    public function skus()
    {
        return $this->belongsToMany(Sku::class, 'shop_sku_tag', 'sku_id', 'tag_id');
    }

    public function skuTagPivots()
    {
        return $this->hasMany(SkuTag::class, 'tag_id', 'id');
    }
}
