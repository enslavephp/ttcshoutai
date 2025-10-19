<?php
// app/shopadmin/model/Category.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * 商品类目（含生效期；顶级 parent_id=0；sort 越小越靠前）
 */
class Category extends BaseModel
{
    protected $table = 'shop_category';

    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'parent_id'   => 'integer',
        'status'      => 'integer',
        'valid_from'  => 'datetime',
        'valid_to'    => 'datetime',
        'sort'        => 'integer',
    ];

    /* ===== 生效期&排序作用域 ===== */

    /** 有效：状态=1 且在生效期内（空=无限制） */
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

    /** 通用排序（sort ASC, id ASC） */
    public function scopeOrdered($query)
    {
        return $query->order('sort', 'asc')->order('id', 'asc');
    }

    /* ===== 关联 ===== */

    // 父类目
    public function parent()
    {
        return $this->belongsTo(Category::class, 'parent_id', 'id');
    }

    // 子类目
    public function children()
    {
        return $this->hasMany(Category::class, 'parent_id', 'id');
    }

    // 多对多：类目 -> SKU（经 shop_sku_category）
    public function skus()
    {
        return $this->belongsToMany(Sku::class, 'shop_sku_category', 'sku_id', 'category_id');
    }

    // 中间表
    public function skuCategoryPivots()
    {
        return $this->hasMany(SkuCategory::class, 'category_id', 'id');
    }
}
