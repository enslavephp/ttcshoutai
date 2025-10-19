<?php
// app/shopadmin/model/Unit.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * 商品单位（按商户隔离）
 */
class Unit extends BaseModel
{
    protected $table = 'shop_unit';

    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'status'      => 'integer',
    ];

    /* 关联 */

    // 一个单位 -> 多个 SPU（库存基础单位）
    public function spus()
    {
        return $this->hasMany(Spu::class, 'unit_id', 'id');
    }

    // 一个单位 -> 多个 SKU（SKU 自有显示/销售单位）
    public function skus()
    {
        return $this->hasMany(Sku::class, 'unit_id', 'id');
    }
}
