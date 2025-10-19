<?php
// app/shopadmin/model/Spu.php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\model\concern\SoftDelete;

/**
 * SPU（父级产品，库存主体）
 * - gallery TEXT（存放 JSON 字符串）自动转 array
 * - 扣减、入库都以 SPU 为单位（基础单位=unit_id）
 */
class Spu extends BaseModel
{
    use SoftDelete;
    protected $deleteTime = 'deleted_at';

    protected $table = 'shop_spu';

    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'unit_id'     => 'integer',
        'status'      => 'integer',
        'sort'        => 'integer',
        'deleted_at'  => 'datetime',
        'gallery'     => 'json',      // TEXT 字段，自动 JSON 转换
    ];

    /* 关联 */

    public function unit()
    {
        return $this->belongsTo(Unit::class, 'unit_id', 'id');
    }

    public function skus()
    {
        return $this->hasMany(Sku::class, 'spu_id', 'id');
    }

    public function stockBatches()
    {
        return $this->hasMany(StockBatch::class, 'spu_id', 'id');
    }

    /* 便捷：聚合库存（基础单位） */

    /** 可用库存（基础单位）：SUM(quantity_base - reserved_base) */
    public function getAvailableBaseAttr()
    {
        if (!$this->getAttr('id')) return 0;
        $sum = $this->stockBatches()
            ->where('status', 1)
            ->sum('quantity_base - reserved_base');
        return (int) $sum;
    }
}
