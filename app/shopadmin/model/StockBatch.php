<?php
// app/shopadmin/model/StockBatch.php
declare(strict_types=1);

namespace app\shopadmin\model;

/**
 * 库存批次（SPU 维度；基础单位计数；FEFO）
 */
class StockBatch extends BaseModel
{
    protected $table = 'shop_stock_batch';

    protected $type = [
        'id'              => 'integer',
        'merchant_id'     => 'integer',
        'spu_id'          => 'integer',
        'purchase_price'  => 'float',
        'quantity_base'   => 'integer',
        'reserved_base'   => 'integer',
        'status'          => 'integer',
        'production_date' => 'date',
        'expiration_at'   => 'date',
    ];

    /* 关联 */

    public function spu()
    {
        return $this->belongsTo(Spu::class, 'spu_id', 'id');
    }

    /* 计算属性 */

    /** 可用数量（基础单位） */
    public function getAvailableBaseAttr()
    {
        $q = (int) $this->getAttr('quantity_base');
        $r = (int) $this->getAttr('reserved_base');
        return max(0, $q - $r);
    }

    /* 作用域 */

    /** FEFO 排序：expiration_at 升序，NULL 最后；再按 id ASC */
    public function scopeFefoOrder($query)
    {
        return $query->orderRaw('expiration_at IS NULL ASC')
            ->order('expiration_at', 'asc')
            ->order('id', 'asc');
        // 说明：MySQL 中 NULL 最小，这里用 IS NULL ASC 将 NULL 放最后
    }

    /** 可用批次：status=1 且 (quantity_base - reserved_base) > 0 */
    public function scopeUsable($query)
    {
        return $query->where('status', 1)->whereRaw('(quantity_base - reserved_base) > 0');
    }
}
