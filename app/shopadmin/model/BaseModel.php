<?php
// app/shopadmin/model/BaseModel.php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 通用基类：统一时间戳、主键、商户数据隔离作用域
 */
class BaseModel extends Model
{
    // 自动时间戳，字段名与库一致
    protected $autoWriteTimestamp = true;
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 主键
    protected $pk = 'id';

    /**
     * 作用域：按商户ID过滤（数据隔离）
     * 用法：Model::forMerchant($mid)->select();
     */
    public function scopeForMerchant($query, int $merchantId)
    {
        return $query->where('merchant_id', $merchantId);
    }
}
