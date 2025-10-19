<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;
use think\model\concern\SoftDelete;

/**
 * 商户模型（与表 shopadmin_merchant 对应）
 *
 * @property int         $id
 * @property string      $merchant_name
 * @property string      $merchant_code
 * @property string      $contact_person
 * @property string      $contact_phone
 * @property string|null $email
 * @property string      $province
 * @property string      $city
 * @property string|null $district
 * @property string      $address
 * @property string|null $logo_url
 * @property string|null $business_license
 * @property int         $max_sub_accounts
 * @property int         $current_sub_accounts
 * @property int         $status
 * @property int         $merchant_level
 * @property string      $create_time
 * @property string      $update_time
 * @property int|null    $created_by
 * @property int|null    $updated_by
 * @property string|null $deleted_at
 */
class ShopAdminMerchant extends Model
{
    use SoftDelete;

    // 表名 & 主键
    protected $name = 'shopadmin_merchant';
    protected $pk   = 'id';

    /** 自动时间戳（使用 create_time / update_time） */
    protected $autoWriteTimestamp = true;
    protected $createTime = 'create_time';
    protected $updateTime = 'update_time';
    protected $dateFormat = 'Y-m-d H:i:s';

    /** 软删字段 */
    protected $deleteTime = 'deleted_at';
    protected $defaultSoftDelete = null;

    /** 字段白名单（与 SQL 同步） */
    protected $field = [
        'id',
        'merchant_name','merchant_code',
        'contact_person','contact_phone','email',
        'province','city','district','address',
        'logo_url','business_license',
        'max_sub_accounts','current_sub_accounts',
        'status','merchant_level',
        'create_time','update_time',
        'created_by','updated_by',
        'deleted_at',
    ];

    /** 类型转换 */
    protected $type = [
        'id'                   => 'integer',
        'max_sub_accounts'     => 'integer',
        'current_sub_accounts' => 'integer',
        'status'               => 'integer',
        'merchant_level'       => 'integer',
        'created_by'           => 'integer',
        'updated_by'           => 'integer',
        'create_time'          => 'datetime',
        'update_time'          => 'datetime',
        'deleted_at'           => 'datetime',
    ];

    /* ================= 关系（shopadmin 侧）================= */

    public function roles()
    {
        return $this->hasMany(\app\shopadmin\model\ShopAdminRole::class, 'merchant_id', 'id');
    }

    public function users()
    {
        return $this->hasMany(\app\shopadmin\model\ShopAdminUser::class, 'merchant_id', 'id');
    }

    /* ================= 查询范围（Scopes）================= */

    /** 关键字搜索：名称/编码/联系人/电话 */
    public function scopeKeyword($query, ?string $kw)
    {
        if ($kw !== null && $kw !== '') {
            $kw = '%' . str_replace(['%','_'], ['\\%','\\_'], $kw) . '%';
            $query->whereLike('merchant_name|merchant_code|contact_person|contact_phone', $kw);
        }
    }

    /** 按编码 */
    public function scopeCode($query, string $code)
    {
        return $query->where('merchant_code', $code);
    }

    /** 按状态（0 禁用 / 1 启用） */
    public function scopeStatus($query, int $status)
    {
        return $query->where('status', $status);
    }

    /** 按等级 */
    public function scopeLevel($query, int $level)
    {
        return $query->where('merchant_level', $level);
    }

    /** 按省市 */
    public function scopeRegion($query, string $province, ?string $city = null)
    {
        $query->where('province', $province);
        if ($city !== null && $city !== '') {
            $query->where('city', $city);
        }
        return $query;
    }

    /** 按创建时间区间（闭区间） */
    public function scopeCreatedBetween($query, ?string $start, ?string $end)
    {
        if ($start) $query->whereTime('create_time', '>=', $start);
        if ($end)   $query->whereTime('create_time', '<=', $end);
        return $query;
    }
}
