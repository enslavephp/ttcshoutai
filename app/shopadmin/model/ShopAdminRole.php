<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 角色模型（ORM）
 *
 * 字段：
 *  - id, merchant_id, code, name, description
 *  - status, valid_from, valid_to, level
 *  - created_at, updated_at
 */
class ShopAdminRole extends Model
{
    protected $name = 'shopadmin_role';
    protected $pk   = 'id';

    /** 自动时间戳映射（created_at/updated_at） */
    protected $autoWriteTimestamp = true;
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';

    /** 字段白名单 */
    protected $field = [
        'id','merchant_id','code','name','description',
        'status','valid_from','valid_to','level',
        'created_at','updated_at',
    ];

    /** 类型转换 */
    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'status'      => 'integer',
        'level'       => 'integer',
        'valid_from'  => 'datetime',
        'valid_to'    => 'datetime',
        'created_at'  => 'datetime',
        'updated_at'  => 'datetime',
    ];

    // ---------- 关系 ----------

    /** 中间表（一个角色在本商户下分配给多个管理员） */
    public function userRoles()
    {
        return $this->hasMany(ShopAdminUserRole::class, 'role_id', 'id');
    }

    /**
     * 多对多：角色 ⇄ 管理员（通过 shopadmin_user_role）
     * 说明：中间表包含 merchant_id，withPivot 一并返回以便做租户校验
     */
    public function users()
    {
        return $this->belongsToMany(
            ShopAdminUser::class,     // 关联模型
            'shopadmin_user_role',    // 中间表
            'admin_id',               // 中间表指向用户的键
            'role_id'                 // 中间表指向当前模型(角色)的键
        )->withPivot(['merchant_id','assigned_at','assigned_by','valid_from','valid_to']);
    }

    // ---------- 查询范围（便于控制器复用） ----------

    /** 限定商户 */
    public function scopeOfMerchant($query, int $merchantId)
    {
        $query->where('merchant_id', $merchantId);
    }

    /** 关键字（code/name/description） */
    public function scopeKeyword($query, ?string $kw)
    {
        if ($kw !== null && $kw !== '') {
            $kw = '%' . str_replace(['%','_'], ['\%','\_'], $kw) . '%';
            $query->whereLike('code|name|description', $kw);
        }
    }

    /** 指定日期是否在有效期内（[from, to)） */
    public function scopeEffectiveOn($query, ?string $date)
    {
        if ($date && ($ts = strtotime($date)) !== false) {
            $dayStart = date('Y-m-d 00:00:00', $ts);
            $dayEnd   = date('Y-m-d 23:59:59', $ts);
            $query->where(function($sub) use ($dayEnd) {
                $sub->whereNull('valid_from')->whereOr('valid_from','<=', $dayEnd);
            })->where(function($sub) use ($dayStart) {
                $sub->whereNull('valid_to')->whereOr('valid_to','>', $dayStart);
            });
        }
    }
}
