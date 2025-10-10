<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 权限表（ORM）
 *
 * 字段:
 *  id, merchant_id, code, name, description,
 *  is_system, resource_type, resource_id, action,
 *  created_at, updated_at, version
 *
 * 说明:
 *  - 由 DB 维护时间戳（DEFAULT CURRENT_TIMESTAMP），这里关闭自动时间戳，避免冲突。
 */
class ShopAdminPermission extends Model
{
    protected $name = 'shopadmin_permission';
    protected $pk   = 'id';

    /** 时间戳交给 DB 维护 */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'id','merchant_id','code','name','description',
        'is_system','resource_type','resource_id','action',
        'created_at','updated_at','version',
    ];

    /** 类型转换 */
    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'is_system'   => 'integer', // 或 'bool'，看你需要
        'version'     => 'integer',
        'created_at'  => 'datetime',
        'updated_at'  => 'datetime',
        // resource_id 保持字符串/NULL 语义
    ];

    // ---------- 查询范围 ----------
    public function scopeOfMerchant($query, int $merchantId)
    {
        $query->where('merchant_id', $merchantId);
    }

    public function scopeKeyword($query, $keyword)
    {
        if ($keyword !== '' && $keyword !== null) {
            $kw = '%' . str_replace(['%','_'], ['\%','\_'], (string)$keyword) . '%';
            $query->whereLike('code|name|description|resource_type|resource_id|action', $kw);
        }
    }

    public function scopeResourceType($query, $resourceType)
    {
        if ($resourceType !== '' && $resourceType !== null) {
            $query->where('resource_type', $resourceType);
        }
    }

    /**
     * 资源ID筛选
     * - 空串/NULL → resource_id IS NULL
     * - 其他值   → resource_id = 值
     */
    public function scopeResourceId($query, $resourceId)
    {
        if ($resourceId === '' || $resourceId === null) {
            $query->whereNull('resource_id');
        } else {
            $query->where('resource_id', $resourceId);
        }
    }

    public function scopeAction($query, $action)
    {
        if ($action !== '' && $action !== null) {
            $query->where('action', $action);
        }
    }

    public function scopePageAndSort($query, $page, $limit, $sortField = 'id', $sortOrder = 'desc')
    {
        $page  = max(1, (int)$page);
        $limit = max(1, (int)$limit);
        return $query->order($sortField, $sortOrder)->page($page, $limit);
    }
}
