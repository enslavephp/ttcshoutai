<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;

/**
 * 权限表（ORM）
 *
 * 字段：
 *  - id, code, name, description
 *  - resource_type, resource_id, action
 *  - created_at
 *
 * 说明：
 *  - 为兼容现有结构，这里关闭自动时间戳。
 */
class AdminPermission extends Model
{
    protected $name = 'admin_permission';
    protected $pk   = 'id';

    /** 表只有 created_at，这里关闭自动时间戳以免报错 */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'id','code','name','description',
        'resource_type','resource_id','action',
        'created_at',
    ];

    /** 类型转换 */
    protected $type = [
        'id'            => 'integer',
        'resource_id'   => 'integer',
        'created_at'    => 'datetime',
    ];

    /**
     * 自定义查询范围：根据关键字进行查询
     */
    public function scopeKeyword($query, $keyword)
    {
        if ($keyword) {
            $query->whereLike('code|name|description|resource_type|resource_id|action', "%{$keyword}%");
        }
    }

    /**
     * 自定义查询范围：根据资源类型进行查询
     */
    public function scopeResourceType($query, $resourceType)
    {
        if ($resourceType) {
            $query->where('resource_type', $resourceType);
        }
    }

    /**
     * 自定义查询范围：根据资源ID进行查询
     */
    public function scopeResourceId($query, $resourceId)
    {
        if ($resourceId) {
            $query->where('resource_id', $resourceId);
        }
    }

    /**
     * 自定义查询范围：根据动作类型进行查询
     */
    public function scopeAction($query, $action)
    {
        if ($action) {
            $query->where('action', $action);
        }
    }

    /**
     * 自定义查询范围：分页和排序
     */
    public function scopePageAndSort($query, $page, $limit, $sortField = 'id', $sortOrder = 'desc')
    {
        return $query->order($sortField, $sortOrder)->page($page, $limit);
    }
}
