<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;

/**
 * 全局权限字典（无 merchant 维度）
 *
 * 表：shopadmin_permission
 *
 * @property int         $id
 * @property string      $code
 * @property string      $name
 * @property string|null $description
 * @property string      $resource_type
 * @property string|null $resource_id
 * @property string      $action
 * @property int         $is_system
 * @property string      $created_at
 * @property string      $updated_at
 * @property int         $version
 */
class ShopAdminPermission extends Model
{
    /** 物理表名 */
    protected $name = 'shopadmin_permission';

    /** 主键 */
    protected $pk   = 'id';

    /** 时间戳交由 DB DEFAULT / ON UPDATE 维护 */
    protected $autoWriteTimestamp = false;

    /** 字段白名单 */
    protected $field = [
        'id',
        'code',
        'name',
        'description',
        'resource_type',
        'resource_id',
        'action',
        'is_system',
        'created_at',
        'updated_at',
        'version',
    ];

    /** 类型转换 */
    protected $type = [
        'id'         => 'integer',
        'is_system'  => 'integer',
        'version'    => 'integer',
        'created_at' => 'datetime',
        'updated_at' => 'datetime',
    ];

    /** 只读字段，避免被业务误改 */
    protected $readonly = ['is_system'];

    /* ---------- 常用作用域 ---------- */

    /**
     * 三元组（resource_type, resource_id, action）筛选
     * - $id === null → resource_id IS NULL
     * - 否则         → resource_id = $id
     */
    public function scopeResource($query, string $type, ?string $id, string $action)
    {
        $query->where('resource_type', $type)->where('action', $action);
        return $id === null
            ? $query->whereNull('resource_id')
            : $query->where('resource_id', $id);
    }

    /** 关键字（code/name/description） */
    public function scopeKeyword($query, $keyword)
    {
        if ($keyword !== '' && $keyword !== null) {
            $kw = '%' . str_replace(['%','_'], ['\%','\_'], (string)$keyword) . '%';
            $query->whereLike('code|name|description', $kw);
        }
    }

    /** 资源类型 */
    public function scopeResourceType($query, $resourceType)
    {
        if ($resourceType !== '' && $resourceType !== null) {
            $query->where('resource_type', $resourceType);
        }
    }

    /**
     * 资源ID：
     * - ''/null → IS NULL
     * - 其他     → '='
     */
    public function scopeResourceId($query, $resourceId)
    {
        if ($resourceId === '' || $resourceId === null) {
            $query->whereNull('resource_id');
        } else {
            $query->where('resource_id', $resourceId);
        }
    }

    /** 动作 */
    public function scopeAction($query, $action)
    {
        if ($action !== '' && $action !== null) {
            $query->where('action', $action);
        }
    }

    /** 分页 + 排序 */
    public function scopePageAndSort($query, $page, $limit, $sortField = 'id', $sortOrder = 'desc')
    {
        $page  = max(1, (int)$page);
        $limit = max(1, (int)$limit);
        return $query->order($sortField, $sortOrder)->page($page, $limit);
    }
}
