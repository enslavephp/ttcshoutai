<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;
use think\facade\Db;

/**
 * 管理员-角色映射表（中间表 ORM）
 *
 * 典型字段：
 *  - id, admin_id, role_id
 *  - assigned_at, assigned_by
 *  - valid_from, valid_to
 *
 * 说明：
 *  - 统一通过 ORM 操作本表，不使用 Db::name('admin_user_role')。
 *  - 提供 attach/detach/sync 便捷方法，供控制器/业务层直接调用。
 */
class AdminUserRole extends Model
{
    /** 物理表名（受前缀管理） */
    protected $name = 'admin_user_role';

    /** 主键字段 */
    protected $pk   = 'id';

    /** 自动时间戳（若表没有 created_at/updated_at，可改成 false） */
    protected $autoWriteTimestamp = false;
    protected $dateFormat = 'Y-m-d H:i:s';

    /** 字段白名单（更安全） */
    protected $field = [
        'id','admin_id','role_id',
        'assigned_at','assigned_by',
    ];

    /** 类型转换（避免字符串数字引起比较错误） */
    protected $type = [
        'id'          => 'integer',
        'admin_id'    => 'integer',
        'role_id'     => 'integer',
        'assigned_by' => 'integer',
        'assigned_at' => 'datetime',
        'valid_from'  => 'datetime',
        'valid_to'    => 'datetime',
    ];

    /** 查询作用域：按用户ID */
    public function scopeAdminId($q, int $adminId) { $q->where('admin_id', $adminId); }

    /** 查询作用域：按角色ID */
    public function scopeRoleId($q, int $roleId)   { $q->where('role_id',  $roleId); }

    /** 获取某用户所有角色ID（不判断有效期） */
    public static function getRoleIdsByUser(int $adminId): array
    { return self::where('admin_id', $adminId)->column('role_id'); }

    /**
     * 绑定（存在即幂等；可附带有效期）
     * @param int         $adminId  管理员ID
     * @param int         $roleId   角色ID
     * @param string|null $from     生效起（可空）
     * @param string|null $to       失效止（可空，开区间）
     * @param int|null    $by       操作者ID（可空）
     */
    public static function attach(int $adminId, int $roleId, ?string $from=null, ?string $to=null, ?int $by=null): bool
    {
        $exists = self::where(['admin_id'=>$adminId,'role_id'=>$roleId])->find();
        if ($exists) {
            // 已存在：只更新有效期（若传入）
            $upd = [];
            if ($from!==null) $upd['valid_from'] = $from;
            if ($to!==null)   $upd['valid_to']   = $to;
            if ($upd) self::where(['admin_id'=>$adminId,'role_id'=>$roleId])->update($upd);
            return true;
        }
        return (bool) self::create([
            'admin_id'    => $adminId,
            'role_id'     => $roleId,
            'assigned_at' => date('Y-m-d H:i:s'),
            'assigned_by' => $by,
            'valid_from'  => $from,
            'valid_to'    => $to,
        ]);
    }

    /**
     * 解绑（不存在也视为成功）
     * @return int 受影响行数
     */
    public static function detach(int $adminId, int $roleId): int
    { return (int) self::where(['admin_id'=>$adminId,'role_id'=>$roleId])->delete(); }

    /**
     * 同步（全量覆盖：只保留给定 $roleIds）
     * - 删除不在 $roleIds 内的映射
     * - 增加缺失的映射
     */
    public static function syncUserRoles(int $adminId, array $roleIds, ?int $by=null): bool
    {
        $roleIds = array_values(array_unique(array_map('intval',$roleIds)));
        return Db::transaction(function() use ($adminId,$roleIds,$by){
            $current = self::where('admin_id',$adminId)->column('role_id');
            $toAdd = array_diff($roleIds, $current);
            $toDel = array_diff($current, $roleIds);

            if ($toDel) self::where('admin_id',$adminId)->whereIn('role_id',$toDel)->delete();
            foreach ($toAdd as $rid) self::create([
                'admin_id'=>$adminId, 'role_id'=>(int)$rid,
                'assigned_at'=>date('Y-m-d H:i:s'), 'assigned_by'=>$by,
            ]);
            return true;
        });
    }

    /** 是否已拥有某角色 */
    public static function userHasRole(int $adminId, int $roleId): bool
    { return self::where(['admin_id'=>$adminId,'role_id'=>$roleId])->count() > 0; }
}
