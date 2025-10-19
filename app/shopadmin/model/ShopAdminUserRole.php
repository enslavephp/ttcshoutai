<?php
declare(strict_types=1);

namespace app\shopadmin\model;

use think\Model;
use think\facade\Db;

/**
 * 【商户侧】管理员-角色映射（中间表 ORM）
 *
 * 建议表结构唯一索引：
 *   UNIQUE KEY uk_user_role_tenant (merchant_id, admin_id, role_id)
 *
 * 参考字段（根据你的库为准）：
 *  - id, merchant_id, admin_id, role_id
 *  - assigned_at, assigned_by
 *  - valid_from, valid_to
 *  - created_at, updated_at
 */
class ShopAdminUserRole extends Model
{
    /** 物理表名（受前缀管理） */
    protected $name = 'shopadmin_user_role';

    /** 主键字段（若你的表无 id，可将 $pk=null 并把 $autoWriteTimestamp=false） */
    protected $pk   = 'id';

    /** 自动时间戳（若表无 created_at/updated_at，改为 false） */
    protected $autoWriteTimestamp = true;
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';

    /** 字段白名单（更安全） */
    protected $field = [
        'id',
        'merchant_id',
        'admin_id',
        'role_id',
        'assigned_at',
        'assigned_by',
        'valid_from',
        'valid_to',
        'created_at',
        'updated_at',
    ];

    /** 类型转换 */
    protected $type = [
        'id'          => 'integer',
        'merchant_id' => 'integer',
        'admin_id'    => 'integer',
        'role_id'     => 'integer',
        'assigned_by' => 'integer',
        'assigned_at' => 'datetime',
        'valid_from'  => 'datetime',
        'valid_to'    => 'datetime',
        'created_at'  => 'datetime',
        'updated_at'  => 'datetime',
    ];

    /* ==================== 查询作用域（含兼容命名） ==================== */

    /** 按商户 */
    public function scopeMerchantId($q, int $merchantId) { $q->where('merchant_id', $merchantId); }
    public function scopeMerchant($q, int $merchantId)   { return $this->scopeMerchantId($q, $merchantId); } // 兼容

    /** 按用户 */
    public function scopeAdminId($q, int $adminId) { $q->where('admin_id', $adminId); }
    public function scopeAdmin($q, int $adminId)   { return $this->scopeAdminId($q, $adminId); } // 兼容

    /** 按角色 */
    public function scopeRoleId($q, int $roleId) { $q->where('role_id',  $roleId); }
    public function scopeRole($q, int $roleId)   { return $this->scopeRoleId($q, $roleId); } // 兼容

    /* ==================== 便捷查询 ==================== */

    /**
     * 获取某商户下某用户的所有角色ID（不判断有效期）
     */
    public static function getRoleIdsByUser(int $merchantId, int $adminId): array
    {
        return array_map('intval',
            self::where(['merchant_id'=>$merchantId,'admin_id'=>$adminId])->column('role_id')
        );
    }

    /**
     * 用户是否拥有某角色（按商户隔离；不判断有效期）
     */
    public static function userHasRole(int $merchantId, int $adminId, int $roleId): bool
    {
        return self::where([
                'merchant_id' => $merchantId,
                'admin_id'    => $adminId,
                'role_id'     => $roleId,
            ])->count() > 0;
    }

    /* ==================== 写操作便捷方法 ==================== */

    /**
     * 绑定（存在则幂等；可更新有效期）
     *
     * @param int         $merchantId  商户ID（强制租户隔离）
     * @param int         $adminId     管理员ID
     * @param int         $roleId      角色ID
     * @param string|null $from        生效起（含），空=不改/不设
     * @param string|null $to          失效止（开区间），空=不改/不设
     * @param int|null    $by          操作者ID（可空）
     */
    public static function attach(
        int $merchantId,
        int $adminId,
        int $roleId,
        ?string $from=null,
        ?string $to=null,
        ?int $by=null
    ): bool {
        $where = ['merchant_id'=>$merchantId,'admin_id'=>$adminId,'role_id'=>$roleId];
        $exists = self::where($where)->find();
        if ($exists) {
            // 已存在：仅在传入时更新有效期（保持幂等）
            $upd = [];
            if ($from !== null) $upd['valid_from'] = $from;
            if ($to   !== null) $upd['valid_to']   = $to;
            if ($upd) self::where($where)->update($upd);
            return true;
        }
        return (bool) self::create([
            'merchant_id' => $merchantId,
            'admin_id'    => $adminId,
            'role_id'     => $roleId,
            'assigned_at' => date('Y-m-d H:i:s'),
            'assigned_by' => $by,
            'valid_from'  => $from,
            'valid_to'    => $to,
        ]);
    }

    /**
     * 解绑（不存在也视为成功；按商户隔离）
     * @return int 受影响行数
     */
    public static function detach(int $merchantId, int $adminId, int $roleId): int
    {
        return (int) self::where([
            'merchant_id'=>$merchantId,'admin_id'=>$adminId,'role_id'=>$roleId
        ])->delete();
    }

    /**
     * 同步（全量覆盖：只保留给定 $roleIds；按商户隔离）
     *  - 删除不在 $roleIds 内的映射
     *  - 新增缺失的映射
     */
    public static function syncUserRoles(int $merchantId, int $adminId, array $roleIds, ?int $by=null): bool
    {
        $roleIds = array_values(array_unique(array_map('intval',$roleIds)));

        return Db::transaction(function() use ($merchantId,$adminId,$roleIds,$by){
            $current = array_map('intval',
                self::where(['merchant_id'=>$merchantId,'admin_id'=>$adminId])->column('role_id')
            );
            $toAdd = array_values(array_diff($roleIds, $current));
            $toDel = array_values(array_diff($current, $roleIds));

            if ($toDel) {
                self::where(['merchant_id'=>$merchantId,'admin_id'=>$adminId])
                    ->whereIn('role_id',$toDel)
                    ->delete();
            }

            if ($toAdd) {
                $now = date('Y-m-d H:i:s');
                $rows = [];
                foreach ($toAdd as $rid) {
                    $rows[] = [
                        'merchant_id' => $merchantId,
                        'admin_id'    => $adminId,
                        'role_id'     => (int)$rid,
                        'assigned_at' => $now,
                        'assigned_by' => $by,
                    ];
                }
                (new self())->saveAll($rows);
            }

            return true;
        });
    }
}
