<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;

/**
 * 管理员模型（ORM）
 *
 * 要点：
 * - activeRoleIds(): 返回当前“有效”的角色ID（考虑角色启停 & 有效期 + 分配有效期）
 * - bestRoleLevel(): 返回“最高权限”的角色等级（按 permission.level_order）
 * - minRoleLevel(): 兼容旧方法名，内部转调 bestRoleLevel()
 * - 提供 attachRole/detachRole/syncRoles 便捷方法
 */
class AdminUser extends Model
{
    /** 物理表名 */
    protected $name = 'admin_user';
    /** 主键 */
    protected $pk   = 'id';

    /** 自动时间戳（created_at/updated_at） */
    protected $autoWriteTimestamp = true;
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';

    /** 字段白名单（防止批量赋值风险） */
    protected $field = [
        'id','username','password','password_algo','password_meta',
        'email','phone','status','login_failed_attempts','locked_until',
        'mfa_enabled','last_login_at','last_login_ip',
        'created_by','updated_by','deleted_at',
        'created_at','updated_at','version',
    ];

    /** 隐藏敏感字段 */
    protected $hidden = [
        'password','mfa_secret','mfa_recovery_codes','password_meta',
    ];

    /** 类型转换 */
    protected $type = [
        'id'                     => 'integer',
        'status'                 => 'integer',
        'login_failed_attempts'  => 'integer',
        'mfa_enabled'            => 'integer',
        'created_by'             => 'integer',
        'updated_by'             => 'integer',
        'version'                => 'integer',
        'created_at'             => 'datetime',
        'updated_at'             => 'datetime',
        'deleted_at'             => 'datetime',
        'locked_until'           => 'datetime',
        'last_login_at'          => 'datetime',
        // last_login_ip 为二进制/字符串，不做转换
    ];

    /** 多对多：用户 ⇄ 角色（返回中间表字段） */
    public function roles()
    {
        return $this->belongsToMany(
            AdminRole::class,
            'admin_user_role',
            'role_id',
            'admin_id'
        )->withPivot(['assigned_at','assigned_by','valid_from','valid_to']);
    }

    /**
     * 当前“有效”的角色ID
     * 规则：
     *  - 角色 status=1
     *  - 角色有效期：valid_from <= now < valid_to（空值视为无限制）
     *  - 分配有效期：valid_from <= now < valid_to（空值视为无限制）
     */
    public function activeRoleIds(): array
    {
        $now = date('Y-m-d H:i:s');
        $rows = AdminUserRole::alias('ur')
            ->join(['admin_role'=>'r'],'r.id = ur.role_id')
            ->where('ur.admin_id', (int)$this->getAttr('id'))
            // 分配有效期
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            // 角色有效期 + 启停
            ->where('r.status',1)
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            ->column('r.id');
        return array_map('intval',$rows);
    }

    /**
     * 最有权限的等级（最高等级）
     * - permission.level_order='asc'：数字越小权限越高 → 取 min
     * - permission.level_order='desc'：数字越大权限越高 → 取 max
     * - 无角色：asc→99；desc→0
     */
    public function bestRoleLevel(): int
    {
        $ids = $this->activeRoleIds();
        $order = (string)(config('permission.level_order') ?? 'asc');
        if (!$ids) return $order==='desc' ? 0 : 99;

        $levels = AdminRole::whereIn('id',$ids)->column('level');
        $levels = array_map('intval',$levels);

        if ($order === 'desc') return (int) max($levels);
        return (int) min($levels);
    }

    /** 兼容旧方法名（历史代码可能在用） */
    public function minRoleLevel(): int
    { return $this->bestRoleLevel(); }

    /** 便捷方法：绑定/解绑/同步 */
    public function attachRole(int $roleId, ?string $from=null, ?string $to=null, ?int $by=null): bool
    { return AdminUserRole::attach((int)$this->id, $roleId, $from, $to, $by); }

    public function detachRole(int $roleId): int
    { return AdminUserRole::detach((int)$this->id, $roleId); }

    public function syncRoles(array $roleIds, ?int $by=null): bool
    { return AdminUserRole::syncUserRoles((int)$this->id, $roleIds, $by); }
}
