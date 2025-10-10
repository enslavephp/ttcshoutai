<?php
declare(strict_types=1);

namespace app\common\service;

use think\facade\Cache;
use app\admin\model\AdminUserRole;
use app\admin\model\AdminRole;
use app\admin\model\AdminPermission;
use app\admin\model\AdminRolePermission;

/**
 * PermissionCacheService
 *
 * 目标：
 *  1) 读取/缓存：角色 → 权限代码集合
 *  2) 读取/缓存：管理员 → 权限代码集合（合并其“当前有效”的所有角色权限）
 *  3) 失效：当角色-权限绑定变化、角色状态/有效期变化、用户-角色映射变化时，精准失效
 *
 * 约定：
 *  - 权限唯一使用 AdminPermission.code（如 "admin.role.update"）
 *  - TTL 可在 config('permission.cache_ttl') 中配置，默认 600 秒
 *  - 管理员权限缓存 key 前缀沿用 config('permission.prefix')，默认 'admin:perms:'
 *  - 角色权限缓存 key 前缀 config('permission.role_perm_prefix')，默认 'admin:roleperms:'
 */
class PermissionCacheService
{
    /** TTL（秒） */
    private static function ttl(): int
    {
        return (int) (config('permission.cache_ttl') ?? 600);
    }

    /** 管理员权限缓存 key */
    private static function adminKey(int $adminId): string
    {
        $prefix = (string) (config('permission.prefix') ?? 'admin:perms:');
        return $prefix . $adminId;
    }

    /** 角色权限缓存 key */
    private static function roleKey(int $roleId): string
    {
        $prefix = (string) (config('permission.role_perm_prefix') ?? 'admin:roleperms:');
        return $prefix . $roleId;
    }

    /**
     * 读取：角色 → 权限代码集合（带缓存）
     * @return string[] 去重且排序后的权限 code 列表
     */
    public static function getRolePermCodes(int $roleId): array
    {
        $key = self::roleKey($roleId);
        $ttl = self::ttl();

        $codes = Cache::remember($key, function() use ($roleId) {
            $list = AdminRolePermission::alias('rp')
                ->join(['admin_permission' => 'p'], 'p.id = rp.permission_id')
                ->where('rp.role_id', $roleId)
                ->field('p.code')
                ->select()
                ->column('code');

            $list = array_map('strval', $list);
            $list = array_values(array_unique($list));
            sort($list, SORT_STRING);
            return $list;
        }, $ttl);

        return is_array($codes) ? $codes : [];
    }

    /**
     * 读取：管理员 → 权限代码集合（带缓存）
     * 只合并“当前有效”的角色（角色启用、角色有效期命中、分配有效期命中）
     * @return string[] 去重且排序后的权限 code 列表
     */
    public static function getAdminPermCodes(int $adminId): array
    {
        $key = self::adminKey($adminId);
        $ttl = self::ttl();

        $codes = Cache::remember($key, function() use ($adminId) {
            $now = date('Y-m-d H:i:s');

            // 找到该管理员当前有效的角色ID
            $roleIds = AdminUserRole::alias('ur')
                ->join(['admin_role' => 'r'], 'r.id = ur.role_id')
                ->where('ur.admin_id', $adminId)
                // 角色启停
                ->where('r.status', 1)
                // 角色有效期：[from, to)
                ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                // 分配有效期：[from, to)
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
                ->column('ur.role_id');

            $roleIds = array_values(array_unique(array_map('intval', $roleIds)));
            if (!$roleIds) return [];

            // 合并所有角色权限（优先复用角色缓存）
            $all = [];
            foreach ($roleIds as $rid) {
                $all = array_merge($all, self::getRolePermCodes($rid));
            }
            $all = array_values(array_unique(array_map('strval', $all)));
            sort($all, SORT_STRING);
            return $all;
        }, $ttl);

        return is_array($codes) ? $codes : [];
    }

    /** 失效：某角色的权限集合缓存 */
    public static function invalidateRole(int $roleId): void
    {
        Cache::delete(self::roleKey($roleId));
    }

    /** 失效：某管理员的权限集合缓存 */
    public static function invalidateAdmin(int $adminId): void
    {
        Cache::delete(self::adminKey($adminId));
    }

    /**
     * 失效：持有该角色的所有管理员权限缓存
     * - 不判断有效期，粗粒度全部失效，保证一致性
     */
    public static function invalidateAdminsByRoleId(int $roleId): void
    {
        $adminIds = AdminUserRole::where('role_id', $roleId)->column('admin_id');
        $adminIds = array_unique(array_map('intval', $adminIds));
        foreach ($adminIds as $aid) self::invalidateAdmin($aid);
    }

    /** 可选：预热一批角色的权限集合缓存 */
    public static function warmRolePerms(array $roleIds): void
    {
        foreach (array_unique(array_map('intval',$roleIds)) as $rid) {
            self::getRolePermCodes($rid);
        }
    }

    /** 可选：预热一批管理员的权限集合缓存 */
    public static function warmAdminPerms(array $adminIds): void
    {
        foreach (array_unique(array_map('intval',$adminIds)) as $aid) {
            self::getAdminPermCodes($aid);
        }
    }
}
