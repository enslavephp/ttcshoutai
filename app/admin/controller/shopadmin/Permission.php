<?php
declare(strict_types=1);

namespace app\admin\controller\shopadmin;

use app\BaseController;
use think\facade\Request;
use think\facade\Validate;
use think\facade\Cache;
use think\facade\Log;
use think\facade\Db;

// 使用 admin 侧的模型命名空间，模型指向 shopadmin_* 表
use app\shopadmin\model\ShopAdminPermission;
use app\shopadmin\model\ShopAdminRolePermission;
use app\shopadmin\model\ShopAdminUserRole;
use app\admin\model\ShopAdminMerchant;

// 商户侧角色模型
use app\shopadmin\model\ShopAdminRole;

/**
 * 后台管理端 - 商户端权限字典 CRUD（操作 shopadmin_permission 表）
 *
 * 全局唯一：
 * 1) code（DB 已唯一）
 * 2) 可选：name（代码层面做全局防重，可按需放开）
 * 3) (resource_type, resource_id, action)  // resource_id 允许 NULL，代码层面防重
 *
 * 关联影响：
 *  - 权限更新后，失效“引用了该权限的所有商户内，通过角色持有该权限的管理员”缓存（shopadmin:perms:{admin_id}）
 *
 * 说明：
 *  - 本控制器不做 JWT/权限校验，依赖上层中间件。
 *  - assignToSuperAdmin：后台管理员把选中的权限集“覆盖同步”到该商户的 super_shopadmin 角色。
 *  - 不依赖 shopadmin_merchant_permission。
 */
class Permission extends BaseController
{
    /* ======================= 工具方法 ======================= */

    /** 去掉首尾 ASCII/全角空格（U+3000） */
    private function normText($v): string
    {
        $s = is_string($v) ? $v : (string)$v;
        return preg_replace('/^[\s\x{3000}]+|[\s\x{3000}]+$/u', '', $s);
    }

    /** shopadmin 侧权限缓存前缀 */
    private function permCachePrefix(): string
    {
        return (string)(\app\common\Helper::getValue('permission.shopadmin_prefix') ?? 'shopadmin:perms:');
    }

    /** 失效某商户内、被这些权限影响到的管理员缓存 */
    private function invalidateMerchantAdminsByPermissionIds(int $merchantId, array $permissionIds): void
    {
        try {
            if (empty($permissionIds)) return;

            $roleIds = ShopAdminRolePermission::where('merchant_id', $merchantId)
                ->whereIn('permission_id', $permissionIds)
                ->column('role_id');

            if (!$roleIds) return;

            $adminIds = ShopAdminUserRole::where('merchant_id', $merchantId)
                ->whereIn('role_id', array_unique(array_map('intval', $roleIds)))
                ->column('admin_id');

            if (!$adminIds) return;

            $prefix = $this->permCachePrefix();
            foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
                if ($aid > 0) Cache::delete($prefix . $aid);
            }
        } catch (\Throwable $e) {
            Log::warning('invalidateMerchantAdminsByPermissionIds failed: ' . $e->getMessage());
        }
    }

    /**
     * 失效“引用了该权限”的所有商户内管理员权限缓存
     * 步骤：
     *  1) 按 permission_id 找到所有 (merchant_id, role_id)
     *  2) 对每个 merchant_id，找该商户下绑定到这些 role_id 的 admin_id
     *  3) 清理对应 admin_id 的缓存
     */
    private function invalidateAdminsByPermissionId(int $permissionId): void
    {
        try {
            $rows = ShopAdminRolePermission::where('permission_id', $permissionId)
                ->field('merchant_id,role_id')
                ->select()
                ->toArray();

            if (!$rows) return;

            $rolesByMerchant = [];
            foreach ($rows as $r) {
                $mid = (int)$r['merchant_id'];
                $rid = (int)$r['role_id'];
                if ($mid > 0 && $rid > 0) {
                    $rolesByMerchant[$mid][$rid] = true;
                }
            }
            if (!$rolesByMerchant) return;

            $prefix = $this->permCachePrefix();

            foreach ($rolesByMerchant as $mid => $roleSet) {
                $roleIds = array_map('intval', array_keys($roleSet));
                if (!$roleIds) continue;

                $adminIds = ShopAdminUserRole::where('merchant_id', $mid)
                    ->whereIn('role_id', $roleIds)
                    ->column('admin_id');

                if (!$adminIds) continue;

                foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
                    if ($aid > 0) Cache::delete($prefix . $aid);
                }
            }
        } catch (\Throwable $e) {
            Log::warning('invalidateAdminsByPermissionId failed: ' . $e->getMessage());
        }
    }

    /* ======================= 业务接口：后台直接给“超级管理员”分配权限 ======================= */

    /**
     * 后台管理员：把选中的权限集分配给【某商户的 super_shopadmin 角色】（覆盖同步，可清空）
     *
     * 入参 JSON：
     * - merchant_id: int       (必填)
     * - permission_ids: int[]  (必填；允许为空数组 -> 清空该角色的所有权限)
     */
    public function assignToSuperAdmin()
    {
        $data = Request::post();
        $rules = [
            'merchant_id'      => 'require|integer',
            'permission_ids'   => 'require|array',   // 允许空数组表示清空
            'permission_ids.*' => 'integer',
        ];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError() ?: '参数校验失败', 422, 'error');
        }

        $merchantId = (int)$data['merchant_id'];
        $want       = array_values(array_unique(array_map('intval', (array)$data['permission_ids'])));

        // 1) 商户存在性（过滤软删）
        $merchant = ShopAdminMerchant::find($merchantId);
        if (!$merchant) return $this->jsonResponse('商户不存在', 404, 'error');

        // 2) 权限存在性（仅在非空时校验）
        if (!empty($want)) {
            $exist = ShopAdminPermission::whereIn('id', $want)->column('id');
            $missing = array_values(array_diff($want, array_map('intval', $exist)));
            if ($missing) {
                return $this->jsonResponse('存在无效的 permission_id: ' . implode(',', $missing), 400, 'error');
            }
        }

        // 3) 找到 super_shopadmin 角色
        $role = ShopAdminRole::where('merchant_id', $merchantId)
            ->where('code', 'super_shopadmin')
            ->find();
        if (!$role) {
            return $this->jsonResponse('未找到该商户的 super_shopadmin 角色', 404, 'error');
        }
        $roleId = (int)$role['id'];

        // 4) 当前角色已有权限
        $current = ShopAdminRolePermission::where(['merchant_id' => $merchantId, 'role_id' => $roleId])
            ->column('permission_id');
        $current = array_map('intval', $current);

        $toAdd = array_values(array_diff($want, $current));
        $toDel = array_values(array_diff($current, $want));

        // 5) 事务：同步角色权限（仅 role_permission）
        Db::transaction(function () use ($merchantId, $roleId, $toAdd, $toDel) {
            foreach ($toAdd as $pid) {
                try {
                    ShopAdminRolePermission::create([
                        'merchant_id'   => $merchantId,
                        'role_id'       => $roleId,
                        'permission_id' => $pid,
                        'assigned_at'   => date('Y-m-d H:i:s'),
                        'assigned_by'   => null,
                    ]);
                } catch (\Throwable $e) {
                    $msg = $e->getMessage();
                    if (strpos($msg, 'Duplicate') === false && strpos($msg, '1062') === false) {
                        throw $e;
                    }
                }
            }
            if ($toDel) {
                ShopAdminRolePermission::where(['merchant_id' => $merchantId, 'role_id' => $roleId])
                    ->whereIn('permission_id', $toDel)
                    ->delete();
            }
        });

        // 6) 失效该商户下绑定 super_shopadmin 角色的所有管理员缓存（至少包含超级管理员）
        try {
            $adminIds = ShopAdminUserRole::where('merchant_id', $merchantId)
                ->where('role_id', $roleId)
                ->column('admin_id');

            $prefix = $this->permCachePrefix();
            foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
                if ($aid > 0) Cache::delete($prefix . $aid);
            }
        } catch (\Throwable $e) {
            Log::warning('invalidate super admin cache failed: ' . $e->getMessage());
        }

        return $this->jsonResponse('分配成功', 200, 'success', [
            'merchant_id' => $merchantId,
            'role_id'     => $roleId,
            'added'       => $toAdd,
            'removed'     => $toDel,
        ]);
    }

    /* ======================= 新增：根据商户ID查看商户权限 ======================= */

    /**
     * 根据商户ID查看该商户当前（super_shopadmin 角色）拥有的权限
     *
     * 入参 JSON：
     * - merchant_id: int   (必填)
     * - page: int          (可选，默认 1)
     * - limit: int         (可选，默认 20，最大 100)
     * - keyword: string    (可选，按 p.name|p.code|p.description 模糊)
     * - resource_type: string (可选)
     * - resource_id: string|null (可选；传空串会被视为 NULL)
     * - action: string     (可选)
     * - ids_only: 0|1      (可选，1=仅返回权限ID数组，忽略分页信息)
     */
    public function merchantPermissions()
    {
        $data = Request::post();
        $rules = [
            'merchant_id'   => 'require|integer',
            'page'          => 'integer|min:1',
            'limit'         => 'integer|min:1|max:100',
            'keyword'       => 'max:128',
            'resource_type' => 'max:32',
            'resource_id'   => 'max:128',
            'action'        => 'max:32',
            'ids_only'      => 'in:0,1',
            'bound'         => 'in:0,1',  // 新增 bound 参数验证规则
        ];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError() ?: '参数校验失败', 422, 'error');
        }

        $merchantId = (int)$data['merchant_id'];
        $page   = max(1, (int)($data['page']  ?? 1));
        $limit  = min(100, max(1, (int)($data['limit'] ?? 20)));
        $kw     = trim((string)($data['keyword'] ?? ''));
        $rtype  = trim((string)($data['resource_type'] ?? ''));
        $ridRaw = $data['resource_id'] ?? null;
        $action = trim((string)($data['action'] ?? ''));
        $idsOnly= (int)($data['ids_only'] ?? 0) === 1;
        $bound  = (int)($data['bound'] ?? 1);  // 获取 bound 参数，默认值为 1

        // 1) 商户存在
        $merchant = ShopAdminMerchant::find($merchantId);
        if (!$merchant) return $this->jsonResponse('商户不存在', 404, 'error');

        // 2) 取 super_shopadmin 角色
        $role = ShopAdminRole::where('merchant_id', $merchantId)
            ->where('code', 'super_shopadmin')
            ->find();
        if (!$role) {
            return $this->jsonResponse('未找到该商户的 super_shopadmin 角色', 404, 'error');
        }
        $roleId = (int)$role['id'];

        // 3) 获取该角色已绑定的权限ID
        $subQuery = ShopAdminRolePermission::where('role_id', $roleId)
            ->column('permission_id');  // 获取已绑定的权限ID列表

        if ($bound === 0) {
            // 查询未绑定的权限（即不在已绑定权限ID列表中的权限）
            $q = ShopAdminPermission::alias('p')
                ->whereNotIn('p.id', $subQuery);
        }else{
            // 4) 组装查询
            $q = ShopAdminPermission::alias('p')
                ->whereIn('p.id', $subQuery);  // 默认查询已绑定的权限
        }
        if ($kw !== '')    $q->whereLike('p.name|p.code|p.description', "%{$kw}%");
        if ($rtype !== '') $q->where('p.resource_type', $rtype);
        if ($action !== '')$q->where('p.action', $action);

        if ($ridRaw !== null) {
            // 空串 -> 视为 NULL
            $rid = $this->normText((string)$ridRaw);
            if ($rid === '') {
                $q->whereNull('p.resource_id');
            } else {
                $q->where('p.resource_id', $rid);
            }
        }

        if ($idsOnly) {
            // 仅返回 ID 数组
            $ids = $q->distinct(true)->column('p.id');
            $ids = array_map('intval', $ids);
            return $this->jsonResponse('OK', 200, 'success', ['permission_ids' => $ids]);
        }

        $countQ = clone $q;
        $total  = (int)$countQ->distinct(true)->count('p.id');

        $rows = $q->field([
            'p.id','p.code','p.name','p.description',
            'p.resource_type','p.resource_id','p.action',
            'p.is_system','p.created_at','p.updated_at','p.version'
        ])
            ->page($page, $limit)
            ->select()
            ->toArray();

        return $this->jsonResponse('OK', 200, 'success', [
            'list'  => $rows,
            'total' => $total,
            'page'  => $page,
            'limit' => $limit,
        ]);
    }
    /* ======================= 业务接口：全局权限字典 CRUD ======================= */

    /** 创建全局权限 */
    public function create()
    {
        $data = Request::post();
        $rules = [
            'code'          => 'require|regex:/^[A-Za-z0-9_.-]{1,64}$/',
            'name'          => 'require|max:64',
            'description'   => 'max:255',
            'resource_type' => 'require|max:32',
            'resource_id'   => 'max:128',
            'action'        => 'require|max:32',
        ];
        $validate = Validate::rule($rules)
            ->message(['code.regex' => 'code 仅允许字母、数字、下划线(_)、中划线(-)、点号(.)']);
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        $code = $this->normText($data['code']);
        $name = $this->normText($data['name']);
        $type = $this->normText($data['resource_type']);
        $act  = $this->normText($data['action']);
        $rid  = array_key_exists('resource_id', $data)
            ? (($data['resource_id'] === '' || $data['resource_id'] === null) ? null : $this->normText($data['resource_id']))
            : null;
        $desc = array_key_exists('description', $data) ? $this->normText($data['description']) : null;

        // 全局唯一性
        if (ShopAdminPermission::where('code', $code)->find()) {
            return $this->jsonResponse('权限代码已存在', 400, 'error');
        }
        // 若你希望 name 可重复，可删除该段
        if (ShopAdminPermission::where('name', $name)->find()) {
            return $this->jsonResponse('权限名称已存在', 400, 'error');
        }
        $q = ShopAdminPermission::where('resource_type', $type)->where('action', $act);
        ($rid === null) ? $q->whereNull('resource_id') : $q->where('resource_id', $rid);
        if ($q->find()) {
            return $this->jsonResponse('同一资源与动作的权限已存在', 400, 'error');
        }

        $perm = new ShopAdminPermission();
        $perm->save([
            'code'          => $code,
            'name'          => $name,
            'description'   => $desc,
            'resource_type' => $type,
            'resource_id'   => $rid,
            'action'        => $act,
            'is_system'     => 0,
        ]);

        return $this->jsonResponse('创建成功', 200, 'success', [
            'permission_id' => (int)$perm->id
        ]);
    }

    /** 更新全局权限 */
    public function update()
    {
        $data = Request::post();
        $rules = [
            'id'            => 'require|integer',
            'code'          => 'regex:/^[A-Za-z0-9_.-]{1,64}$/',
            'name'          => 'max:64',
            'description'   => 'max:255',
            'resource_type' => 'max:32',
            'resource_id'   => 'max:128',
            'action'        => 'max:32',
        ];
        $validate = Validate::rule($rules)
            ->message(['code.regex' => 'code 仅允许字母、数字、下划线(_)、中划线(-)、点号(.)']);
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        /** @var ShopAdminPermission|null $perm */
        $perm = ShopAdminPermission::where('id', (int)$data['id'])->find();
        if (!$perm) return $this->jsonResponse('权限不存在', 404, 'error');

        // 赋值（仅更新传入字段）
        $set = function (string $k) use (&$data, $perm) {
            if (!array_key_exists($k, $data)) return;
            $val = $data[$k];
            $val = ($k === 'resource_id')
                ? (($val === '' || $val === null) ? null : $this->normText((string)$val))
                : $this->normText((string)$val);
            $perm->setAttr($k, $val);
        };
        foreach (['code','name','description','resource_type','resource_id','action'] as $f) $set($f);

        $changed = $perm->getChangedData();
        if (empty($changed)) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

        // 全局唯一性
        if (array_key_exists('code', $changed)) {
            $dup = ShopAdminPermission::where('code', $changed['code'])->where('id', '<>', $perm->id)->find();
            if ($dup) return $this->jsonResponse('权限代码已存在', 400, 'error');
        }
        if (array_key_exists('name', $changed)) {
            $dup = ShopAdminPermission::where('name', $changed['name'])->where('id', '<>', $perm->id)->find();
            if ($dup) return $this->jsonResponse('权限名称已存在', 400, 'error');
        }
        // 三元组唯一（仅当涉及变更时校验）
        $tripTouched = array_intersect(['resource_type','resource_id','action'], array_keys($changed));
        if (!empty($tripTouched)) {
            $newType   = array_key_exists('resource_type', $changed) ? $changed['resource_type'] : $perm->getOrigin('resource_type');
            $newRid    = array_key_exists('resource_id', $changed)   ? $changed['resource_id']   : $perm->getOrigin('resource_id');
            $newAction = array_key_exists('action', $changed)        ? $changed['action']        : $perm->getOrigin('action');

            $q = ShopAdminPermission::where('resource_type', $newType)->where('action', $newAction)
                ->where('id', '<>', $perm->id);
            ($newRid === null) ? $q->whereNull('resource_id') : $q->where('resource_id', $newRid);
            if ($q->find()) return $this->jsonResponse('同一资源与动作的权限已存在', 400, 'error');
        }

        $perm->save();

        // 失效所有商户内引用该权限的管理员缓存
        $this->invalidateAdminsByPermissionId((int)$perm->id);

        return $this->jsonResponse('更新成功', 200, 'success');
    }

    /** 删除全局权限（若仍被任何商户角色绑定则阻止） */
    public function delete()
    {
        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) {
            return $this->jsonResponse('缺少 id', 400, 'error');
        }

        $row = ShopAdminPermission::where('id', $id)->find();
        if (!$row) return $this->jsonResponse('删除成功', 200, 'success'); // 幂等

        $cnt = ShopAdminRolePermission::where('permission_id', $id)->count();
        if ($cnt > 0) return $this->jsonResponse('该权限仍绑定于某些角色，不能删除', 400, 'error');

        try {
            ShopAdminPermission::where('id', $id)->delete();
        } catch (\Throwable $e) {
            Log::warning('delete permission failed: ' . $e->getMessage());
            return $this->jsonResponse('删除失败：存在外键引用（请先解除引用）', 400, 'error');
        }

        return $this->jsonResponse('删除成功', 200, 'success');
    }

    /** 解绑商户的某个权限（同租户；不存在也成功） */
    /** 解绑商户的某个权限（同租户；不存在也成功）
     * 入参：
     * - merchant_id     int    必填
     * - permission_id   int    必填
     * - role_id         int    可选（与 role_code 二选一）
     * - role_code       string 可选（不传则默认 super_shopadmin）
     */
    /** 解绑商户的某个权限（同租户；不存在也成功）
     * 入参：
     * - merchant_id     int    必填
     * - permission_id   int    必填
     * - role_id         int    可选（与 role_code 至少传一个）
     * - role_code       string 可选（与 role_id 至少传一个）
     */
    public function unbindPermission()
    {
        $data = Request::post();
        $rules = [
            'merchant_id'   => 'require|integer',
            'permission_id' => 'require|integer',
            'role_id'       => 'integer',
            'role_code'     => 'max:64',
        ];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError() ?: '参数校验失败', 422, 'error');
        }

        // 必须至少提供一个角色标识
        $hasRoleId   = array_key_exists('role_id', $data) && (int)$data['role_id'] > 0;
        $hasRoleCode = array_key_exists('role_code', $data) && trim((string)$data['role_code']) !== '';
        if (!$hasRoleId && !$hasRoleCode) {
            return $this->jsonResponse('缺少角色标识（role_id 或 role_code 必须传一个）', 422, 'error');
        }

        $merchantId   = (int)$data['merchant_id'];
        $permissionId = (int)$data['permission_id'];

        // 解析角色
        $roleId = (int)($data['role_id'] ?? 0);
        if ($roleId <= 0) {
            $roleCode = trim((string)$data['role_code']);
            /** @var \app\shopadmin\model\ShopAdminRole|null $role */
            $role = ShopAdminRole::where('merchant_id', $merchantId)
                ->where('code', $roleCode)
                ->find();
            // 角色不存在也视为解绑成功（幂等）
            if (!$role) {
                return $this->jsonResponse('解绑成功', 200, 'success', ['affected' => 0]);
            }
            $roleId = (int)$role->id;
        }

        // 删除前拿到该角色的管理员，便于失效缓存
        $adminIds = ShopAdminUserRole::where('merchant_id', $merchantId)
            ->where('role_id', $roleId)
            ->column('admin_id');

        // 执行解绑（不存在则 0 行）
        $affected = ShopAdminRolePermission::where([
            'merchant_id'   => $merchantId,
            'role_id'       => $roleId,
            'permission_id' => $permissionId,
        ])->delete();

        // 失效这些管理员的权限缓存
        try {
            $prefix = $this->permCachePrefix();
            foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
                if ($aid > 0) Cache::delete($prefix . $aid);
            }
        } catch (\Throwable $e) {
            Log::warning('unbindPermission invalidate cache failed: ' . $e->getMessage());
        }

        return $this->jsonResponse('解绑成功', 200, 'success', ['affected' => (int)$affected]);
    }


    /** 权限详情（全局） */
    public function info()
    {
        $id = (int)(Request::post('id') ?? Request::get('id') ?? 0);
        if ($id <= 0) {
            return $this->jsonResponse('缺少 id', 400, 'error');
        }

        $row = ShopAdminPermission::where('id', $id)->find();
        if (!$row) return $this->jsonResponse('权限不存在', 404, 'error');

        return $this->jsonResponse('OK', 200, 'success', ['detail' => $row]);
    }

    /** 权限列表（分页 + 检索） */
    public function list()
    {
        $page   = max(1, (int)(Request::post('page') ?? Request::get('page') ?? 1));
        $limit  = min(100, max(1, (int)(Request::post('limit') ?? Request::get('limit') ?? 20)));
        $kw     = trim((string)(Request::post('keyword') ?? Request::get('keyword') ?? ''));
        $rtype  = trim((string)(Request::post('resource_type') ?? Request::get('resource_type') ?? ''));
        $rid    = Request::post('resource_id') ?? Request::get('resource_id');
        $action = trim((string)(Request::post('action') ?? Request::get('action') ?? ''));

        $q = ShopAdminPermission::where([]);
        if ($kw !== '')     $q->whereLike('name|code|description', "%{$kw}%");
        if ($rtype !== '')  $q->where('resource_type', $rtype);
        if ($action !== '') $q->where('action', $action);
        if ($rid !== null && $rid !== '') {
            $q->where('resource_id', $this->normText((string)$rid));
        }

        $total = (clone $q)->count();
        $rows  = $q->page($page, $limit)->order('id', 'desc')->select()->toArray();

        return $this->jsonResponse('OK', 200, 'success', [
            'list'  => $rows,
            'total' => $total,
            'page'  => $page,
            'limit' => $limit,
        ]);
    }
}
