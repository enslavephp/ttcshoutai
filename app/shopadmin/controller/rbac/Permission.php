<?php
declare(strict_types=1);

namespace app\shopadmin\controller\rbac;

use app\BaseController;
use think\facade\Request;
use think\facade\Validate;
use think\facade\Cache;
use think\facade\Log;

use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;

use app\shopadmin\model\ShopAdminPermission;
use app\shopadmin\model\ShopAdminRolePermission;
use app\shopadmin\model\ShopAdminUserRole;

/**
 * 【商户侧】权限管理 CRUD（Tenant-aware）
 * - 表：shopadmin_permission
 * - 唯一性（均在 merchant_id 作用域内）：
 *    1) code 唯一
 *    2) (resource_type, resource_id, action) 唯一（resource_id 可为 NULL）
 * - 关联影响：
 *    当权限被更新/删除时，失效所有“通过角色持有该权限”的管理员的权限缓存
 */
class Permission extends BaseController
{
    private TokenService $tokenService;

    public function __construct()
    {
        $cache = new CacheFacadeAdapter();
        $clock = new SystemClock();
        $cfg   = config('jwt') ?: [];
        $this->tokenService = new TokenService($cache, $clock, $cfg);
    }

    /* ======================= 基础工具 ======================= */

    /** 去掉首尾 ASCII/全角空格（U+3000） */
    private function normText($v): string
    {
        $s = is_string($v) ? $v : (string)$v;
        return preg_replace('/^[\s\x{3000}]+|[\s\x{3000}]+$/u', '', $s);
    }

    /** 权限缓存前缀（shopadmin 默认前缀） */
    private function permCachePrefix(): string
    {
        return (string)(config('permission.prefix') ?? 'shopadmin:perms:');
    }

    /** 失效某管理员的权限缓存 */
    private function evictAdminPermCache(int $adminId): void
    {
        if ($adminId <= 0) return;
        $prefix = $this->permCachePrefix();
        Cache::delete($prefix . $adminId);
    }

    /** 失效本商户内“通过角色持有该权限”的所有管理员权限缓存 */
    private function invalidateAdminsByPermissionId(int $merchantId, int $permissionId): void
    {
        // 本商户内：先查包含该权限的角色
        $roleIds = ShopAdminRolePermission::where('merchant_id', $merchantId)
            ->where('permission_id', $permissionId)
            ->column('role_id');
        if (empty($roleIds)) return;

        // 再查拥有这些角色的管理员（仍限定本商户）
        $adminIds = ShopAdminUserRole::where('merchant_id', $merchantId)
            ->whereIn('role_id', $roleIds)
            ->column('admin_id');

        foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
            $this->evictAdminPermCache($aid);
        }
    }

    /** 解析 shopadmin 身份：返回 [merchant_id, admin_id, errorResponse|null] */
    private function requireShopAdminAuth(): array
    {
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return [0, 0, $this->jsonResponse('未登录', 401, 'error')];

        try { $claims = $this->tokenService->parse($raw); }
        catch (\Throwable $e) { return [0, 0, $this->jsonResponse('会话无效', 401, 'error')]; }

        if (($claims->realm ?? '') !== 'shopadmin') {
            return [0, 0, $this->jsonResponse('非法领域', 403, 'error')];
        }
        $merchantId = (int)($claims->merchant_id ?? 0);
        $adminId    = (int)($claims->user_id ?? 0);
        if ($merchantId <= 0 || $adminId <= 0) {
            return [0, 0, $this->jsonResponse('会话缺少租户标识', 401, 'error')];
        }
        return [$merchantId, $adminId, null];
    }

    /* ======================= 业务接口 ======================= */

    /** 创建权限（merchant 内唯一） */
    public function create()
    {
        [, , $err] = $this->requireShopAdminAuth(); if ($err) return $err;
        [$merchantId, $adminId] = $this->requireShopAdminAuth(); // 已有校验，这里安全

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
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        // 规范化字段
        $code = $this->normText($data['code']);
        $name = $this->normText($data['name']);
        $type = $this->normText($data['resource_type']);
        $act  = $this->normText($data['action']);
        $rid  = array_key_exists('resource_id',$data)
            ? (($data['resource_id'] === '' || $data['resource_id'] === null) ? null : $this->normText($data['resource_id']))
            : null;
        $desc = array_key_exists('description',$data) ? $this->normText($data['description']) : null;

        // 唯一性（本商户内）
        if (ShopAdminPermission::where(['merchant_id'=>$merchantId,'code'=>$code])->find())
            return $this->jsonResponse('权限代码已存在', 400, 'error');
        if (ShopAdminPermission::where(['merchant_id'=>$merchantId,'name'=>$name])->find())
            return $this->jsonResponse('权限名称已存在', 400, 'error');

        $q = ShopAdminPermission::where('merchant_id',$merchantId)
            ->where('resource_type', $type)
            ->where('action', $act);
        ($rid === null) ? $q->whereNull('resource_id') : $q->where('resource_id', $rid);
        if ($q->find()) return $this->jsonResponse('同一资源与动作的权限已存在', 400, 'error');

        // 创建
        $perm = new ShopAdminPermission();
        $perm->save([
            'merchant_id'   => $merchantId,
            'code'          => $code,
            'name'          => $name,
            'description'   => $desc,
            'resource_type' => $type,
            'resource_id'   => $rid,
            'action'        => $act,
            'created_by'    => $adminId,
        ]);

        return $this->jsonResponse('创建成功', 200, 'success', ['permission_id' => (int)$perm->id]);
    }

    /** 更新权限（仅同商户；唯一性均在 merchant 内校验） */
    public function update()
    {
        [, , $err] = $this->requireShopAdminAuth(); if ($err) return $err;
        [$merchantId, $adminId] = $this->requireShopAdminAuth();

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
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        /** @var ShopAdminPermission|null $perm */
        $perm = ShopAdminPermission::where('merchant_id',$merchantId)->where('id',(int)$data['id'])->find();
        if (!$perm) return $this->jsonResponse('权限不存在', 404, 'error');

        // 赋值（resource_id 空串 -> NULL）
        $set = function(string $k) use (&$data, $perm) {
            if (!array_key_exists($k, $data)) return;
            $val = $data[$k];
            $val = ($k === 'resource_id')
                ? (($val === '' || $val === null) ? null : $this->normText($val))
                : $this->normText((string)$val);
            $perm->setAttr($k, $val);
        };
        foreach (['code','name','description','resource_type','resource_id','action'] as $f) $set($f);

        $changed = $perm->getChangedData();
        if (empty($changed)) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

        // 唯一性（merchant 内）
        if (array_key_exists('code', $changed)) {
            $dup = ShopAdminPermission::where('merchant_id',$merchantId)
                ->where('code', $changed['code'])->where('id','<>',$perm->id)->find();
            if ($dup) return $this->jsonResponse('权限代码已存在', 400, 'error');
        }
        if (array_key_exists('name', $changed)) {
            $dup = ShopAdminPermission::where('merchant_id',$merchantId)
                ->where('name', $changed['name'])->where('id','<>',$perm->id)->find();
            if ($dup) return $this->jsonResponse('权限名称已存在', 400, 'error');
        }

        // 三元组唯一（涉及 resource_type/resource_id/action 变化时校验）
        $tripletTouched = array_intersect(['resource_type', 'resource_id', 'action'], array_keys($changed));
        if (!empty($tripletTouched)) {
            $newType   = array_key_exists('resource_type', $changed) ? $changed['resource_type'] : $perm->getOrigin('resource_type');
            $newRid    = array_key_exists('resource_id', $changed)   ? $changed['resource_id']   : $perm->getOrigin('resource_id');
            $newAction = array_key_exists('action', $changed)        ? $changed['action']        : $perm->getOrigin('action');

            $q = ShopAdminPermission::where('merchant_id',$merchantId)
                ->where('resource_type', $newType)
                ->where('action', $newAction)
                ->where('id', '<>', $perm->id);
            ($newRid === null) ? $q->whereNull('resource_id') : $q->where('resource_id', $newRid);
            if ($q->find()) return $this->jsonResponse('同一资源与动作的权限已存在', 400, 'error');
        }

        $perm->setAttr('updated_by', $adminId);
        $perm->save();

        // 失效绑定该权限的管理员权限缓存
        $this->invalidateAdminsByPermissionId($merchantId, (int)$perm->id);

        return $this->jsonResponse('更新成功', 200, 'success');
    }

    /** 删除权限（若被角色绑定则阻止；同商户） */
    public function delete()
    {
        [, , $err] = $this->requireShopAdminAuth(); if ($err) return $err;
        [$merchantId] = $this->requireShopAdminAuth();

        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        $row = ShopAdminPermission::where('merchant_id',$merchantId)->where('id',$id)->find();
        if (!$row) return $this->jsonResponse('删除成功', 200, 'success'); // 已不存在，幂等

        $cnt = ShopAdminRolePermission::where('merchant_id',$merchantId)->where('permission_id',$id)->count();
        if ($cnt > 0) return $this->jsonResponse('该权限仍绑定角色，不能删除', 400, 'error');

        ShopAdminPermission::where('merchant_id',$merchantId)->where('id',$id)->delete();
        // 无角色引用，无需额外失效；若谨慎，也可失效一遍：
        // $this->invalidateAdminsByPermissionId($merchantId, $id);
        return $this->jsonResponse('删除成功', 200, 'success');
    }

    /** 权限详情（同商户） */
    public function info()
    {
        [, , $err] = $this->requireShopAdminAuth(); if ($err) return $err;
        [$merchantId] = $this->requireShopAdminAuth();

        $id = (int)(Request::post('id') ?? Request::get('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        $row = ShopAdminPermission::where('merchant_id',$merchantId)->where('id',$id)->find();
        if (!$row) return $this->jsonResponse('权限不存在', 404, 'error');

        return $this->jsonResponse('OK', 200, 'success', ['detail' => $row]);
    }

    /** 权限列表（分页 + 多条件检索；同商户） */
    public function list()
    {
        [, , $err] = $this->requireShopAdminAuth(); if ($err) return $err;
        [$merchantId] = $this->requireShopAdminAuth();

        $page   = max(1, (int)(Request::post('page') ?? Request::get('page') ?? 1));
        $limit  = min(100, max(1, (int)(Request::post('limit') ?? Request::get('limit') ?? 20)));
        $kw     = trim((string)(Request::post('keyword') ?? Request::get('keyword') ?? ''));
        $rtype  = trim((string)(Request::post('resource_type') ?? Request::get('resource_type') ?? ''));
        $rid    = Request::post('resource_id') ?? Request::get('resource_id');
        $action = trim((string)(Request::post('action') ?? Request::get('action') ?? ''));

        $q = ShopAdminPermission::where('merchant_id', $merchantId);
        if ($kw !== '')     $q->whereLike('name|code|description', "%{$kw}%");
        if ($rtype !== '')  $q->where('resource_type', $rtype);
        if ($action !== '') $q->where('action', $action);
        if ($rid !== null && $rid !== '') {
            $q->where('resource_id', $this->normText((string)$rid));
        }

        $total = (clone $q)->count();
        $rows  = $q->page($page, $limit)->order('id','desc')->select()->toArray();

        return $this->jsonResponse('OK', 200, 'success', [
            'list'  => $rows,
            'total' => $total,
            'page'  => $page,
            'limit' => $limit,
        ]);
    }
}
