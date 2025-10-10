<?php
declare(strict_types=1);

namespace app\admin\controller\rbac;

use app\BaseController;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;
use think\facade\Request;
use think\facade\Validate;
use app\admin\model\AdminPermission;
use app\admin\model\AdminRolePermission;
use app\admin\model\AdminUserRole;
use think\facade\Cache;

/**
 * 权限管理 CRUD
 * - 表：admin_permission
 * - 业务唯一性：
 *     1) code 唯一（uk_admin_permission_code）
 *     2) (resource_type, resource_id, action) 唯一（uk_admin_permission_resource），resource_id 允许 NULL
 * - 关联影响：
 *     当权限被更新/删除时，失效所有“通过角色持有该权限”的管理员的权限缓存（读取 config('permission.prefix')）
 */
class Permission extends BaseController
{
    private TokenService $tokenService;

    // 构造函数，初始化 TokenService
    public function __construct()
    {
        $cache = new CacheFacadeAdapter(); // 缓存适配器
        $clock = new SystemClock(); // 系统时钟
        $cfg = config('jwt') ?: []; // 获取配置文件中的 jwt 配置
        $this->tokenService = new TokenService($cache, $clock, $cfg); // 初始化 TokenService
    }

    /** 去掉首尾 ASCII/全角空格（U+3000） */
    private function normText($v): string
    {
        $s = is_string($v) ? $v : (string)$v;
        return preg_replace('/^[\s\x{3000}]+|[\s\x{3000}]+$/u', '', $s); // 清除字符串首尾空格
    }

    /** 统一读取权限缓存前缀 */
    private function permCachePrefix(): string
    {
        return (string)(config('permission.prefix') ?? 'admin:perms:'); // 获取权限缓存前缀
    }

    /** 失效所有“通过角色持有该权限”的管理员的权限缓存 */
    private function invalidateAdminsByPermissionId(int $permissionId): void
    {
        // 先找包含该权限的角色
        $roleIds = AdminRolePermission::where('permission_id', $permissionId)->column('role_id');
        if (empty($roleIds)) return;

        // 再找拥有这些角色的管理员
        $adminIds = AdminUserRole::whereIn('role_id', $roleIds)->column('admin_id');

        if (empty($adminIds)) return;

        $prefix = $this->permCachePrefix(); // 获取权限缓存前缀
        foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
            if ($aid > 0) Cache::delete($prefix . $aid); // 删除缓存
        }
    }

    /** 创建权限 */
    public function create()
    {
        $data = Request::post(); // 获取请求数据

        $rules = [
            'code'          => 'require|regex:/^[A-Za-z0-9_.-]{1,64}$/', // 权限代码规则
            'name'          => 'require|max:64', // 权限名称规则
            'description'   => 'max:255', // 描述最多 255 字符
            'resource_type' => 'require|max:32', // 资源类型规则
            'resource_id'   => 'max:128', // 资源ID规则
            'action'        => 'require|max:32', // 动作规则
        ];
        $validate = Validate::rule($rules)
            ->message(['code.regex' => 'code 仅允许字母、数字、下划线(_)、中划线(-)、点号(.)']); // 自定义错误消息
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error'); // 校验失败返回错误

        // 规范化字段
        $code = $this->normText($data['code']);
        $name = $this->normText($data['name']);
        $type = $this->normText($data['resource_type']);
        $act  = $this->normText($data['action']);
        $rid  = array_key_exists('resource_id',$data)
            ? (($data['resource_id'] === '' || $data['resource_id'] === null) ? null : $this->normText($data['resource_id']))
            : null;
        $desc = array_key_exists('description',$data) ? $this->normText($data['description']) : null;

        // 唯一性检查
        if (AdminPermission::where('code', $code)->find())
            return $this->jsonResponse('权限代码已存在', 400, 'error');
        if (AdminPermission::where('name', $name)->find())
            return $this->jsonResponse('权限名称已存在', 400, 'error');
        if ($rid !== null && AdminPermission::where('resource_id', $rid)->find())
            return $this->jsonResponse('资源ID已存在', 400, 'error');

        // 检查三元组（resource_type, resource_id, action）唯一性
        $q = AdminPermission::where('resource_type', $type)->where('action', $act);
        ($rid === null) ? $q->whereNull('resource_id') : $q->where('resource_id', $rid);
        if ($q->find()) return $this->jsonResponse('同一资源与动作的权限已存在', 400, 'error');

        // 创建权限
        $perm = new AdminPermission;
        $perm->save([
            'code'          => $code,
            'name'          => $name,
            'description'   => $desc,
            'resource_type' => $type,
            'resource_id'   => $rid,
            'action'        => $act,
        ]);

        return $this->jsonResponse('创建成功', 200, 'success', ['permission_id' => (int)$perm->id]); // 返回创建结果
    }

    /** 更新权限 */
    public function update()
    {
        $data = Request::post(); // 获取请求数据

        $rules = [
            'id'            => 'require|integer', // 权限ID
            'code'          => 'regex:/^[A-Za-z0-9_.-]{1,64}$/', // 权限代码规则
            'name'          => 'max:64', // 权限名称规则
            'description'   => 'max:255', // 描述规则
            'resource_type' => 'max:32', // 资源类型规则
            'resource_id'   => 'max:128', // 资源ID规则
            'action'        => 'max:32', // 动作规则
        ];
        $validate = Validate::rule($rules)
            ->message(['code.regex' => 'code 仅允许字母、数字、下划线(_)、中划线(-)、点号(.)']); // 自定义错误消息
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error'); // 校验失败返回错误

        /** @var \app\admin\model\AdminPermission $perm */
        $perm = AdminPermission::find((int)$data['id']);
        if (!$perm) return $this->jsonResponse('权限不存在', 404, 'error'); // 权限不存在返回错误

        // 赋值（只给传入字段，赋值前做规范化；resource_id 空串 -> NULL）
        $set = function(string $k) use (&$data, $perm) {
            if (!array_key_exists($k, $data)) return;
            $val = $data[$k];
            $val = ($k === 'resource_id')
                ? (($val === '' || $val === null) ? null : $this->normText($val))
                : $this->normText($val);
            $perm->setAttr($k, $val); // 设置权限字段
        };
        foreach (['code','name','description','resource_type','resource_id','action'] as $f) $set($f);

        // 只获取“真的变了”的字段
        $changed = $perm->getChangedData();
        if (empty($changed)) return $this->jsonResponse('没有需要更新的字段', 400, 'error'); // 无变化返回错误

        // 唯一性校验
        if (array_key_exists('code', $changed)) {
            $dup = AdminPermission::where('code', $changed['code'])->where('id', '<>', $perm->id)->find();
            if ($dup) return $this->jsonResponse('权限代码已存在', 400, 'error');
        }
        if (array_key_exists('name', $changed)) {
            $dup = AdminPermission::where('name', $changed['name'])->where('id', '<>', $perm->id)->find();
            if ($dup) return $this->jsonResponse('权限名称已存在', 400, 'error');
        }
        if (array_key_exists('resource_id', $changed) && $changed['resource_id'] !== null) {
            $dup = AdminPermission::where('resource_id', $changed['resource_id'])->where('id', '<>', $perm->id)->find();
            if ($dup) return $this->jsonResponse('资源ID已存在', 400, 'error');
        }

        // 三元组唯一：只在涉及三元组字段变化时校验
        $tripletTouched = array_intersect(['resource_type', 'resource_id', 'action'], array_keys($changed));
        if (!empty($tripletTouched)) {
            $newType   = array_key_exists('resource_type', $changed) ? $changed['resource_type'] : $perm->getOrigin('resource_type');
            $newRid    = array_key_exists('resource_id', $changed)   ? $changed['resource_id']   : $perm->getOrigin('resource_id');
            $newAction = array_key_exists('action', $changed)        ? $changed['action']        : $perm->getOrigin('action');

            $q = AdminPermission::where('resource_type', $newType)
                ->where('action', $newAction)
                ->where('id', '<>', $perm->id);
            ($newRid === null) ? $q->whereNull('resource_id') : $q->where('resource_id', $newRid);
            if ($q->find()) return $this->jsonResponse('同一资源与动作的权限已存在', 400, 'error');
        }

        // 保存（只更新变化字段）
        $perm->save();

        // 失效绑定了该权限的管理员的权限缓存
        if (method_exists($this, 'invalidateAdminsByPermissionId')) {
            $this->invalidateAdminsByPermissionId((int)$perm->id);
        }

        return $this->jsonResponse('更新成功', 200, 'success');
    }

    /** 解析 admin 身份（要求 realm=admin） */
    private function requireAdminAuth(): array
    {
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return [false, $this->jsonResponse('未登录', 401, 'error')];

        try {
            $claims = $this->tokenService->parse($raw); // 使用 JWT 解析 token
        } catch (\Throwable $e) {
            return [false, $this->jsonResponse('会话无效', 401, 'error')]; // 处理解析失败的情况
        }

        // 确保 `realm` 是 `admin`
        if (($claims->realm ?? '') !== 'admin') {
            return [false, $this->jsonResponse('非法领域', 403, 'error')];
        }

        // 返回管理员的 ID 信息
        return [true, ['admin_id' => (int)$claims->user_id]];
    }

    /** 删除权限（若被角色绑定则阻止） */
    public function delete()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); // 验证管理员身份
        if (!$ok) return $ctx;

        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        $row = AdminPermission::find($id); // 查找权限
        if (!$row) return $this->jsonResponse('删除成功', 200, 'success'); // 权限已不存在，返回成功

        // 绑定检查
        $cnt = AdminRolePermission::where('permission_id', $id)->count();
        if ($cnt > 0) return $this->jsonResponse('该权限仍绑定角色，不能删除', 400, 'error');

        AdminPermission::destroy($id); // 删除权限
        // 删除权限本身不需要失效任何管理员（因无角色引用）
        return $this->jsonResponse('删除成功', 200, 'success');
    }

    /** 权限详情 */
    public function info()
    {
        $id = (int)(Request::post('id') ?? Request::get('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        $row = AdminPermission::find($id); // 查找权限
        if (!$row) return $this->jsonResponse('权限不存在', 404, 'error');

        return $this->jsonResponse('OK', 200, 'success', ['detail' => $row]); // 返回权限详情
    }

    /** 权限列表（分页 + 多条件检索） */
    public function list()
    {
        $page   = max(1, (int)(Request::post('page') ?? Request::get('page') ?? 1)); // 页码
        $limit  = min(100, max(1, (int)(Request::post('limit') ?? Request::get('limit') ?? 20))); // 每页限制
        $kw     = trim((string)(Request::post('keyword') ?? Request::get('keyword') ?? '')); // 关键字
        $rtype  = trim((string)(Request::post('resource_type') ?? Request::get('resource_type') ?? '')); // 资源类型
        $action = trim((string)(Request::post('action') ?? Request::get('action') ?? '')); // 动作

        $query = AdminPermission::keyword($kw)   // 使用 keyword 范围
        ->resourceType($rtype)                // 使用 resource_type 范围
        ->resourceId($rtype)                  // 使用 resource_id 范围
        ->action($action);                    // 使用 action 范围

        $total = $query->count(); // 获取总数
        $rows  = $query->pageAndSort($page, $limit, 'id', 'desc')->select()->toArray(); // 分页查询

        return $this->jsonResponse('OK', 200, 'success', [
            'list'  => $rows,
            'total' => $total,
            'page'  => $page,
            'limit' => $limit,
        ]); // 返回分页结果
    }

}
