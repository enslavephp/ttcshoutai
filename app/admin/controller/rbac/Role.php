<?php
declare(strict_types=1);

namespace app\admin\controller\rbac;

use app\BaseController;
use think\facade\Request;
use think\facade\Validate;

use app\admin\model\AdminRole;
use app\admin\model\AdminUserRole;
use app\admin\model\AdminPermission;
use app\admin\model\AdminRolePermission;

use app\common\util\SystemClock;
use app\common\service\TokenService;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\PermissionCacheService;

/**
 * 角色管理控制器（RBAC）
 *
 * 关键变化：
 *  - 越权判断基于“最高等级”（bestRoleLevel），而不是“最低等级”
 *  - 通过 isSuperior() 统一比较逻辑，支持 permission.level_order 配置：
 *      * 'asc'（默认）：数字越小权限越高（1 > 2 > 3）
 *      * 'desc'：数字越大权限越高（999 > 10 > 1）
 *  - 彻底改用 ORM（AdminUserRole/AdminRolePermission/AdminPermission/AdminRole）
 *  - 与 PermissionCacheService 打通：角色/权限/映射改动 → 秒级失效缓存
 */
class Role extends BaseController
{
    private TokenService $tokenService;

    // 构造函数，初始化 TokenService
    public function __construct()
    {
        // 初始化 TokenService 用于生成和验证 JWT token
        $jwtSecret = (string)(\app\common\Helper::getValue('jwt.secret') ?? 'PLEASE_CHANGE_ME');
        $jwtCfg['secret'] = $jwtSecret;

        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            $jwtCfg
        );
    }

    /** 文本规范化（去前后空白与全角空格） */
    private function normText($v): string
    {
        $s = is_string($v) ? $v : (string)$v;
        return preg_replace('/^[\s\x{3000}]+|[\s\x{3000}]+$/u', '', $s); // 清除字符串首尾空格
    }

    // ===================== 等级与越权核心 =====================

    /** 等级排序方向：asc=数字越小权限越高；desc=数字越大权限越高 */
    private function levelOrder(): string
    {
        $order = (string) (\app\common\Helper::getValue('permission.level_order') ?? 'asc');
        return ($order === 'desc') ? 'desc' : 'asc';
    }

    /**
     * 取“最佳”（最高权限）的等级值
     * - 无角色：asc → 99（最低）；desc → 0（最低）
     */
    private function bestRoleLevelOfAdmin(int $adminId): int
    {
        $now = date('Y-m-d H:i:s');
        $levels = AdminUserRole::alias('ur')
            ->join(['admin_role'=>'r'],'r.id = ur.role_id')
            ->where('ur.admin_id', $adminId)
            ->where('r.status', 1)
            // 角色有效期 [from, to)
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            // 分配有效期 [from, to)
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            ->column('r.level');

        if (empty($levels)) return $this->levelOrder()==='desc' ? 0 : 99;
        $levels = array_map('intval', $levels);

        return $this->levelOrder()==='desc' ? (int)max($levels) : (int)min($levels);
    }

    /** 兼容旧命名：历史代码若调用 minRoleLevelOfAdmin()，仍返回“最佳等级” */
    private function minRoleLevelOfAdmin(int $adminId): int
    { return $this->bestRoleLevelOfAdmin($adminId); }

    /**
     * 比较器：A 是否“高于” B（A 能操作 B）
     * - asc：数字越小权限越高 → A < B
     * - desc：数字越大权限越高 → A > B
     * - 严格比较：同级不可操作
     */
    private function isSuperior(int $aLevel, int $bLevel): bool
    {
        if ($this->levelOrder() === 'desc') return $aLevel > $bLevel;
        return $aLevel < $bLevel;
    }

    /** 是否超管（启用且在有效期内；code 可配置） */
    private function isSuperAdmin(int $adminId): bool
    {
        if ($adminId <= 0) return false;
        $now   = date('Y-m-d H:i:s');
        $super = (string)(\app\common\Helper::getValue('permission.super_admin_code') ?? 'super_admin');
        return AdminUserRole::alias('ur')
                ->join(['admin_role'=>'r'],'r.id = ur.role_id')
                ->where('ur.admin_id', $adminId)
                ->where('r.code', $super)
                ->where('r.status', 1)
                ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                ->count() > 0;
    }

    // ===================== 缓存失效（对接 PermissionCacheService） =====================

    /** 失效：一批管理员权限缓存 */
    private function invalidateAdminPermCache(array $adminIds): void
    {
        foreach (array_unique(array_map('intval', $adminIds)) as $aid) {
            if ($aid > 0) PermissionCacheService::invalidateAdmin($aid);
        }
    }

    /** 失效：角色自身缓存 + 所有持有该角色的管理员权限缓存 */
    private function invalidateAdminsByRoleId(int $roleId): void
    {
        PermissionCacheService::invalidateRole($roleId);
        PermissionCacheService::invalidateAdminsByRoleId($roleId);
    }

    // ===================== 认证 =====================

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

    // ===================== 业务接口 =====================

    /** 创建角色（非超管只能创建“严格低于自己最高等级”的角色） */
    public function create()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;

        $data = Request::post();
        $rules = [
            'code'        => 'require|alphaDash|max:64',
            'name'        => 'require|max:64',
            'description' => 'max:255',
            'status'      => 'in:0,1',
            'valid_from'  => 'date',
            'valid_to'    => 'date',
            'level'       => 'integer|between:1,65535',
        ];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        // 规范化数据
        $code   = $this->normText($data['code']);
        $name   = $this->normText($data['name']);
        $desc   = array_key_exists('description',$data) ? $this->normText($data['description']) : null;
        $status = array_key_exists('status',$data) ? (int)$data['status'] : 1;
        $vf     = array_key_exists('valid_from',$data) ? $this->normText($data['valid_from']) : null;
        $vt     = array_key_exists('valid_to',$data)   ? $this->normText($data['valid_to'])   : null;
        $defaultLv = $this->levelOrder()==='desc' ? 0 : 99;
        $lvl    = (int)($data['level'] ?? $defaultLv);

        if (AdminRole::where('code',$code)->find())
            return $this->jsonResponse('角色代码已存在', 400, 'error');

        if ($vf && $vt && strtotime($vf) >= strtotime($vt))
            return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');

        // 检查越权
        if (!$this->isSuperAdmin((int)$ctx['admin_id'])) {
            $opBest = $this->bestRoleLevelOfAdmin((int)$ctx['admin_id']);
            if (!$this->isSuperior($opBest, $lvl)) {
                return $this->jsonResponse('越权：不能创建不低于你等级的角色', 403, 'error');
            }
        }

        $role = new AdminRole();
        $role->save([
            'code'        => $code,
            'name'        => $name,
            'description' => $desc,
            'status'      => $status,
            'valid_from'  => $vf ?: null,
            'valid_to'    => $vt ?: null,
            'level'       => $lvl,
        ]);

        return $this->jsonResponse('创建成功', 200, 'success', ['role_id' => (int)$role->id]);
    }

    /** 更新角色（level 变更按“最高等级”校验；其余保持原逻辑） */
    public function update()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;

        $data = Request::post();

        // 先把时间字段做“空串->NULL；合法->标准化”的预处理
        $normalizeDT = function($v) {
            if (!isset($v)) return null;
            $v = trim((string)$v);
            if ($v === '') return null;                // 关键：空串写成 NULL
            $ts = strtotime($v);
            if ($ts === false) return '__INVALID__';   // 标记非法，稍后拦截
            return date('Y-m-d H:i:s', $ts);           // 统一成秒精度
        };
        foreach (['valid_from','valid_to'] as $k) {
            if (array_key_exists($k, $data)) {
                $data[$k] = $normalizeDT($data[$k]);
            }
        }
        if (($data['valid_from'] ?? null) === '__INVALID__' ||
            ($data['valid_to']   ?? null) === '__INVALID__') {
            return $this->jsonResponse('时间格式不正确，应为 YYYY-MM-DD 或 YYYY-MM-DD HH:mm:ss', 422, 'error');
        }

        // 校验数据
        $rules = [
            'id'          => 'require|integer',
            'code'        => 'alphaDash|max:64',
            'name'        => 'max:64',
            'description' => 'max:255',
            'status'      => 'in:0,1',
            'level'       => 'integer|between:1,65535',
        ];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        // 查找角色
        $role = AdminRole::find((int)$data['id']);
        if (!$role) return $this->jsonResponse('角色不存在', 404, 'error');

        // 检查越权
        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], (int)$role->id)) return $resp;

        // 更新角色字段（仅对传参字段）
        $set = function(string $k) use (&$data, $role) {
            if (!array_key_exists($k, $data)) return;
            $val = $data[$k];
            // 文本字段做 normText；时间字段已在前面处理完毕
            if (in_array($k, ['code','name','description'], true)) {
                $val = $this->normText((string)$val);
            }
            if ($k === 'status' || $k === 'level') $val = (int)$val;
            $role->setAttr($k, $val);
        };
        foreach (['code','name','description','status','valid_from','valid_to','level'] as $f) $set($f);

        $changed = $role->getChangedData();
        if (empty($changed)) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

        // 检查权限代码唯一
        if (array_key_exists('code',$changed)) {
            $dup = AdminRole::where('code',$changed['code'])->where('id','<>',$role->id)->find();
            if ($dup) return $this->jsonResponse('角色代码已存在', 400, 'error');
        }

        // 校验有效期顺序（允许任一为空；都不为空时才比较）
        if (array_intersect(['valid_from','valid_to'], array_keys($changed))) {
            $vf = array_key_exists('valid_from',$changed) ? $changed['valid_from'] : $role->getOrigin('valid_from');
            $vt = array_key_exists('valid_to',$changed)   ? $changed['valid_to']   : $role->getOrigin('valid_to');
            if ($vf && $vt && strtotime((string)$vf) >= strtotime((string)$vt)) {
                return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
            }
        }

        // 等级变更时的越权校验
        if (array_key_exists('level',$changed) && !$this->isSuperAdmin((int)$ctx['admin_id'])) {
            $opBest = $this->bestRoleLevelOfAdmin((int)$ctx['admin_id']);
            if (!$this->isSuperior($opBest, (int)$changed['level'])) {
                return $this->jsonResponse('越权：不能把角色等级改成不低于你的等级', 403, 'error');
            }
        }

        $role->save();

        // 失效权限缓存
        if (array_intersect(['status','valid_from','valid_to'], array_keys($changed))) {
            $this->invalidateAdminsByRoleId((int)$role->id);
        }

        return $this->jsonResponse('更新成功', 200, 'success');
    }

    /** 删除角色（未解绑用户/权限前不允许） */
    public function delete()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;

        $id = (int)(Request::post('id') ?? 0);
        if (!$id) return $this->jsonResponse('缺少 id', 400, 'error');

        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $id)) return $resp;

        $hasUsers = AdminUserRole::where('role_id',$id)->count();
        if ($hasUsers > 0) return $this->jsonResponse('该角色已分配给用户，不能删除', 400, 'error');

        $hasPerms = AdminRolePermission::where('role_id',$id)->count();
        if ($hasPerms > 0) return $this->jsonResponse('该角色仍绑定权限，不能删除', 400, 'error');

        AdminRole::where('id',$id)->delete();
        return $this->jsonResponse('删除成功', 200, 'success');
    }

    /** 角色详情（editable 按“最高等级”判断） */
    public function info()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;

        $id = (int)(Request::post('id') ?? Request::get('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        $row = AdminRole::where('id',$id)->find();
        if (!$row) return $this->jsonResponse('角色不存在', 404, 'error');
        $data = $row->toArray();

        $opBest    = $this->bestRoleLevelOfAdmin((int)$ctx['admin_id']);
        $roleLv    = (int)($data['level'] ?? ($this->levelOrder()==='desc' ? 0 : 99));
        $opIsSuper = $this->isSuperAdmin((int)$ctx['admin_id']);

        $data['editable'] = $opIsSuper ? 1 : ($this->isSuperior($opBest, $roleLv) ? 1 : 0);

        return $this->jsonResponse('OK', 200, 'success', ['detail' => $data]);
    }

    /** 角色列表（分页 + 过滤 + editable 按“最高等级”） */
    public function list()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $operatorId = (int)$ctx['admin_id'];
        $opBest     = $this->bestRoleLevelOfAdmin($operatorId);
        $opIsSuper  = $this->isSuperAdmin($operatorId);

        $page   = max(1, (int)(Request::post('page') ?? Request::get('page') ?? 1));
        $limit  = min(1000, max(1, (int)(Request::post('limit') ?? Request::get('limit') ?? 20)));
        $status = Request::post('status') ?? Request::get('status');
        $kw     = trim((string)(Request::post('keyword') ?? Request::get('keyword') ?? ''));
        $onDate = trim((string)(Request::post('effective_on') ?? Request::get('effective_on') ?? ''));
        $editableParam = Request::post('editable') ?? Request::get('editable'); // 0/1

        $q = AdminRole::where([]);

        if ($kw !== '') $q->whereLike('name|code|description', "%{$kw}%");
        if ($status !== null && $status !== '') $q->where('status', (int)$status);

        if ($onDate !== '') {
            $ts = strtotime($onDate);
            if ($ts !== false) {
                $dayStart = date('Y-m-d 00:00:00', $ts);
                $dayEnd   = date('Y-m-d 23:59:59', $ts);
                $q->where(function($sub) use ($dayEnd) {
                    $sub->whereNull('valid_from')->whereOr('valid_from','<=',$dayEnd);
                })->where(function($sub) use ($dayStart) {
                    $sub->whereNull('valid_to')->whereOr('valid_to','>',$dayStart);
                });
            }
        }

        // editable 过滤（最高等级）
        if ($editableParam !== null && $editableParam !== '') {
            $editable = (int)$editableParam;
            if ($opIsSuper) {
                // 超管：可改=1 => 全部；可改=0 => 返回空
                if ($editable === 0) $q->whereRaw('1=0');
            } else {
                if ($this->levelOrder()==='desc') {
                    // 数字越大权限越高 → 可编辑：opBest > level
                    if ($editable === 1) $q->whereRaw('(level IS NULL OR level < ?)', [$opBest]);
                    elseif ($editable === 0) $q->whereRaw('(level IS NOT NULL AND level >= ?)', [$opBest]);
                } else {
                    // 数字越小权限越高 → 可编辑：opBest < level
                    if ($editable === 1) $q->whereRaw('(level IS NULL OR level > ?)', [$opBest]);
                    elseif ($editable === 0) $q->whereRaw('(level IS NOT NULL AND level <= ?)', [$opBest]);
                }
            }
        }

        $total = (clone $q)->count();
        $rows  = $q->page($page, $limit)->order('id','asc')->select()->toArray();

        foreach ($rows as &$r) {
            $roleLv = isset($r['level']) ? (int)$r['level'] : ($this->levelOrder()==='desc' ? 0 : 99);
            $r['editable'] = $opIsSuper ? 1 : ($this->isSuperior($opBest, $roleLv) ? 1 : 0);
        } unset($r);

        return $this->jsonResponse('OK', 200, 'success', [
            'list'  => $rows,
            'total' => $total,
            'page'  => $page,
            'limit' => $limit,
        ]);
    }

    /** 给用户分配角色（存在则更新有效期；越权用“最高等级”判断） */
    public function AdminUserhasrole()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $adminId = (int)(Request::post('admin_id') ?? 0);

        if ($adminId<=0) return $this->jsonResponse('缺少 admin_id', 400, 'error');
        $data = AdminUserRole::alias('ur')
            ->join(['admin_role'=>'r'],'r.id = ur.role_id')
            ->where('ur.admin_id', $adminId)
            ->select()->toArray();
        return $this->jsonResponse('当前管理员绑定的角色', 200, 'success',$data);
    }

    /** 给用户分配角色（存在则更新有效期；越权用“最高等级”判断） */
    public function assignToUser()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $adminId = (int)(Request::post('admin_id') ?? 0);
        $roleId  = (int)(Request::post('role_id')  ?? 0);
        $vf = Request::post('valid_from') ?: null;
        $vt = Request::post('valid_to')   ?: null;

        if ($adminId<=0 || $roleId<=0) return $this->jsonResponse('缺少 admin_id 或 role_id', 400, 'error');

        if ($resp = $this->assertCanOperateUser((int)$ctx['admin_id'], $adminId)) return $resp;
        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $roleId))  return $resp;

        if ($vf && $vt && strtotime($vf) >= strtotime($vt))
            return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');

        AdminUserRole::attach($adminId, $roleId, $vf, $vt, (int)$ctx['admin_id']);
        $this->invalidateAdminsByRoleId($roleId);
        return $this->jsonResponse('分配成功', 200, 'success');
    }

    /** 撤销用户的某个角色（不存在也当成功；越权用“最高等级”） */
    public function revokeFromUser()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $adminId = (int)(Request::post('admin_id') ?? 0);
        $roleId  = (int)(Request::post('role_id')  ?? 0);
        if ($adminId<=0 || $roleId<=0) return $this->jsonResponse('缺少 admin_id 或 role_id', 400, 'error');

        if ($resp = $this->assertCanOperateUser((int)$ctx['admin_id'], $adminId)) return $resp;
        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $roleId))  return $resp;

        AdminUserRole::detach($adminId, $roleId);
        $this->invalidateAdminsByRoleId($roleId);
        return $this->jsonResponse('撤销成功', 200, 'success');
    }

    /** 批量绑定权限到角色（重复自动跳过；自动失效缓存） */
    public function bindPermissions()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $roleId  = (int)(Request::post('role_id') ?? 0);
        $permIds = Request::post('permission_ids') ?? [];
        if ($roleId<=0 || !is_array($permIds) || !$permIds) return $this->jsonResponse('缺少 role_id 或 permission_ids[]', 400, 'error');

        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $roleId)) return $resp;

        // 过滤有效权限ID
        $permIds = array_values(array_unique(array_map('intval',$permIds)));
        $exists  = AdminPermission::whereIn('id',$permIds)->column('id');
        $exists  = array_map('intval',$exists);
        if (!$exists) return $this->jsonResponse('无有效的权限ID', 400, 'error');

        // 已绑定的跳过
        $already = AdminRolePermission::where('role_id',$roleId)->whereIn('permission_id',$exists)->column('permission_id');
        $todo = array_values(array_diff($exists, array_map('intval',$already)));

        if ($todo) {
            $rows = [];
            $now  = date('Y-m-d H:i:s');
            foreach ($todo as $pid) {
                $rows[] = [
                    'role_id'       => $roleId,
                    'permission_id' => (int)$pid,
                    'assigned_at'   => $now,
                    'assigned_by'   => (int)$ctx['admin_id'],
                ];
            }
            // 批量插入（ORM）
            (new AdminRolePermission())->saveAll($rows);
            $this->invalidateAdminsByRoleId($roleId);
            return $this->jsonResponse('绑定成功', 200, 'success', [
                'added'   => count($rows),
                'skipped' => count($exists) - count($rows),
            ]);
        }

        return $this->jsonResponse('全部已绑定（幂等）', 200, 'success');
    }

    /** 解绑角色的某个权限（不存在也视为成功；自动失效缓存） */
    public function unbindPermission()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $roleId = (int)(Request::post('role_id') ?? 0);
        $pid    = (int)(Request::post('permission_id') ?? 0);
        if ($roleId<=0 || $pid<=0) return $this->jsonResponse('缺少 role_id 或 permission_id', 400, 'error');

        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $roleId)) return $resp;

        AdminRolePermission::where(['role_id'=>$roleId,'permission_id'=>$pid])->delete();
        $this->invalidateAdminsByRoleId($roleId);
        return $this->jsonResponse('解绑成功', 200, 'success');
    }

    /** 一键撤销该角色的所有用户分配（带越权校验；自动失效缓存） */
    public function revokeAllUsersOfRole()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $roleId = (int)(Request::post('role_id') ?? 0);
        if ($roleId <= 0) return $this->jsonResponse('缺少 role_id', 400, 'error');
        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $roleId)) return $resp;

        $ids = AdminUserRole::where('role_id',$roleId)->column('admin_id');
        foreach ($ids as $aid) {
            if ($this->assertCanOperateUser((int)$ctx['admin_id'], (int)$aid) === null) {
                AdminUserRole::where(['admin_id'=>(int)$aid,'role_id'=>$roleId])->delete();
            }
        }
        $this->invalidateAdminsByRoleId($roleId);
        return $this->jsonResponse('已撤销所有用户分配', 200, 'success');
    }

    /** 一键解绑该角色的所有权限（带越权校验；自动失效缓存） */
    public function unbindAllPermissionsOfRole()
    {
        [$ok, $ctx] = $this->requireAdminAuth(); if (!$ok) return $ctx;
        $roleId = (int)(Request::post('role_id') ?? 0);
        if ($roleId <= 0) return $this->jsonResponse('缺少 role_id', 400, 'error');
        if ($resp = $this->assertCanOperateRole((int)$ctx['admin_id'], $roleId)) return $resp;

        AdminRolePermission::where('role_id',$roleId)->delete();
        $this->invalidateAdminsByRoleId($roleId);
        return $this->jsonResponse('已解绑所有权限', 200, 'success');
    }

    // ===================== 越权判定封装（便于在接口里复用） =====================

    /** 是否允许对“角色”操作（要求：操作者最高等级 > 目标角色等级；超管直通） */
    private function assertCanOperateRole(int $operatorId, int $roleId)
    {
        if ($this->isSuperAdmin($operatorId)) return null;

        $opBest = $this->bestRoleLevelOfAdmin($operatorId);
        $role   = AdminRole::where('id',$roleId)->find();
        if (!$role) return $this->jsonResponse('角色不存在', 404, 'error');

        $roleLv = (int)($role->getAttr('level') ?? ($this->levelOrder()==='desc' ? 0 : 99));
        if (!$this->isSuperior($opBest, $roleLv)) {
            return $this->jsonResponse('越权：只能操作比你级别低的角色', 403, 'error');
        }
        return null;
    }

    /** 是否允许对“账号”操作（要求：操作者最高等级 > 目标账号最高等级；超管直通） */
    private function assertCanOperateUser(int $operatorId, int $targetAdminId)
    {
        if ($this->isSuperAdmin($operatorId)) return null;

        $opBest = $this->bestRoleLevelOfAdmin($operatorId);
        $taBest = $this->bestRoleLevelOfAdmin($targetAdminId);

        if (!$this->isSuperior($opBest, $taBest)) {
            return $this->jsonResponse('越权：只能操作比你级别低的账号', 403, 'error');
        }
        return null;
    }
}
