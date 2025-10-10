<?php
declare(strict_types=1);

namespace app\shopadmin\controller\rbac;

use app\BaseController;
use think\facade\Request;
use think\facade\Db;
use think\facade\Cache;
use think\facade\Validate;
use think\facade\Log;

use app\common\util\SystemClock;
use app\common\service\TokenService;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\PermissionCacheService;

use app\shopadmin\model\ShopAdminRole;
use app\shopadmin\model\ShopAdminUserRole;
use app\shopadmin\model\ShopAdminPermission;
use app\shopadmin\model\ShopAdminRolePermission;

/**
 * 【商户侧】角色管理控制器（RBAC, Tenant-aware）
 *
 * 关键能力：
 * - 租户隔离：所有查询/修改均绑定 merchant_id
 * - 超管直通：持 super_shopadmin（本租户）则不受等级限制
 * - 等级比较：基于“最高权限等级”（bestRoleLevel），支持 asc/desc 两种排序语义
 * - 缓存一致性：角色/授权变更后失效本租户受影响账号的权限缓存
 */
class Role extends BaseController
{
    private TokenService $tokenService;
    private string $SUPER_CODE = 'super_shopadmin';

    public function __construct()
    {
        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            config('jwt') ?: []
        );
    }

    /* ==================== 基础工具 ==================== */

    /** 文本规范化（去前后 ASCII/全角空格） */
    private function normText($v): string
    {
        $s = is_string($v) ? $v : (string)$v;
        return preg_replace('/^[\s\x{3000}]+|[\s\x{3000}]+$/u', '', $s);
    }

    /** 解析 shopadmin 领域会话：返回 [merchant_id, admin_id, errorResponse|null] */
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

    /** 等级排序方向：asc=数字越小权限越高；desc=数字越大权限越高 */
    private function levelOrder(): string
    {
        $order = (string)(config('permission.level_order') ?? 'asc');
        return ($order === 'desc') ? 'desc' : 'asc';
    }

    /** A 是否“高于” B（严格比较：同级不可操作） */
    private function isSuperior(int $aLevel, int $bLevel): bool
    {
        return $this->levelOrder() === 'desc' ? ($aLevel > $bLevel) : ($aLevel < $bLevel);
    }

    /** 是否超管（本租户） */
    private function isSuperAdmin(int $merchantId, int $adminId): bool
    {
        $now = date('Y-m-d H:i:s');
        return ShopAdminUserRole::alias('ur')
                ->join(['shopadmin_role'=>'r'],'r.id=ur.role_id')
                ->where('ur.merchant_id',$merchantId)->where('ur.admin_id',$adminId)
                ->where('r.merchant_id',$merchantId)->where('r.code',$this->SUPER_CODE)->where('r.status',1)
                // 角色有效期
                ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
                // 分配有效期
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
                ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
                ->count() > 0;
    }

    /** 账号在本租户内的“最高权限等级”（无角色：asc→99；desc→0） */
    private function bestRoleLevelOfAdmin(int $merchantId, int $adminId): int
    {
        $now = date('Y-m-d H:i:s');
        $levels = ShopAdminUserRole::alias('ur')
            ->join(['shopadmin_role'=>'r'],'r.id=ur.role_id')
            ->where('ur.merchant_id',$merchantId)->where('ur.admin_id',$adminId)
            ->where('r.merchant_id',$merchantId)->where('r.status',1)
            // 角色有效期
            ->where(function($q) use ($now){ $q->whereNull('r.valid_from')->whereOr('r.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('r.valid_to')->whereOr('r.valid_to','>',$now); })
            // 分配有效期
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_from')->whereOr('ur.valid_from','<=',$now); })
            ->where(function($q) use ($now){ $q->whereNull('ur.valid_to')->whereOr('ur.valid_to','>',$now); })
            ->column('r.level');

        if (empty($levels)) return $this->levelOrder()==='desc' ? 0 : 99;
        $levels = array_map('intval',$levels);
        return $this->levelOrder()==='desc' ? (int)max($levels) : (int)min($levels);
    }

    /* ============ 缓存一致性（shopadmin 侧） ============ */

    /** 失效一个账号的权限缓存（优先服务，兜底前缀） */
    private function evictPermCache(int $adminId): void
    {
        try {
            if (method_exists(PermissionCacheService::class, 'evictAdminPermCodes')) {
                PermissionCacheService::evictAdminPermCodes($adminId);
                return;
            }
        } catch (\Throwable $e) {}
        $prefix = (string)(config('permission.prefix') ?? 'shopadmin:perms:');
        Cache::delete($prefix . $adminId);
    }

    /** 失效：本租户某角色涉及的所有账号权限缓存 */
    private function invalidateAdminsByRoleId(int $merchantId, int $roleId): void
    {
        $adminIds = ShopAdminUserRole::where('merchant_id',$merchantId)->where('role_id',$roleId)->column('admin_id');
        foreach (array_unique(array_map('intval',$adminIds)) as $aid) {
            if ($aid>0) $this->evictPermCache($aid);
        }
    }

    /* ============ 越权判定（租户内） ============ */

    /** 操作者是否可操作“角色”（要求：同租户 && 超管直通 || opBest > role.level） */
    private function assertCanOperateRole(int $merchantId, int $operatorId, int $roleId)
    {
        if ($this->isSuperAdmin($merchantId, $operatorId)) return null;

        $opBest = $this->bestRoleLevelOfAdmin($merchantId, $operatorId);

        /** @var ShopAdminRole|null $role */
        $role = ShopAdminRole::where('merchant_id',$merchantId)->where('id',$roleId)->find();
        if (!$role) return $this->jsonResponse('角色不存在', 404, 'error');

        $roleLv = (int)($role->getAttr('level') ?? ($this->levelOrder()==='desc' ? 0 : 99));
        if (!$this->isSuperior($opBest, $roleLv)) {
            return $this->jsonResponse('越权：只能操作比你级别低的角色', 403, 'error');
        }
        return null;
    }

    /** 操作者是否可操作“账号”（要求：同租户 && 超管直通 || opBest > targetBest） */
    private function assertCanOperateUser(int $merchantId, int $operatorId, int $targetAdminId)
    {
        if ($this->isSuperAdmin($merchantId, $operatorId)) return null;

        $opBest = $this->bestRoleLevelOfAdmin($merchantId, $operatorId);
        $taBest = $this->bestRoleLevelOfAdmin($merchantId, $targetAdminId);

        if (!$this->isSuperior($opBest, $taBest)) {
            return $this->jsonResponse('越权：只能操作比你级别低的账号', 403, 'error');
        }
        return null;
    }

    /* ==================== 业务接口 ==================== */

    /** 创建角色（唯一性与范围均在本租户内判断） */
    public function create()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

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

        $code = $this->normText($data['code']);
        $name = $this->normText($data['name']);
        $desc = array_key_exists('description',$data) ? $this->normText($data['description']) : null;
        $status = array_key_exists('status',$data) ? (int)$data['status'] : 1;
        $vf = array_key_exists('valid_from',$data) ? $this->normText($data['valid_from']) : null;
        $vt = array_key_exists('valid_to',$data)   ? $this->normText($data['valid_to'])   : null;
        $defaultLv = $this->levelOrder()==='desc' ? 0 : 99;
        $lvl = (int)($data['level'] ?? $defaultLv);

        if (ShopAdminRole::where('merchant_id',$merchantId)->where('code',$code)->find())
            return $this->jsonResponse('角色代码已存在', 400, 'error');

        if (ShopAdminRole::where('merchant_id',$merchantId)->where('name',$name)->find())
            return $this->jsonResponse('角色名称已存在', 400, 'error');

        if ($vf && $vt && strtotime($vf) >= strtotime($vt))
            return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');

        // 越权校验（超管直通）
        if (!$this->isSuperAdmin($merchantId, $operatorId)) {
            $opBest = $this->bestRoleLevelOfAdmin($merchantId, $operatorId);
            if (!$this->isSuperior($opBest, $lvl)) {
                return $this->jsonResponse('越权：不能创建不低于你等级的角色', 403, 'error');
            }
        }

        $role = new ShopAdminRole();
        $role->save([
            'merchant_id' => $merchantId,
            'code'        => $code,
            'name'        => $name,
            'description' => $desc,
            'status'      => $status,
            'valid_from'  => $vf ?: null,
            'valid_to'    => $vt ?: null,
            'level'       => $lvl,
            'is_system'   => 0,
        ]);

        return $this->jsonResponse('创建成功', 200, 'success', ['role_id' => (int)$role->id]);
    }

    /** 更新角色（仅同租户；系统内置 super_shopadmin 受保护不可停用/删除/改 code/level） */
    public function update()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $data = Request::post();
        $rules = [
            'id'          => 'require|integer',
            'code'        => 'alphaDash|max:64',
            'name'        => 'max:64',
            'description' => 'max:255',
            'status'      => 'in:0,1',
            'level'       => 'integer|between:1,65535',
            'valid_from'  => 'date',
            'valid_to'    => 'date',
        ];
        $validate = Validate::rule($rules);
        if (!$validate->check($data)) return $this->jsonResponse($validate->getError(), 422, 'error');

        /** @var ShopAdminRole|null $role */
        $role = ShopAdminRole::where('merchant_id',$merchantId)->where('id',(int)$data['id'])->find();
        if (!$role) return $this->jsonResponse('角色不存在', 404, 'error');

        $isSuperRole = ((string)$role->getAttr('code') === $this->SUPER_CODE);

        // 越权（对角色目标本身）
        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, (int)$role->id)) {
            // 超管可改超管角色的名称/描述/有效期，但禁止改 code/level/停用
            if (!$this->isSuperAdmin($merchantId, $operatorId)) return $resp;
        }

        // 赋值（仅对传参字段）
        $set = function(string $k) use (&$data, $role, $isSuperRole) {
            if (!array_key_exists($k, $data)) return;
            $val = $data[$k];

            if (in_array($k,['code','name','description'],true)) $val = $this->normText((string)$val);
            if (in_array($k,['status','level'],true)) $val = (int)$val;

            // 保护：super_shopadmin 禁止改 code/level/停用
            if ($isSuperRole && in_array($k, ['code','level','status'], true)) {
                return; // 忽略这些字段
            }
            $role->setAttr($k, $val);
        };
        foreach (['code','name','description','status','level','valid_from','valid_to'] as $f) $set($f);

        $changed = $role->getChangedData();
        if (empty($changed)) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

        // 本租户内唯一性
        if (array_key_exists('code',$changed)) {
            $dup = ShopAdminRole::where('merchant_id',$merchantId)->where('code',$changed['code'])->where('id','<>',$role->id)->find();
            if ($dup) return $this->jsonResponse('角色代码已存在', 400, 'error');
        }
        if (array_key_exists('name',$changed)) {
            $dup = ShopAdminRole::where('merchant_id',$merchantId)->where('name',$changed['name'])->where('id','<>',$role->id)->find();
            if ($dup) return $this->jsonResponse('角色名称已存在', 400, 'error');
        }

        // 等级越权（当 level 变化且不是超管直通）
        if (array_key_exists('level',$changed) && !$this->isSuperAdmin($merchantId, $operatorId)) {
            $opBest = $this->bestRoleLevelOfAdmin($merchantId, $operatorId);
            if (!$this->isSuperior($opBest, (int)$changed['level'])) {
                return $this->jsonResponse('越权：不能把角色等级改成不低于你的等级', 403, 'error');
            }
        }

        // 有效期顺序校验
        $vf = array_key_exists('valid_from',$changed) ? $changed['valid_from'] : $role->getOrigin('valid_from');
        $vt = array_key_exists('valid_to',$changed)   ? $changed['valid_to']   : $role->getOrigin('valid_to');
        if ($vf && $vt && strtotime((string)$vf) >= strtotime((string)$vt)) {
            return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
        }

        $role->save();

        // 角色启停/有效期变更 → 失效绑定该角色的账号权限缓存
        if (array_intersect(['status','valid_from','valid_to','level'], array_keys($changed))) {
            $this->invalidateAdminsByRoleId($merchantId, (int)$role->id);
        }

        return $this->jsonResponse('更新成功', 200, 'success');
    }

    /** 删除角色（仅同租户；未解绑用户/权限前不允许；super_shopadmin 禁止删除） */
    public function delete()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        /** @var ShopAdminRole|null $role */
        $role = ShopAdminRole::where('merchant_id',$merchantId)->where('id',$id)->find();
        if (!$role) return $this->jsonResponse('角色不存在', 404, 'error');

        if ((string)$role->getAttr('code') === $this->SUPER_CODE) {
            return $this->jsonResponse('系统内置角色不可删除', 400, 'error');
        }

        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $id)) return $resp;

        $hasUsers = ShopAdminUserRole::where('merchant_id',$merchantId)->where('role_id',$id)->count();
        if ($hasUsers > 0) return $this->jsonResponse('该角色已分配给用户，不能删除', 400, 'error');

        $hasPerms = ShopAdminRolePermission::where('merchant_id',$merchantId)->where('role_id',$id)->count();
        if ($hasPerms > 0) return $this->jsonResponse('该角色仍绑定权限，不能删除', 400, 'error');

        ShopAdminRole::where('merchant_id',$merchantId)->where('id',$id)->delete();
        return $this->jsonResponse('删除成功', 200, 'success');
    }

    /** 角色详情（含 editable 判定） */
    public function info()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $id = (int)(Request::post('id') ?? Request::get('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 400, 'error');

        $row = ShopAdminRole::where('merchant_id',$merchantId)->where('id',$id)->find();
        if (!$row) return $this->jsonResponse('角色不存在', 404, 'error');
        $data = $row->toArray();

        $opIsSuper = $this->isSuperAdmin($merchantId, $operatorId);
        $opBest    = $this->bestRoleLevelOfAdmin($merchantId, $operatorId);
        $roleLv    = (int)($data['level'] ?? ($this->levelOrder()==='desc' ? 0 : 99));

        $data['editable'] = $opIsSuper ? 1 : ($this->isSuperior($opBest, $roleLv) ? 1 : 0);

        return $this->jsonResponse('OK', 200, 'success', ['detail' => $data]);
    }

    /** 角色列表（分页 + 过滤 + editable 判定，全部按租户过滤） */
    public function list()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $opIsSuper = $this->isSuperAdmin($merchantId, $operatorId);
        $opBest    = $this->bestRoleLevelOfAdmin($merchantId, $operatorId);

        $page   = max(1, (int)(Request::post('page') ?? Request::get('page') ?? 1));
        $limit  = min(1000, max(1, (int)(Request::post('limit') ?? Request::get('limit') ?? 20)));
        $status = Request::post('status') ?? Request::get('status');
        $kw     = trim((string)(Request::post('keyword') ?? Request::get('keyword') ?? ''));
        $onDate = trim((string)(Request::post('effective_on') ?? Request::get('effective_on') ?? ''));
        $editableParam = Request::post('editable') ?? Request::get('editable'); // 0/1/空

        $q = ShopAdminRole::where('merchant_id',$merchantId);
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

        // editable 过滤（按操作者最高等级）
        if ($editableParam !== null && $editableParam !== '') {
            $editable = (int)$editableParam;
            if ($opIsSuper) {
                if ($editable === 0) $q->whereRaw('1=0'); // 超管要“只看不可编辑”则返回空
            } else {
                if ($this->levelOrder()==='desc') {
                    if ($editable === 1) $q->whereRaw('(level IS NULL OR level < ?)', [$opBest]);
                    elseif ($editable === 0) $q->whereRaw('(level IS NOT NULL AND level >= ?)', [$opBest]);
                } else {
                    if ($editable === 1) $q->whereRaw('(level IS NULL OR level > ?)', [$opBest]);
                    elseif ($editable === 0) $q->whereRaw('(level IS NOT NULL AND level <= ?)', [$opBest]);
                }
            }
        }

        $total = (clone $q)->count();
        $rows  = $q->page($page, $limit)->order('level','asc')->order('id','desc')->select()->toArray();

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

    /** 给用户分配角色（同租户；存在则更新有效期；变更后失效缓存） */
    public function assignToUser()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $adminId = (int)(Request::post('admin_id') ?? 0);
        $roleId  = (int)(Request::post('role_id')  ?? 0);
        $vf = Request::post('valid_from') ?: null;
        $vt = Request::post('valid_to')   ?: null;

        if ($adminId<=0 || $roleId<=0) return $this->jsonResponse('缺少 admin_id 或 role_id', 400, 'error');

        // 越权校验（对账号与角色）
        if ($resp = $this->assertCanOperateUser($merchantId, $operatorId, $adminId)) return $resp;
        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $roleId))  return $resp;

        // 归属校验
        $userOk = Db::table('shopadmin_user')->where(['id'=>$adminId,'merchant_id'=>$merchantId])->whereNull('deleted_at')->find();
        if (!$userOk) return $this->jsonResponse('账号不存在', 404, 'error');

        $roleOk = ShopAdminRole::where(['id'=>$roleId,'merchant_id'=>$merchantId])->find();
        if (!$roleOk) return $this->jsonResponse('角色不存在', 404, 'error');

        if ($vf && $vt && strtotime($vf) >= strtotime($vt))
            return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');

        // 幂等 upsert
        $now = date('Y-m-d H:i:s');
        $exists = ShopAdminUserRole::where(['merchant_id'=>$merchantId,'admin_id'=>$adminId,'role_id'=>$roleId])->find();
        if ($exists) {
            ShopAdminUserRole::where(['merchant_id'=>$merchantId,'admin_id'=>$adminId,'role_id'=>$roleId])
                ->update([
                    'valid_from' => $vf ?: $exists->getAttr('valid_from'),
                    'valid_to'   => $vt ?: $exists->getAttr('valid_to'),
                    'assigned_by'=> $operatorId,
                ]);
        } else {
            Db::name('shopadmin_user_role')->insert([
                'admin_id'    => $adminId,
                'role_id'     => $roleId,
                'merchant_id' => $merchantId,
                'assigned_at' => $now,
                'assigned_by' => $operatorId,
                'valid_from'  => $vf ?: $now,
                'valid_to'    => $vt ?: null,
            ]);
        }

        $this->invalidateAdminsByRoleId($merchantId, $roleId);
        $this->evictPermCache($adminId);
        return $this->jsonResponse('分配成功', 200, 'success');
    }

    /** 撤销用户的某个角色（同租户；不存在也当成功） */
    public function revokeFromUser()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $adminId = (int)(Request::post('admin_id') ?? 0);
        $roleId  = (int)(Request::post('role_id')  ?? 0);
        if ($adminId<=0 || $roleId<=0) return $this->jsonResponse('缺少 admin_id 或 role_id', 400, 'error');

        if ($resp = $this->assertCanOperateUser($merchantId, $operatorId, $adminId)) return $resp;
        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $roleId))  return $resp;

        ShopAdminUserRole::where(['merchant_id'=>$merchantId,'admin_id'=>$adminId,'role_id'=>$roleId])->delete();

        $this->invalidateAdminsByRoleId($merchantId, $roleId);
        $this->evictPermCache($adminId);
        return $this->jsonResponse('撤销成功', 200, 'success');
    }

    /** 批量绑定权限到角色（同租户；重复跳过；变更后失效缓存） */
    public function bindPermissions()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $roleId  = (int)(Request::post('role_id') ?? 0);
        $permIds = Request::post('permission_ids') ?? [];
        if ($roleId<=0 || !is_array($permIds) || !$permIds) return $this->jsonResponse('缺少 role_id 或 permission_ids[]', 400, 'error');

        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $roleId)) return $resp;

        $permIds = array_values(array_unique(array_map('intval',$permIds)));
        // 仅保留本租户的有效权限
        $exists  = ShopAdminPermission::where('merchant_id',$merchantId)->whereIn('id',$permIds)->column('id');
        $exists  = array_map('intval',$exists);
        if (!$exists) return $this->jsonResponse('无有效的权限ID', 400, 'error');

        $already = ShopAdminRolePermission::where('merchant_id',$merchantId)
            ->where('role_id',$roleId)->whereIn('permission_id',$exists)->column('permission_id');
        $todo = array_values(array_diff($exists, array_map('intval',$already)));

        if ($todo) {
            $rows = [];
            $now  = date('Y-m-d H:i:s');
            foreach ($todo as $pid) {
                $rows[] = [
                    'role_id'       => $roleId,
                    'permission_id' => (int)$pid,
                    'merchant_id'   => $merchantId,
                    'assigned_at'   => $now,
                    'assigned_by'   => $operatorId,
                ];
            }
            (new ShopAdminRolePermission())->saveAll($rows);
            $this->invalidateAdminsByRoleId($merchantId, $roleId);
            return $this->jsonResponse('绑定成功', 200, 'success', [
                'added'   => count($rows),
                'skipped' => count($exists) - count($rows),
            ]);
        }

        return $this->jsonResponse('全部已绑定（幂等）', 200, 'success');
    }

    /** 解绑角色的某个权限（同租户；不存在也成功） */
    public function unbindPermission()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $roleId = (int)(Request::post('role_id') ?? 0);
        $pid    = (int)(Request::post('permission_id') ?? 0);
        if ($roleId<=0 || $pid<=0) return $this->jsonResponse('缺少 role_id 或 permission_id', 400, 'error');

        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $roleId)) return $resp;

        ShopAdminRolePermission::where(['merchant_id'=>$merchantId,'role_id'=>$roleId,'permission_id'=>$pid])->delete();
        $this->invalidateAdminsByRoleId($merchantId, $roleId);
        return $this->jsonResponse('解绑成功', 200, 'success');
    }

    /** 一键撤销该角色的所有用户分配（同租户；越权安全；变更后失效缓存） */
    public function revokeAllUsersOfRole()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $roleId = (int)(Request::post('role_id') ?? 0);
        if ($roleId <= 0) return $this->jsonResponse('缺少 role_id', 400, 'error');
        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $roleId)) return $resp;

        $ids = ShopAdminUserRole::where(['merchant_id'=>$merchantId,'role_id'=>$roleId])->column('admin_id');
        foreach ($ids as $aid) {
            if ($this->assertCanOperateUser($merchantId, $operatorId, (int)$aid) === null) {
                ShopAdminUserRole::where(['merchant_id'=>$merchantId,'admin_id'=>(int)$aid,'role_id'=>$roleId])->delete();
                $this->evictPermCache((int)$aid);
            }
        }
        $this->invalidateAdminsByRoleId($merchantId, $roleId);
        return $this->jsonResponse('已撤销所有用户分配', 200, 'success');
    }

    /** 一键解绑该角色的所有权限（同租户；变更后失效缓存） */
    public function unbindAllPermissionsOfRole()
    {
        [$merchantId, $operatorId, $err] = $this->requireShopAdminAuth(); if ($err) return $err;

        $roleId = (int)(Request::post('role_id') ?? 0);
        if ($roleId <= 0) return $this->jsonResponse('缺少 role_id', 400, 'error');
        if ($resp = $this->assertCanOperateRole($merchantId, $operatorId, $roleId)) return $resp;

        ShopAdminRolePermission::where(['merchant_id'=>$merchantId,'role_id'=>$roleId])->delete();
        $this->invalidateAdminsByRoleId($merchantId, $roleId);
        return $this->jsonResponse('已解绑所有权限', 200, 'success');
    }
}
