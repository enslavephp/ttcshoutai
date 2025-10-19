<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use think\facade\Request;
use think\facade\Validate;
use think\facade\Log;
use think\facade\Db;
use app\shopadmin\model\Category as CategoryModel;
use app\shopadmin\model\SkuCategory as SkuCategoryModel;

/**
 * 类目管理（写+查）
 * - 顶级 parent_id = 0
 * - sort 越小越靠前
 * - 生效期 valid_from/valid_to（NULL=不限）
 * - 变更后刷新绑定该类目的 SKU 的 ES
 * - 全部方法添加容错 try/catch；涉及数据变动处包事务（失败自动回滚）
 * - 与 shop_sku_category 交互统一使用 ORM（SkuCategoryModel）
 */
class Category extends BaseShopAdmin
{
    /** 创建类目 */
    public function create()
    {
        try {
            [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $rules = [
                'name'       => 'require|max:64',
                'parent_id'  => 'integer',
                'valid_from' => 'date',
                'valid_to'   => 'date',
                'sort'       => 'integer',
                'status'     => 'in:0,1',
            ];
            $v = Validate::rule($rules);
            if (!$v->check($d)) return $this->jsonResponse($v->getError(), 422, 'error');

            $parentId = (int)($d['parent_id'] ?? 0);
            $nameTrim = trim((string)$d['name']);

            // 父级存在性校验（>0 时）
            if ($parentId > 0) {
                $parentOk = CategoryModel::where('merchant_id', $merchantId)->where('id', $parentId)->value('id');
                if (!$parentOk) return $this->jsonResponse('父类目不存在', 404, 'error');
            }

            // 同父级重名
            $dup = CategoryModel::where('merchant_id', $merchantId)
                ->where('parent_id', $parentId)
                ->where('name', $nameTrim)
                ->count();
            if ($dup > 0) return $this->jsonResponse('同一父类目下已存在同名类目', 409, 'error');

            $vf = isset($d['valid_from']) && trim((string)$d['valid_from']) !== '' ? date('Y-m-d H:i:s', strtotime($d['valid_from'])) : null;
            $vt = isset($d['valid_to'])   && trim((string)$d['valid_to'])   !== '' ? date('Y-m-d H:i:s', strtotime($d['valid_to']))   : null;
            if ($vf && $vt && strtotime($vf) >= strtotime($vt)) {
                return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
            }

            $rowId = 0;
            Db::transaction(function() use ($merchantId, $adminId, $nameTrim, $parentId, $vf, $vt, $d, &$rowId) {
                $row = new CategoryModel();
                $row->save([
                    'merchant_id' => $merchantId,
                    'name'        => $nameTrim,
                    'parent_id'   => $parentId,
                    'valid_from'  => $vf,
                    'valid_to'    => $vt,
                    'sort'        => (int)($d['sort'] ?? 0),
                    'status'      => (int)($d['status'] ?? 1),
                    'created_by'  => $adminId, // 表已添加该列
                ]);
                $rowId = (int)$row->id;
            });

            // 新类目一般暂无 SKU 绑定，无需刷新
            return $this->jsonResponse('创建成功', 200, 'success', ['category_id' => $rowId]);
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            Log::error('category.create: '.$msg);
            if (stripos($msg, 'uk_category_name') !== false || stripos($msg, 'Duplicate') !== false) {
                return $this->jsonResponse('同一父类目下已存在同名类目', 409, 'error');
            }
            return $this->jsonResponse('创建失败', 500, 'error');
        }
    }

    /** 更新类目（仅更新传入字段；时间空串 => NULL；更新后刷新绑定 SKU 的 ES） */
    public function update()
    {
        try {
            [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $id = (int)($d['id'] ?? 0);
            if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

            /** @var CategoryModel|null $row */
            $row = CategoryModel::where('id', $id)->where('merchant_id', $merchantId)->find();
            if (!$row) return $this->jsonResponse('类目不存在', 404, 'error');

            $sets = [];
            if (array_key_exists('name', $d))       $sets['name'] = trim((string)$d['name']);
            if (array_key_exists('parent_id', $d))  $sets['parent_id'] = (int)$d['parent_id'];
            if (array_key_exists('sort', $d))       $sets['sort'] = (int)$d['sort'];
            if (array_key_exists('status', $d))     $sets['status'] = (int)$d['status'];

            if (array_key_exists('valid_from', $d)) {
                $vf = trim((string)$d['valid_from']);
                $sets['valid_from'] = ($vf === '') ? null : date('Y-m-d H:i:s', strtotime($vf));
            }
            if (array_key_exists('valid_to', $d)) {
                $vt = trim((string)$d['valid_to']);
                $sets['valid_to'] = ($vt === '') ? null : date('Y-m-d H:i:s', strtotime($vt));
            }
            if (isset($sets['valid_from'], $sets['valid_to']) && $sets['valid_from'] && $sets['valid_to'] && strtotime((string)$sets['valid_from']) >= strtotime((string)$sets['valid_to'])) {
                return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
            }
            if (!$sets) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

            // 若设置了 parent_id：禁止自指；并校验父类目存在且同商户
            if (array_key_exists('parent_id', $sets)) {
                $newPid = (int)$sets['parent_id'];
                if ($newPid === $id) return $this->jsonResponse('父类目不能选择自身', 422, 'error');
                if ($newPid > 0) {
                    $p = CategoryModel::where('merchant_id', $merchantId)->where('id', $newPid)->field('id,parent_id')->find();
                    if (!$p) return $this->jsonResponse('父类目不存在', 404, 'error');
                    // 防止形成环：newPid 不能是自己的任意子孙
                    $walker = $newPid;
                    while ($walker > 0) {
                        if ($walker === $id) return $this->jsonResponse('不可将类目移动到其子类目下', 422, 'error');
                        $walker = (int)(CategoryModel::where('merchant_id', $merchantId)->where('id', $walker)->value('parent_id') ?? 0);
                        if ($walker === 0) break;
                    }
                }
            }

            // 若 name 或 parent_id 改动，做“同父级重名”校验
            $newName   = array_key_exists('name', $sets)      ? (string)$sets['name']      : (string)$row->getAttr('name');
            $newParent = array_key_exists('parent_id', $sets) ? (int)$sets['parent_id']    : (int)$row->getAttr('parent_id');
            if ($newName !== (string)$row->getAttr('name') || $newParent !== (int)$row->getAttr('parent_id')) {
                $dup = CategoryModel::where('merchant_id', $merchantId)
                    ->where('parent_id', $newParent)
                    ->where('name', $newName)
                    ->where('id', '<>', $id)
                    ->count();
                if ($dup > 0) return $this->jsonResponse('同一父类目下已存在同名类目', 409, 'error');
            }

            Db::transaction(function() use ($row, $sets, $adminId) {
                $sets['updated_by'] = $adminId; // 表已添加该列
                $row->save($sets);
            });

            // 刷新该类目下 SKU 的 ES（内部已容错）
            $this->esRefreshByCategorySafe((int)$row->getAttr('merchant_id'), (int)$row->getAttr('id'));
            return $this->jsonResponse('OK', 200, '更新成功');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            Log::error('category.update: '.$msg);
            if (stripos($msg, 'uk_category_name') !== false || stripos($msg, 'Duplicate') !== false) {
                return $this->jsonResponse('同一父类目下已存在同名类目', 409, 'error');
            }
            return $this->jsonResponse('更新失败', 500, 'error');
        }
    }

    /** 删除类目（若被 SKU 使用则禁止） */
    public function delete()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $id = (int)(Request::post('id') ?? 0);
            if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

            // 子类目检查
            $child = CategoryModel::where('merchant_id', $merchantId)->where('parent_id', $id)->count();
            if ($child > 0) return $this->jsonResponse('存在子类目，无法删除', 400, 'error');

            // SKU 绑定检查（ORM）
            $skuCnt = SkuCategoryModel::where('merchant_id', $merchantId)->where('category_id', $id)->count();
            if ($skuCnt > 0) return $this->jsonResponse('仍有关联 SKU，无法删除', 400, 'error');

            Db::transaction(function() use ($merchantId, $id) {
                CategoryModel::where('id', $id)->where('merchant_id', $merchantId)->delete();
            });
            return $this->jsonResponse('OK', 200, '删除成功');
        } catch (\Throwable $e) {
            Log::error('category.delete: '.$e->getMessage(), ['id' => Request::post('id')]);
            return $this->jsonResponse('删除失败', 500, 'error');
        }
    }

    /** 类目列表 */
    public function list()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $page      = max(1, (int)Request::param('page', 1));
            $pageSize  = max(1, min(200, (int)Request::param('page_size', 50)));
            $statusRaw = Request::param('status', null);
            $parentId  = (int)Request::param('parent_id', -1);
            $keyword   = trim((string)Request::param('keyword', ''));
            $treeMode  = (int)Request::param('tree', 0) === 1;
            $validNow  = (int)Request::param('valid_now', 0) === 1;
            $all       = (int)Request::param('all', 0) === 1;

            $orderBy  = (string)Request::param('order_by', 'sort');
            $orderDir = strtolower((string)Request::param('order_dir', 'asc'));
            $orderWhitelist = ['id','name','parent_id','sort','status','valid_from','valid_to','created_at','updated_at'];
            if (!in_array($orderBy, $orderWhitelist, true)) $orderBy = 'sort';
            if (!in_array($orderDir, ['asc','desc'], true)) $orderDir = 'asc';

            $q = CategoryModel::where('merchant_id', $merchantId);

            if ($statusRaw !== null && $statusRaw !== '') $q->where('status', (int)$statusRaw);
            if ($parentId >= 0) $q->where('parent_id', $parentId);
            if ($keyword !== '') {
                $kw = '%' . addcslashes($keyword, '%_') . '%';
                $q->whereLike('name', $kw);
            }
            if ($validNow) {
                $now = date('Y-m-d H:i:s');
                $q->where(function($w) use ($now){ $w->whereNull('valid_from')->whereOr('valid_from','<=',$now); });
                $q->where(function($w) use ($now){ $w->whereNull('valid_to')->whereOr('valid_to','>',$now); });
            }

            $q->field('id,merchant_id,name,parent_id,valid_from,valid_to,sort,status,created_at,updated_at')
                ->order($orderBy, $orderDir)->order('id','asc');

            if ($treeMode) {
                $rows = $q->select()->toArray();
                $map = [];
                foreach ($rows as $r) { $r['children']=[]; $map[$r['id']]=$r; }
                $tree = [];
                foreach ($map as $cid => $r) {
                    $pid = (int)$r['parent_id'];
                    if ($pid > 0 && isset($map[$pid])) $map[$pid]['children'][] = &$map[$cid];
                    else $tree[] = &$map[$cid];
                }
                return $this->jsonResponse('OK', 200, 'success', ['items'=>$tree, 'total'=>count($rows)]);
            }

            if ($all) {
                $rows = $q->select()->toArray();
                return $this->jsonResponse('OK', 200, 'success', [
                    'items'=>$rows,'total'=>count($rows),'page'=>1,'page_size'=>count($rows),
                ]);
            }

            $list = $q->paginate(['list_rows'=>$pageSize, 'page'=>$page])->toArray();
            return $this->jsonResponse('OK', 200, 'success', [
                'items'=>$list['data'] ?? [], 'total'=>$list['total'] ?? 0,
                'page'=>$list['current_page'] ?? $page, 'page_size'=>$list['per_page'] ?? $pageSize,
            ]);
        } catch (\Throwable $e) {
            Log::error('category.list: '.$e->getMessage());
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }
}
