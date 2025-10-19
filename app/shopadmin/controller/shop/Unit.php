<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use think\facade\Request;
use think\facade\Validate;
use think\facade\Log;
use think\facade\Db;

use app\shopadmin\model\Unit as UnitModel;
use app\shopadmin\model\Spu as SpuModel;
use app\shopadmin\model\Sku as SkuModel;

/**
 * 单位管理（写 + 查）
 * - 被 SPU 或 SKU 使用则不可删除
 * - 增删改后刷新受影响 SKU 的 ES（SKU.unit_id 或 其 SPU.unit_id 命中）
 */
class Unit extends BaseShopAdmin
{
    /** 新增单位 */
    public function create()
    {
        [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

        $data = Request::post();
        $rules = [
            'code'   => 'require|max:32',
            'name'   => 'require|max:32',
            'symbol' => 'max:16',
            'status' => 'in:0,1',
        ];
        $v = Validate::rule($rules);
        if (!$v->check($data)) return $this->jsonResponse($v->getError(), 422, 'error');

        $code   = trim((string)$data['code']);
        $name   = trim((string)$data['name']);
        $symbol = trim((string)($data['symbol'] ?? ''));
        $status = (int)($data['status'] ?? 1);

        $exists = UnitModel::where('merchant_id', $merchantId)->where('code', $code)->count();
        if ($exists > 0) return $this->jsonResponse('单位编码已存在', 409, 'error');

        try {
            $m = new UnitModel();
            $m->save([
                'merchant_id' => $merchantId,
                'code'        => $code,
                'name'        => $name,
                'symbol'      => $symbol !== '' ? $symbol : null,
                'status'      => $status,
            ]);

            // 新建无需刷新（无 SKU 引用）
            return $this->jsonResponse('创建成功', 200, 'success', ['unit_id' => (int)$m->id]);
        } catch (\Throwable $e) {
            Log::error('unit.create: '.$e->getMessage());
            if (stripos($e->getMessage(), 'uk_unit_code_merchant') !== false) {
                return $this->jsonResponse('单位编码已存在', 409, 'error');
            }
            return $this->jsonResponse('创建失败', 500, 'error');
        }
    }

    /** 更新单位（仅变更传入字段；若修改 code 需保持唯一；更新后刷新 ES） */
    public function update()
    {
        [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

        $data = Request::post();
        $id = (int)($data['id'] ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

        /** @var UnitModel|null $m */
        $m = UnitModel::where('id', $id)->where('merchant_id', $merchantId)->find();
        if (!$m) return $this->jsonResponse('单位不存在', 404, 'error');

        $changed = [];
        if (array_key_exists('code', $data))   $changed['code']   = trim((string)$data['code']);
        if (array_key_exists('name', $data))   $changed['name']   = trim((string)$data['name']);
        if (array_key_exists('symbol', $data)) $changed['symbol'] = trim((string)$data['symbol']) !== '' ? trim((string)$data['symbol']) : null;
        if (array_key_exists('status', $data)) $changed['status'] = (int)$data['status'];
        if (!$changed) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

        if (isset($changed['code']) && $changed['code'] !== $m->getAttr('code')) {
            $exists = UnitModel::where('merchant_id', $merchantId)
                ->where('code', $changed['code'])
                ->where('id', '<>', $id)
                ->count();
            if ($exists > 0) return $this->jsonResponse('单位编码已存在', 409, 'error');
        }

        try {
            $m->save($changed);

            // 刷新受影响 SKU 的 ES
            $this->esRefreshByUnitSafe($merchantId, $id);

            return $this->jsonResponse('更新成功', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('unit.update: '.$e->getMessage());
            if (stripos($e->getMessage(), 'uk_unit_code_merchant') !== false) {
                return $this->jsonResponse('单位编码已存在', 409, 'error');
            }
            return $this->jsonResponse('更新失败', 500, 'error');
        }
    }

    /** 删除单位（若被 SPU/SKU 使用则禁止） */
    public function delete()
    {
        [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

        $spuCnt = SpuModel::where('merchant_id', $merchantId)->where('unit_id', $id)->count();
        if ($spuCnt > 0) return $this->jsonResponse('该单位已被 SPU 使用，无法删除', 400, 'error');

        $skuCnt = SkuModel::where('merchant_id', $merchantId)->where('unit_id', $id)->count();
        if ($skuCnt > 0) return $this->jsonResponse('该单位已被 SKU 使用，无法删除', 400, 'error');

        try {
            UnitModel::where('id', $id)->where('merchant_id', $merchantId)->delete();
            return $this->jsonResponse('删除成功', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('unit.delete: '.$e->getMessage());
            return $this->jsonResponse('删除失败', 500, 'error');
        }
    }

    /** 列表 */
    public function list()
    {
        [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

        $page      = max(1, (int)Request::param('page', 1));
        $pageSize  = max(1, min(200, (int)Request::param('page_size', 50)));
        $statusRaw = Request::param('status', null);
        $keyword   = trim((string)Request::param('keyword', ''));
        $all       = (int)Request::param('all', 0) === 1;

        $idsParam  = Request::param('ids', []);
        if (is_string($idsParam) && $idsParam !== '') {
            $ids = array_values(array_filter(array_map('intval', explode(',', $idsParam)), fn($x)=>$x>0));
        } elseif (is_array($idsParam)) {
            $ids = array_values(array_filter(array_map('intval', $idsParam), fn($x)=>$x>0));
        } else { $ids = []; }

        $orderBy  = (string)Request::param('order_by', 'id');
        $orderDir = strtolower((string)Request::param('order_dir', 'asc'));
        $orderWhitelist = ['id','code','name','symbol','status','created_at','updated_at'];
        if (!in_array($orderBy, $orderWhitelist, true)) $orderBy = 'id';
        if (!in_array($orderDir, ['asc','desc'], true)) $orderDir = 'asc';

        $q = UnitModel::where('merchant_id', $merchantId);

        if ($ids) $q->whereIn('id', $ids);
        if ($statusRaw !== null && $statusRaw !== '') $q->where('status', (int)$statusRaw);
        if ($keyword !== '') {
            $kw = '%' . addcslashes($keyword, '%_') . '%';
            $q->where(function($w) use ($kw){
                $w->whereLike('code', $kw)->whereOr('name', 'like', $kw)->whereOr('symbol', 'like', $kw);
            });
        }

        $q->field('id,merchant_id,code,name,symbol,status,created_at,updated_at')
            ->order($orderBy, $orderDir)->order('id','asc');

        if ($all) {
            $rows = $q->select()->toArray();
            return $this->jsonResponse('OK', 200, 'success', [
                'items'=>$rows,'total'=>count($rows),'page'=>1,'page_size'=>count($rows),
            ]);
        }

        $list = $q->paginate(['list_rows'=>$pageSize,'page'=>$page])->toArray();
        return $this->jsonResponse('OK', 200, 'success', [
            'items'=>$list['data'] ?? [], 'total'=>$list['total'] ?? 0,
            'page'=>$list['current_page'] ?? $page, 'page_size'=>$list['per_page'] ?? $pageSize,
        ]);
    }
}
