<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use app\shopadmin\model\StockBatch as StockBatchModel;
use app\shopadmin\model\Spu as SpuModel;
use think\facade\Request;
use think\facade\Validate;
use think\facade\Db;
use think\facade\Log;

/**
 * 库存批次（SPU 维度）增改删查
 * - FEFO: expiration_at 越早越先出（查询时可按此排序）
 * - 每次变更会刷新该 SPU 下所有 SKU 的 ES（has_stock 依赖 SPU 总库存）
 * - 批次号：若未传入，按日期自动生成（如 251010-261010）
 * - 写操作包裹事务；失败回滚
 * - 列表返回附带 spu_name
 */
class Stock extends BaseShopAdmin
{
    /** 新增批次（入库） */
    public function create()
    {
        try {
            [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $rules = [
                'spu_id'          => 'require|integer',
                'batch_no'        => 'max:64',
                'production_date' => 'date',
                'expiration_at'   => 'date',
                'purchase_price'  => 'require|float|>=:0',
                'quantity_base'   => 'require|integer|>=:0',
                'reserved_base'   => 'integer|>=:0',
                'status'          => 'in:0,1',
            ];
            $v = Validate::rule($rules);
            if (!$v->check($d)) return $this->jsonResponse($v->getError(), 422, 'error');

            /** 校验 SPU 存在 */
            $spu = SpuModel::where('merchant_id', $merchantId)->where('id', (int)$d['spu_id'])->field('id')->find();
            if (!$spu) return $this->jsonResponse('SPU 不存在', 404, 'error');

            /** 生产/到期逻辑校验 */
            if (!empty($d['production_date']) && !empty($d['expiration_at'])) {
                if (strtotime($d['production_date']) >= strtotime($d['expiration_at'])) {
                    return $this->jsonResponse('到期日期必须晚于生产日期', 422, 'error');
                }
            }

            /** 解析日期（入库保存为 Y-m-d 或 NULL） */
            $prodDate = (isset($d['production_date']) && $d['production_date']!=='') ? date('Y-m-d', strtotime($d['production_date'])) : null;
            $expDate  = (isset($d['expiration_at'])   && $d['expiration_at']  !=='') ? date('Y-m-d', strtotime($d['expiration_at']))   : null;

            /** 批次号生成（未传时） */
            $batchNo = trim((string)($d['batch_no'] ?? ''));
            if ($batchNo === '') {
                $p = $prodDate ? strtotime($prodDate) : null;
                $e = $expDate  ? strtotime($expDate)  : null;
                if ($p && $e) {
                    $batchNo = date('ymd', $p) . '-' . date('ymd', $e);     // 例如 251010-261010
                } elseif ($p) {
                    $batchNo = date('ymd', $p);                              // 仅生产日
                } elseif ($e) {
                    $batchNo = date('ymd', $e);                              // 仅到期日
                } else {
                    $batchNo = date('ymd');                                  // 今日
                }
            }

            $batchId = 0;
            Db::transaction(function() use ($merchantId, $adminId, $d, $prodDate, $expDate, $batchNo, &$batchId) {
                $m = new StockBatchModel();
                $m->save([
                    'merchant_id'     => $merchantId,
                    'spu_id'          => (int)$d['spu_id'],
                    'batch_no'        => $batchNo,
                    'production_date' => $prodDate,
                    'expiration_at'   => $expDate,
                    'purchase_price'  => (float)$d['purchase_price'],
                    'quantity_base'   => (int)$d['quantity_base'],
                    'reserved_base'   => (int)($d['reserved_base'] ?? 0),
                    'status'          => (int)($d['status'] ?? 1),
                    'created_by'      => $adminId,   // 表已添加
                ]);
                $batchId = (int)$m->id;
            });

            // 刷新 ES（该 SPU 下全部 SKU）——外部调用不影响事务
            $this->esRefreshBySpuSafe($merchantId, (int)$d['spu_id']);

            return $this->jsonResponse('入库成功', 200, 'success', ['batch_id' => $batchId]);
        } catch (\Throwable $e) {
            Log::error('stock.create: '.$e->getMessage(), ['post' => Request::post()]);
            return $this->jsonResponse('入库失败', 500, 'error');
        }
    }

    /** 修改批次 */
    public function update()
    {
        try {
            [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $id = (int)($d['id'] ?? 0);
            if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

            /** @var StockBatchModel|null $m */
            $m = StockBatchModel::where('merchant_id', $merchantId)->where('id', $id)->find();
            if (!$m) return $this->jsonResponse('批次不存在', 404, 'error');

            $sets = [];
            if (array_key_exists('batch_no', $d))        $sets['batch_no'] = trim((string)$d['batch_no']);
            if (array_key_exists('purchase_price', $d))  $sets['purchase_price'] = (float)$d['purchase_price'];
            if (array_key_exists('quantity_base', $d))   $sets['quantity_base']  = (int)$d['quantity_base'];
            if (array_key_exists('reserved_base', $d))   $sets['reserved_base']  = (int)$d['reserved_base'];
            if (array_key_exists('status', $d))          $sets['status']         = (int)$d['status'];
            if (array_key_exists('production_date', $d)) $sets['production_date']= ($d['production_date']===''?null:date('Y-m-d', strtotime($d['production_date'])));
            if (array_key_exists('expiration_at', $d))   $sets['expiration_at']  = ($d['expiration_at']===''  ?null:date('Y-m-d', strtotime($d['expiration_at'])));

            // 简单约束：不可出现负数
            if (isset($sets['quantity_base']) && $sets['quantity_base'] < 0) return $this->jsonResponse('quantity_base 不能为负', 422, 'error');
            if (isset($sets['reserved_base']) && $sets['reserved_base'] < 0) return $this->jsonResponse('reserved_base 不能为负', 422, 'error');

            // 如果未传 batch_no 但有日期改动，且当前 batch_no 为空，可自动生成
            if ((!isset($d['batch_no']) || trim((string)$d['batch_no']) === '') && (array_key_exists('production_date', $d) || array_key_exists('expiration_at', $d))) {
                $p = array_key_exists('production_date', $sets) ? $sets['production_date'] : $m->getAttr('production_date');
                $e = array_key_exists('expiration_at',   $sets) ? $sets['expiration_at']   : $m->getAttr('expiration_at');
                if (!$m->getAttr('batch_no')) {
                    if ($p && $e)        $sets['batch_no'] = date('ymd', strtotime((string)$p)) . '-' . date('ymd', strtotime((string)$e));
                    elseif ($p)          $sets['batch_no'] = date('ymd', strtotime((string)$p));
                    elseif ($e)          $sets['batch_no'] = date('ymd', strtotime((string)$e));
                }
            }

            Db::transaction(function() use ($m, $sets, $adminId) {
                if ($sets) {
                    $sets['updated_by'] = $adminId; // 表已添加
                    $m->save($sets);
                }
            });

            // 刷新 ES
            $this->esRefreshBySpuSafe($merchantId, (int)$m->getAttr('spu_id'));

            return $this->jsonResponse('OK', 200, '更新成功');
        } catch (\Throwable $e) {
            Log::error('stock.update: '.$e->getMessage(), ['post' => Request::post()]);
            return $this->jsonResponse('更新失败', 500, 'error');
        }
    }

    /** 删除批次（必要时可加校验：不可删除有可用/预留数量的批次） */
    public function delete()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $id = (int)(Request::post('id') ?? 0);
            if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

            /** @var StockBatchModel|null $m */
            $m = StockBatchModel::where('merchant_id', $merchantId)->where('id', $id)->find();
            if (!$m) return $this->jsonResponse('批次不存在', 404, 'error');

            $spuId = (int)$m->getAttr('spu_id');

            Db::transaction(function() use ($merchantId, $id) {
                StockBatchModel::where('merchant_id', $merchantId)->where('id', $id)->delete();
            });

            // 刷新 ES
            $this->esRefreshBySpuSafe($merchantId, $spuId);

            return $this->jsonResponse('OK', 200, '删除成功');
        } catch (\Throwable $e) {
            Log::error('stock.delete: '.$e->getMessage(), ['post' => Request::post()]);
            return $this->jsonResponse('删除失败', 500, 'error');
        }
    }

    /** 批次列表 / 查询 */
    public function list()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $page     = max(1, (int)Request::param('page', 1));
            $pageSize = max(1, min(200, (int)Request::param('page_size', 50)));

            $spuId    = (int)Request::param('spu_id', 0);
            $status   = Request::param('status', null);
            $orderBy  = (string)Request::param('order_by', 'expiration_at'); // FEFO 优先
            $orderDir = strtolower((string)Request::param('order_dir', 'asc'));
            $whitelist= ['id','spu_id','batch_no','production_date','expiration_at','purchase_price','quantity_base','reserved_base','status','created_at','updated_at'];
            if (!in_array($orderBy, $whitelist, true)) $orderBy = 'expiration_at';
            if (!in_array($orderDir, ['asc','desc'], true)) $orderDir = 'asc';

            $q = StockBatchModel::alias('b')->where('b.merchant_id', $merchantId);
            if ($spuId > 0) $q->where('b.spu_id', $spuId);
            if ($status !== null && $status !== '') $q->where('b.status', (int)$status);

            // 关联 SPU 名称
            $q->leftJoin('shop_spu p', 'p.id = b.spu_id');

            $q->field([
                'b.id','b.merchant_id','b.spu_id','b.batch_no','b.production_date','b.expiration_at',
                'b.purchase_price','b.quantity_base','b.reserved_base','b.status','b.created_at','b.updated_at',
                'p.name AS spu_name',
            ])->orderRaw('b.expiration_at IS NULL ASC')
                ->order('b.'.$orderBy, $orderDir)
                ->order('b.id','asc');

            $list = $q->paginate(['list_rows'=>$pageSize,'page'=>$page])->toArray();

            // 附带可用量（基础单位）：quantity_base - reserved_base
            $items = $list['data'] ?? [];
            foreach ($items as &$it) {
                $it['available_base'] = max(0, (int)$it['quantity_base'] - (int)$it['reserved_base']);
            } unset($it);

            return $this->jsonResponse('OK', 200, 'success', [
                'items'     => $items,
                'total'     => $list['total'] ?? 0,
                'page'      => $list['current_page'] ?? $page,
                'page_size' => $list['per_page'] ?? $pageSize,
            ]);
        } catch (\Throwable $e) {
            Log::error('stock.list: '.$e->getMessage(), ['params' => Request::param()]);
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }
}
