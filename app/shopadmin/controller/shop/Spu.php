<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use think\facade\Request;
use think\facade\Validate;
use think\facade\Db;
use think\facade\Log;
use app\shopadmin\model\Spu as SpuModel;
use app\shopadmin\model\Sku as SkuModel;
use app\shopadmin\model\StockBatch as StockBatchModel;

/**
 * SPU（父级产品，库存主体）
 * - 创建：只接收 gallery_files[] 文件；gallery 存 [{id, url, rel, uploaded_at}, ...]
 * - 更新：支持 gallery_remove_ids（字符串数组或 JSON 字符串）+ gallery_files[]（新增图片）
 *   * 未传 gallery_remove_ids 且未传新文件 => 不改动图片
 * - 删除：事务成功后再物理删除图片文件
 * - 创建 SPU 时必建一条库存批次（数量可为 0）；batch_no 未传则按日期自动生成，如 251010-261010
 * - 仅当该 SPU 下存在 SKU 时触发 ES 刷新（以 SKU 为主）
 */
class Spu extends BaseShopAdmin
{
    /** 新建 SPU（多图上传：gallery_files；库存批次可选） */
    public function create()
    {
        [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

        // 多文件：Apifox 里“允许多文件”的 form-data 字段
        $galleryFiles = Request::file('gallery_files');
        if ($galleryFiles && !is_array($galleryFiles)) $galleryFiles = [$galleryFiles];

        $d = Request::post();
        $rules = [
            'name'            => 'require|max:128', // 去掉全局 unique 规则，改为下面按商户校验
            'unit_id'         => 'require|integer',
            'status'          => 'in:0,1',
            'sort'            => 'integer',

            // 批次字段（全部可选）
            'batch_no'        => 'max:64',
            'production_date' => 'date',
            'expiration_at'   => 'date',
            'purchase_price'  => 'float|>=:0',
            'quantity_base'   => 'integer|>=:0',
            'reserved_base'   => 'integer|>=:0',
            'batch_status'    => 'in:0,1',
        ];
        $v = Validate::rule($rules);
        if (!$v->check($d)) return $this->jsonResponse($v->getError(), 422, 'error');

        // 按商户重名校验（如需全局唯一保留你的唯一索引/规则）
        $exists = SpuModel::where('merchant_id', $merchantId)->where('name', trim((string)$d['name']))->count();
        if ($exists > 0) {
            return $this->jsonResponse('同商户下商品名称已存在', 409, 'error');
        }

        // 校验并保存文件
        $savedRel = [];
        $galleryItems = [];
        if (is_array($galleryFiles)) {
            foreach ($galleryFiles as $gf) {
                if (!$this->verifyImageFile($gf)) {
                    return $this->jsonResponse('轮播图格式异常或损坏', 422, 'error');
                }
            }
            foreach ($galleryFiles as $gf) {
                [$rel, $url] = $this->saveUploadPublic($gf, 'spu/gallery');
                $savedRel[] = $rel;
                $galleryItems[] = $this->makeGalleryItem($rel, $url);
            }
        }

        try {
            $spuId = 0;
            Db::transaction(function() use ($merchantId,$adminId,$d,$galleryItems,&$spuId){
                // 1) 写 SPU（gallery 已是数组，模型字段为 json，会自动序列化）
                $m = new SpuModel();
                $m->save([
                    'merchant_id' => $merchantId,
                    'name'        => trim((string)$d['name']),
                    'unit_id'     => (int)$d['unit_id'],
                    'status'      => (int)($d['status'] ?? 1),
                    'sort'        => (int)($d['sort'] ?? 0),
                    'gallery'     => $galleryItems ?: [],
                    'created_by'  => $adminId, // 若表无此列可去掉
                ]);
                $spuId = (int)$m->id;

                // 2) 创建一条库存批次（数量可为 0；满足“创建时就有库存容器”的需求）
                $purchase = isset($d['purchase_price']) ? (float)$d['purchase_price'] : 0.00;
                $qtyBase  = isset($d['quantity_base'])   ? (int)$d['quantity_base']   : 0;
                $resBase  = isset($d['reserved_base'])   ? (int)$d['reserved_base']   : 0;
                $bStatus  = isset($d['batch_status'])    ? (int)$d['batch_status']    : 1;

                if ($resBase > $qtyBase) {
                    throw new \RuntimeException('首批次的 reserved_base 不可大于 quantity_base');
                }

                $prodDate = isset($d['production_date']) && $d['production_date']!=='' ? date('Y-m-d', strtotime($d['production_date'])) : null;
                $expDate  = isset($d['expiration_at'])   && $d['expiration_at']  !=='' ? date('Y-m-d', strtotime($d['expiration_at']))   : null;

                // 批次号：未传则自动生成
                $batchNo = trim((string)($d['batch_no'] ?? ''));
                if ($batchNo === '') {
                    $p = $prodDate ? strtotime($prodDate) : null;
                    $e = $expDate  ? strtotime($expDate)  : null;
                    if ($p && $e)      $batchNo = date('ymd',$p).'-'.date('ymd',$e);
                    elseif ($p)        $batchNo = date('ymd',$p);
                    elseif ($e)        $batchNo = date('ymd',$e);
                    else               $batchNo = date('ymd');
                }

                $batch = new StockBatchModel();
                $batch->save([
                    'merchant_id'     => $merchantId,
                    'spu_id'          => $spuId,
                    'batch_no'        => $batchNo,
                    'production_date' => $prodDate,
                    'expiration_at'   => $expDate,
                    'purchase_price'  => $purchase,
                    'quantity_base'   => $qtyBase,
                    'reserved_base'   => $resBase,
                    'status'          => $bStatus,
                    'created_by'      => $adminId, // 新增列
                ]);
            });

            // 如果该 SPU 已经有 SKU（通常新建时没有），就刷新 ES
            $this->esRefreshBySpuSafe($merchantId, $spuId);

            return $this->jsonResponse('创建成功', 200, 'success', ['spu_id' => $spuId]);
        } catch (\Throwable $e) {
            // 失败回滚：清理已上传文件
            foreach ($savedRel as $rel) { $this->deleteRelIfExists($rel); }
            Log::error('spu.create: '.$e->getMessage(), ['post'=>Request::post()]);
            // 唯一索引冲突（如果保留了全局唯一索引）
            if (stripos($e->getMessage(), 'idx_spu_name') !== false) {
                return $this->jsonResponse('商品名称已存在', 409, 'error');
            }
            return $this->jsonResponse('创建失败', 500, 'error');
        }
    }

    /** 更新 SPU：仅改传入字段；图片支持增量添加 + 精确删除；不传新图则保持不变 */
    public function update()
    {
        [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;
        $d = Request::post();
        $spuId = (int)($d['id'] ?? 0);
        if ($spuId<=0) return $this->jsonResponse('缺少 id', 422, 'error');

        /** @var SpuModel|null $m */
        $m = SpuModel::where('id',$spuId)->where('merchant_id',$merchantId)->find();
        if (!$m) return $this->jsonResponse('SPU 不存在', 404, 'error');

        // 如有改名，按商户维度做重名校验
        if (array_key_exists('name',$d)) {
            $newName = trim((string)$d['name']);
            if ($newName !== '' && $newName !== (string)$m->getAttr('name')) {
                $dup = SpuModel::where('merchant_id',$merchantId)->where('name',$newName)->where('id','<>',$spuId)->count();
                if ($dup > 0) return $this->jsonResponse('同商户下商品名称已存在', 409, 'error');
            }
        }

        // 新增图片（可选）
        $galleryFiles = Request::file('gallery_files');
        if ($galleryFiles && !is_array($galleryFiles)) $galleryFiles = [$galleryFiles];

        // 删除图片 id（可选，支持 ["xx","yy"] 或 JSON 字符串）
        $removeIds = $d['gallery_remove_ids'] ?? [];
        if (is_string($removeIds) && $removeIds!=='') {
            $tmp = json_decode($removeIds, true);
            if (is_array($tmp)) $removeIds = $tmp;
        }
        if (!is_array($removeIds)) $removeIds = [];
        $removeIds = array_values(array_filter(array_map('strval', $removeIds)));

        $sets = [];
        if (array_key_exists('name',$d))    $sets['name']    = trim((string)$d['name']);
        if (array_key_exists('unit_id',$d)) $sets['unit_id'] = (int)$d['unit_id'];
        if (array_key_exists('status',$d))  $sets['status']  = (int)$d['status'];
        if (array_key_exists('sort',$d))    $sets['sort']    = (int)$d['sort'];

        // 当前 gallery（模型 json 类型：已是数组）
        $cur = $m->getAttr('gallery') ?: [];
        if (is_string($cur)) { // 兼容历史数据是字符串的情况
            $cur = $cur !== '' ? (json_decode($cur, true) ?: []) : [];
        }

        $toDeleteRels = [];   // 延迟到 DB 保存成功后再删
        $galleryChanged = false;

        // 1) 删除指定 id 的图片（先标记要删，保存成功再删物理文件）
        if ($removeIds) {
            $keep = [];
            foreach ($cur as $it) {
                $gid = (string)($it['id'] ?? '');
                if (in_array($gid, $removeIds, true)) {
                    if (!empty($it['rel'])) { $toDeleteRels[] = (string)$it['rel']; }
                    $galleryChanged = true;
                } else {
                    $keep[] = $it;
                }
            }
            $cur = $keep;
        }

        // 2) 新增图片
        $savedRel = [];
        if (is_array($galleryFiles) && !empty($galleryFiles)) {
            foreach ($galleryFiles as $gf) {
                if (!$this->verifyImageFile($gf)) {
                    return $this->jsonResponse('轮播图格式异常或损坏', 422, 'error');
                }
            }
            foreach ($galleryFiles as $gf) {
                [$rel, $url] = $this->saveUploadPublic($gf, 'spu/gallery');
                $savedRel[] = $rel;
                $cur[] = $this->makeGalleryItem($rel, $url);
            }
            $galleryChanged = true;
        }

        if ($galleryChanged) {
            $sets['gallery'] = $cur; // 直接给数组，模型会自动 JSON 化
        }

        if (!$sets) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

        try {
            $sets['updated_by'] = $adminId; // 若表无此列可去掉
            Db::transaction(function() use ($m, $sets){
                $m->save($sets);
            });

            // 事务成功后再删物理文件
            foreach ($toDeleteRels as $rel) { $this->deleteRelIfExists($rel); }

            // 存在 SKU 则刷新其 ES
            $this->esRefreshBySpuSafe($merchantId, $spuId);

            return $this->jsonResponse('更新成功', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('spu.update: '.$e->getMessage(), ['post'=>Request::post()]);
            // 新增图片已写磁盘，不做回滚，避免误删
            return $this->jsonResponse('更新失败', 500, 'error');
        }
    }

    /** 删除 SPU：无 SKU 时允许；并清理所有已存图片文件（事务成功后再删） */
    public function delete()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;
            $id = (int)(Request::post('id') ?? 0);
            if ($id<=0) return $this->jsonResponse('缺少 id', 422, 'error');

            $skuCnt = SkuModel::where('merchant_id',$merchantId)->where('spu_id',$id)->count();
            if ($skuCnt>0) return $this->jsonResponse('存在 SKU，不可删除', 400, 'error');

            // 先收集要删的图片 rel（注意：模型 json 类型，读出来多半是数组）
            $relsToDelete = [];
            $spu = SpuModel::where('id',$id)->where('merchant_id',$merchantId)->field('gallery')->find();
            if ($spu) {
                $gal = $spu->getAttr('gallery') ?: [];
                if (is_string($gal)) { $gal = $gal !== '' ? (json_decode($gal, true) ?: []) : []; }
                foreach ($gal as $it) {
                    if (!empty($it['rel'])) $relsToDelete[] = (string)$it['rel'];
                }
            }

            Db::transaction(function() use ($merchantId,$id){
                // 外键 ON DELETE CASCADE，会同时清理该 SPU 的库存批次
                SpuModel::where('id',$id)->where('merchant_id',$merchantId)->delete();
            });

            // DB 成功后删物理文件
            foreach ($relsToDelete as $rel) { $this->deleteRelIfExists($rel); }

            return $this->jsonResponse('删除成功', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('spu.delete: '.$e->getMessage(), ['post'=>Request::post()]);
            return $this->jsonResponse('删除失败', 500, 'error');
        }
    }

    /**
     * SPU 列表（查询 + 展示合一；不传筛选即查全部；all=1 返回全量）
     * @query page,page_size,all,id,ids,status,keyword,with_skus,with_gallery,order_by,order_dir
     * - 仅命中 name 关键字；SPU 不再含副标题/主图/价格/类目/标签
     */
    public function list()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $page      = max(1, (int)Request::param('page', 1));
            $pageSize  = max(1, min(200, (int)Request::param('page_size', 20)));
            $all       = (int)Request::param('all', 0) === 1;

            $id        = (int)Request::param('id', 0);
            $idsRaw    = trim((string)Request::param('ids', ''));
            $statusRaw = Request::param('status', null);
            $keyword   = trim((string)Request::param('keyword', ''));

            $withSkus    = (int)Request::param('with_skus', 1) === 1;
            $withGallery = (int)Request::param('with_gallery', 0) === 1;

            $orderBy   = (string)Request::param('order_by', 'sort');
            $orderDir  = strtolower((string)Request::param('order_dir', 'asc'));
            $orderWhitelist = ['id','name','sort','created_at','updated_at','status'];
            if (!in_array($orderBy, $orderWhitelist, true)) $orderBy = 'sort';
            if (!in_array($orderDir, ['asc','desc'], true)) $orderDir = 'asc';

            $q = SpuModel::where('merchant_id', $merchantId);

            if ($id > 0) $q->where('id', $id);
            if ($idsRaw !== '') {
                $ids = array_values(array_filter(array_map('intval', explode(',', $idsRaw))));
                if ($ids) $q->whereIn('id', $ids);
            }
            if ($statusRaw !== null && $statusRaw !== '') $q->where('status', (int)$statusRaw);
            if ($keyword !== '') {
                $kw = '%' . addcslashes($keyword, '%_') . '%';
                $q->whereLike('name', $kw);
            }

            $q->field('id,merchant_id,unit_id,name,gallery,status,sort,created_at,updated_at');

            if ($withSkus) {
                $q->with([
                    'skus' => function($w) use ($merchantId){
                        $w->where('merchant_id', $merchantId)
                            ->field('id,merchant_id,spu_id,barcode,name,unit_id,image,sale_price,market_price,conversion_base_qty,sort,status,created_at,updated_at')
                            ->order('sort','asc')->order('id','asc');
                    }
                ]);
            }

            $q->order($orderBy, $orderDir)->order('id','asc');

            if ($all) {
                $arr = $q->select()->toArray();
                $total = count($arr);
            } else {
                $list = $q->paginate(['list_rows' => $pageSize, 'page' => $page])->toArray();
                $arr  = $list['data'] ?? [];
                $total= $list['total'] ?? 0;
            }

            if ($withGallery && $arr) {
                foreach ($arr as &$r) {
                    // 兼容：如果是字符串则解码，否则保持数组
                    if (isset($r['gallery']) && !is_array($r['gallery'])) {
                        $r['gallery'] = $r['gallery'] !== '' ? (json_decode((string)$r['gallery'], true) ?: []) : [];
                    } elseif (!isset($r['gallery'])) {
                        $r['gallery'] = [];
                    }
                }
                unset($r);
            }

            return $this->jsonResponse('OK', 200, 'success', [
                'items'     => $arr,
                'total'     => $total,
                'page'      => $all ? 1 : ($list['current_page'] ?? $page),
                'page_size' => $all ? count($arr) : ($list['per_page'] ?? $pageSize),
            ]);
        } catch (\Throwable $e) {
            Log::error('spu.list: '.$e->getMessage(), ['params'=>Request::param()]);
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }

    /** 根据 SPU 获取其 SKU 列表（支持 all=1 返回全量） */
    public function skuListBySpu()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $spuId = (int)Request::param('spu_id', 0);
            if ($spuId <= 0) return $this->jsonResponse('缺少 spu_id', 422, 'error');

            $statusRaw = Request::param('status', null);
            $keyword   = trim((string)Request::param('keyword', ''));
            $page      = max(1, (int)Request::param('page', 1));
            $pageSize  = max(1, min(200, (int)Request::param('page_size', 50)));
            $all       = (int)Request::param('all', 0) === 1;

            $q = SkuModel::where('merchant_id', $merchantId)->where('spu_id', $spuId);

            if ($statusRaw !== null && $statusRaw !== '') $q->where('status', (int)$statusRaw);
            if ($keyword !== '') {
                $kw = '%' . addcslashes($keyword, '%_') . '%';
                $q->where(function($w) use ($kw){
                    $w->whereLike('name', $kw)->whereOr('barcode','like',$kw);
                });
            }

            $q->field('id,merchant_id,spu_id,barcode,name,unit_id,image,sale_price,market_price,conversion_base_qty,sort,status,created_at,updated_at')
                ->order('sort','asc')->order('id','asc');

            if ($all) {
                $items = $q->select()->toArray();
                $total = count($items);
            } else {
                $list = $q->paginate(['list_rows' => $pageSize, 'page' => $page])->toArray();
                $items= $list['data'] ?? [];
                $total= $list['total'] ?? 0;
            }

            return $this->jsonResponse('OK', 200, 'success', [
                'items'     => $items,
                'total'     => $total,
                'page'      => $all ? 1 : ($list['current_page'] ?? $page),
                'page_size' => $all ? count($items) : ($list['per_page'] ?? $pageSize),
            ]);
        } catch (\Throwable $e) {
            Log::error('spu.skuListBySpu: '.$e->getMessage(), ['params'=>Request::param()]);
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }

    /* ================== 内部工具 ================== */

    /** 生成一条 gallery 项（带可追溯 id 与相对路径） */
    protected function makeGalleryItem(string $rel, string $url): array
    {
        $id = bin2hex(random_bytes(8)); // 16位可读ID
        return [
            'id'          => $id,
            'url'         => $url,
            'rel'         => $rel,
            'uploaded_at' => date('Y-m-d H:i:s'),
        ];
    }
}
