<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use think\facade\Request;
use think\facade\Validate;
use think\facade\Db;
use think\facade\Log;
use app\shopadmin\model\Spu as SpuModel;
use app\shopadmin\model\Sku as SkuModel;
use app\shopadmin\model\Category as CategoryModel;
use app\shopadmin\model\Tag as TagModel;

class Sku extends BaseShopAdmin
{
    /** 创建 SKU（必须绑定 SPU；条码商户内唯一；必须有图片；绑定分类/标签可选） */
    public function create()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $rules = [
                'spu_id'              => 'require|integer',
                'barcode'             => 'require|max:64',
                'name'                => 'max:128',
                'unit_id'             => 'integer',
                'sale_price'          => 'require|float|>=:0',
                'market_price'        => 'float|>=:0',
                'conversion_base_qty' => 'integer|>=:1',
                'status'              => 'in:0,1',
                'sort'                => 'integer',
                'category_ids'        => 'array',
                'tag_ids'             => 'array',
            ];
            $v = Validate::rule($rules);
            if (!$v->check($d)) return $this->jsonResponse($v->getError(), 422, 'error');

            // 必须绑定的 SPU
            $spu = SpuModel::where('merchant_id',$merchantId)->where('id',(int)$d['spu_id'])->field('id')->find();
            if (!$spu) return $this->jsonResponse('SPU 不存在', 404, 'error');

            // 条码商户内唯一
            $dup = SkuModel::where('merchant_id',$merchantId)->where('barcode',trim((string)$d['barcode']))->count();
            if ($dup>0) return $this->jsonResponse('条码已存在', 409, 'error');

            // 必须有图片
            $image = Request::file('image');
            if (!$image) return $this->jsonResponse('必须上传图片', 422, 'error');
            if (!$this->verifyImageFile($image)) {
                return $this->jsonResponse('图片格式异常或损坏', 422, 'error');
            }
            [$imgRel, $imgUrl] = $this->saveUploadPublic($image, 'sku'); // 存库仍保存 URL（兼容现有返回），删除时做 URL->rel 映射

            $skuId = 0;
            Db::transaction(function() use ($merchantId,$d,$imgUrl,&$skuId){
                $m = new SkuModel();
                $m->save([
                    'merchant_id'         => $merchantId,
                    'spu_id'              => (int)$d['spu_id'],
                    'barcode'             => trim((string)$d['barcode']),
                    'name'                => isset($d['name']) ? trim((string)$d['name']) : null,
                    'unit_id'             => isset($d['unit_id']) ? (int)$d['unit_id'] : null,
                    'image'               => $imgUrl, // 存 URL
                    'sale_price'          => (float)$d['sale_price'],
                    'market_price'        => ($d['market_price']===''||$d['market_price']===null) ? null : (float)$d['market_price'],
                    'conversion_base_qty' => (int)($d['conversion_base_qty'] ?? 1),
                    'status'              => (int)($d['status'] ?? 1),
                    'sort'                => (int)($d['sort'] ?? 0),
                ]);
                $skuId = (int)$m->id;

                // 绑定分类（SKU 维度）
                if (!empty($d['category_ids'])) {
                    $rows=[]; foreach ((array)$d['category_ids'] as $cid) {
                        $rows[]=['merchant_id'=>$merchantId,'sku_id'=>$skuId,'category_id'=>(int)$cid];
                    }
                    if ($rows) Db::table('shop_sku_category')->insertAll($rows);
                }
                // 绑定标签（SKU 维度）
                if (!empty($d['tag_ids'])) {
                    $rows=[]; foreach ((array)$d['tag_ids'] as $tid) {
                        $rows[]=['merchant_id'=>$merchantId,'sku_id'=>$skuId,'tag_id'=>(int)$tid];
                    }
                    if ($rows) Db::table('shop_sku_tag')->insertAll($rows);
                }
            });

            // 刷新 ES
            $this->esIndexSkuSafe($merchantId, $skuId);

            return $this->jsonResponse('创建成功', 200, 'success', ['sku_id'=>$skuId]);
        } catch (\Throwable $e) {
            Log::error('sku.create: '.$e->getMessage(), ['post'=>Request::post()]);
            return $this->jsonResponse('创建失败', 500, 'error');
        }
    }


    /** 更新 SKU（可改基础字段、分类/标签覆盖式同步） */
    public function update()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $id = (int)($d['id'] ?? 0);
            if ($id<=0) return $this->jsonResponse('缺少 id', 422, 'error');

            /** @var SkuModel|null $m */
            $m = SkuModel::where('id',$id)->where('merchant_id',$merchantId)->find();
            if (!$m) return $this->jsonResponse('SKU 不存在', 404, 'error');

            if (isset($d['barcode'])) {
                $dup = SkuModel::where('merchant_id',$merchantId)->where('barcode',trim((string)$d['barcode']))->where('id','<>',$id)->count();
                if ($dup>0) return $this->jsonResponse('条码已存在', 409, 'error');
            }

            $sets=[];
            foreach (['barcode','name'] as $f) if (array_key_exists($f,$d)) $sets[$f]=trim((string)$d[$f]);
            foreach (['unit_id','status','sort','conversion_base_qty'] as $f) if (array_key_exists($f,$d)) $sets[$f]=(int)$d[$f];
            foreach (['sale_price','market_price'] as $f) if (array_key_exists($f,$d)) $sets[$f]=($d[$f]===''?null:(float)$d[$f]);

            // 检查是否上传了新图片
            $image = Request::file('image');
            $toDeleteRel = null;
            if ($image) {
                if (!$this->verifyImageFile($image)) {
                    return $this->jsonResponse('图片格式异常或损坏', 422, 'error');
                }
                // 旧图删（URL -> rel）
                if (!empty($m->image)) {
                    $toDeleteRel = $this->guessRelFromUrlOrRel((string)$m->image);
                }
                // 保存新图片
                [$rel, $url] = $this->saveUploadPublic($image, 'sku');
                $sets['image'] = $url; // 仍保存 URL
            }

            Db::transaction(function() use ($merchantId,$id,$d,$sets){
                if ($sets) {
                    SkuModel::where('id',$id)->where('merchant_id',$merchantId)->save($sets);
                }

                // 覆盖分类
                if (array_key_exists('category_ids',$d)) {
                    Db::table('shop_sku_category')->where('merchant_id',$merchantId)->where('sku_id',$id)->delete();
                    $rows=[]; foreach ((array)$d['category_ids'] as $cid) $rows[]=['merchant_id'=>$merchantId,'sku_id'=>$id,'category_id'=>(int)$cid];
                    if ($rows) Db::table('shop_sku_category')->insertAll($rows);
                }
                // 覆盖标签
                if (array_key_exists('tag_ids',$d)) {
                    Db::table('shop_sku_tag')->where('merchant_id',$merchantId)->where('sku_id',$id)->delete();
                    $rows=[]; foreach ((array)$d['tag_ids'] as $tid) $rows[]=['merchant_id'=>$merchantId,'sku_id'=>$id,'tag_id'=>(int)$tid];
                    if ($rows) Db::table('shop_sku_tag')->insertAll($rows);
                }

                // 事务里不做物理删除，避免回滚不一致
            });

            // 事务成功后再删旧图
            if ($toDeleteRel) {
                $this->deleteRelIfExists($toDeleteRel);
            }

            // 刷新 ES
            $this->esIndexSkuSafe($merchantId, $id);

            return $this->jsonResponse('更新成功');
        } catch (\Throwable $e) {
            Log::error('sku.update: '.$e->getMessage(), ['post'=>Request::post()]);
            return $this->jsonResponse('更新失败', 500, 'error');
        }
    }


    /** 删除 SKU（直接删除；随后删 ES 文档） */
    public function delete()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;
            $id = (int)(Request::post('id') ?? 0);
            if ($id<=0) return $this->jsonResponse('缺少 id', 422, 'error');

            // 先取出图片路径（URL/REL），事务成功后删
            $sku = SkuModel::where('id',$id)->where('merchant_id',$merchantId)->field('image')->find();
            $imgRel = $sku ? $this->guessRelFromUrlOrRel((string)$sku->getAttr('image')) : null;

            Db::transaction(function() use ($merchantId,$id){
                Db::table('shop_sku_category')->where('merchant_id',$merchantId)->where('sku_id',$id)->delete();
                Db::table('shop_sku_tag')->where('merchant_id',$merchantId)->where('sku_id',$id)->delete();
                SkuModel::where('id',$id)->where('merchant_id',$merchantId)->delete();
            });

            // ES 删除
            $this->esDeleteSkuSafe($merchantId, $id);

            // 物理删图
            if ($imgRel) $this->deleteRelIfExists($imgRel);

            return $this->jsonResponse('删除成功');
        } catch (\Throwable $e) {
            Log::error('sku.delete: '.$e->getMessage(), ['post'=>Request::post()]);
            return $this->jsonResponse('删除失败', 500, 'error');
        }
    }

    /** 一键重建 ES（支持条件） */
    public function esRebuildAll()
    {
        // 若未开启ES，直接跳过并给出友好结果
        if (!\app\common\Helper::getValue('app.start_es')) {
            return $this->jsonResponse('ES 未开启，已跳过重建', 200, 'success', [
                'skipped' => true, 'reason' => 'config app.start_es = false'
            ]);
        }

        if (!$this->client) {
            return $this->jsonResponse('Elasticsearch 客户端未初始化', 500, 'error');
        }

        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $spuId     = (int)(Request::param('spu_id') ?? 0);
            $statusRaw = Request::param('status', null);
            $fromId    = (int)(Request::param('from_id') ?? 0);
            $chunkSize = max(1, min(1000, (int)(Request::param('chunk_size') ?? 300)));

            // 确保索引存在（不存在时创建）
            try {
                $this->ensureEsSkuIndex($merchantId);
            } catch (\Throwable $e) {
                return $this->jsonResponse('创建索引失败：'.$e->getMessage(), 500, 'error');
            }

            $q = SkuModel::where('merchant_id',$merchantId);
            if ($spuId>0) $q->where('spu_id',$spuId);
            if ($fromId>0) $q->where('id','>',$fromId);
            if ($statusRaw!==null && $statusRaw!=='') $q->where('status',(int)$statusRaw);

            $total = (int)$q->count();
            if ($total===0) {
                return $this->jsonResponse('没有可同步的 SKU', 200, 'success', [
                    'total'=>0,'success'=>0,'failed'=>0,'batches'=>0,'took'=>0,'failedIds'=>[]
                ]);
            }

            $success=0;$failed=0;$batches=0;$failedIds=[];$firstError=null;$t0=microtime(true);
            $index = 'sku_'.$merchantId;

            // 1) 清空旧数据：索引不存在或本来就空时，不视为错误
            try {
                $this->client->deleteByQuery([
                    'index' => $index,
                    'body'  => [ 'query' => [ 'match_all' => new \stdClass() ] ],
                    'conflicts' => 'proceed',
                    'ignore_unavailable' => true,
                    'refresh' => true,
                ]);
            } catch (\Throwable $e) {
                $msg = strtolower($e->getMessage());
                if (strpos($msg, 'index_not_found') === false && strpos($msg, 'index_not_found_exception') === false) {
                    return $this->jsonResponse('清空ES数据失败：' . $e->getMessage(), 500, 'error');
                }
            }

            $q->order('id','asc')->chunk($chunkSize, function($skus) use ($merchantId,$index,&$success,&$failed,&$batches,&$failedIds,&$firstError){
                $body=[];$idMap=[];
                foreach ($skus as $row) {
                    $sid=(int)$row->id;
                    try {
                        $doc = $this->buildEsSkuDoc($merchantId,$sid);
                        if (!$doc) { $failed++; $failedIds[]=$sid; continue; }
                        $body[]=['index'=>['_index'=>$index,'_id'=>(string)$sid]];
                        $body[]=$doc; $idMap[]=$sid;
                    } catch (\Throwable $e) {
                        $failed++; $failedIds[]=$sid; if($firstError===null) $firstError='build doc error: '.$e->getMessage();
                    }
                }
                if (!$body) return;

                try {
                    $resp = $this->client->bulk(['body'=>$body,'refresh'=>true]);
                    $items = $resp['items'] ?? [];
                    if ($items) {
                        foreach ($items as $i=>$it) {
                            $act = $it['index'] ?? null;
                            if ($act && isset($act['error'])) {
                                $failed++; $failedIds[]=$idMap[$i] ?? 0;
                                if($firstError===null) $firstError=json_encode($act['error'],JSON_UNESCAPED_UNICODE);
                            } else { $success++; }
                        }
                    } else {
                        $success += (int)(count($body)/2);
                    }
                } catch (\Throwable $e) {
                    $batchSize=(int)(count($body)/2);
                    $failed+=$batchSize; foreach ($idMap as $sid){$failedIds[]=$sid;}
                    if($firstError===null) $firstError='bulk commit error: '.$e->getMessage();
                }
                $batches++;
            });

            $took=(int)round((microtime(true)-$t0)*1000);
            $failedIds=array_values(array_unique(array_filter($failedIds)));
            if(count($failedIds)>100) $failedIds=array_slice($failedIds,0,100);

            return $this->jsonResponse('ES 批量同步完成', 200, 'success', compact('total','success','failed','batches','took','failedIds','firstError'));
        } catch (\Throwable $e) {
            Log::error('sku.esRebuildAll: '.$e->getMessage(), ['params'=>Request::param()]);
            return $this->jsonResponse('重建失败', 500, 'error');
        }
    }


    /**
     * SKU 列表（含按 SPU 聚合库存：available/has_stock）
     * - 加上主产品名称：spu_name
     * - 附带 categories / tags（SKU 维度绑定；标签含生效期判断）
     * - fields_desc：返回关键字段中文说明，便于前端对接
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
            $spuId     = (int)Request::param('spu_id', 0);
            $statusRaw = Request::param('status', null);
            $keyword   = trim((string)Request::param('keyword', '')); // 命中 name / barcode
            $orderBy   = (string)Request::param('order_by', 'sort');
            $orderDir  = strtolower((string)Request::param('order_dir', 'asc'));
            $withStock = (int)Request::param('with_stock', 1) === 1;   // 是否附带库存聚合

            $orderWhitelist = ['id','spu_id','name','barcode','sort','sale_price','created_at','updated_at','status'];
            if (!in_array($orderBy, $orderWhitelist, true)) $orderBy = 'sort';
            if (!in_array($orderDir, ['asc','desc'], true)) $orderDir = 'asc';

            // —— SPU 维度库存批次聚合子查询（只统计启用批次 status=1）
            $aggSql = Db::table('shop_stock_batch')->alias('b')
                ->field('b.spu_id, SUM(b.quantity_base) AS qty_sum, SUM(b.reserved_base) AS res_sum')
                ->where('b.merchant_id', $merchantId)
                ->where('b.status', 1)
                ->group('b.spu_id')
                ->buildSql();

            $q = SkuModel::alias('s')->where('s.merchant_id', $merchantId);

            if ($id > 0) $q->where('s.id', $id);
            if ($idsRaw !== '') {
                $ids = array_values(array_filter(array_map('intval', explode(',', $idsRaw))));
                if ($ids) $q->whereIn('s.id', $ids);
            }
            if ($spuId > 0) $q->where('s.spu_id', $spuId);
            if ($statusRaw !== null && $statusRaw !== '') $q->where('s.status', (int)$statusRaw);
            if ($keyword !== '') {
                $kw = '%' . addcslashes($keyword, '%_') . '%';
                $q->where(function($w) use ($kw){
                    $w->whereLike('s.name', $kw)->whereOr('s.barcode','like',$kw);
                });
            }

            // join 上聚合库存
            if ($withStock) {
                $q->leftJoin([$aggSql => 'st'], 'st.spu_id = s.spu_id');
            }

            // 关联主产品名称
            $q->leftJoin('shop_spu p', 'p.id = s.spu_id AND p.merchant_id = s.merchant_id');

            // 选择字段
            $fields = [
                's.id','s.merchant_id','s.spu_id','s.barcode','s.name','s.unit_id','s.image',
                's.sale_price','s.market_price','s.conversion_base_qty','s.sort','s.status',
                's.created_at','s.updated_at',
                'p.name AS spu_name', // 主产品名称
            ];

            if ($withStock) {
                // available_base = GREATEST(qty_sum - res_sum, 0)
                $totalBase     = 'IFNULL(st.qty_sum,0) AS stock_total_base';
                $reservedBase  = 'IFNULL(st.res_sum,0) AS stock_reserved_base';
                $availableBase = 'GREATEST(IFNULL(st.qty_sum,0)-IFNULL(st.res_sum,0),0) AS stock_available_base';
                $availableUnit = 'FLOOR(GREATEST(IFNULL(st.qty_sum,0)-IFNULL(st.res_sum,0),0)/IFNULL(s.conversion_base_qty,1)) AS stock_available';
                $hasStock      = 'CASE WHEN FLOOR(GREATEST(IFNULL(st.qty_sum,0)-IFNULL(st.res_sum,0),0)/IFNULL(s.conversion_base_qty,1)) > 0 THEN 1 ELSE 0 END AS has_stock';
                $fields = array_merge($fields, [Db::raw($totalBase), Db::raw($reservedBase), Db::raw($availableBase), Db::raw($availableUnit), Db::raw($hasStock)]);
            }

            $q->field($fields)->order('s.'.$orderBy, $orderDir)->order('s.id', 'asc');

            if ($all) {
                $items = $q->select()->toArray();
                $total = count($items);
                $pageNow = 1; $pageSz = count($items);
            } else {
                $list  = $q->paginate(['list_rows'=>$pageSize,'page'=>$page])->toArray();
                $items = $list['data'] ?? [];
                $total = $list['total'] ?? 0;
                $pageNow = $list['current_page'] ?? $page;
                $pageSz  = $list['per_page'] ?? $pageSize;
            }

            // ===== 补充：批量附带分类 & 标签（ORM + 一次性映射） =====
            $skuIds = array_values(array_filter(array_map(fn($r)=> (int)($r['id'] ?? 0), $items)));
            if ($skuIds) {
                // 分类（只取启用的分类）
                $catRows = CategoryModel::alias('c')
                    ->join('shop_sku_category sc','sc.category_id = c.id')
                    ->where('sc.merchant_id',$merchantId)
                    ->whereIn('sc.sku_id',$skuIds)
                    ->where('c.status',1)
                    ->field('sc.sku_id AS sku_id, c.id, c.name')
                    ->select()->toArray();
                $catMap = [];
                foreach ($catRows as $r) {
                    $sid = (int)$r['sku_id'];
                    $catMap[$sid][] = ['id'=>(int)$r['id'], 'name'=>(string)$r['name']];
                }

                // 标签（只取启用且生效期命中的标签）
                $now = date('Y-m-d H:i:s');
                $tagRows = TagModel::alias('t')
                    ->join('shop_sku_tag st','st.tag_id = t.id')
                    ->where('st.merchant_id',$merchantId)
                    ->whereIn('st.sku_id',$skuIds)
                    ->where('t.status',1)
                    ->where(function($w) use ($now){ $w->whereNull('t.valid_from')->whereOr('t.valid_from','<=',$now); })
                    ->where(function($w) use ($now){ $w->whereNull('t.valid_to')->whereOr('t.valid_to','>',$now); })
                    ->field('st.sku_id AS sku_id, t.id, t.name')
                    ->select()->toArray();
                $tagMap = [];
                foreach ($tagRows as $r) {
                    $sid = (int)$r['sku_id'];
                    $tagMap[$sid][] = ['id'=>(int)$r['id'], 'name'=>(string)$r['name']];
                }

                // 回填
                foreach ($items as &$it) {
                    $sid = (int)($it['id'] ?? 0);
                    $it['categories'] = $catMap[$sid] ?? [];
                    $it['tags']       = $tagMap[$sid] ?? [];
                }
                unset($it);
            }

            // 中文字段说明（仅一次返回，前端可忽略）
            $fieldsDesc = [
                'spu_name'             => '主产品名称（SPU 名称）',
                'categories'           => 'SKU 绑定的分类数组（仅启用分类），元素包含 {id, name}',
                'tags'                 => 'SKU 绑定的标签数组（仅启用且在生效期内），元素包含 {id, name}',
                'conversion_base_qty'  => '换算比：1个“销售单位”包含多少“基础单位”（例：1箱=12瓶，则为12）',
                'stock_total_base'     => 'SPU 维度启用批次的“基础单位”库存总数（合计）',
                'stock_reserved_base'  => 'SPU 维度启用批次的“基础单位”预留数量（合计）',
                'stock_available_base' => '可售“基础单位”= stock_total_base - stock_reserved_base（不小于0）',
                'stock_available'      => '可售“销售单位”= floor(stock_available_base / conversion_base_qty)',
                'has_stock'            => '是否有库存（可售销售单位 > 0 则为 1，否则为 0）',
            ];

            return $this->jsonResponse('OK', 200, 'success', [
                'items'       => $items,
                'total'       => $total,
                'page'        => $pageNow,
                'page_size'   => $pageSz,
                'fields_desc' => $fieldsDesc,
            ]);
        } catch (\Throwable $e) {
            Log::error('sku.list: '.$e->getMessage(), ['params'=>Request::param()]);
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }

    /**
     * 按 SPU 查看（包含 SPU 汇总库存 + 该 SPU 的 SKU 列表及各自可售量）
     * - items 内也附带 spu_name，便于直接展示
     * - 附带 fields_desc 中文说明
     */
    public function bySpu()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $spuId = (int)Request::param('spu_id', 0);
            if ($spuId <= 0) return $this->jsonResponse('缺少 spu_id', 422, 'error');

            // 取 SPU 名称
            $spuName = (string)SpuModel::where('merchant_id',$merchantId)->where('id',$spuId)->value('name') ?? '';

            // 1) 取 SPU 汇总库存（启用批次）
            $agg = Db::table('shop_stock_batch')->alias('b')
                ->where('b.merchant_id', $merchantId)
                ->where('b.spu_id', $spuId)
                ->where('b.status', 1)
                ->fieldRaw('COALESCE(SUM(b.quantity_base),0) AS stock_total_base,
                            COALESCE(SUM(b.reserved_base),0) AS stock_reserved_base')
                ->find();

            $totalBase    = (int)($agg['stock_total_base'] ?? 0);
            $reservedBase = (int)($agg['stock_reserved_base'] ?? 0);
            $availableBase= max($totalBase - $reservedBase, 0);

            // 2) 取该 SPU 下 SKU 列表，并映射出各自可售量（基于 conversion_base_qty）
            $skus = SkuModel::where('merchant_id',$merchantId)->where('spu_id',$spuId)
                ->field('id,merchant_id,spu_id,barcode,name,unit_id,image,sale_price,market_price,conversion_base_qty,sort,status,created_at,updated_at')
                ->order('sort','asc')->order('id','asc')->select()->toArray();

            foreach ($skus as &$r) {
                $conv = max(1, (int)($r['conversion_base_qty'] ?? 1));
                $r['stock_available']       = (int)floor($availableBase / $conv);
                $r['stock_available_base']  = $availableBase; // 同 SPU 下每个 SKU 的底层可用基数一致
                $r['has_stock']             = $r['stock_available'] > 0 ? 1 : 0;
                $r['spu_name']              = $spuName; // 补充主产品名称
            } unset($r);

            $fieldsDesc = [
                'spu.name'               => '主产品名称（SPU 名称）',
                'conversion_base_qty'    => '换算比：1个“销售单位”包含多少“基础单位”（例：1箱=12瓶，则为12）',
                'stock_total_base'       => 'SPU 维度启用批次的“基础单位”库存总数（合计）',
                'stock_reserved_base'    => 'SPU 维度启用批次的“基础单位”预留数量（合计）',
                'stock_available_base'   => '可售“基础单位”= stock_total_base - stock_reserved_base（不小于0）',
                'stock_available'        => '可售“销售单位”= floor(stock_available_base / conversion_base_qty)',
                'has_stock'              => '是否有库存（可售销售单位 > 0 则为 1，否则为 0）',
            ];

            return $this->jsonResponse('OK', 200, 'success', [
                'spu' => [
                    'id'                   => $spuId,
                    'name'                 => $spuName,
                    'stock_total_base'     => $totalBase,
                    'stock_reserved_base'  => $reservedBase,
                    'stock_available_base' => $availableBase,
                ],
                'items'       => $skus,
                'fields_desc' => $fieldsDesc,
            ]);
        } catch (\Throwable $e) {
            Log::error('sku.bySpu: '.$e->getMessage(), ['params'=>Request::param()]);
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }

    /* ================== 内部工具 ================== */

    /** 传入 URL 或 rel，尽力反推出 public 磁盘下的相对路径 */
    protected function guessRelFromUrlOrRel(?string $val): ?string
    {
        if (!$val) return null;
        $val = trim($val);
        if ($val === '') return null;

        // 已经看起来像 rel
        if (strpos($val, '://') === false) {
            // 可能是 '/storage/sku/xxx.jpg' 或 'sku/xxx.jpg'
            if (strpos($val, '/storage/') === 0) {
                return ltrim(substr($val, strlen('/storage/')), '/');
            }
            return ltrim($val,'/');
        }

        // 全量 URL：截取 /storage/ 之后的部分
        $p = strpos($val, '/storage/');
        if ($p !== false) {
            return ltrim(substr($val, $p + strlen('/storage/')), '/');
        }
        return null;
    }
}
