<?php
declare (strict_types = 1);

namespace app;

use think\App;
use think\exception\ValidateException;
use think\facade\Db;
use think\Validate;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use think\facade\Log;
use Elastic\Elasticsearch\ClientBuilder;

// ==== 额外依赖：用于 DB 回退检索商品 ====
use app\shopadmin\model\Sku as SkuModel;

/**
 * 控制器基础类（已整合商品检索/详情的 ES 优先 + DB 回退能力）
 *
 * 约定：
 * - ES 开关：\app\common\Helper::getValue('app.start_es') （true 时优先走 ES，失败自动回退 DB）
 * - ES 索引：sku_{merchantId}（文档结构与 Admin ES 同步逻辑一致）
 * - 库存口径（DB 回退）：按批次表 shop_stock_batch 对 SPU 聚合，available_base = SUM(quantity_base) - SUM(reserved_base)
 * - 不涉及任何“快照列”（严格按用户要求：不要快照功能）
 */
abstract class BaseController
{
    /** @var \think\Request */
    protected $request;

    /** @var \think\App */
    protected $app;

    /** @var bool */
    protected $batchValidate = false;

    /** @var array */
    protected $middleware = [];

    /** @var \Elastic\Elasticsearch\Client|null */
    protected $client = null;

    /**
     * 构造方法
     */
    public function __construct(App $app)
    {
        // ========== 初始化 Elasticsearch 客户端（保持向后兼容） ==========
        try {
            $hostStr = (string)(\app\common\Helper::getValue('elasticsearch.hosts') ?? 'http://127.0.0.1:9200');
            $hosts   = [$hostStr];
            $user    = (string)(\app\common\Helper::getValue('elasticsearch.auth.username') ?? '');
            $pass    = (string)(\app\common\Helper::getValue('elasticsearch.auth.password') ?? '');
            $verify  = (bool)(\app\common\Helper::getValue('elasticsearch.ssl_verify') ?? false);

            $builder = ClientBuilder::create()->setHosts($hosts);
            if ($user !== '' || $pass !== '') {
                $builder->setBasicAuthentication($user, $pass);
            }
            $this->client = $builder->setSSLVerification($verify)->build();
        } catch (\Throwable $e) {
            // 若连接失败，后续会自动走 DB 回退
            Log::warning('ES client init failed: '.$e->getMessage());
            $this->client = null;
        }

        $this->app     = $app;
        $this->request = $this->app->request;

        $this->initialize();
    }

    // ================= 通用工具 =================

    /** 规范化时间字段：空串->NULL；合法->标准化到秒；非法返回 '__INVALID__' */
    protected function normalizeDT($v)
    {
        if (!isset($v)) return null;
        $v = trim((string)$v);
        if ($v === '') return null;
        $ts = strtotime($v);
        if ($ts === false) return '__INVALID__';
        return date('Y-m-d H:i:s', $ts);
    }

    // 初始化（留空占位）
    protected function initialize() {}

    /**
     * 验证数据
     * @param array $data
     * @param string|array $validate
     * @param array $message
     * @param bool $batch
     * @return array|string|true
     * @throws ValidateException
     */
    protected function validate(array $data, $validate, array $message = [], bool $batch = false)
    {
        if (is_array($validate)) {
            $v = new Validate();
            $v->rule($validate);
        } else {
            if (strpos($validate, '.')) {
                [$validate, $scene] = explode('.', $validate);
            }
            $class = false !== strpos($validate, '\\') ? $validate : $this->app->parseClass('validate', $validate);
            $v     = new $class();
            if (!empty($scene)) {
                $v->scene($scene);
            }
        }

        $v->message($message);
        if ($batch || $this->batchValidate) $v->batch(true);
        return $v->failException(true)->check($data);
    }

    /**
     * 统一 JSON 响应
     */
    protected function jsonResponse(string $msg, int $code = 200, string $status = 'success', array $data = [])
    {
        return json([ 'msg'=>$msg, 'code'=>$code, 'status'=>$status, 'data'=>$data ]);
    }

    // =================== 登录/权限（原有保持不变） ===================

    protected function checkAdminRole($request, $name)
    {
        $authHeader = $request->header('Authorization');
        $token = substr((string)$authHeader, 7);
        $jwtCfg = \app\common\Helper::getValue('jwt') ?? [];

        try {
            $secret = (string)(\app\common\Helper::getValue('jwt_secret') ?? ($jwtCfg['secret'] ?? 'PLEASE_CHANGE_ME'));
            $decoded = JWT::decode($token, new Key($secret, 'HS256'));
            $userId = $decoded->user_id ?? null;
            if (!$userId) return $this->jsonResponse('无效的用户凭据', 401, 'error');
        } catch (\Exception $e) {
            return $this->jsonResponse('Token 验证失败: ' . $e->getMessage(), 401, 'error');
        }

        $shop_id = $request->post('shop_id');
        if (!$shop_id) return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        session('shop_id', $shop_id);

        $isAdmin = Db::name('admin_users')->alias('au')
                ->join('admin_role_permissions arp', 'au.id = arp.admin_id')
                ->join('admin_permissions ap', 'ap.id = arp.permission_id')
                ->where('au.user_id', $userId)
                ->where('ap.name', $name)
                ->where('arp.shop_id', $shop_id)
                ->where('status', 1)
                ->count() > 0;

        if (!$isAdmin) return $this->jsonResponse('权限不足，仅管理员可以执行此操作', 403, 'error');
        return true;
    }

    // =================== ES 可用性 & 索引管理 ===================

    /** ES 功能是否开启（配置开关） */
    protected function isEsEnabled(): bool
    {
        return (bool)\app\common\Helper::getValue('app.start_es');
    }

    /** 运行时检测 ES 是否可用（不会抛异常） */
    protected function isElasticsearchAvailable(): bool
    {
        if (!$this->client) return false;
        try { $this->client->info(); return true; }
        catch (\Throwable $e) { return false; }
    }

    /** 确保 sku_{merchantId} 索引存在（仅在需要时调用） */
    protected function ensureEsSkuIndex(int $merchantId): void
    {
        $index = 'sku_' . $merchantId;
        if (!$this->isElasticsearchAvailable()) throw new \Exception("Elasticsearch 服务不可用");
        if ($this->indexExists($index)) return;
        $this->createSkuIndex($index);
    }

    protected function indexExists(string $index): bool
    {
        try {
            $resp = $this->client->indices()->exists(['index' => $index]);
            // 一些 SDK 版本返回 Response 对象，一些直接返回数组/布尔，这里尽量兼容
            if (is_object($resp) && method_exists($resp, 'getStatusCode')) return $resp->getStatusCode() === 200;
            if (is_array($resp) && isset($resp['status'])) return ((int)$resp['status']) === 200;
            // 某些版本直接返回 bool
            if (is_bool($resp)) return $resp;
            return false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    protected function createSkuIndex(string $index): void
    {
        $mapping = [
            'settings' => [
                'number_of_shards'   => 1,
                'number_of_replicas' => 0,
                'refresh_interval'   => '1s',
            ],
            'mappings' => [
                'dynamic' => true,
                'properties' => [
                    'merchant_id' => ['type' => 'integer'],
                    'status'      => ['type' => 'byte'],
                    'available'   => ['type' => 'integer'],
                    'created_at'  => ['type' => 'date', 'format' => 'strict_date_optional_time||epoch_millis'],
                    'updated_at'  => ['type' => 'date', 'format' => 'strict_date_optional_time||epoch_millis'],
                    'spu' => [
                        'type' => 'object',
                        'properties' => [
                            'id'           => ['type' => 'integer'],
                            'name'         => ['type' => 'text', 'analyzer' => 'ik_max_word', 'fields' => ['keyword' => ['type' => 'keyword']]],
                            'subtitle'     => ['type' => 'text', 'analyzer' => 'ik_max_word'],
                            'unit_id'      => ['type' => 'integer'],
                            'sale_price'   => ['type' => 'scaled_float', 'scaling_factor' => 100],
                            'market_price' => ['type' => 'scaled_float', 'scaling_factor' => 100],
                        ]
                    ],
                    'sku' => [
                        'type' => 'object',
                        'properties' => [
                            'id'       => ['type' => 'integer'],
                            'sku_code' => ['type' => 'keyword'],
                            'barcode'  => ['type' => 'keyword'],
                            'name'     => ['type' => 'text', 'analyzer' => 'ik_max_word', 'fields' => ['keyword' => ['type' => 'keyword']]],
                            'unit_id'  => ['type' => 'integer'],
                            'status'   => ['type' => 'byte'],
                            'sort'     => ['type' => 'integer'],
                            'sale_price'=>['type'=>'scaled_float','scaling_factor'=>100],
                        ]
                    ],
                    'categories' => [
                        'type' => 'object',
                        'properties' => [
                            'id'   => ['type' => 'integer'],
                            'name' => ['type' => 'text', 'analyzer' => 'ik_max_word', 'fields' => ['keyword' => ['type' => 'keyword']]],
                        ]
                    ],
                    'tags' => [
                        'type' => 'object',
                        'properties' => [
                            'id'   => ['type' => 'integer'],
                            'name' => ['type' => 'text', 'analyzer' => 'ik_max_word', 'fields' => ['keyword' => ['type' => 'keyword']]],
                        ]
                    ]
                ]
            ]
        ];

        try {
            $this->client->indices()->create(['index' => $index, 'body' => $mapping]);
            $this->client->cluster()->health(['index' => $index, 'wait_for_status' => 'yellow', 'timeout' => '30s']);
        } catch (\Throwable $e) {
            throw new \Exception("创建索引 {$index} 失败: " . $e->getMessage());
        }
    }

    // =================== 商品能力（ES 优先 + DB 回退） ===================

    /**
     * 统一的 SKU 检索入口（供各 Controller 复用）
     * @param array $opts 入参：
     *  - merchant_id(int) 必填
     *  - page(int)=1, per_page(int)=20
     *  - keyword(string), category_id(int), tag_id(int)
     *  - min_price(float|null), max_price(float|null)
     * @return array { total, current_page, per_page, items[] } —— items 结构与 ES 文档一致
     */
    protected function skuSearch(array $opts): array
    {
        $merchantId = (int)($opts['merchant_id'] ?? 0);
        if ($merchantId <= 0) throw new \InvalidArgumentException('merchant_id 必填');

        if ($this->isEsEnabled() && $this->isElasticsearchAvailable()) {
            try { return $this->esSkuSearch($opts); }
            catch (\Throwable $e) { Log::error('skuSearch.es_failed: '.$e->getMessage(), ['opts'=>$opts]); }
        }
        return $this->dbSkuSearch($opts);
    }

    /**
     * 统一的 SKU 详情入口（供各 Controller 复用）
     * @return array { spu:[], sku:{sku,stock,has_stock,name,categories,tags}, related_skus:[] }
     */
    protected function skuDetail(int $merchantId, int $skuId): array
    {
        if ($merchantId <= 0 || $skuId <= 0) throw new \InvalidArgumentException('参数错误');
        if ($this->isEsEnabled() && $this->isElasticsearchAvailable()) {
            try { return $this->esSkuDetail($merchantId, $skuId); }
            catch (\Throwable $e) { Log::error('skuDetail.es_failed: '.$e->getMessage(), compact('merchantId','skuId')); }
        }
        return $this->dbSkuDetail($merchantId, $skuId);
    }

    /** 使用 ES 执行 SKU 检索 */
    private function esSkuSearch(array $opts): array
    {
        $merchantId = (int)$opts['merchant_id'];
        $page    = max(1, (int)($opts['page'] ?? 1));
        $perPage = min(100, max(1, (int)($opts['per_page'] ?? 20)));
        $categoryId = (int)($opts['category_id'] ?? 0);
        $tagId      = (int)($opts['tag_id'] ?? 0);
        $keyword    = trim((string)($opts['keyword'] ?? ''));
        $minPrice   = $opts['min_price'] ?? null;
        $maxPrice   = $opts['max_price'] ?? null;
        $hasMin     = ($minPrice !== null && $minPrice !== '');
        $hasMax     = ($maxPrice !== null && $maxPrice !== '');
        $minVal     = $hasMin ? (float)$minPrice : null;
        $maxVal     = $hasMax ? (float)$maxPrice : null;

        $bool = ['must' => [], 'filter' => [], 'should' => []];

        if ($keyword !== '') {
            $bool['should'][] = [
                'multi_match' => [
                    'query'    => $keyword,
                    'fields'   => ['sku.name^4', 'name^3', 'spu.name^2', 'categories_name', 'tags_name'],
                    'type'     => 'best_fields',
                    'operator' => 'and',
                ],
            ];
            $bool['should'][] = ['term'     => ['sku.barcode' => $keyword]];
            $bool['should'][] = ['wildcard' => ['sku.barcode' => ['value' => '*'.strtolower($keyword).'*']]];
            $bool['minimum_should_match'] = 1;
        } else {
            $bool['must'][] = ['match_all' => (object)[]];
        }

        if ($categoryId > 0) {
            $bool['filter'][] = [
                'nested' => [ 'path' => 'categories', 'query' => ['term' => ['categories.id' => $categoryId]] ],
            ];
        }
        if ($tagId > 0) {
            $bool['filter'][] = [
                'nested' => [ 'path' => 'tags', 'query' => ['term' => ['tags.id' => $tagId]] ],
            ];
        }
        if ($hasMin || $hasMax) {
            $range = [];
            if ($hasMin) $range['gte'] = $minVal;
            if ($hasMax) $range['lte'] = $maxVal;
            $bool['filter'][] = ['range' => ['sku.sale_price' => $range]];
        }

        $params = [
            'index' => 'sku_'.$merchantId,
            'body'  => [
                'from'  => ($page - 1) * $perPage,
                'size'  => $perPage,
                'query' => ['bool' => $bool],
                'sort'  => [
                    ['_score'   => ['order' => 'desc']],
                    ['sku.sort' => ['order' => 'asc']],
                    ['sku.id'   => ['order' => 'asc']],
                ],
            ],
        ];

        $resp = $this->client->search($params);
        $arr  = $this->esToArray($resp);
        $hits = $arr['hits']['hits'] ?? [];
        $total= (int)($arr['hits']['total']['value'] ?? 0);

        $list = [];
        foreach ($hits as $h) if (!empty($h['_source'])) $list[] = $h['_source'];

        return [
            'total'        => $total,
            'current_page' => $page,
            'per_page'     => $perPage,
            'items'        => $list,
        ];
    }

    /** 使用 DB 执行 SKU 检索，返回结构与 ES 对齐 */
    private function dbSkuSearch(array $opts): array
    {
        $merchantId = (int)$opts['merchant_id'];
        $page    = max(1, (int)($opts['page'] ?? 1));
        $perPage = min(100, max(1, (int)($opts['per_page'] ?? 20)));
        $categoryId = (int)($opts['category_id'] ?? 0);
        $tagId      = (int)($opts['tag_id'] ?? 0);
        $keyword    = trim((string)($opts['keyword'] ?? ''));
        $minPrice   = $opts['min_price'] ?? null;
        $maxPrice   = $opts['max_price'] ?? null;
        $hasMin     = ($minPrice !== null && $minPrice !== '');
        $hasMax     = ($maxPrice !== null && $maxPrice !== '');
        $minVal     = $hasMin ? (float)$minPrice : null;
        $maxVal     = $hasMax ? (float)$maxPrice : null;

        $q = SkuModel::alias('s')->where('s.merchant_id', $merchantId);
        $q->leftJoin('shop_spu sp', 'sp.id = s.spu_id AND sp.merchant_id = s.merchant_id');

        if ($keyword !== '') {
            $kw = '%' . addcslashes($keyword, '%_') . '%';
            $q->where(function($w) use ($kw) {
                $w->whereLike('s.name', $kw)
                    ->whereOr('sp.name', 'like', $kw)
                    ->whereOr('s.barcode', 'like', $kw);
            });
        }
        if ($categoryId > 0) {
            $q->leftJoin('shop_sku_category sc', 'sc.sku_id = s.id AND sc.merchant_id = s.merchant_id')
                ->where('sc.category_id', $categoryId);
        }
        if ($tagId > 0) {
            $q->leftJoin('shop_sku_tag st', 'st.sku_id = s.id AND st.merchant_id = s.merchant_id')
                ->where('st.tag_id', $tagId);
        }
        if ($hasMin) $q->where('s.sale_price', '>=', $minVal);
        if ($hasMax) $q->where('s.sale_price', '<=', $maxVal);

        $q->field('s.*, sp.name AS spu_name, sp.id AS spu_real_id, sp.unit_id AS spu_unit_id, sp.gallery AS spu_gallery, sp.status AS spu_status, sp.sort AS spu_sort, sp.created_at AS spu_created_at, sp.updated_at AS spu_updated_at');
        $q->order('s.sort','asc')->order('s.id','asc');

        $list  = $q->paginate(['list_rows'=>$perPage, 'page'=>$page])->toArray();
        $rows  = $list['data'] ?? [];
        $total = (int)($list['total'] ?? 0);

        if (!$rows) return ['total'=>0,'current_page'=>$page,'per_page'=>$perPage,'items'=>[]];

        $skuIds = array_column($rows, 'id');
        $spuIds = array_values(array_unique(array_column($rows, 'spu_id')));

        // 1) SPU 聚合库存（启用批次）
        $stockAgg = [];
        if ($spuIds) {
            $stockRows = Db::table('shop_stock_batch')
                ->whereIn('spu_id', $spuIds)
                ->where('merchant_id', $merchantId)
                ->where('status', 1)
                ->fieldRaw('spu_id, COALESCE(SUM(quantity_base),0) AS qty_sum, COALESCE(SUM(reserved_base),0) AS res_sum')
                ->group('spu_id')->select()->toArray();
            foreach ($stockRows as $r) {
                $sid=(int)$r['spu_id']; $qty=(int)$r['qty_sum']; $res=(int)$r['res_sum'];
                $stockAgg[$sid] = ['total_base'=>$qty,'reserved_base'=>$res,'available_base'=>max(0,$qty-$res)];
            }
        }

        // 2) 类目/标签名称
        $catMap=[]; $catNames=[]; $tagMap=[]; $tagNames=[];
        if ($skuIds) {
            $catRows = Db::table('shop_sku_category')->alias('sc')
                ->leftJoin('shop_category c', 'c.id = sc.category_id AND c.merchant_id = sc.merchant_id')
                ->where('sc.merchant_id', $merchantId)->whereIn('sc.sku_id', $skuIds)
                ->field('sc.sku_id, sc.category_id AS id, c.name')->select()->toArray();
            foreach ($catRows as $r) { $sid=(int)$r['sku_id']; $catMap[$sid][]=['id'=>(int)$r['id'],'name'=>(string)($r['name']??'')]; }
            foreach ($catMap as $sid=>$arr) { $catNames[$sid]=implode(' ', array_filter(array_map(fn($x)=> (string)$x['name'], $arr))); }

            $tagRows = Db::table('shop_sku_tag')->alias('st')
                ->leftJoin('shop_tag t', 't.id = st.tag_id AND t.merchant_id = st.merchant_id')
                ->where('st.merchant_id', $merchantId)->whereIn('st.sku_id', $skuIds)
                ->field('st.sku_id, st.tag_id AS id, t.name')->select()->toArray();
            foreach ($tagRows as $r) { $sid=(int)$r['sku_id']; $tagMap[$sid][]=['id'=>(int)$r['id'],'name'=>(string)($r['name']??'')]; }
            foreach ($tagMap as $sid=>$arr) { $tagNames[$sid]=implode(' ', array_filter(array_map(fn($x)=> (string)$x['name'], $arr))); }
        }

        // 3) 组装与 ES 对齐的文档
        $items = [];
        foreach ($rows as $r) {
            $spuId = (int)$r['spu_id'];
            $conv  = max(1, (int)$r['conversion_base_qty']);
            $stAgg = $stockAgg[$spuId] ?? ['total_base'=>0,'reserved_base'=>0,'available_base'=>0];
            $availableUnits = (int)floor(($stAgg['available_base'] ?? 0) / $conv);
            $hasStock = $availableUnits > 0 ? 1 : 0;

            $spu = [
                'id'         => $spuId,
                'merchant_id'=> (int)$r['merchant_id'],
                'unit_id'    => (int)$r['spu_unit_id'],
                'name'       => (string)($r['spu_name'] ?? ''),
                'gallery'    => $this->tryDecodeJson((string)($r['spu_gallery'] ?? '')),
                'status'     => (int)$r['spu_status'],
                'sort'       => (int)$r['spu_sort'],
                'created_at' => (string)$r['spu_created_at'],
                'updated_at' => (string)$r['spu_updated_at'],
            ];

            $sku = [
                'id'                  => (int)$r['id'],
                'merchant_id'         => (int)$r['merchant_id'],
                'spu_id'              => $spuId,
                'barcode'             => (string)$r['barcode'],
                'name'                => (string)$r['name'],
                'unit_id'             => (int)$r['unit_id'],
                'image'               => (string)$r['image'],
                'sale_price'          => (float)$r['sale_price'],
                'market_price'        => $r['market_price'] === null ? null : (float)$r['market_price'],
                'conversion_base_qty' => (int)$r['conversion_base_qty'],
                'sort'                => (int)$r['sort'],
                'status'              => (int)$r['status'],
                'created_at'          => (string)$r['created_at'],
                'updated_at'          => (string)$r['updated_at'],
            ];

            $cats = $catMap[$r['id']] ?? [];
            $tags = $tagMap[$r['id']] ?? [];

            $items[] = [
                'name'             => $sku['name'] ?: ($spu['name'] ?? ''),
                'sku'              => $sku,
                'spu'              => $spu,
                'stock'            => [
                    'total_base'     => (int)$stAgg['total_base'],
                    'reserved_base'  => (int)$stAgg['reserved_base'],
                    'available_base' => (int)$stAgg['available_base'],
                    'available'      => $availableUnits,
                ],
                'has_stock'        => $hasStock,
                'categories'       => $cats,
                'tags'             => $tags,
                'categories_name'  => $catNames[$r['id']] ?? '',
                'tags_name'        => $tagNames[$r['id']] ?? '',
            ];
        }

        return [
            'total'        => $total,
            'current_page' => $page,
            'per_page'     => $perPage,
            'items'        => $items,
        ];
    }

    /** 使用 ES 获取 SKU 详情 */
    private function esSkuDetail(int $merchantId, int $skuId): array
    {
        $index = 'sku_' . $merchantId;

        // 1) 读主文档
        $doc = null;
        try {
            $get = $this->client->get(['index'=>$index,'id'=>(string)$skuId]);
            if (!empty($get['_source'])) $doc = $get['_source'];
        } catch (\Throwable $e) {
            // 兼容：若 _id 不是 skuId，则使用 term 查询
            $res = $this->client->search([
                'index' => $index,
                'body'  => ['query' => ['term' => ['sku.id' => $skuId]], 'size'=>1],
            ]);
            $arr = $this->esToArray($res);
            $doc = $arr['hits']['hits'][0]['_source'] ?? null;
        }
        if (!$doc) throw new \RuntimeException('SKU 不存在');

        // 2) related_skus：同 SPU 下其他 SKU
        $related = [];
        $spuData = $doc['spu'] ?? [];
        $spuId   = (int)($spuData['id'] ?? 0);
        if ($spuId > 0) {
            $relResp = $this->client->search([
                'index' => $index,
                'body'  => [
                    'size' => 200,
                    'query' => ['term' => ['sku.spu_id' => $spuId]],
                    'sort'  => [
                        ['sku.sort' => ['order'=>'asc']],
                        ['sku.id'   => ['order'=>'asc']],
                    ],
                ],
            ]);
            $arr = $this->esToArray($relResp);
            foreach (($arr['hits']['hits'] ?? []) as $h) {
                $src = $h['_source'] ?? [];
                if ($src) {
                    $related[] = [
                        'sku'       => $src['sku'] ?? [],
                        'stock'     => $src['stock'] ?? [],
                        'has_stock' => $src['has_stock'] ?? 0,
                        'name'      => $src['name'] ?? '',
                    ];
                }
            }
        }

        $skuFull = [
            'sku'       => $doc['sku'] ?? ['id'=>$skuId],
            'stock'     => $doc['stock'] ?? [],
            'has_stock' => $doc['has_stock'] ?? 0,
            'name'      => $doc['name'] ?? '',
            'categories'=> $doc['categories'] ?? [],
            'tags'      => $doc['tags'] ?? [],
        ];

        return [
            'spu'          => $spuData,
            'sku'          => $skuFull,
            'related_skus' => $related,
        ];
    }

    /** 使用 DB 获取 SKU 详情（与 ES 输出对齐） */
    private function dbSkuDetail(int $merchantId, int $skuId): array
    {
        $r = SkuModel::alias('s')
            ->leftJoin('shop_spu sp', 'sp.id = s.spu_id AND sp.merchant_id = s.merchant_id')
            ->where('s.merchant_id', $merchantId)->where('s.id', $skuId)
            ->field('s.*, sp.name AS spu_name, sp.id AS spu_real_id, sp.unit_id AS spu_unit_id, sp.gallery AS spu_gallery, sp.status AS spu_status, sp.sort AS spu_sort, sp.created_at AS spu_created_at, sp.updated_at AS spu_updated_at')
            ->find();
        if (!$r) throw new \RuntimeException('SKU 不存在');
        $r = $r->toArray();
        $spuId = (int)$r['spu_id'];

        $aggRow = Db::table('shop_stock_batch')
            ->where('merchant_id',$merchantId)->where('spu_id',$spuId)->where('status',1)
            ->fieldRaw('COALESCE(SUM(quantity_base),0) AS qty_sum, COALESCE(SUM(reserved_base),0) AS res_sum')->find();
        $qtySum = (int)($aggRow['qty_sum'] ?? 0);
        $resSum = (int)($aggRow['res_sum'] ?? 0);
        $availableBase = max(0, $qtySum - $resSum);
        $conv = max(1, (int)$r['conversion_base_qty']);
        $availableUnits = (int)floor($availableBase / $conv);
        $hasStock = $availableUnits > 0 ? 1 : 0;

        $cats = Db::table('shop_sku_category')->alias('sc')
            ->leftJoin('shop_category c', 'c.id = sc.category_id AND c.merchant_id = sc.merchant_id')
            ->where('sc.merchant_id',$merchantId)->where('sc.sku_id',$skuId)
            ->field('sc.category_id AS id, c.name')->select()->toArray();
        $tags = Db::table('shop_sku_tag')->alias('st')
            ->leftJoin('shop_tag t', 't.id = st.tag_id AND t.merchant_id = st.merchant_id')
            ->where('st.merchant_id',$merchantId)->where('st.sku_id',$skuId)
            ->field('st.tag_id AS id, t.name')->select()->toArray();

        $spu = [
            'id'         => $spuId,
            'merchant_id'=> (int)$r['merchant_id'],
            'unit_id'    => (int)$r['spu_unit_id'],
            'name'       => (string)($r['spu_name'] ?? ''),
            'gallery'    => $this->tryDecodeJson((string)($r['spu_gallery'] ?? '')),
            'status'     => (int)$r['spu_status'],
            'sort'       => (int)$r['spu_sort'],
            'created_at' => (string)$r['spu_created_at'],
            'updated_at' => (string)$r['spu_updated_at'],
        ];

        $sku = [
            'id'                  => (int)$r['id'],
            'merchant_id'         => (int)$r['merchant_id'],
            'spu_id'              => $spuId,
            'barcode'             => (string)$r['barcode'],
            'name'                => (string)$r['name'],
            'unit_id'             => (int)$r['unit_id'],
            'image'               => (string)$r['image'],
            'sale_price'          => (float)$r['sale_price'],
            'market_price'        => $r['market_price'] === null ? null : (float)$r['market_price'],
            'conversion_base_qty' => (int)$r['conversion_base_qty'],
            'sort'                => (int)$r['sort'],
            'status'              => (int)$r['status'],
            'created_at'          => (string)$r['created_at'],
            'updated_at'          => (string)$r['updated_at'],
        ];

        $skuFull = [
            'sku'       => $sku,
            'stock'     => [
                'total_base'     => $qtySum,
                'reserved_base'  => $resSum,
                'available_base' => $availableBase,
                'available'      => $availableUnits,
            ],
            'has_stock' => $hasStock,
            'name'      => $sku['name'] ?: ($spu['name'] ?? ''),
            'categories'=> $cats,
            'tags'      => $tags,
        ];

        // related_skus
        $related = [];
        $relRows = SkuModel::where('merchant_id',$merchantId)->where('spu_id',$spuId)
            ->order('sort','asc')->order('id','asc')->select()->toArray();
        foreach ($relRows as $rr) {
            $conv2 = max(1, (int)$rr['conversion_base_qty']);
            $avail2= (int)floor($availableBase / $conv2);
            $related[] = [
                'sku'       => [
                    'id'=>(int)$rr['id'], 'merchant_id'=>(int)$rr['merchant_id'], 'spu_id'=>(int)$rr['spu_id'],
                    'barcode'=>(string)$rr['barcode'], 'name'=>(string)$rr['name'], 'unit_id'=>(int)$rr['unit_id'],
                    'image'=>(string)$rr['image'], 'sale_price'=>(float)$rr['sale_price'],
                    'market_price'=>$rr['market_price']===null?null:(float)$rr['market_price'],
                    'conversion_base_qty'=>(int)$rr['conversion_base_qty'],'sort'=>(int)$rr['sort'],
                    'status'=>(int)$rr['status'],'created_at'=>(string)$rr['created_at'],'updated_at'=>(string)$rr['updated_at'],
                ],
                'stock'     => [
                    'total_base'     => $qtySum,
                    'reserved_base'  => $resSum,
                    'available_base' => $availableBase,
                    'available'      => $avail2,
                ],
                'has_stock' => $avail2>0?1:0,
                'name'      => (string)$rr['name'],
            ];
        }

        return [
            'spu'          => $spu,
            'sku'          => $skuFull,
            'related_skus' => $related,
        ];
    }

    // =================== 兼容：旧的产品接口（如有使用） ===================

    /**
     * （兼容旧代码）按“products”索引检查库存
     * 注意：推荐迁移到 sku/spu 口径；此方法保持不改动
     */
    public function checkProductStock($productId, $quantity, $shop_id)
    {
        try {
            $params = [
                'index' => 'products',
                'body' => [
                    'query' => [
                        'bool' => [
                            'must' => [
                                ['term' => ['id' => $productId]],
                                ['term' => ['shop_id' => $shop_id]]
                            ]
                        ]
                    ]
                ]
            ];
            if (!$this->isElasticsearchAvailable()) throw new \Exception('ES 不可用');
            $response = $this->client->search($params);
            $hits = $this->esToArray($response)['hits']['hits'] ?? [];
            if (empty($hits)) throw new \Exception('商品不存在');
            $product = $hits[0]['_source'];
            if (($product['stock'] ?? 0) < $quantity) throw new \Exception('库存不足');
            return $product;
        } catch (\Exception $e) {
            throw new \Exception('库存检查失败: ' . $e->getMessage());
        }
    }

    /** （兼容旧代码）从“products”索引批量取商品 */
    public function getProductsFromElasticsearch(array $productIds, int $shop_id): array
    {
        if (!$this->isElasticsearchAvailable()) return [];
        try {
            $params = [
                'index' => 'products',
                'body' => [
                    'query' => [
                        'bool' => [
                            'must' => [
                                ['terms' => ['id' => $productIds]],
                                ['term'  => ['shop_id' => $shop_id]]
                            ]
                        ]
                    ],
                    'size' => count($productIds),
                ]
            ];
            $response = $this->client->search($params);
            $arr = $this->esToArray($response);
            $products = [];
            foreach (($arr['hits']['hits'] ?? []) as $hit) {
                $product = $hit['_source'] ?? null;
                if ($product && isset($product['id'])) $products[$product['id']] = $product;
            }
            return $products;
        } catch (\Throwable $e) {
            Log::error('从 Elasticsearch 获取商品详情失败: ' . $e->getMessage());
            return [];
        }
    }

    // =================== 辅助 ===================

    /** ES 响应兼容转数组 */
    protected function esToArray($resp): array
    {
        if (is_array($resp)) return $resp;
        if (is_object($resp)) {
            if (method_exists($resp, 'asArray')) return $resp->asArray();
            if (method_exists($resp, 'toArray')) return $resp->toArray();
            if (method_exists($resp, '__toString')) {
                $s = (string)$resp;
                $arr = json_decode($s, true);
                if (is_array($arr)) return $arr;
            }
        }
        return [];
    }

    /** 安全解 JSON */
    protected function tryDecodeJson(?string $s)
    {
        if (!$s) return [];
        $s = trim($s);
        if ($s === '') return [];
        try { $arr = json_decode($s, true); return is_array($arr) ? $arr : []; }
        catch (\Throwable $e) { return []; }
    }
}
