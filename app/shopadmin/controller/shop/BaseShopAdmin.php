<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use app\BaseController;
use think\facade\Request;
use think\facade\Log;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;
use Elastic\Elasticsearch\ClientBuilder;

use app\shopadmin\model\Sku as SkuModel;
use app\shopadmin\model\Spu as SpuModel;
use app\shopadmin\model\Category as CategoryModel;
use app\shopadmin\model\Tag as TagModel;

/**
 * 商户后台写操作基类
 * - 统一 JSON 返回
 * - 统一校验并解析 shopadmin 的 JWT
 * - 统一提供 ES 同步工具方法（以 SKU 为主）
 * - 当未开启 ES（config('app.start_es')=false）或客户端初始化失败时，所有 ES 方法自动跳过
 */
class BaseShopAdmin extends BaseController
{
    protected TokenService $tokenService;

    /** @var \Elastic\Elasticsearch\Client|null */
    protected $client = null;

    public function __construct()
    {
        // 先初始化父 & Token
        $this->initialize();
        // 初始化 TokenService 用于生成和验证 JWT token
        $jwtSecret = (string)(\app\common\Helper::getValue('jwt.secret') ?? 'PLEASE_CHANGE_ME');
        $jwtCfg['secret'] = $jwtSecret;

        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            $jwtCfg
        );

        // ES 开关判断；未开启则不初始化客户端
        $startEs = (bool)\app\common\Helper::getValue('app.start_es', true);
        if (!$startEs) {
            $this->client = null;
            return;
        }

        // 构建 ES 客户端（失败则降级为 null）
        try {
            $cfg   = (array)\app\common\Helper::getValue('elasticsearch') ?: [];
            $hosts = $cfg['hosts'] ?? [];
            $user  = $cfg['auth']['username'] ?? '';
            $pass  = $cfg['auth']['password'] ?? '';

            if (!$hosts) {
                Log::warning('ES init skipped: empty hosts config');
                $this->client = null;
                return;
            }

            $builder = ClientBuilder::create()->setHosts($hosts)->setSSLVerification(false);
            if ($user !== '' || $pass !== '') {
                $builder->setBasicAuthentication($user, $pass);
            }
            $this->client = $builder->build();
        } catch (\Throwable $e) {
            Log::error('ES client init failed: '.$e->getMessage());
            $this->client = null; // 降级：所有 ES 方法早退
        }
    }

    /** 生成 gallery 数组项：包含稳定 id、公开 url 与相对存储路径 rel（用于后续删除） */
    protected function makeGalleryItem(string $rel, string $url): array
    {
        // 稳定 id：基于相对路径生成（方便以后用 id 精确删除）
        $id = substr(sha1($rel), 0, 16);
        return ['id' => $id, 'url' => $url, 'rel' => $rel];
    }

    /** @return array [merchant_id, admin_id, errorResponse|null] */
    protected function requireShopAdmin(): array
    {
        $auth = Request::header('Authorization') ?: '';
        $raw  = (stripos($auth, 'Bearer ') === 0) ? substr($auth, 7) : '';
        if (!$raw) return [0, 0, $this->jsonResponse('未登录', 401, 'error')];

        try {
            $claims = $this->tokenService->parse($raw);
        } catch (\Throwable $e) {
            Log::warning('parse token failed: '.$e->getMessage());
            return [0, 0, $this->jsonResponse('会话无效', 401, 'error')];
        }
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

    /* --------------- 上传文件校验 & 存储 --------------- */

    protected function verifyImageFile(\think\File $file): bool
    {
        $path = $file->getPathname();
        if (!is_file($path) || filesize($path) <= 0) return false;

        $okMime = true;
        if (function_exists('finfo_open')) {
            $f = finfo_open(FILEINFO_MIME_TYPE);
            $mime = @finfo_file($f, $path) ?: '';
            finfo_close($f);
            $white = ['image/png','image/jpeg','image/webp','image/gif'];
            $okMime = in_array($mime, $white, true);
        }
        $okExif = true;
        if (function_exists('exif_imagetype')) {
            $t = @exif_imagetype($path);
            $okExif = in_array($t, [IMAGETYPE_PNG, IMAGETYPE_JPEG, IMAGETYPE_WEBP, IMAGETYPE_GIF], true);
        }
        $okMagic = (function($p){
            $fp = @fopen($p, 'rb'); if (!$fp) return false;
            $sig = bin2hex(@fread($fp, 12)); fclose($fp);
            if (strpos($sig, '89504e470d0a1a0a') === 0) return true;        // PNG
            if (strpos($sig, 'ffd8ff') === 0) return true;                  // JPG
            if (strpos($sig, '47494638') === 0) return true;                // GIF
            if (preg_match('/^52494646.{8}57454250/i', $sig)) return true;  // WEBP (RIFF....WEBP)
            return false;
        })($path);

        return $okMime || $okExif || $okMagic;
    }

    protected function saveUploadPublic(\think\File $file, string $dir): array
    {
        $rel = \think\facade\Filesystem::disk('public')->putFile($dir, $file);
        $url = \think\facade\Filesystem::disk('public')->url($rel);
        return [$rel, $url];
    }

    protected function deleteRelIfExists(string $rel): void
    {
        try { \think\facade\Filesystem::disk('public')->delete($rel); } catch (\Throwable $e) {}
    }

    /* ======================= ES 开关辅助 ======================= */

    /** 当前是否允许执行 ES 操作（开关开启 & 客户端可用） */
    protected function esEnabled(): bool
    {
        return (bool)\app\common\Helper::getValue('app.start_es', true) && (bool)$this->client;
    }

    /* ======================= ES（以 SKU 为主） ======================= */

    /** 确保索引存在 */
    protected function ensureIndexIfMissing(string $index, array $properties): void
    {
        if (!$this->esEnabled()) return;
        try {
            $exists = $this->client->indices()->exists(['index' => $index]);
            $isExists = is_bool($exists) ? $exists : (method_exists($exists, 'asBool') ? $exists->asBool() : (bool)$exists);
            if (!$isExists) {
                $this->client->indices()->create([
                    'index' => $index,
                    'body'  => [
                        'mappings' => ['properties' => $properties],
                    ],
                ]);
            }
        } catch (\Throwable $e) {
            Log::error("ensureIndexIfMissing($index) failed: ".$e->getMessage());
        }
    }

    /** 删除 ES 文档 */
    protected function esDeleteSkuSafe(int $merchantId, int $skuId): void
    {
        if (!$this->esEnabled()) return;
        try {
            $index = 'sku_' . $merchantId;
            $this->client->delete([
                'index'   => $index,
                'id'      => (string)$skuId,
                'ignore'  => [404],
            ]);
        } catch (\Throwable $e) {
            Log::warning('es.delete.sku: '.$e->getMessage(), ['merchant_id'=>$merchantId,'sku_id'=>$skuId]);
        }
    }

    /** 按类目刷新（SKU 绑定） —— ORM 写法 */
    protected function esRefreshByCategorySafe(int $merchantId, int $categoryId): void
    {
        if (!$this->esEnabled()) return;
        try {
            $skuIds = SkuModel::alias('s')
                ->join('shop_sku_category sc','sc.sku_id = s.id')
                ->where('s.merchant_id',$merchantId)
                ->where('sc.category_id',$categoryId)
                ->column('s.id');

            $skuIds = array_values(array_unique(array_map('intval',$skuIds)));
            foreach ($skuIds as $sid) $this->esIndexSkuSafe($merchantId, $sid);
        } catch (\Throwable $e) {
            Log::error('es.refresh.byCategory: '.$e->getMessage(), ['merchant_id'=>$merchantId,'category_id'=>$categoryId]);
        }
    }

    /** 按标签刷新（SKU 绑定） —— ORM 写法 */
    protected function esRefreshByTagSafe(int $merchantId, int $tagId): void
    {
        if (!$this->esEnabled()) return;
        try {
            $skuIds = SkuModel::alias('s')
                ->join('shop_sku_tag st','st.sku_id = s.id')
                ->where('s.merchant_id',$merchantId)
                ->where('st.tag_id',$tagId)
                ->column('s.id');

            $skuIds = array_values(array_unique(array_map('intval',$skuIds)));
            foreach ($skuIds as $sid) $this->esIndexSkuSafe($merchantId, $sid);
        } catch (\Throwable $e) {
            Log::error('es.refresh.byTag: '.$e->getMessage(), ['merchant_id'=>$merchantId,'tag_id'=>$tagId]);
        }
    }

    /** 按单位刷新（SKU.unit_id 或 SPU.unit_id 命中） */
    protected function esRefreshByUnitSafe(int $merchantId, int $unitId): void
    {
        if (!$this->esEnabled()) return;
        try {
            $skuIds1 = SkuModel::where('merchant_id',$merchantId)->where('unit_id',$unitId)->column('id');
            $spuIds  = SpuModel::where('merchant_id',$merchantId)->where('unit_id',$unitId)->column('id');
            $skuIds2 = [];
            if ($spuIds) {
                $skuIds2 = SkuModel::where('merchant_id',$merchantId)->whereIn('spu_id',$spuIds)->column('id');
            }
            $skuIds = array_values(array_unique(array_map('intval', array_merge($skuIds1,$skuIds2))));
            foreach ($skuIds as $sid) $this->esIndexSkuSafe($merchantId, $sid);
        } catch (\Throwable $e) {
            Log::error('es.refresh.byUnit: '.$e->getMessage(), ['merchant_id'=>$merchantId,'unit_id'=>$unitId]);
        }
    }

    /* ======================= ES：索引结构 & 文档构建（按新表） ======================= */

    /** 确保 sku_{merchantId} 映射存在（以 SKU 为主；库存来源 SPU 批次；带 has_stock） */
    protected function ensureEsSkuIndex(int $merchantId): void
    {
        if (!$this->esEnabled()) return;
        $index = 'sku_' . $merchantId;
        $this->ensureIndexIfMissing($index, [
            'merchant_id'     => ['type'=>'integer'],
            'name'            => ['type'=>'text'],     // 用于搜索：优先 SKU.name，空则用 SPU.name
            'categories_name' => ['type'=>'text'],
            'tags_name'       => ['type'=>'text'],
            'has_stock'       => ['type'=>'integer'],  // 0/1：floor(spu_avail_base / conversion_base_qty) > 0
            'spu' => ['properties'=>[
                'id'=>['type'=>'integer'],
                'name'=>['type'=>'text'],
                'unit_id'=>['type'=>'integer'],
                'status'=>['type'=>'integer'],
                'sort'=>['type'=>'integer'],
                'created_at'=>['type'=>'date','format'=>'yyyy-MM-dd HH:mm:ss||epoch_millis'],
                'updated_at'=>['type'=>'date','format'=>'yyyy-MM-dd HH:mm:ss||epoch_millis'],
            ]],
            'sku' => ['properties'=>[
                'id'=>['type'=>'integer'],
                'spu_id'=>['type'=>'integer'],
                'barcode'=>['type'=>'keyword'],
                'name'=>['type'=>'text'],
                'unit_id'=>['type'=>'integer'],
                'image'=>['type'=>'keyword'],
                'sale_price'=>['type'=>'float'],
                'market_price'=>['type'=>'float'],
                'conversion_base_qty'=>['type'=>'integer'],
                'status'=>['type'=>'integer'],
                'sort'=>['type'=>'integer'],
                'created_at'=>['type'=>'date','format'=>'yyyy-MM-dd HH:mm:ss||epoch_millis'],
                'updated_at'=>['type'=>'date','format'=>'yyyy-MM-dd HH:mm:ss||epoch_millis'],
            ]],
            'stock' => ['properties'=>[
                'available_base'=>['type'=>'integer'],    // SPU 维度基础单位可用量汇总
                'available_sku' =>['type'=>'integer'],    // floor(available_base / conversion_base_qty)
            ]],
            'categories' => ['type'=>'nested','properties'=>[
                'id'=>['type'=>'integer'],
                'name'=>['type'=>'text'],
            ]],
            'tags' => ['type'=>'nested','properties'=>[
                'id'=>['type'=>'integer'],
                'name'=>['type'=>'text'],
            ]],
        ]);
    }

    /** 构建 SKU 的 ES 文档（以 SPU 批次汇总库存；分类/标签由 SKU 维度关系表获取；带 has_stock） */
    protected function buildEsSkuDoc(int $merchantId, int $skuId): ?array
    {
        /** SKU */
        /** @var \app\shopadmin\model\Sku|null $sku */
        $sku = SkuModel::where('merchant_id',$merchantId)
            ->where('id',$skuId)
            ->field('id,merchant_id,spu_id,barcode,name,unit_id,image,sale_price,market_price,conversion_base_qty,status,sort,created_at,updated_at')
            ->find();
        if (!$sku) return null;

        $spuId = (int)$sku->getAttr('spu_id');

        /** SPU */
        /** @var \app\shopadmin\model\Spu|null $spu */
        $spu = SpuModel::where('merchant_id',$merchantId)
            ->where('id',$spuId)
            ->field('id,merchant_id,name,unit_id,status,sort,created_at,updated_at')
            ->find();
        if (!$spu) return null;

        /** 库存（SPU 维度聚合基础单位可用量） */
        $row = \app\shopadmin\model\StockBatch::where('merchant_id',$merchantId)
            ->where('spu_id',$spuId)
            ->where('status',1)
            ->fieldRaw('SUM(quantity_base - reserved_base) AS avail_base')
            ->find();
        $availBase = (int)($row['avail_base'] ?? 0);
        $conv      = max(1, (int)$sku->getAttr('conversion_base_qty'));
        $availSku  = ($conv>0 ? intdiv(max(0,$availBase), $conv) : 0);
        $hasStock  = $availSku > 0 ? 1 : 0;

        /** 分类（SKU 维度） —— ORM + join */
        $categories = CategoryModel::alias('c')
            ->join('shop_sku_category sc','sc.category_id = c.id')
            ->where('sc.merchant_id',$merchantId)
            ->where('sc.sku_id',$skuId)
            ->where('c.status',1)
            ->field('c.id,c.name')
            ->select()
            ->toArray();

        /** 标签（SKU 维度；需生效） —— ORM + join */
        $now = date('Y-m-d H:i:s');
        $tags = TagModel::alias('t')
            ->join('shop_sku_tag st','st.tag_id = t.id')
            ->where('st.merchant_id',$merchantId)
            ->where('st.sku_id',$skuId)
            ->where('t.status',1)
            ->where(function($q) use ($now){
                $q->whereNull('t.valid_from')->whereOr('t.valid_from','<=',$now);
            })
            ->where(function($q) use ($now){
                $q->whereNull('t.valid_to')->whereOr('t.valid_to','>',$now);
            })
            ->field('t.id,t.name')
            ->select()
            ->toArray();

        // 顶层便于搜索的字段
        $catsName = array_values(array_map(fn($x)=>(string)$x['name'],$categories));
        $tagsName = array_values(array_map(fn($x)=>(string)$x['name'],$tags));
        $topName  = trim((string)($sku->getAttr('name') ?: $spu->getAttr('name')));

        return [
            'merchant_id'     => $merchantId,
            'name'            => $topName,
            'categories_name' => $catsName,
            'tags_name'       => $tagsName,
            'has_stock'       => $hasStock,

            'spu' => [
                'id'         => (int)$spu->getAttr('id'),
                'name'       => (string)$spu->getAttr('name'),
                'unit_id'    => (int)$spu->getAttr('unit_id'),
                'status'     => (int)$spu->getAttr('status'),
                'sort'       => (int)$spu->getAttr('sort'),
                'created_at' => (string)$spu->getAttr('created_at'),
                'updated_at' => (string)$spu->getAttr('updated_at'),
            ],
            'sku' => [
                'id'                  => (int)$sku->getAttr('id'),
                'spu_id'              => (int)$sku->getAttr('spu_id'),
                'barcode'             => (string)$sku->getAttr('barcode'),
                'name'                => (string)($sku->getAttr('name') ?? ''),
                'unit_id'             => $sku->getAttr('unit_id') !== null ? (int)$sku->getAttr('unit_id') : null,
                'image'               => (string)$sku->getAttr('image'),
                'sale_price'          => (float)$sku->getAttr('sale_price'),
                'market_price'        => $sku->getAttr('market_price') !== null ? (float)$sku->getAttr('market_price') : null,
                'conversion_base_qty' => $conv,
                'status'              => (int)$sku->getAttr('status'),
                'sort'                => (int)$sku->getAttr('sort'),
                'created_at'          => (string)$sku->getAttr('created_at'),
                'updated_at'          => (string)$sku->getAttr('updated_at'),
            ],
            'stock' => [
                'available_base' => max(0,$availBase),
                'available_sku'  => $availSku,
            ],
            'categories' => $categories,
            'tags'       => $tags,
        ];
    }

    /** 单条 + 同 SPU 全量安全上报（失败仅记日志）——用于 SKU/库存变更后刷新 */
    protected function esIndexSkuSafe(int $merchantId, int $skuId): void
    {
        if (!$this->esEnabled()) return;

        $index = 'sku_' . $merchantId;
        try {
            $this->ensureEsSkuIndex($merchantId);

            // 先 upsert 当前 SKU
            $doc = $this->buildEsSkuDoc($merchantId, $skuId);
            if ($doc) {
                $this->client->index(['index'=>$index,'id'=>(string)$skuId,'body'=>$doc]);
            } else {
                // 如果当前 SKU 已不存在，尝试删除 ES 文档
                $this->client->delete(['index'=>$index,'id'=>(string)$skuId,'ignore'=>[404]]);
                return;
            }

            // 取 SPU 下所有 SKU，一并重建（保持 has_stock 与库存一致）
            $spuId = (int)($doc['spu']['id'] ?? 0);
            if ($spuId > 0) {
                $skuIds = SkuModel::where('merchant_id',$merchantId)->where('spu_id',$spuId)->column('id');
                $body=[]; $cnt=0;
                foreach ($skuIds as $sid) {
                    $sid = (int)$sid;
                    if ($sid === $skuId) continue;
                    $d = $this->buildEsSkuDoc($merchantId,$sid);
                    if (!$d) continue;
                    $body[] = ['index'=>['_index'=>$index,'_id'=>(string)$sid]];
                    $body[] = $d; $cnt++;
                    if ($cnt >= 500) { $this->client->bulk(['body'=>$body]); $body=[]; $cnt=0; }
                }
                if ($body) $this->client->bulk(['body'=>$body]);
            }
        } catch (\Throwable $e) {
            Log::error('es.index.sku.bulk: '.$e->getMessage(), ['merchant_id'=>$merchantId,'sku_id'=>$skuId]);
        }
    }

    /** 库存/批次变更后：按 SPU 刷新全部 SKU */
    protected function esRefreshBySpuSafe(int $merchantId, int $spuId): void
    {
        if (!$this->esEnabled()) return;
        try {
            $skuIds = SkuModel::where('merchant_id',$merchantId)->where('spu_id',$spuId)->column('id');
            foreach ($skuIds as $sid) {
                $this->esIndexSkuSafe($merchantId, (int)$sid);
            }
        } catch (\Throwable $e) {
            Log::warning('es.refresh.spu: '.$e->getMessage(), ['merchant_id'=>$merchantId,'spu_id'=>$spuId]);
        }
    }

}
