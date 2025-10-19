<?php
declare(strict_types=1);

namespace app\shop\controller\product;

use app\BaseController;
use think\Request;
use think\facade\Log;

/**
 * C 端商品检索/详情（精简版）
 *
 * 说明：
 * - 业务逻辑已下沉到 BaseController：skuSearch / skuDetail（ES 优先，ES 关或不可用时自动回退 DB）
 * - 这里仅做参数获取与简单校验，然后直接调用通用方法，保持返回结构与 ES 一致：
 *   name / sku / spu / stock / has_stock / categories / tags / categories_name / tags_name
 */
class Product extends BaseController
{
    /**
     * SKU 检索（组合过滤：关键字/类目/标签/价格区间）
     * GET/POST 参数：
     * - merchant_id(int, 必填)
     * - page(int, 可选，默认1)、per_page(int, 可选，默认20，最大100)
     * - keyword(string, 可选)
     * - category_id(int, 可选)、tag_id(int, 可选)
     * - min_price(float, 可选)、max_price(float, 可选)
     */
    public function search(Request $request)
    {
        try {
            $merchantId = (int)$request->param('merchant_id', 0);
            if ($merchantId <= 0) {
                return $this->jsonResponse('缺少 merchant_id', 422, 'error');
            }

            $page       = (int)$request->param('page', 1);
            $perPage    = (int)$request->param('per_page', 20);
            $categoryId = (int)$request->param('category_id', 0);
            $tagId      = (int)$request->param('tag_id', 0);
            $keyword    = (string)$request->param('keyword', '');
            $minPrice   = $request->param('min_price', null);
            $maxPrice   = $request->param('max_price', null);

            // 价格区间的轻量校验（保持与旧实现一致）
            $hasMin = ($minPrice !== null && $minPrice !== '');
            $hasMax = ($maxPrice !== null && $maxPrice !== '');
            $minVal = $hasMin ? (float)$minPrice : null;
            $maxVal = $hasMax ? (float)$maxPrice : null;
            if ($hasMin && $hasMax && $minVal > $maxVal) {
                return $this->jsonResponse('min_price 不能大于 max_price', 422, 'error');
            }

            $data = $this->skuSearch([
                'merchant_id' => $merchantId,
                'page'        => max(1, $page),
                'per_page'    => min(100, max(1, $perPage)),
                'keyword'     => trim($keyword),
                'category_id' => $categoryId,
                'tag_id'      => $tagId,
                'min_price'   => $minPrice,
                'max_price'   => $maxPrice,
            ]);

            return $this->jsonResponse('OK', 200, 'success', $data);
        } catch (\Throwable $e) {
            Log::error('product.search.failed', ['err' => $e->getMessage(), 'trace' => $e->getTrace()]);
            return $this->jsonResponse('查询失败：' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * SKU 详情
     * GET/POST 参数：
     * - merchant_id(int, 必填)
     * - sku_id(int, 必填)
     *
     * 返回：
     * - spu：当前 SKU 所属 SPU 的信息
     * - sku：{ sku对象, stock聚合, has_stock, name, categories, tags }
     * - related_skus：该 SPU 下的其它 SKU 及各自库存状态
     */
    public function detail(Request $request)
    {
        try {
            $merchantId = (int)$request->param('merchant_id', 0);
            $skuId      = (int)$request->param('sku_id', 0);
            if ($merchantId <= 0 || $skuId <= 0) {
                return $this->jsonResponse('缺少必要参数', 422, 'error');
            }

            $data = $this->skuDetail($merchantId, $skuId);
            return $this->jsonResponse('OK', 200, 'success', $data);
        } catch (\Throwable $e) {
            Log::error('product.detail.failed', ['err' => $e->getMessage(), 'sku_id' => $request->param('sku_id'), 'merchant_id' => $request->param('merchant_id')]);
            return $this->jsonResponse('查询失败：' . $e->getMessage(), 500, 'error');
        }
    }
}
