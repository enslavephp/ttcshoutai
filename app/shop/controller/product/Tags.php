<?php
// app/shop/controller/product/Tags.php
declare(strict_types=1);

namespace app\shop\controller\product;

use app\BaseController;
use app\shopadmin\model\Tag as TagModel;
use think\facade\Request;
use think\facade\Log;

/**
 * 前台标签查询（读） - ORM 版（表：shop_tag）
 * - 仅返回启用且在有效期内的标签
 * - 排序：sort 升序（越小越靠前），再按 id 升序
 */
class Tags extends BaseController
{
    public function list()
    {
        try {
            $merchantId = (int)(Request::get('merchant_id') ?? Request::post('merchant_id') ?? 0);
            if ($merchantId <= 0) {
                return $this->jsonResponse('缺少 merchant_id', 422, 'error');
            }

            $now = date('Y-m-d H:i:s');

            $rows = TagModel::where('merchant_id', $merchantId)
                ->where('status', 1)
                ->where(function ($q) use ($now) {
                    $q->whereNull('valid_from')->whereOr('valid_from', '<=', $now);
                })
                ->where(function ($q) use ($now) {
                    $q->whereNull('valid_to')->whereOr('valid_to', '>', $now);
                })
                ->order('sort', 'asc')
                ->order('id', 'asc')
                ->field('id,name,sort,status,valid_from,valid_to,created_at,updated_at')
                ->select()
                ->toArray();

            return $this->jsonResponse('OK', 200, 'success', ['list' => $rows]);
        } catch (\Throwable $e) {
            Log::error('tags.list: '.$e->getMessage(), ['params' => Request::param()]);
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }
}
