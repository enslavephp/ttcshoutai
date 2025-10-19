<?php
// app/shop/controller/product/Category.php
declare(strict_types=1);

namespace app\shop\controller\product;

use app\BaseController;
use app\shopadmin\model\Category as CategoryModel;
use think\facade\Log;

class Category extends BaseController
{
    /**
     * 类目树（根=0；NULL 也按 0 处理）
     * - 仅返回启用且在有效期内的类目
     * - 排序：sort ASC（越小越靠前），其次 id ASC
     */
    public function tree()
    {
        try {
            $merchantId = (int)(request()->get('merchant_id') ?? request()->post('merchant_id') ?? 0);
            if ($merchantId <= 0) {
                return $this->jsonResponse('缺少 merchant_id', 422, 'error');
            }

            $now = date('Y-m-d H:i:s');

            $rows = CategoryModel::where('merchant_id', $merchantId)
                ->where('status', 1)
                ->where(function ($q) use ($now) {
                    $q->whereNull('valid_from')->whereOr('valid_from', '<=', $now);
                })
                ->where(function ($q) use ($now) {
                    $q->whereNull('valid_to')->whereOr('valid_to', '>', $now);
                })
                ->order('sort', 'asc')       // 关键：使用 sort 且升序
                ->order('id', 'asc')
                ->field('id,parent_id,name,sort,status,valid_from,valid_to,created_at,updated_at')
                ->select()
                ->toArray();

            // 建索引：把 NULL 也归一成 0，当作根
            $byPid = [];
            foreach ($rows as $r) {
                $pid = (int)($r['parent_id'] ?? 0);   // NULL -> 0
                $byPid[$pid][] = $r;
            }

            // 递归组树：根节点用 0
            $build = function ($pid) use (&$build, &$byPid) {
                $pid = (int)($pid ?? 0);
                $res = [];
                foreach ($byPid[$pid] ?? [] as $n) {
                    $n['children'] = $build((int)$n['id']);
                    $res[] = $n;
                }
                return $res;
            };

            return $this->jsonResponse('OK', 200, 'success', ['tree' => $build(0)]);
        } catch (\Throwable $e) {
            Log::error('category.tree: '.$e->getMessage());
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }
}
