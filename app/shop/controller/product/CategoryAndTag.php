<?php
namespace app\shop\controller\product;

use app\BaseController;
use app\shop\model\CategoryTag;
use app\shop\model\Category;
use app\shop\model\Tag;
use think\facade\Db;
use think\Request;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class CategoryAndTag extends BaseController
{
    /**
     * 新增或修改分类标签关联
     * 如果传入的ID存在，则更新，否则进行新增操作
     */
    public function saveCategoryTag(Request $request)
    {
    try {
        // 从中间件注入的用户信息中获取用户 ID
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        // 获取商户 ID
        $shop_id = $request->post('shop_id');
        if (!$shop_id) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }

        // 获取传递的分类 ID 和标签数据
        $data = $request->post();
        $category_id = $data['category_id'] ?? null;
        $tags = $data['tags'] ?? [];

        // 验证分类 ID 和标签数据是否存在
        if (!$category_id || empty($tags)) {
            return $this->jsonResponse('缺少分类 ID 或标签数据', 400, 'error');
        }

        // 验证标签数据格式
        foreach ($tags as $tag) {
            if (!isset($tag['tag_id']) || !isset($tag['weight']) || !isset($tag['is_delete'])) {
                return $this->jsonResponse('标签数据格式不正确'.json_encode($tag), 400, 'error');
            }
        }

        // 获取当前分类的所有标签关联
        $existingCategoryTags = CategoryTag::where('category_id', $category_id)->select();

        // 处理每个标签
        foreach ($tags as $tag) {
            $tag_id = $tag['tag_id'];
            $is_delete = $tag['is_delete'];
            $weight = $tag['weight'];

            // 判断是否删除
            if ($is_delete) {
                // 删除标签
                CategoryTag::where('category_id', $category_id)
                    ->where('tag_id', $tag_id)
                    ->delete();
                continue;
            }
            // 判断是否已存在关联
            $existingCategoryTag = $existingCategoryTags->where('tag_id', $tag_id)->first();
            if ($existingCategoryTag) {
                CategoryTag::where('category_id', $category_id)
                    ->where('tag_id', $tag_id)
                    ->update(['weight' => $weight]); // 直接更新
            } else {
                // 如果不存在，新增一条记录
                CategoryTag::create([
                    'category_id' => $category_id,
                    'tag_id' => $tag_id,
                    'weight' => $weight,
                    'is_show' => 1, // 假设新增时默认为展示
                    'shop_id' => $shop_id,
                    'create_time' => date('Y-m-d H:i:s'),
                    'updated_at' => date('Y-m-d H:i:s'),
                ]);
            }
        }

        return $this->jsonResponse('分类标签关联操作成功', 200, 'success');
    } catch (\Exception $e) {
        \think\facade\Log::error('新增或修改分类标签关联失败: ' . $e->getMessage());
        return $this->jsonResponse('操作失败，请稍后重试'. $e->getMessage(), 500, 'error');
    }
}

    /**
     * 批量删除分类标签关联
     */
    public function deleteCategoryTags(Request $request)
    {
        try {
            // 从中间件注入的用户信息中获取用户 ID
            $user = $request->user ?? null;
            if (!$user || !isset($user['id'])) {
                return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
            }
            $userId = $user['id'];

            // 获取商户 ID
            $shop_id = $request->post('shop_id');
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }
            // 检查权限
            $function_name = '删除分类和tag的关联关系';
            $roleCheck = $this->checkAdminRole($request,$function_name);
            if ($roleCheck !== true) {
                return $roleCheck; // 如果权限验证失败，返回响应
            }
            $categoryIds = $request->param('category_ids');
            $tagIds = $request->param('tag_ids');

            if (empty($categoryIds) || empty($tagIds)) {
                return $this->jsonResponse('缺少分类ID或标签ID', 400, 'error');
            }

            // 批量删除
            $deletedCount = CategoryTag::whereIn('category_id', $categoryIds)
                ->whereIn('tag_id', $tagIds)
                ->delete();

            return $this->jsonResponse('批量删除成功', 200, 'success', ['deleted_count' => $deletedCount]);
        } catch (\Exception $e) {
            \think\facade\Log::error('批量删除分类标签关联失败: ' . $e->getMessage());
            return $this->jsonResponse('批量删除失败，请稍后重试', 500, 'error');
        }
    }
    /**
     * 展示分类标签关联详情
     */
    public function getCategoryTagDetail(Request $request)
    {
        try {
            $categoryId = $request->param('category_id');
            $tagId = $request->param('tag_id');

            if (!$categoryId || !$tagId) {
                return $this->jsonResponse('缺少分类ID或标签ID', 400, 'error');
            }

            // 获取指定分类标签的详情
            $categoryTag = CategoryTag::where('category_id', $categoryId)
                ->where('tag_id', $tagId)
                ->with(['category', 'tag'])
                ->find();

            if ($categoryTag) {
                return $this->jsonResponse('分类标签关联详情获取成功', 200, 'success', $categoryTag);
            }

            return $this->jsonResponse('分类标签关联不存在', 404, 'error');
        } catch (\Exception $e) {
            \think\facade\Log::error('获取分类标签关联详情失败: ' . $e->getMessage());
            return $this->jsonResponse('获取失败，请稍后重试', 500, 'error');
        }
    }

    /**
     * 验证分类标签关联数据
     */
    private function validateCategoryTagData($data)
    {
        if (empty($data['category_id']) || empty($data['tag_id'])) {
            throw new \Exception('分类ID和标签ID不能为空');
        }

        // 这里可以添加更多的验证规则，例如数据格式、存在性等
        return $data;
    }
    /**
     * 获取分类及其标签列表
     * 支持查询多个分类
     */
    public function listCategoryTags(Request $request)
    {
        try {
            // 获取分类 ID 参数，可能是数组
            $categoryIds = $request->param('category_id');
            $shop_id = $request->param('shop_id');
            // 如果前端传递了 category_id 参数，使用该参数过滤
            if ($categoryIds) {
                if (is_array($categoryIds)) {
                    // 查询传递的分类 ID
                    $categories = Category::whereIn('id', $categoryIds)->select();
                } else {
                    // 查询单个分类 ID
                    $categories = Category::where('id', $categoryIds)->select();
                }
            } else {
                // 如果没有传递 category_id，查询所有分类
                $categories = Category::select()->where('shop_id', $shop_id);
            }
            // 继续处理每个分类及其标签...
            $categories = $categories->toArray();
            // 如果没有分类，返回提示
            if (empty($categories)) {
                return $this->jsonResponse('没有找到分类', 404, 'error');
            }

            // 这里你可以继续获取关联的标签数据（按更新顺序和权重排序）
            foreach ($categories as &$category) {
                // 查询 category_id 对应的所有 CategoryTag 数据，包含关联的 Tag 数据
                $categoryTags = CategoryTag::where('category_id', $category['id'])
                    ->where('shop_id', $shop_id)
                    ->with(['tag' => function($query) {
                        // 排序 Tag 表中的数据
                        $query->order('updated_at', 'desc')
                            ->order('weight', 'asc');
                    }])
                    ->order('updated_at', 'desc')  // 排序 CategoryTag 表中的数据
                    ->order('weight', 'asc')
                    ->select();


                // 将标签添加到分类中
                $category['tags'] = $categoryTags->toArray();
            }

            return $this->jsonResponse('获取分类和标签成功', 200, 'success', $categories);

        } catch (\Exception $e) {
            \think\facade\Log::error('获取分类信息失败: ' . $e->getMessage());
            return $this->jsonResponse('获取失败，请稍后重试', 500, 'error');
        }
    }

}
