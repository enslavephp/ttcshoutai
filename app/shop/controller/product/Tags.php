<?php
namespace app\shop\controller\product;

use app\BaseController;
use think\Request;
use app\shop\model\Tag;
use think\facade\Db;
use think\facade\Log;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use app\shop\validate\TagValidate;

class Tags extends BaseController
{
    /**
     * 获取标签列表（支持分页）
     */
    public function index(Request $request)
    {
        try {
            $page = $request->get('page', 1);           // 页码
            $perPage = $request->get('per_page', 10);   // 每页显示的数量
            $search = $request->get('search', '');      // 搜索关键字（标签名称）
            $shop_id = $request->get('shop_id');      // 搜索关键字（标签名称）

            // 进行分页查询，并通过 with 方法加载关联的分类数据
            $query = Tag::where('name', 'like', "%$search%")->where('shop_id',$shop_id)->with('category');  // 加载 category 关联

            // 使用 paginate 方法进行分页查询
            $tags = $query->paginate($perPage);

            // 使用 map 遍历集合并添加 category_name
            $tags->getCollection()->map(function ($tag) {
                // 如果关联了分类并且存在分类数据，则返回 category_name
                $tag->category_name = $tag->category ? $tag->category->name : null;
                return $tag;
            });

            return $this->jsonResponse('获取标签列表成功', 200, 'success', $tags->toArray());
        } catch (\Exception $e) {
            Log::error('获取标签列表失败: ' . $e->getMessage());
            return $this->jsonResponse('服务器内部错误，请稍后重试', 500, 'error');
        }
    }



    /**
     * 获取标签详情
     */
    public function show(int $id)
    {
        try {
            // 获取标签数据并加载关联的分类
            $tag = Tag::with('category')->find($id);

            if (!$tag) {
                return $this->jsonResponse('标签未找到', 404, 'error');
            }

            // 如果关联了分类并且有分类名称，则显示分类名称
            $tag->category_name = $tag->category ? $tag->category->name : null;

            return $this->jsonResponse('获取标签详情成功', 200, 'success', $tag->toArray());
        } catch (\Exception $e) {
            Log::error('获取标签详情失败: ' . $e->getMessage());
            return $this->jsonResponse('服务器内部错误，请稍后重试', 500, 'error');
        }
    }

    /**
     * 创建新标签
     */
    public function store(Request $request)
    {
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
        $function_name = '创建标签';
        $roleCheck = $this->checkAdminRole($request,$function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 获取请求数据
        $data = $request->post();

        // 验证输入数据
        $validate = new TagValidate();
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        // 创建标签
        Db::startTrans();

        try {
            $tag = Tag::create([
                'name' => $data['name'],
                'remark' => $data['remark'] ?? '',
                'weight' => $data['weight'] ?? 99,
                'shop_id' => $data['shop_id'],
                'categorie_id' => $data['categorie_id'],
                'status' => $data['status'] ?? 1,
                'is_show' => $data['is_show'] ?? 1,
            ]);
            Db::commit();
            return $this->jsonResponse('标签创建成功', 200, 'success', $tag->toArray());
        } catch (\Exception $e) {
            Db::rollback();
            return $this->jsonResponse('标签创建失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 更新标签
     */
    public function update(Request $request)
    {

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
        $function_name = '更新标签';
        $roleCheck = $this->checkAdminRole($request,$function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 获取请求数据
        $data = $request->post();
        if (empty($data['id'])) {
            return $this->jsonResponse('标签 ID 必须提供', 400, 'error');
        }

        // 查找标签
        $tag = Tag::find($data['id']);
        if (!$tag) {
            return $this->jsonResponse('标签未找到', 404, 'error');
        }

        // 验证输入数据
        $validate = new TagValidate();
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        Db::startTrans();

        try {
            // 更新标签
            $tag->save([
                'name' => $data['name'],
                'remark' => $data['remark'] ?? '',
                'weight' => $data['weight'] ?? 99,
                'shop_id' => $data['shop_id'],
                'categorie_id' => $data['categorie_id'],
                'status' => $data['status'] ?? 1,
                'is_show' => $data['is_show'] ?? 1,
            ]);

            Db::commit();
            return $this->jsonResponse('标签更新成功', 200, 'success', $tag->toArray());
        } catch (\Exception $e) {
            Db::rollback();
            return $this->jsonResponse('标签更新失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 删除标签
     */
    public function destroy(Request $request)
    {
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
        $function_name = '删除标签';
        $roleCheck = $this->checkAdminRole($request,$function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 获取请求数据
        $data = $request->post();
        // 验证 ID 数组
        if (empty($data['id']) || !is_array($data['id'])) {
            return $this->jsonResponse('标签 ID 数组不能为空', 400, 'error');
        }

        $id = $data['id'];
            // 查找标签
        $tags = Tag::whereIn('id', $id)->select();
        $tags = $tags->toArray();
        if (!$tags) {
            return $this->jsonResponse('未找到指定的标签', 404, 'error');
        }

        // 确保所有标签都属于当前商户
        foreach ($tags as $tag) {
            if ($tag['shop_id'] != $shop_id) {
                return $this->jsonResponse('标签属于不同的商户，无法删除', 403, 'error');
            }
        }

        Db::startTrans();

        try {
            // 批量删除标签
            Tag::whereIn('id', $id)->delete();

            Db::commit();
            return $this->jsonResponse('标签删除成功', 200, 'success');
        } catch (\Exception $e) {
            Db::rollback();
            return $this->jsonResponse('标签删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }
}
