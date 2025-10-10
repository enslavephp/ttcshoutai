<?php
namespace app\shop\controller\product;

use app\BaseController;
use app\shop\model\CategoryTag;
use app\shop\model\Tag;
use app\shop\validate\CategoryValidate;
use think\facade\Db;
use think\facade\Filesystem;
use think\facade\Log;
use think\Request;
use app\shop\model\Category as CategoryModel;
use app\shop\model\Product as ProductModel;

class Category extends BaseController
{
    /**
     * 获取分类列表
     */
    public function index(Request $request)
    {
        $page = $request->get('page', 1);          // 页码
        $perPage = $request->get('per_page', 8);  // 每页显示的数量
        $shop_id = $request->get('shop_id');       // 分类筛选参数

        if (!$shop_id) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }
        // 查询条件
        $conditions['shop_id'] = $shop_id;
        // 查询并根据权重升序排序，支持分页
        $shop_data = CategoryModel::where($conditions)
            ->order(['updated_at' => 'desc', 'weight' => 'asc']) // 按更新时间降序，权重升序排序
            ->paginate([
                'list_rows' => $perPage,
                'page' => $page,
            ]);

        return $this->jsonResponse('获取分类列表成功', 200, 'success', $shop_data->toArray());
    }
// 获取单个分类属性
    public function show(int $id)
    {
        try {
            // 查询分类
            $category = CategoryModel::find($id);

            if (!$category) {
                return $this->jsonResponse('分类不存在', 404, 'error');
            }

            // 返回分类详细信息
            return $this->jsonResponse('分类详情获取成功', 200, 'success', $category->toArray());
        } catch (\Throwable $e) {
            // 捕获异常并返回错误信息
            return $this->jsonResponse('获取分类失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    //根据分类获取产品
    public function getProductsByCategory(Request $request, $categoryId, $tagId = null)
    {
        try {
            // 获取商户 ID
            $shop_id = $request->get('shop_id', env('DEFAULT_SHOP_ID'));
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }

            // 查询分类是否存在
            $category = CategoryModel::find($categoryId);
            if (!$category) {
                return $this->jsonResponse('分类未找到', 404, 'error');
            }

            // 接收分页参数
            $page = $request->get('page', 1); // 当前页，默认为第1页
            $limit = $request->get('limit', 10); // 每页条数，默认为10

            // 查询分类下的产品
            $productsQuery = ProductModel::alias('p')
                ->join('product_category pc', 'p.id = pc.product_id')
                ->join('categories c', 'pc.category_id = c.id') // 正确关联分类表
                ->where('pc.category_id', $categoryId)
                ->where('c.shop_id', $shop_id); // 验证分类是否属于当前商户

            if ($tagId) {
                $productsQuery = $productsQuery->join('product_tag pt', 'p.id = pt.product_id')
                    ->where('pt.tag_id', $tagId);
            }

            // 分页查询
            $products = $productsQuery->field('p.*') // 查询产品表的字段
            ->page($page, $limit)
                ->select();

//        foreach ($products as $key => $product) {
//            // 获取某个折扣记录
//            $productDiscount = ProductDiscount::where('product_id',$product['id'])->find();
//            $discountedPrice = $product['sale_price'];
//            if ($productDiscount) {
//                // 计算折后价格
//                $discountedPrice = $productDiscount->calculateDiscount($product['price']);
//            }
//            $products[$key]['price'] = $discountedPrice;
//        }
            // 获取总数
            $total = $productsQuery->count(); // 获取产品总数，用于分页

            // 如果没有找到任何产品
            if ($products->isEmpty()) {
                return $this->jsonResponse('分类下没有找到产品', 404, 'error');
            }

            // 转换为数组
            $products = $products->toArray();

            // 返回分页数据
            return $this->jsonResponse('获取分类下产品成功', 200, 'success', [
                'products' => $products,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                ],
            ]);
        } catch (\Throwable $e) {
            // 捕获异常并记录错误日志
            Log::error('获取分类产品失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTrace(),
                'params' => $request->get(),
            ]);
            return $this->jsonResponse('获取分类产品失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    public function getProductsByCategoryAndTag(Request $request, $categoryId, $tagId = null)
    {
        // 获取商户 ID
        $shop_id = $request->get('shop_id', env('DEFAULT_SHOP_ID'));
        if (!$shop_id) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }

        // 查询分类是否存在
        $category = CategoryModel::find($categoryId);
        if (!$category) {
            return $this->jsonResponse('分类未找到', 404, 'error');
        }

        // 查询分类与标签关联
        $existingCategoryTagsQuery = CategoryTag::where('category_id', $categoryId);
        if ($tagId) {
            $existingCategoryTagsQuery->where('tag_id', $tagId);
        }
        $existingCategoryTags = $existingCategoryTagsQuery->select()->toArray();

        if (empty($existingCategoryTags)) {
            return $this->jsonResponse('该分类下没有与指定标签关联的产品', 404, 'error');
        }

        // 查询分类下的产品
        $productsQuery = ProductModel::alias('p')
            ->join('product_category pc', 'p.id = pc.product_id')
            ->join('categories c', 'pc.category_id = c.id') // 正确关联分类表
            ->where('pc.category_id', $categoryId)
            ->where('c.shop_id', $shop_id); // 验证分类是否属于当前商户

        if ($tagId) {
            $productsQuery->join('product_tag pt', 'p.id = pt.product_id')->where('pt.tag_id', $tagId);
        }

        $productsQuery->field('p.*'); // 查询产品表的字段

        // 添加分页
        $page = $request->get('page', 1);        // 当前页码，默认为第 1 页
        $limit = $request->get('limit', 10);     // 每页记录数，默认为 10
        $products = $productsQuery->paginate($limit, false, ['page' => $page]);

//        foreach ($products as $key => $product) {
//            // 获取某个折扣记录
//            $productDiscount = ProductDiscount::where('product_id',$product['id'])->find();
//            $discountedPrice = $product['sale_price'];
//            if ($productDiscount) {
//                // 计算折后价格
//                $discountedPrice = $productDiscount->calculateDiscount($product['price']);
//            }
//            $products[$key]['price'] = $discountedPrice;
//        }
        // 检查是否有产品数据
        if ($products->isEmpty()) {
            return $this->jsonResponse('分类下没有找到产品', 404, 'error');
        }

        return $this->jsonResponse('获取分类下产品成功', 200, 'success', [
            'products' => $products->items(), // 当前页的产品数据
            'pagination' => [
                'total'        => $products->total(),      // 总记录数
                'per_page'     => $products->listRows(),  // 每页记录数
                'current_page' => $products->currentPage(), // 当前页码
                'last_page'    => $products->lastPage(),   // 总页数
            ],
        ]);
    }

    //获取没有分类的标签，排除无效的 categorie_id
    public function getTagsWithoutValidCategory(Request $request)
    {
        try {
            // 获取商户 ID
            $shop_id = $request->get('shop_id', env('DEFAULT_SHOP_ID'));
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }


            // 查询标签表，获取没有有效分类的标签
            $tags = Tag::alias('t')  // 给 tags 表设置别名
            ->RightJoin('categories c', 't.categorie_id = c.id')  // 左连接 categories 表，t.categorie_id = c.id
            ->where(function ($query) {
                // 条件：categorie_id 为空 或 categorie_id 不在 categories 表中
                $query->whereNull('t.categorie_id')  // 如果 categorie_id 为空
                ->whereOr('c.id', null);  // 或者 categorie_id 在 categories 表中不存在
            })
                ->where('t.shop_id', $shop_id)  // 限制查询商户 ID
                ->order(['t.updated_at' => 'desc', 't.weight' => 'asc'])  // 排序
                ->field('t.*')  // 只返回 tags 表的字段
                ->select();

            // 如果没有查询到标签，返回提示信息
            if ($tags->isEmpty()) {
                return $this->jsonResponse('未找到没有有效分类的标签', 404, 'error');
            }

            // 返回成功响应，包含标签数据
            return $this->jsonResponse('获取没有有效分类的标签成功', 200, 'success', $tags->toArray());

        } catch (\Exception $e) {
            // 捕获异常并记录日志
            Log::error('获取没有有效分类的标签失败: ' . $e->getMessage());
            return $this->jsonResponse('服务器内部错误，请稍后重试', 500, 'error');
        }
    }
    // 创建分类
    public function add(Request $request)
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
        $function_name = '创建分类';
        $roleCheck = $this->checkAdminRole($request,$function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 获取请求数据
        $data = $request->post();
        // 数据验证

        // 验证输入数据
        $validate = new CategoryValidate();
        if (!$validate->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        // 设置默认权重
        $data['weight'] = $data['weight'] ?? 99;

        // 如果有上传图片，处理图片保存
        if ($request->file('image')) {
            try {
                $file = $request->file('image');
                $data['image'] = 'uploads/' .Filesystem::disk('public')->putFile('categories', $file);
            } catch (\Exception $e) {
                Log::error('图片上传失败: ' . $e->getMessage());
                return $this->jsonResponse('图片上传失败: ' . $e->getMessage(), 500, 'error');
            }
        }

        // 创建分类
        try {
            $category = CategoryModel::create([
                'name' => $data['name'],
                'image' => $data['image'] ?? null,
                'weight' => $data['weight'] ?? 99,  //权重
                'shop_id' => $shop_id,
                'discount_rate'=>$data['discount_rate'] ?? 0,  //默认折扣
                'stock_warning'=>$data['stock_warning'] ?? 0,//库存预警
                'default_conversion'=>$data['default_conversion'] ?? 0,//是否默认转化
                'remark'=>$data['remark'] ?? '',//是否默认转化
            ]);

            return $this->jsonResponse('分类创建成功', 200, 'success', $category->toArray());
        } catch (\Exception $e) {
            Log::error('分类创建失败: ' . $e->getMessage());
            return $this->jsonResponse('分类创建失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    // 更新分类
    public function update(Request $request, $id)
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
        $function_name = '更新分类';
        $roleCheck = $this->checkAdminRole($request, $function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 查询分类是否存在
        $category = CategoryModel::find($id);
        if (!$category) {
            return $this->jsonResponse('分类未找到', 404, 'error');
        }

        $data = $request->post();
        // 需要对所有前端传参做校验，但图片字段根据情况进行处理
        $validate = new CategoryValidate();

        // 处理图片字段，视情况而定
        if ($request->file('image')) {
            // 用户上传了新图片，走正常的图片验证
            if (!$validate->scene('update')->check($data)) {
                return $this->jsonResponse($validate->getError(), 422, 'error');
            }
        } else {
            // 如果没有上传图片，移除 image 校验
            // 检查用户是否要求删除图片
            if (isset($data['delete_image']) && $data['delete_image'] === true) {
                // 用户要求删除图片，图片字段为空
                $data['image'] = null;
            } else {
                // 没有上传图片，保留旧图片路径
                $data['image'] = $category->image;
            }
            // 对其他字段进行验证，但不验证图片字段
            if (!$validate->scene('update_without_image')->check($data)) {
                return $this->jsonResponse($validate->getError(), 422, 'error');
            }
        }

        // 判断是否需要删除旧图片
        $deleteOldImage = $request->post('delete_image', false); // 获取删除图片的标识


        // 如果有上传图片，处理图片保存
        if ($request->file('image')) {
            try {
                $file = $request->file('image');
                // 上传新图片
                $data['image'] = 'uploads/' . Filesystem::disk('public')->putFile('categories', $file);
                // 删除旧图片
                if ($category->image && file_exists(public_path() . $category->image)) {
                    unlink(public_path() . $category->image);
                }
            } catch (\Exception $e) {
                Log::error('图片更新失败: ' . $e->getMessage(), [
                    'category_id' => $id,
                    'user_id' => $userId,
                    'shop_id' => $shop_id,
                ]);
                return $this->jsonResponse('图片更新失败: ' . $e->getMessage(), 500, 'error');
            }
        } else {
            // 如果没有上传新图片，且要求删除图片
            if ($deleteOldImage && $category->image && file_exists(public_path() . $category->image)) {
                unlink(public_path() . $category->image); // 删除旧图片
                $data['image'] = null; // 清空图片路径
            }
        }

        // 更新分类
        try {
            $category->save([
                'name' => $data['name'] ?? $category->name,
                'image' => $data['image'],
                'weight' => $data['weight'] ?? $category->weight,
                'remark' => $data['remark'] ?? $category->remark,
                'discount_rate' => $data['discount_rate'] ?? $category->discount_rate,
                'stock_warning' => $data['stock_warning'] ?? $category->stock_warning,
                'default_conversion' => $data['default_conversion'] ?? $category->default_conversion, // 是否默认转化
            ]);
        } catch (\Exception $e) {
            Log::error('分类更新失败: ' . $e->getMessage(), [ 
                'category_id' => $id,
                'user_id' => $userId,
                'shop_id' => $shop_id,
                'data' => $data,
            ]);
            return $this->jsonResponse('分类更新失败: ' . $e->getMessage(), 500, 'error');
        }

        return $this->jsonResponse('分类更新成功', 200, 'success', $category->toArray());
    }
    /**
     * 删除分类
     */
    public function destroy(Request $request)
    {
        // 检查权限
        $function_name = '删除分类';
        $roleCheck = $this->checkAdminRole($request,$function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 获取分类 ID 数组
        $ids = $request->post('id', []);
        if (empty($ids) || !is_array($ids)) {
            return $this->jsonResponse('分类 ID 列表不能为空，且必须是数组', 400, 'error');
        }

        Db::startTrans(); // 开启事务

        try {
            // 查找分类
            $categories = CategoryModel::whereIn('id', $ids)->select();
            if ($categories->isEmpty()) {
                return $this->jsonResponse('未找到任何匹配的分类', 404, 'error');
            }

            // 删除分类图片和分类
            foreach ($categories as $category) {
                if ($category->image) {
                    $imagePath = public_path().$category->image;
                    if (file_exists($imagePath)) {
                        unlink($imagePath); // 删除图片文件
                    }
                }
                $category->delete(); // 删除分类
            }

            Db::commit(); // 提交事务
            return $this->jsonResponse('批量分类删除成功', 200, 'success');
        } catch (\Exception $e) {
            Db::rollback(); // 回滚事务
            Log::error('批量分类删除失败: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'ids' => $ids,
            ]);
            return $this->jsonResponse('批量分类删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }
}
