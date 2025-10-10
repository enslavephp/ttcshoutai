<?php
namespace app\shop\controller\product;

use app\BaseController;
use app\shop\model\Tag;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;
use think\facade\Cache;
use think\Request;
use think\facade\Db;
use think\facade\Filesystem;
use think\facade\Log;
use app\shop\model\Product as ProductModel;
use app\shop\model\ProductRelationship;
use app\shop\model\Category;
use app\shop\validate\ProductValidate;
use Elastic\Elasticsearch\ClientBuilder;
use Intervention\Image\Facades\Image;

class Product extends BaseController
{

    /**
     * 获取商品详情
     */
    public function show(int $id)
    {
        try {
            // 尝试从 Elasticsearch 获取数据
            $product = $this->getFromElasticsearch($id);

            if ($product) {
                return $this->jsonResponse('从 Elasticsearch 获取商品详情成功', 200, 'success', $product);
            }
            $this->syncToElasticsearch(array('id'=>$id));
            $product = $this->getFromElasticsearch($id);

            return $this->jsonResponse('从数据库获取商品详情成功', 200, 'success', $product);

        } catch (\Exception $e) {
            // 捕获异常并记录日志
            Log::error('商品详情接口异常: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'id' => $id,
            ]);
            return $this->jsonResponse('服务器内部错误，请稍后重试' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 从 Elasticsearch 获取商品数据
     */
    private function getFromElasticsearch(int $id)
    {
        try {
            // 检查 Elasticsearch 是否存在该文档
            $response = $this->client->get([
                'index' => 'products', // 索引名称
                'id'    => $id        // 文档 ID
            ]);

            if ($response['found']) {
                return $response['_source']; // 返回文档数据
            }

        } catch (\Exception $e) {
            // 如果文档不存在或发生其他错误，返回 null
            Log::info("Elasticsearch 数据获取失败: {$e->getMessage()}");
        }

        return null;
    }
    /**
     * 格式化分类和标签（支持 Collection 和 普通数组）
     */
    private function formatCategoryOrTag($data)
    {
        if ($data instanceof \think\Collection) {
            // 如果是 Collection 类型，使用 map() 方法处理
            return $data->map(function ($item) {
                return [
                    'id' => $item['id'],
                    'name' => $item['name'],
                ];
            })->toArray();  // 转为数组返回
        }

        // 如果是普通数组，使用 array_map() 进行处理
        return array_map(function ($item) {
            return [
                'id' => $item['id'],
                'name' => $item['name'],
            ];
        }, $data);
    }
    public function getUserId($request)
    {
        $user_id = 0;
        // 从请求头中获取 Authorization
        $authHeader = $request->header('Authorization');
        if (!$authHeader || !str_starts_with($authHeader, 'Bearer ')) {
            return $user_id;
        }
        $token = substr($authHeader, 7); // 提取 Token
        $config = config('jwt');

        try {
            // 解码 Token，获取用户信息
            $decoded = JWT::decode($token, new Key($config['secret'], 'HS256'));
            $userId = $decoded->user_id ?? null;
            $jti = $decoded->jti ?? null;
            if (!$userId || !$jti) {
                return $user_id;
            }
            // 验证会话是否有效
            $cacheKey = "active_token_jti:{$userId}";
            $activeJti = Cache::get($cacheKey); // 使用 Cache 门面获取
            if (!$activeJti) {
                return $user_id;
            }

            if ($activeJti !== $jti) {
                return $user_id;
            }

            // 继续请求
            return $user_id;
        } catch (\Exception $e) {
            return $user_id;
        }
    }
    public function getSearchData(Request $request)
    {
        try {
            // 获取分页参数
            $page = $request->get('page', 1); // 当前页码
            $perPage = $request->get('per_page', 10); // 每页数量

            // 初始化 Elasticsearch 客户端
            $client = $this->client;
            // 获取热门关键词，返回聚合结果
            $params = [
                'index' => 'search_logs',
                'body' => [
                    'size' => 0, // 不返回具体文档，只返回聚合结果
                    'aggs' => [
                        'popular_keywords' => [
                            'terms' => [
                                'field' => 'keyword.keyword', // 使用 keyword 子字段进行聚合
                                'size' => 10,                // 返回最多 10 个热门关键词
                                'order' => [
                                    '_count' => 'desc'       // 按出现次数降序排列
                                ]
                            ]
                        ]
                    ]
                ]
            ];

            $response = $client->search($params);
            $hot_keywords = array_map(function ($bucket) {
                return [
                    'keyword' => $bucket['key'],      // 关键词
                    'count' => $bucket['doc_count'], // 出现次数
                ];
            }, $response['aggregations']['popular_keywords']['buckets']);
            // 返回成功响应
            return $this->jsonResponse('获取热门关键词成功', 200, 'success', [
                'current_page' => $page,
                'per_page' => $perPage,
                'hot_keywords' => $hot_keywords
            ]);
        } catch (\Exception $e) {
            // 捕获异常并记录日志
            Log::error('获取热门关键词失败: ' . $e->getMessage());
            return $this->jsonResponse('服务器内部错误，请稍后重试', 500, 'error');
        }
    }

    public function index(Request $request)
    {
        try {
            // 获取请求参数
            $keyword = $request->get('keyword');   // 前端传递的模糊关键词
            $page = $request->get('page', 1);      // 页码
            $perPage = $request->get('per_page', 10); // 每页显示的数量

            $shop_id = $request->get('shop_id'); // 商户 ID
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }

            // 初始化 Elasticsearch 客户端
            $client = $this->client;

            // Elasticsearch 查询条件
            $params = [
                'index' => 'products', // 索引名称
                'body' => [
                    'from' => ($page - 1) * $perPage, // 分页起始位置
                    'size' => $perPage,              // 每页数量
                    'query' => [
                        'bool' => [
                            'must' => [
                                ['term' => ['shop_id' => $shop_id]] // 必须匹配商户 ID
                            ]
                        ]
                    ]
                ]
            ];

            // 如果关键词不为空，添加 `multi_match` 查询
            if (!empty($keyword)) {
                $params['body']['query']['bool']['should'][] = [
                    'multi_match' => [
                        'query' => $keyword,
                        'fields' => [
                            'name^4',          // 商品名称，高权重
                            'categories.name^3', // 分类名称，更高权重
                            'tags.name^2'      // 标签名称
                        ],
                        'type' => 'best_fields', // 匹配最佳字段
                        'operator' => 'and'     // 必须同时满足所有分词
                    ]
                ];
                $params['body']['query']['bool']['minimum_should_match'] = 1; // 至少匹配一个 should 条件
            }
            $response = $client->search($params);
            // 格式化 Elasticsearch 返回的数据
            $hits = $response['hits']['hits'];
            $total = $response['hits']['total']['value'];
            $products = array_map(function ($hit) {
                $product = $hit['_source'];
                $product['has_stock'] = $product['stock'] > 0; // 是否有库存
                return $product;
            }, $hits);
            $params = [
                'index' => 'search_logs', // 索引名称
                'body' => [              // 提交的数据
                    'keyword' => $keyword,           // 搜索关键词
                    'shop_id' => $shop_id,           // 商户 ID
                    'user_id' => $this->getUserId($request), // 获取用户 ID，可以为空
                    'search_time' => date('c')       // ISO 8601 时间格式
                ]
            ];

            // 提交数据到 Elasticsearch
            $client->index($params);
            $responseData = [
                'total' => $total,
                'current_page' => $page,
                'per_page' => $perPage,
                'data' => $products,
            ];
            return $this->jsonResponse('获取商品列表成功', 200, 'success', $responseData);
        } catch (\Exception $e) {
            Log::error('商品列表接口异常: ' . $e->getMessage());
            return $this->jsonResponse('服务器内部错误，请稍后重试' . $e->getMessage(), 500, 'error');
        }
    }
    /**
     * 获取商品列表（支持分页、分类筛选、名称搜索、SKU搜索）
     */
    public function syncProductsToElasticsearch(Request $request)
    {
        try {
            // 初始化商品查询，预加载分类和标签
            $products = ProductModel::with(['categories', 'tags'])->select();

            // 格式化返回的数据
            $response = $products->toArray();

            // 格式化商品的分类和标签数据
            foreach ($response as $key => $product) {
                $response[$key]['has_stock'] = $product['stock'] > 0;  // 是否有库存
                $response[$key]['categories'] = $this->formatCategoryOrTag($product['categories']);
                $response[$key]['tags'] = $this->formatCategoryOrTag($product['tags']);
            }

            // 批量同步数据到 Elasticsearch
            $this->syncAllToElasticsearch($response);

            // 返回成功的响应
            return $this->jsonResponse('获取商品列表成功', 200, 'success', $response);
        } catch (\Exception $e) {
            // 捕获异常并记录日志
            Log::error('商品列表接口异常: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
            ]);
            // 返回错误响应
            return $this->jsonResponse('服务器内部错误，请稍后重试' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 批量同步商品数据到 Elasticsearch
     *
     * @param array $products 商品列表
     */
    private function syncAllToElasticsearch(array $products)
    {
        $client = $this->client;

        // 批量操作参数
        $params = ['body' => []];

        foreach ($products as $product) {
            $params['body'][] = [
                'index' => [
                    '_index' => 'products',    // 索引名称
                    '_id'    => $product['id'] // 文档 ID
                ]
            ];
            $params['body'][] = $product; // 商品数据
        }

        try {
            // 执行批量同步
            $response = $client->bulk($params);

            // 检查同步结果是否有错误
            if (isset($response['errors']) && $response['errors']) {
                Log::error('部分商品数据同步到 Elasticsearch 失败', [
                    'response' => $response,
                ]);
            }
        } catch (\Exception $e) {
            Log::error('批量同步到 Elasticsearch 失败: ' . $e->getMessage());
        }
    }


    public function checkSku($shop_id,$sku,$id = 0)
    {
        $exists = ProductModel::where('shop_id', $shop_id)
            ->where('sku', $sku)
            ->where('id', '<>', $id)  // 排除当前更新的记录
            ->count();
        if($exists > 0){
            return true;
        }
        return false;
    }
    /**
     * 创建或更新商品（通用逻辑）
     */
    public function saveProduct(Request $request, $isUpdate = false)
    {
        // 检查权限
        $function_name = $isUpdate ? '更新商品' : '创建新商品';
        $roleCheck = $this->checkAdminRole($request, $function_name);
        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 处理请求数据
        $data = $request->post();
        $data['categories'] = isset($data['categories']) && is_string($data['categories']) ? json_decode($data['categories'], true) : [];
        $data['tags'] = isset($data['tags']) && is_string($data['tags']) ? json_decode($data['tags'], true) : [];

        // 验证分类和标签是否存在
        $validCategories = Category::whereIn('id', $data['categories'])->column('id');
        $validTags = Tag::whereIn('id', $data['tags'])->column('id');
        if (count($data['categories']) !== count($validCategories)) {
            return $this->jsonResponse('部分分类不存在', 400, 'error');
        }
        if (count($data['tags']) !== count($validTags)) {
            return $this->jsonResponse('部分Tag不存在', 400, 'error');
        }

        // 查询商品（仅更新时需要）
        $product = $isUpdate ? ProductModel::find($data['id']) : null;
        if ($isUpdate && !$product) {
            return $this->jsonResponse('商品未找到', 404, 'error');
        }

        // 场景验证，传递当前产品ID用于sku唯一性验证
        $scene = $isUpdate ? ($request->file('image') ? 'update' : 'update_without_image') : 'create';
        $validate = new ProductValidate();
        if (!$validate->scene($scene)->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }
        $id = 0;
        if ($isUpdate) {
            $id = $data['id'];
        }
        if ($this->checkSku($data['shop_id'], $data['sku'], $id)) {
            return $this->jsonResponse("商品sku已存在", 422, 'error');
        }

        // 处理图片上传或删除
        $image = $this->handleImage($request, $product, $data);

        // 开启事务
        Db::startTrans();
        try {
            if ($isUpdate) {
                // 更新商品
                $product->save(array_merge($data, ['image' => $image]));
                // 更新分类和标签
                $product->categories()->sync($data['categories'] ?? []);
                $product->tags()->sync($data['tags'] ?? []);
            } else {
                // 创建商品
                $product = ProductModel::create(array_merge($data, ['image' => $image]));
                // 添加分类和标签
                $product->categories()->sync($data['categories'] ?? []);
                $product->tags()->sync($data['tags'] ?? []);
            }

            // 提交事务
            Db::commit();

            // 将数据同步到 Elasticsearch
            $this->syncToElasticsearch($product);

            return $this->jsonResponse($isUpdate ? '商品更新成功' : '商品创建成功', 200, 'success', $product->toArray());
        } catch (\Exception $e) {
            Db::rollback();
            Log::error(($isUpdate ? '商品更新失败: ' : '商品创建失败: ') . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'data' => $data,
            ]);
            return $this->jsonResponse($isUpdate ? '商品更新失败' . $e->getMessage() : '商品创建失败' . $e->getMessage(), 500, 'error');
        }
    }
    public function syncToElasticsearch($data)
    {
        // 初始化商品查询，预加载分类和标签
        $products = ProductModel::with(['categories', 'tags'])->where('id',$data['id'])->select();
        // 格式化返回的数据
        $response = $products->toArray();

        // 格式化商品的分类和标签数据
        foreach ($response as $key => $product) {
            $response[$key]['has_stock'] = $product['stock'] > 0;  // 是否有库存
            $response[$key]['categories'] = $this->formatCategoryOrTag($product['categories']);
            $response[$key]['tags'] = $this->formatCategoryOrTag($product['tags']);
        }
        // 批量同步数据到 Elasticsearch
        $this->syncAllToElasticsearch(array($product));
    }
    /**
     * 处理图片的上传、保留或删除逻辑
     */
    /**
     * 处理图片上传、压缩并返回图片路径
     */
    private function handleImage(Request $request, $product, &$data)
    {
        // 如果用户上传了新图片
        if ($request->file('image')) {
            try {
                $file = $request->file('image');
                // 获取文件扩展名和原文件路径
                $extension = $file->extension();
                $imagePath = Filesystem::disk('public')->putFile('products', $file);
                $imageFullPath = public_path() . '/' . $imagePath;

                // 使用 Intervention Image 对图片进行压缩
//                $img = Image::make($imageFullPath);
//                $img->resize(800, 600);  // 你可以调整尺寸
//                $img->save($imageFullPath);  // 保存压缩后的图片
                // 删除旧图片（仅更新时）
                if ($product && $product->image && file_exists(public_path() . $product->image)) {
                    unlink(public_path() . $product->image);
                }
                file_put_contents("/www/sjc.txt",'123'."\r\n",FILE_APPEND);

                return 'uploads/'.$imagePath;
            } catch (\Exception $e) {
                Log::error('图片上传失败: ' . $e->getMessage());
                throw new \Exception('图片上传失败: ' . $e->getMessage());
            }
        }

        // 如果用户要求删除图片
        if (isset($data['delete_image']) && $data['delete_image'] === true) {
            if ($product && $product->image && file_exists(public_path() . $product->image)) {
                unlink(public_path() . $product->image); // 删除旧图片
            }
            return null; // 图片路径置空
        }

        // 保留旧图片路径（仅更新时）
        return $product ? $product->image : null;
    }


    /**
     * 创建新商品
     */
    public function store(Request $request)
    {
        return $this->saveProduct($request, false);
    }

    /**
     * 更新商品
     */
    public function update(Request $request)
    {
        return $this->saveProduct($request, true);
    }


    /**
     * 删除商品
     */
    public function destroy(\think\Request $request)
    {
        // 检查权限
        $function_name = '删除商品';
        $roleCheck = $this->checkAdminRole($request, $function_name);

        if ($roleCheck !== true) {
            return $roleCheck; // 如果权限验证失败，返回响应
        }

        // 获取批量删除的商品ID数组
        $data = $request->post();
        $productIds = $data['id']; // 商品ID数组

        if (empty($productIds)) {
            return $this->jsonResponse('没有传入要删除的商品ID', 400, 'error');
        }

        // 开启事务处理
        Db::startTrans();

        try {
            // 查询所有要删除的商品
            $products = ProductModel::whereIn('id', $productIds)->select();

            if ($products->isEmpty()) {
                return $this->jsonResponse('没有找到要删除的商品', 404, 'error');
            }

            // 初始化 Elasticsearch 客户端
            $client = $this->client;

            // 循环处理每个商品
            foreach ($products as $product) {
                // 删除商品图片
                if ($product->image && file_exists(public_path() . $product->image)) {
                    unlink(public_path() . $product->image);
                }

                // 删除商品与分类的关联
                $product->categories()->detach();

                // 删除 Elasticsearch 中的文档
                $this->deleteFromElasticsearch($client, $product->id);

                // 删除商品本身
                $product->delete();
            }

            // 提交事务
            Db::commit();
            return $this->jsonResponse('商品批量删除成功', 200, 'success');
        } catch (\Exception $e) {
            // 发生错误，回滚事务
            Db::rollback();
            Log::error('商品批量删除失败: ' . $e->getMessage(), [
                'trace' => $e->getTraceAsString(),
                'product_ids' => $productIds,
            ]);
            return $this->jsonResponse('商品批量删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 删除 Elasticsearch 中的文档
     *
     * @param \Elastic\Elasticsearch\Client $client
     * @param int $productId
     */
    private function deleteFromElasticsearch($client, $productId)
    {
        $params = [
            'index' => 'products',  // Elasticsearch 索引名称
            'id'    => $productId   // 文档 ID
        ];

        try {
            $client->delete($params); // 删除 Elasticsearch 文档
        } catch (\Exception $e) {
            Log::error('Elasticsearch 文档删除失败: ' . $e->getMessage(), [
                'product_id' => $productId,
            ]);
        }
    }
    //库存转换
    public function reduceStock($productId, $quantity)
    {
        $product = ProductModel::find($productId);

        if (!$product) {
            return ['status' => 'error', 'msg' => '商品不存在'];
        }

        // 当前商品库存不足时，尝试转换库存
        if ($product->stock < $quantity) {
            $relationships = ProductRelationship::where('product_id', $productId)->select();

            foreach ($relationships as $relation) {
                $relatedProduct = ProductModel::find($relation->related_product_id);

                // 计算需要的关联商品数量
                $requiredRelatedStock = $quantity * $relation->conversion_rate;

                if ($relatedProduct && $relatedProduct->stock >= $requiredRelatedStock) {
                    // 减少关联商品库存
                    $relatedProduct->stock -= $requiredRelatedStock;
                    $relatedProduct->save();

                    // 增加当前商品库存
                    $product->stock += $quantity;
                    $product->save();

                    return ['status' => 'success', 'msg' => '库存已通过关联商品补充'];
                }
            }

            return ['status' => 'error', 'msg' => '库存不足，无法完成订单'];
        }

        // 当前商品库存充足，直接减少库存
        $product->stock -= $quantity;
        $product->save();

        return ['status' => 'success', 'msg' => '库存减少成功'];
    }

//查询主商品的所有关联商品
    public function a1()
    {
        $product = ProductModel::find(1); // 获取主商品
        $relationships = $product->relationships; // 获取主商品的关联关系

        foreach ($relationships as $relation) {
            $relatedProduct = $relation->relatedProduct; // 关联商品
            echo "关联商品名称: {$relatedProduct->name}, 转换比率: {$relation->conversion_rate}";
        }
    }

//查询某商品是哪些商品的关联商品
    public function a2()
    {
        $product = ProductModel::find(2); // 获取商品
        $relatedTo = $product->relatedTo; // 获取它被关联的记录

        foreach ($relatedTo as $relation) {
            $mainProduct = $relation->product; // 主商品
            echo "主商品名称: {$mainProduct->name}, 转换比率: {$relation->conversion_rate}";
        }

    }

}
