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

/**
 * 控制器基础类
 */
abstract class BaseController
{
    /**
     * Request实例
     * @var \think\Request
     */
    protected $request;

    /**
     * 应用实例
     * @var \think\App
     */
    protected $app;

    /**
     * 是否批量验证
     * @var bool
     */
    protected $batchValidate = false;

    /**
     * 控制器中间件
     * @var array
     */
    protected $middleware = [];

    protected $client;
    /**
     * 构造方法
     * @access public
     * @param  App  $app  应用对象
     */
    public function __construct(App $app)
    {
        // 获取 Elasticsearch 配置信息
        $config = config('elasticsearch');
        // 初始化 Elasticsearch 客户端
        $this->client = ClientBuilder::create()
            ->setHosts($config['hosts']) // 主机地址
            ->setBasicAuthentication($config['auth']['username'], $config['auth']['password']) // 用户名和密码
            ->build();
        $this->app     = $app;
        $this->request = $this->app->request;

        // 控制器初始化
        $this->initialize();
    }

    // 初始化
    protected function initialize()
    {}

    /**
     * 验证数据
     * @access protected
     * @param  array        $data     数据
     * @param  string|array $validate 验证器名或者验证规则数组
     * @param  array        $message  提示信息
     * @param  bool         $batch    是否批量验证
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
                // 支持场景
                [$validate, $scene] = explode('.', $validate);
            }
            $class = false !== strpos($validate, '\\') ? $validate : $this->app->parseClass('validate', $validate);
            $v     = new $class();
            if (!empty($scene)) {
                $v->scene($scene);
            }
        }

        $v->message($message);

        // 是否批量验证
        if ($batch || $this->batchValidate) {
            $v->batch(true);
        }

        return $v->failException(true)->check($data);
    }
    /**
     * 返回统一格式的 JSON 响应
     *
     * @param string $msg 响应消息
     * @param int $code 响应状态码
     * @param string $status 响应状态（如 success, error）
     * @param array $data 返回数据
     * @return \think\Response
     */
    protected function jsonResponse(string $msg, int $code, string $status, array $data = [])
    {
        return json([
            'msg' => $msg,
            'code' => $code,
            'status' => $status,
            'data' => $data,
        ]);
    }

    protected function checkAdminRole($request, $name)
    {
        // 从 Authorization Header 中获取用户 ID
        $authHeader = $request->header('Authorization');
        $token = substr($authHeader, 7);
        $config = config('jwt');

        try {
            // 解码 Token，获取用户信息
            $decoded = JWT::decode($token, new Key($config['secret'], 'HS256'));
            $userId = $decoded->user_id ?? null;

            if (!$userId) {
                return $this->jsonResponse('无效的用户凭据', 401, 'error');
            }
        } catch (\Exception $e) {
            return $this->jsonResponse('Token 验证失败: ' . $e->getMessage(), 401, 'error');
        }

        // 获取商户 ID
        $shop_id = $request->post('shop_id');
        if (!$shop_id) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }
        session('shop_id', $shop_id);
        // 检查用户是否是管理员
        $isAdmin = Db::name('admin_users')
                ->alias('au')
                ->join('admin_role_permissions arp', 'au.id = arp.admin_id')
                ->join('admin_permissions ap', 'ap.id = arp.permission_id')
                ->where('au.user_id', $userId)
                ->where('ap.name', $name) // 权限名称必须匹配
                ->where('arp.shop_id', $shop_id) // 限制在当前商户范围
                ->where('status', 1) // 用户必须是启用状态
                ->count() > 0;

        if (!$isAdmin) {
            return $this->jsonResponse('权限不足，仅管理员可以执行此操作', 403, 'error');
        }

        return true; // 用户具有管理员权限且有操作该接口的权限
    }

    /**
     * 验证商品库存
     */
    public function checkProductStock($productId, $quantity,$shop_id)
    {
        try {
            // Elasticsearch 查询条件
            $params = [
                'index' => 'products', // Elasticsearch 索引名称
                'body' => [
                    'query' => [
                        'bool' => [
                            'must' => [
                                ['term' => ['id' => $productId]], // 商品 ID
                                ['term' => ['shop_id' => $shop_id]] // 商户 ID
                            ]
                        ]
                    ]
                ]
            ];
            // 查询 Elasticsearch
            $response = $this->client->search($params);
            $hits = $response['hits']['hits'];
            // 检查商品是否存在
            if (empty($hits)) {
                throw new \Exception('商品不存在');
            }
            // 获取商品数据
            $product = $hits[0]['_source'];
            // 检查库存是否足够
            if ($product['stock'] < $quantity) {
                throw new \Exception('库存不足');
            }
            return $product; // 返回商品信息
        } catch (\Exception $e) {
            // 捕获异常并抛出
            throw new \Exception('库存检查失败: ' . $e->getMessage());
        }
    }
    public function getProductsFromElasticsearch(array $productIds, int $shop_id): array
    {
        // 初始化 Elasticsearch 客户端
        $client = $this->client;

        try {
            // 构造 Elasticsearch 查询参数
            $params = [
                'index' => 'products', // 索引名称
                'body' => [
                    'query' => [
                        'bool' => [
                            'must' => [
                                ['terms' => ['id' => $productIds]],  // 批量查询商品 ID
                                ['term' => ['shop_id' => $shop_id]] // 限定商户 ID
                            ]
                        ]
                    ],
                    'size' => count($productIds), // 限制返回的文档数量
                ]
            ];

            // 执行查询
            $response = $client->search($params);

            // 解析查询结果
            $products = [];
            foreach ($response['hits']['hits'] as $hit) {
                $product = $hit['_source'];
                $products[$product['id']] = $product; // 按商品 ID 索引
            }

            return $products;
        } catch (\Exception $e) {
            Log::error('从 Elasticsearch 获取商品详情失败: ' . $e->getMessage());
            return [];
        }
    }
}
