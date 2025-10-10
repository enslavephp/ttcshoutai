<?php

namespace app\shop\controller\order;

use app\BaseController;
use app\shop\model\Address;
use app\shop\model\Order as OrderModel;
use app\shop\model\OrderItem;
use app\shop\model\Cart;
use app\shop\model\Shops;
use app\shop\model\Users;
use think\facade\Db;
use think\Request;
use think\facade\Log;
use app\shop\model\OrderAddress;

class Order extends BaseController
{
    /**
     * 生成订单
     */
    public function createOrder(Request $request)
    {
        // 获取用户信息
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];
//        备注
        $remarks = $request->post('remarks');

        // 获取地址 ID
        $order_type = $request->post('order_type');
        if (!$order_type) {
            return $this->jsonResponse('order_type不能为空', 400, 'error');
        }
        // 获取商户 ID
        $shopId = $request->post('shop_id');
        if (!$shopId) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }


        if($order_type == 1){
            // 获取地址 ID
            $addressId = $request->post('address_id');
            if (!$addressId) {
                return $this->jsonResponse('地址 ID 不能为空', 400, 'error');
            }
            // 获取用户选择的地址
            $userAddress = Address::where('id', $addressId)
                ->where('user_id', $userId)
                ->find();
            if (!$userAddress) {
                return $this->jsonResponse('地址不存在或无权限', 404, 'error');
            }
        }

        // 获取商家名称
        $shop = Shops::where('shop_id', $shopId)->find();
        if (!$shop) {
            return $this->jsonResponse('商家不存在', 404, 'error');
        }
        $shopName = $shop->shop_name;

        // 获取购物车数据
        $cartItems = Cart::where('user_id', $userId)
            ->where('is_checked', 1)
            ->select()
            ->toArray();
        if (empty($cartItems)) {
            return $this->jsonResponse('购物车为空', 411, 'error');
        }

        // 计算订单总金额和商品数量
        $totalAmount = array_reduce($cartItems, function ($total, $item) {
            return $total + $item['quantity'] * $item['price'];
        }, 0);
        $totalNum = array_sum(array_column($cartItems, 'quantity'));

        // 开启事务
        Db::startTrans();
        try {
            // 创建订单
            $order = OrderModel::create([
                'user_id' => $userId,
                'shop_id' => $shopId,
                'shop_name' => $shopName,
                'total_amount' => $totalAmount,
                'total_num' => $totalNum,
                'remarks' => $remarks,
                'order_data' => date('ymd'),
                'order_type' =>$order_type,
                'status' => 1, // 初始状态为“待支付”
            ]);
            $order_address = array();
            if($order_type == 1){
                // 创建订单地址
                $order_address = OrderAddress::create([
                    'order_id' => $order->order_id,
                    'full_address' => $userAddress->full_address,
                    'full_address_name' => $userAddress->full_address_name,
                    'address' => $userAddress->address,
                    'tel' => $userAddress->tel,
                    'zipcode' => $userAddress->zipcode,
                    'recipient_name' => $userAddress->recipient_name,
                    'latitude' => $userAddress->latitude,
                    'longitude' => $userAddress->longitude,
                    'location' => $userAddress->location, // 直接使用地址模型的 location 字段
                ])->toArray();
                unset($order_address['location']);
            }

            // 创建订单项并检查库存
            $orderItems = [];
            foreach ($cartItems as $key => $item) {
                $product = $this->checkProductStock($item['product_id'], $item['quantity'], $shopId);
                $orderItems[$key] = OrderItem::create([
                    'order_id' => $order->order_id,
                    'product_id' => $item['product_id'],
                    'product_name' => $product['name'],
                    'quantity' => $item['quantity'],
                    'unit_price' => $product['sale_price'],
                    'total_price' => $item['quantity'] * $product['sale_price'],
                ])->toArray();
                // 将商品数据嵌套到订单项中
                $orderItems[$key]['products'] = $product;
            }

            // 清空购物车
            Cart::where('user_id', $userId)
                ->where('is_checked', 1)
                ->delete();

            // 提交事务
            Db::commit();

            // 返回订单数据
            return $this->jsonResponse('订单创建成功', 200, 'success', [
                'order' => $order->toArray(),
                'order_items' => $orderItems,
                'order_address' => $order_address,
            ]);
        } catch (\Exception $e) {
            // 回滚事务
            Db::rollback();

            Log::error('订单创建失败'.$e->getMessage(), [
                'error' => $e->getMessage(),
                'trace' => $e->getTraceAsString(),
            ]);

            return $this->jsonResponse('订单创建失败: ' . $e->getMessage(), 412, 'error');
        }
    }

    /**
     * 删除订单
     */
    public function deleteOrder(Request $request)
    {
        // 获取请求参数
        $orderIds = $request->post('order_id'); // 订单 ID 列表
        $allDelete = $request->post('all_delete'); // 是否删除所有订单

        // 获取用户信息
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        // 获取商户 ID
        $shopId = $request->post('shop_id');
        if (!$shopId) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }

        // 参数校验
        if (!$allDelete && (empty($orderIds) || !is_array($orderIds))) {
            return $this->jsonResponse('订单 ID 列表不能为空', 400, 'error');
        }

        // 开启事务
        Db::startTrans();
        try {
            if ($allDelete) {
                // 删除当前用户在该商户下的所有订单
                $orders = OrderModel::where('shop_id', $shopId)
                    ->where('user_id', $userId)
                    ->select();

                if ($orders->isEmpty()) {
                    return $this->jsonResponse('没有可删除的订单', 404, 'error');
                }

                foreach ($orders as $order) {
                    $order->delete();
                }
            } else {
                // 删除指定订单
                foreach ($orderIds as $orderId) {
                    $order = OrderModel::where('order_id', $orderId)
                        ->where('shop_id', $shopId)
                        ->where('user_id', $userId)
                        ->find();

                    if (!$order) {
                        // 如果订单不存在，跳过
                        continue;
                    }

                    $order->delete();
                }
            }

            // 提交事务
            Db::commit();
            return $this->jsonResponse('订单删除成功', 200, 'success');
        } catch (\Throwable $e) {
            // 回滚事务
            Db::rollback();
            // 记录日志
            Log::error('删除订单失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTrace(),
                'params' => $request->post(),
            ]);

            return $this->jsonResponse('订单删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 删除订单并回滚到购物车
     */
    public function deleteOrderAndAddCart(Request $request)
    {
        $orderId = $request->post('order_id');
        $user = $request->user ?? null;

        // 验证用户登录状态
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        // 验证商户 ID
        $shopId = $request->post('shop_id');
        if (!$shopId) {
            return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
        }

        // 查询订单
        $order = OrderModel::where('order_id', $orderId)
            ->where('shop_id', $shopId)
            ->where('user_id', $userId)
            ->find();

        if (!$order) {
            return $this->jsonResponse('订单不存在或没有权限', 404, 'error');
        }

        // 开启事务
        Db::startTrans();
        try {
            // 获取订单项数据
            $orderItems = OrderItem::where('order_id', $orderId)->select();

            $outOfStockProducts = []; // 记录库存不足的商品

            foreach ($orderItems as $item) {
                // 检查购物车中是否已有该商品
                $cartItem = Cart::where('user_id', $userId)
                    ->where('shop_id', $shopId)
                    ->where('product_id', $item->product_id)
                    ->find();

                // 商品库存检查
                try {
                    $productStock = $this->checkProductStock($item->product_id, $item->quantity, $shopId);
                } catch (\Exception $e) {
                    $outOfStockProducts[] = $item->product_id;
                    continue; // 跳过库存不足的商品
                }

                if ($cartItem) {
                    // 如果购物车中已有该商品，增加数量
                    $cartItem->quantity += $item->quantity;
                    $cartItem->save();
                } else {
                    // 如果购物车中没有该商品，新增记录
                    Cart::create([
                        'user_id' => $userId,
                        'shop_id' => $shopId,
                        'product_id' => $item->product_id,
                        'quantity' => $item->quantity,
                        'price' => $item->unit_price,
                        'cost_price' => $productStock['cost_price'] ?? 0,
                        'sale_price' => $productStock['sale_price'] ?? 0,
                        'is_checked' => 1,
                    ]);
                }
            }

            // 删除订单项
            OrderItem::where('order_id', $orderId)->delete();

            // 删除订单
            $order->delete();

            // 提交事务
            Db::commit();

            return $this->jsonResponse(
                '订单删除成功，商品已回滚到购物车',
                200,
                'success',
                ['out_of_stock_products' => $outOfStockProducts]
            );
        } catch (\Exception $e) {
            // 回滚事务
            Db::rollback();

            // 记录日志
            Log::error('删除订单并回滚购物车失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTrace(),
                'params' => $request->post(),
            ]);

            return $this->jsonResponse('订单删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 修改订单
     */
    public function updateOrder(Request $request)
    {
        Db::startTrans();
        try {
            // 获取用户信息
            $user = $request->user ?? null;
            if (!$user || !isset($user['id'])) {
                return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
            }
            // 获取商户 ID
            $shop_id = $request->post('shop_id');
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }
            $userId = $user['id']; // 当前用户 ID
            $orderId = $request->post('order_id'); // 订单 ID
            $remarks = $request->post('remarks'); // 新备注内容
            $status = $request->post('status'); // 新备注内容

            // 校验参数
            if (!$orderId || !$remarks) {
                return $this->jsonResponse('订单 ID 和备注内容不能为空', 400, 'error');
            }

            // 查找订单
            $order = Db::name('orders')->where('order_id', $orderId)->where('user_id', $userId)->find();
            if (!$order) {
                return $this->jsonResponse('订单不存在或无权限修改', 404, 'error');
            }

            // 更新备注
            $order = OrderModel::find($orderId);
            $order->save([
                'remarks' => $remarks ?? $order->remarks,
                'status' => $status ?? $order->status,
                'updated_at' => date('Y-m-d H:i:s'),
            ]);
            Db::commit();
            return $this->jsonResponse('订单修改成功', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('修改订单备注失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTrace(),
                'params' => $request->post(),
            ]);
            return $this->jsonResponse('修改订单失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    /**
     * 获取订单列表
     */
    public function getOrderList(Request $request)
    {
        try {
            // 获取用户信息
            $user = $request->user ?? null;
            if (!$user || !isset($user['id'])) {
                return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
            }

            $userId = $user['id']; // 当前用户 ID

            // 获取商户 ID
            $shop_id = $request->post('shop_id');
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }

            // 接收筛选条件
            $status = $request->post('status'); // 订单状态 (可选)
            $page = $request->post('page', 1); // 当前页
            $limit = $request->post('limit', 10); // 每页显示条数


            // 构建查询条件
            $query = OrderModel::with([
                'items' => function ($query) {
                    $query->with('productItems'); // 关联 items 表中的 product 信息
                },
                'orderAddress' // 关联 order_address 表
            ])
                ->where('user_id', $userId);


            if (!is_null($status) && !empty($status)) {
                $query->whereIn('status', $status);
            }

            $order_id = $request->post('order_id');
            if (!is_null($order_id)) {
                $query->where('order_id', $order_id);
            }

            // 获取分页数据
            $orders = $query
                ->order('created_at', 'desc')
                ->page($page, $limit)
                ->select();

            // 获取总数
            $total = $query->count();

            // 返回结果
            return $this->jsonResponse('订单列表获取成功', 200, 'success', [
                'orders' => $orders,
                'pagination' => [
                    'page' => $page,
                    'limit' => $limit,
                    'total' => $total,
                ],
            ]);
        } catch (\Throwable $e) {
            Log::error(json_encode([
                'error' => '获取订单列表失败'.$e->getMessage(),
                'trace' => $e->getTrace(),
                'params' => $request->get(),
            ]));
            return $this->jsonResponse('获取订单列表失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    public function getSandboxKey($mchId, $key) {
        $url = env('api_mch_weixin_qq_com');
        $url = "https://api.mch.weixin.qq.com/xdc/apiv2getsignkey/sign/getsignkey";
        $nonceStr = bin2hex(random_bytes(8)); // 生成随机字符串
        $payload = [
            'mch_id' => $mchId,
            'nonce_str' => $nonceStr,
        ];

        // 签名生成
        $payload['sign'] = $this->generateSign($payload, $key);

        $xmlPayload = $this->arrayToXml($payload);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xmlPayload);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: text/xml']);

        $response = curl_exec($ch);
        curl_close($ch);

        $responseArray = $this->xmlToArray($response);

        if (!isset($responseArray['sandbox_signkey'])) {
            throw new \Exception('获取沙箱密钥失败: ' . $response);
        }

        return $responseArray['sandbox_signkey'];
    }

    public function generateSign($data, $key) {
        ksort($data); // 按键名排序
        $queryString = urldecode(http_build_query($data)) . "&key=" . $key;
        return strtoupper(md5($queryString)); // MD5 签名
    }

    public function arrayToXml($data) {
        $xml = "<xml>";
        foreach ($data as $key => $value) {
            $xml .= "<$key><![CDATA[$value]]></$key>";
        }
        $xml .= "</xml>";
        return $xml;
    }

    public function xmlToArray($xml)
    {
        // 安全解析 XML
        $result = simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA);
        if ($result === false) {
            throw new \Exception('Failed to parse XML: ' . implode(', ', libxml_get_errors()));
        }
        return json_decode(json_encode($result), true);
    }

}
