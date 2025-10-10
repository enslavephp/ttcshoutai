<?php

namespace app\shop\controller\cart;

use app\BaseController;
use app\shop\model\Cart as CartModel;
use app\shop\validate\CartValidate;
use think\facade\Db;
use think\facade\Log;
use think\Request;

class Cart extends BaseController
{
    /**
     * 添加商品到购物车
     */
    public function add(Request $request)
    {
        Db::startTrans();
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

            $data = $request->post();
            $validate = new CartValidate();

            if (!$validate->scene('add')->check($data)) {
                return $this->jsonResponse($validate->getError(), 400, 'error');
            }

            $products = $this->checkProductStock($data['product_id'], $data['quantity'],$shop_id);
//            产品价格
            $products_sale_price = $products['sale_price'];
            $products_cost_price = $products['cost_price'];
            $products_price = $products['price'];
            $cartItem = CartModel::where('user_id', $userId)
                ->where('product_id', $data['product_id'])
                ->where('shop_id', $shop_id)
                ->find();

            if ($cartItem) {
                $cartItem->quantity += $data['quantity'];
                $cartItem->is_checked = 1;
                $cartItem->save();
            } else {
                $cartItem = CartModel::create([
                    'user_id'    => $userId,
                    'product_id' => $data['product_id'],
                    'shop_id' => $data['shop_id'],
                    'quantity'   => $data['quantity'],
                    'price'   =>$products_price,
                    'cost_price'   => $products_cost_price,
                    'sale_price'   => $products_sale_price,
                ]);
            }

            Db::commit();
            return $this->jsonResponse('商品已添加到购物车', 200, 'success',$cartItem->toArray());
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('添加购物车失败', [
                'error'  => $e->getMessage(),
                'trace'  => $e->getTrace(),
                'params' => $request->post(),
            ]);
            return $this->jsonResponse('添加购物车失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    /**
     * 修改购物车中的商品
     */
    public function update(Request $request)
    {
        Db::startTrans();
        try {
            // 从中间件注入的用户信息中获取用户 ID
            $user = $request->user ?? null;
            if (!$user || !isset($user['id'])) {
                return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
            }
            $userId = $user['id'];

            // 获取商户 ID 和购物车商品 ID
            $shop_id = $request->post('shop_id');
            $cart_item_id = $request->post('cart_item_id'); // 购物车项 ID
            $new_quantity = $request->post('quantity'); // 新的商品数量
            $is_checked = $request->post('is_checked'); // 新的商品数量

            if (!$shop_id || !$cart_item_id || !$new_quantity) {
                return $this->jsonResponse('商户 ID、购物车项 ID 或商品数量不能为空、是否默认选中', 400, 'error');
            }

            // 获取购物车中的商品
            $cartItem = CartModel::where('id', $cart_item_id)
                ->where('user_id', $userId)
                ->where('shop_id', $shop_id)
                ->find();

            if (!$cartItem) {
                return $this->jsonResponse('购物车中没有该商品', 400, 'error');
            }

            // 检查商品库存，避免超过库存
            $product = $this->checkProductStock($cartItem->product_id, $new_quantity, $shop_id);
            if (!$product) {
                return $this->jsonResponse('库存不足', 400, 'error');
            }

            // 产品价格
            $products_sale_price = $product['sale_price'];
            $products_cost_price = $product['cost_price'];
            $products_price = $product['price'];

            // 更新购物车项
            $cartItem->is_checked = $is_checked;
            $cartItem->quantity = $new_quantity;
            $cartItem->price = $products_price;
            $cartItem->cost_price = $products_cost_price;
            $cartItem->sale_price = $products_sale_price;

            $cartItem->save();

            Db::commit();
            return $this->jsonResponse('购物车商品已更新', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('修改购物车失败', [
                'error'  => $e->getMessage(),
                'trace'  => $e->getTrace(),
                'params' => $request->post(),
            ]);
            return $this->jsonResponse('修改购物车失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     *
     * 查看购物车
     */
    public function index(Request $request)
    {
        try {
            // 从中间件注入的用户信息中获取用户 ID
            $user = $request->user ?? null;
            if (!$user || !isset($user['id'])) {
                return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
            }
            $userId = $user['id'];

            // 获取商户 ID
            $shop_id = $request->get('shop_id');
            if (!$shop_id) {
                return $this->jsonResponse('商户 ID 不能为空', 400, 'error');
            }
            $cartItems = CartModel::where('user_id', $userId)
                ->where('shop_id', $shop_id)
                ->select() // 查询多条记录
                ->toArray(); // 转换为数组

            if (empty($cartItems)) {
                return $this->jsonResponse('购物车为空', 200, 'success', [
                    'items'       => [],
                    'total_price' => 0,
                ]);
            }

// 获取所有商品的 ID
            $productIds = array_column($cartItems, 'product_id');

// 从 Elasticsearch 中批量获取商品详情
            $products = $this->getProductsFromElasticsearch($productIds, $shop_id);

// 计算总价，并为购物车项附加商品详情
            $totalPrice = 0;
            foreach ($cartItems as &$item) {
                $productId = $item['product_id'];
                if (isset($products[$productId])) {
                    $item['product'] = $products[$productId]; // 添加商品详情
                    if ($item['is_checked']) {
                        $price = $products[$productId]['price'] ?? 0;
                        $quantity = $item['quantity'] ?? 0;
                        $totalPrice += $price * $quantity;
                    }
                } else {
                    $item['product'] = null; // 商品在 Elasticsearch 中未找到
                }
            }

// 返回购物车详情
            return $this->jsonResponse('购物车详情', 200, 'success', [
                'items'       => $cartItems,
                'total_price' => $totalPrice,
            ]);

        } catch (\Throwable $e) {
            Log::error('获取购物车详情失败', [
                'error'  => $e->getMessage(),
                'trace'  => $e->getTrace(),
            ]);
            return $this->jsonResponse('获取购物车详情失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    /**
     * 删除购物车中的商品
     */
    public function remove(Request $request)
    {
        Db::startTrans();
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

            // 获取要删除的购物车商品 ID 列表
            $cartIds = $request->post('cart_id');
            if (empty($cartIds) || !is_array($cartIds)) {
                return $this->jsonResponse('购物车商品 ID 列表不能为空', 400, 'error');
            }
            CartModel::destroy($cartIds);

            Db::commit();
            return $this->jsonResponse('商品已从购物车移除', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('移除购物车失败', [
                'error'  => $e->getMessage(),
                'trace'  => $e->getTrace(),
                'params' => $request->post(),
            ]);
            return $this->jsonResponse('移除购物车失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 清空购物车
     */
    public function clear(Request $request)
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

            CartModel::where('user_id', $userId)->where('shop_id', $shop_id)->delete();

            return $this->jsonResponse('购物车已清空', 200, 'success');
        } catch (\Throwable $e) {
            Log::error('清空购物车失败', [
                'error'  => $e->getMessage(),
                'trace'  => $e->getTrace(),
            ]);
            return $this->jsonResponse('清空购物车失败: ' . $e->getMessage(), 500, 'error');
        }
    }
}
