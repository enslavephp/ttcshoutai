<?php
// +----------------------------------------------------------------------
// | ThinkPHP [ WE CAN DO IT JUST THINK ]
// +----------------------------------------------------------------------
// | Copyright (c) 2006~2018 http://thinkphp.cn All rights reserved.
// +----------------------------------------------------------------------
// | Licensed ( http://www.apache.org/licenses/LICENSE-2.0 )
// +----------------------------------------------------------------------
// | Author: liu21st <liu21st@gmail.com>
// +----------------------------------------------------------------------
use think\facade\Route;

Route::get('think', function () {
    return 'hello,ThinkPHP6!';
});

Route::get('hello/:name', 'index/hello');
//login
Route::post('user/login', 'userlogin.Login/login');//登录
Route::post('user/wxlogin', 'userlogin.Login/phoneLogin');//微信手机号登录
Route::post('user/wxregister', 'userlogin.Login/phoneRegister');//微信手机号注册
Route::post('user/checknumber', 'userlogin.Login/checkUnique');//检查手机号是否唯一
Route::post('user/register', 'userlogin.Login/register');//注册
Route::post('user/refresh', 'userlogin.Login/refresh');//刷新token
Route::post('user/logout', 'userlogin.Login/logout');//退出登录

//商家
Route::get('shop/list', 'shop.shop/index');//商家列表
//商品标签
Route::get('tags', 'product.tags/index');       // 获取标签列表
Route::get('tag/:id', 'product.tags/show');    // 获取标签详情
//product
Route::get('products', 'product.product/index');       // 获取商品列表
Route::post('products/syncProductsToElasticsearch', 'product.product/syncProductsToElasticsearch');       // 同步热门产品
Route::post('products/getSearchData', 'product.product/getSearchData');       // 获取商品列表
Route::get('getProductsByCategory', 'product.category/getProductsByCategory');        // 根据分类获取产品
Route::get('getProductsByCategoryAndTag', 'product.category/getProductsByCategoryAndTag');        // 根据分类和tag获取产品
Route::get('product/:id', 'product.product/show');    // 获取商品详情
//Category
Route::get('categories', 'product.category/index');        // 获取分类列表
Route::get('category/:id', 'product.category/show');    // 获取分类详情

//Category and tag
Route::get('CategoryAndTag/show', 'product.CategoryAndTag/getCategoryTagDetail');  //展示单个Category and tag详情
Route::post('CategoryAndTag/listCategoryTags', 'product.CategoryAndTag/listCategoryTags');  //展示全部Category and tag详情

Route::group('', function () {
//    login
    Route::post('user/getUserInfo', 'userlogin.Login/getUserInfo');//获取用户信息
    Route::post('user/loginOut', 'userlogin.Login/loginOut');//获取用户信息
//product
    Route::post('product/add', 'product.product/store');      // 创建商品
    Route::post('product/upt', 'product.product/update');  // 更新商品
    Route::post('product/delete', 'product.product/destroy'); // 删除商品
    Route::post('product/batch/del', 'product.product/destroyBa
    ch'); // 删除商品
//Category
    Route::post('category/add', 'product.category/add');       // 创建分类
    Route::post('category/add', 'product.category/add');       // 创建分类
    Route::post('category/upt', 'product.category/update');   // 更新分类
    Route::post('category/batch/del', 'product.category/batchDestroy');   // 批量删除
    Route::post('category/delete', 'product.category/destroy'); // 删除分类
//Tag
    Route::post('tags/add', 'product.tags/store');      // 创建新标签
    Route::post('tags/upt', 'product.tags/update');  // 更新标签
    Route::post('tags/delete', 'product.tags/destroy');  // 删除标签

//Category and tag
    Route::post('CategoryAndTag/add', 'product.CategoryAndTag/saveCategoryTag');  // 新增分类标签关联   修改分类标签关联
    Route::post('CategoryAndTag/delete', 'product.CategoryAndTag/deleteCategoryTags');  // 删除分类和tag的关联关系
//Cart
    Route::get('cart', 'cart.Cart/index');    // 获取分类详情
    Route::post('Cart/add', 'cart.Cart/add');  // 新增分类标签关联   修改分类标签关联
    Route::post('Cart/update', 'cart.Cart/update');  // 新增分类标签关联   修改分类标签关联
    Route::post('Cart/delete', 'cart.Cart/remove');  // 删除分类和tag的关联关系
    Route::post('Cart/clear', 'cart.Cart/clear');  // 删除分类和tag的关联关系

//    order
    Route::post('order/create', 'order.Order/createOrder'); // 创建订单
    Route::post('order/deleteOrder', 'order.Order/deleteOrder'); // 删除订单
    Route::post('order/deleteOrderAndAddCart', 'order.Order/deleteOrderAndAddCart');//订单删除商品回滚
    Route::post('order/updateOrder', 'order.Order/updateOrder'); // 订单修改
    Route::post('order/getOrderList', 'order.Order/getOrderList'); // 订单列表

    Route::post('wechat/notify', 'order.Wxpay/notify');      // 支付回调
    Route::post('wechat/createWxOrder', 'order.Wxpay/createWxOrder');      // 吊起微信支付

//    address
    Route::post('user/create/address', 'user.Address/createAddress');      // 创建用户地址
    Route::post('user/update/address', 'user.Address/updateAddress');      // 创建用户地址
    Route::post('user/delete/address', 'user.Address/deleteAddress');      // 创建用户地址
    Route::post('user/get/address', 'user.Address/getUserAddresses');      // 创建用户地址
})->middleware(\app\middleware\TokenMiddleware::class);
// 为单个路由绑定中间件
//Route::get('user/profile', 'UserController@profile')
//    ->middleware(\app\middleware\TokenMiddleware::class);
