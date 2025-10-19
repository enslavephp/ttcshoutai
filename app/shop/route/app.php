<?php
// +----------------------------------------------------------------------
// | 路由配置（加入 TokenMiddleware 至刷新与退出登录；地址控制器名与新实现对齐）
// +----------------------------------------------------------------------
use think\facade\Route;
use app\middleware\TokenMiddleware;

Route::get('think', function () {
    return 'hello,ThinkPHP6!';
});

Route::get('hello/:name', 'index/hello');

// ========================= 认证相关（公开） =========================
Route::post('user/login',       'userlogin.Login/login');         // 登录（手机号 + 密码）
Route::post('user/wxlogin',     'userlogin.Login/phoneLogin');    // 微信手机号登录（存在即登录）
Route::post('user/wxregister',  'userlogin.Login/phoneRegister'); // 微信手机号注册（并登录）
Route::post('user/checknumber', 'userlogin.Login/checkUnique');   // 检查手机号是否唯一
Route::post('user/register',    'userlogin.Login/register');      // 注册（手机号 + 密码）

// 刷新 Token —— 需登录且携带 Authorization: Bearer <token>
Route::post('user/refresh', 'userlogin.Login/refresh');

// 退出登录 —— 需登录且携带 Authorization: Bearer <token>
// 注意：控制器方法名为 loginOut，这里做统一映射
Route::post('user/logout', 'userlogin.Login/loginOut')
    ->middleware(TokenMiddleware::class);

// ========================= 受保护接口（需要 Token） =========================
Route::group('', function () {
    Route::post('user/getUserInfo', 'userlogin.Login/getUserInfo'); // 获取当前登录用户信息

    // 兼容旧路径：/user/loginOut 亦可登出（已在组上挂中间件）
    Route::post('user/loginOut', 'userlogin.Login/loginOut');      // 退出登录（旧）

    // 用户地址
    Route::post('user/create/address', 'user.Address/createAddress');    // 创建用户地址
    Route::post('user/update/address', 'user.Address/updateAddress');    // 更新用户地址
    Route::post('user/delete/address', 'user.Address/deleteAddress');    // 删除用户地址
    Route::post('user/get/address',    'user.Address/getUserAddresses'); // 获取用户地址列表
})->middleware(TokenMiddleware::class);

// ========================= 商品相关 =========================
Route::get('product/detail', 'product.Product/detail');  // 商品详情（SPU + SKU + 可售）
Route::get('product/search', 'product.product/search');  // 商品搜索（ES）

// 标签与类目
Route::get('tags',       'product.tags/list');           // 标签列表
Route::get('categories', 'product.category/tree');       // 商品类目树（仅返回有效类目）
