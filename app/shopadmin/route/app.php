<?php
use think\facade\Route;

use app\middleware\ShopAdminPermissionMiddleware;
use app\middleware\ShopAdminSensitiveOperationMiddleware;
use app\middleware\ShopAdminTokenMiddleware;

/**
 * ================================
 * /auth 路由组
 * ================================
 */
Route::group('auth', function () {
    // 登录：不鉴权
    Route::post('login', 'auth.ShopAdminAuth/login');

    // 退出：仅校验 shopadmin token
    Route::post('logout', 'auth.ShopAdminAuth/logout')
        ->middleware(ShopAdminTokenMiddleware::class);

    // 注册子账号：需要权限（shopadmin.auth.register）
    Route::post('register', 'auth.ShopAdminAuth/register')
        ->middleware(ShopAdminTokenMiddleware::class)
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.register');

    // 管理员列表：需要权限（shopadmin.auth.listAdmins）
    Route::post('list', 'auth.ShopAdminAuth/listAdmins')
        ->middleware(ShopAdminTokenMiddleware::class)
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.listAdmins');

    // 修改子账号：需要权限（shopadmin.auth.updateSubAccount）
    Route::post('updateSubAccount', 'auth.ShopAdminAuth/updateSubAccount')
        ->middleware(ShopAdminTokenMiddleware::class)
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.updateSubAccount');

    // 删除子账号：需要权限（shopadmin.auth.deleteSubAccount）
    Route::post('deleteSubAccount', 'auth.ShopAdminAuth/deleteSubAccount')
        ->middleware(ShopAdminTokenMiddleware::class)
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.deleteSubAccount');

    // 本人改密：校验 token + 权限（shopadmin.auth.password.change）
    Route::post('password/change', 'auth.ShopAdminAuth/changePassword')
        ->middleware(ShopAdminTokenMiddleware::class)
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.password.change');
});


/**
 * ================================
 * /role 路由组（角色管理）
 * ================================
 */
Route::group('role', function () {
    Route::post('create', 'rbac.Role/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.create');

    Route::post('update', 'rbac.Role/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.update');

    Route::post('delete', 'rbac.Role/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'ROLE_DELETE');

    Route::post('info', 'rbac.Role/info')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.read');

    Route::post('list', 'rbac.Role/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.read');

    Route::post('bindPermissions', 'rbac.Role/bindPermissions')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.bindPermissions');

    Route::post('unbindPermission', 'rbac.Role/unbindPermission')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.unbindPermission');

    Route::post('revokeAllUsersOfRole', 'rbac.Role/revokeAllUsersOfRole')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.revokeAllUsersOfRole');

    Route::post('unbindAllPermissionsOfRole', 'rbac.Role/unbindAllPermissionsOfRole')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.update');

    // 角色分配：强制仅首位超管 + 二次确认（控制器已做首位超管校验；此处加确认流程）
    Route::post('merchantPermissions', 'rbac.Role/merchantPermissions')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.merchantPermissions');
    // 角色分配：强制仅首位超管 + 二次确认（控制器已做首位超管校验；此处加确认流程）
    Route::post('assignToUser', 'rbac.Role/assignToUser')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.assignToUser')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'ROLE_ASSIGN');

    // 撤销用户角色：同上，二次确认
    Route::post('revokeFromUser', 'rbac.Role/revokeFromUser')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.revokeFromUser')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'ROLE_REVOKE');

})->middleware(ShopAdminTokenMiddleware::class);  // 该组统一校验 shopadmin token

/**
 * ================================
 * /secure/confirm 路由组（二次确认）
 * ================================
 */
Route::group('secure/confirm', function () {
    // 二次确认校验
    Route::post('verify', 'secure.Confirm/verify')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.secure.confirm.verify');
})->middleware(ShopAdminTokenMiddleware::class);

/**
 * ================================
 * /permission 路由组（权限管理）
 * ================================
 */
Route::group('permission', function () {
    Route::post('create', 'rbac.Permission/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.permission.create');

    Route::post('update', 'rbac.Permission/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.permission.update');

    Route::post('delete', 'rbac.Permission/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.permission.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'PERMISSION_DELETE');

    Route::post('info', 'rbac.Permission/info')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.permission.read');

    Route::post('list', 'rbac.Permission/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.permission.read');
})->middleware(ShopAdminTokenMiddleware::class);



/**
 * 约定的权限码（仅供示例，可按需调整）：
 * shopadmin.shop.category.write
 * shopadmin.shop.tag.write
 * shopadmin.shop.unit.write
 * shopadmin.shop.sku.write
 * shopadmin.shop.spu.write
 * shopadmin.shop.stock.write
 * shopadmin.shop.relation.write
 */

// ========== Category ==========
/**
 * Category
 */
Route::group('category', function () {
    Route::get('list', 'shop.Category/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.category.list');

    Route::post('create', 'shop.Category/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.category.create');

    Route::post('update', 'shop.Category/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.category.update');

    Route::post('delete', 'shop.Category/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.category.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'CATEGORY_DELETE');
})->middleware(ShopAdminTokenMiddleware::class);

/**
 * SKU
 */
Route::group('sku', function () {
    Route::get('list', 'shop.Sku/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.sku.list');

    Route::get('bySpu', 'shop.Sku/bySpu')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.sku.list');

    Route::post('create', 'shop.Sku/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.sku.create');

    Route::post('update', 'shop.Sku/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.sku.update');

    // 一键重建 ES（原 esBulkUpsertAll 重命名为 esRebuildAll）
    Route::post('esRebuildAll', 'shop.Sku/esRebuildAll')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.sku.esRebuildAll');

    Route::post('delete', 'shop.Sku/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.sku.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'SKU_DELETE');
})->middleware(ShopAdminTokenMiddleware::class);

/**
 * SPU
 */
Route::group('spu', function () {
    Route::get('list', 'shop.Spu/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.spu.list');

    Route::get('skuListBySpu', 'shop.Spu/skuListBySpu')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.spu.list');

    Route::post('create', 'shop.Spu/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.spu.create');

    Route::post('update', 'shop.Spu/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.spu.update');

    Route::post('delete', 'shop.Spu/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.spu.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'SPU_DELETE');
})->middleware(ShopAdminTokenMiddleware::class);

/**
 * Tag
 */
Route::group('tag', function () {
    Route::get('list', 'shop.Tag/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.tag.list');

    Route::post('create', 'shop.Tag/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.tag.create');

    Route::post('update', 'shop.Tag/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.tag.update');

    Route::post('delete', 'shop.Tag/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.tag.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'TAG_DELETE');
})->middleware(ShopAdminTokenMiddleware::class);

/**
 * Unit
 */
Route::group('unit', function () {
    Route::get('list', 'shop.Unit/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.unit.list');

    Route::post('create', 'shop.Unit/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.unit.create');

    Route::post('update', 'shop.Unit/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.unit.update');

    Route::post('delete', 'shop.Unit/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.unit.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'UNIT_DELETE');
})->middleware(ShopAdminTokenMiddleware::class);

/**
 * Stock（库存批次，SPU 维度）
 */
Route::group('stock', function () {
    Route::get('list', 'shop.Stock/list')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.stock.list');

    Route::post('create', 'shop.Stock/create')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.stock.create');

    Route::post('update', 'shop.Stock/update')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.stock.update');

    Route::post('delete', 'shop.Stock/delete')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.product.stock.delete')
        ->middleware(ShopAdminSensitiveOperationMiddleware::class, 'STOCK_BATCH_DELETE');
})->middleware(ShopAdminTokenMiddleware::class);

// 说明：SPU 路由不变（只是行为更新：创建可带首批库存、更新/删除按 gallery JSON 精准处理图片）
