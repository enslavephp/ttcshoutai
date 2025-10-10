<?php
use think\facade\Route;
use app\middleware\AdminPermissionMiddleware;
use app\middleware\AdminSensitiveOperationMiddleware;
use app\middleware\AdminTokenMiddleware;

/**
 * ================================
 * /auth 路由组
 * ================================
 */
Route::group('auth', function () {
    // 登录：不需要权限
    Route::post('login', 'auth.AdminAuth/login');

    // 退出：需要 Token
    Route::post('logout', 'auth.AdminAuth/logout')
        ->middleware(AdminTokenMiddleware::class);

    // 注册：需要权限 admin.auth.register
    Route::post('register', 'auth.AdminAuth/register')
        ->middleware(AdminPermissionMiddleware::class, 'admin.auth.register');

    // 管理员列表：需要权限 admin.auth.listAdmins
    Route::post('list', 'auth.AdminAuth/listAdmins')
        ->middleware(AdminPermissionMiddleware::class, 'admin.auth.listAdmins');

    // 修改密码：需要 Token + 权限 admin.auth.password.change
    Route::post('password/change', 'auth.AdminAuth/changePassword')
        ->middleware(AdminTokenMiddleware::class)
        ->middleware(AdminPermissionMiddleware::class, 'admin.auth.password.change');
});

/**
 * ================================
 * /role 路由组（角色管理，需 JWT）
 * ================================
 */
Route::group('role', function () {
    Route::post('create', 'admin/rbac.Role/create')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.create');

    Route::post('update', 'admin/rbac.Role/update')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.update');

    Route::post('delete', 'admin/rbac.Role/delete')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.delete')
        ->middleware(AdminSensitiveOperationMiddleware::class, 'ROLE_DELETE');

    Route::post('info', 'admin/rbac.Role/info')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.read');

    Route::post('list', 'admin/rbac.Role/list')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.read');

    Route::post('bindPermissions', 'admin/rbac.Role/bindPermissions')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.bindPermissions');

    Route::post('unbindPermission', 'admin/rbac.Role/unbindPermission')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.unbindPermission');

    Route::post('unbindAllPermissionsOfRole', 'admin/rbac.Role/unbindAllPermissionsOfRole')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.update');

    Route::post('assignToUser', 'admin/rbac.Role/assignToUser')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.assignToUser');

    Route::post('revokeFromUser', 'admin/rbac.Role/revokeFromUser')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.revokeFromUser');

    Route::post('revokeAllUsersOfRole', 'admin/rbac.Role/revokeAllUsersOfRole')
        ->middleware(AdminPermissionMiddleware::class, 'admin.role.update');

})->middleware(AdminTokenMiddleware::class);

/**
 * ================================
 * /secure/confirm 路由组（需 JWT）
 * ================================
 */
Route::group('secure/confirm', function () {
    Route::post('verify', 'admin/secure.Confirm/verify')
        ->middleware(AdminPermissionMiddleware::class, 'admin.secure.confirm.verify');
})->middleware(AdminTokenMiddleware::class);

/**
 * ================================
 * /permission 路由组（权限管理，需 JWT）
 * ================================
 */
Route::group('permission', function () {
    Route::post('create', 'admin/rbac.Permission/create')
        ->middleware(AdminPermissionMiddleware::class, 'admin.permission.create');

    Route::post('update', 'admin/rbac.Permission/update')
        ->middleware(AdminPermissionMiddleware::class, 'admin.permission.update');

    Route::post('delete', 'admin/rbac.Permission/delete')
        ->middleware(AdminPermissionMiddleware::class, 'admin.permission.delete')
        ->middleware(AdminSensitiveOperationMiddleware::class, 'PERMISSION_DELETE');

    Route::post('info', 'admin/rbac.Permission/info')
        ->middleware(AdminPermissionMiddleware::class, 'admin.permission.read');

    Route::post('list', 'admin/rbac.Permission/list')
        ->middleware(AdminPermissionMiddleware::class, 'admin.permission.read');
})->middleware(AdminTokenMiddleware::class);

/**
 * ================================
 * /merchant 路由组（商户管理，需 JWT）
 * ================================
 */
Route::group('merchant', function () {
    // 创建商户
    Route::post('create', 'admin/shopadmin.Merchant/create')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.create');

    // 更新商户
    Route::post('update', 'admin/shopadmin.Merchant/update')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.update');

    // 软删商户
    Route::post('delete', 'admin/shopadmin.Merchant/delete')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.delete');

    // 物理删除（建议加敏感操作中间件）
    Route::post('delete_force', 'admin/shopadmin.Merchant/delete_force')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.delete_force')
        ->middleware(AdminSensitiveOperationMiddleware::class, 'MERCHANT_DELETE_FORCE');

    // 恢复软删
    Route::post('restore', 'admin/shopadmin.Merchant/restore')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.restore');

    // 详情
    Route::post('info', 'admin/shopadmin.Merchant/info')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.read');

    // 列表（若也想支持 GET，可以把下面这一行换成 rule + GET|POST）
    Route::post('list', 'admin/shopadmin.Merchant/list')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.read');
})->middleware(AdminTokenMiddleware::class);

/**
 * ================================
 * /region 路由组（省市区，需 JWT）
 * ================================
 */
Route::group('region', function () {

    // 详情
    Route::post('provinces', 'admin/shopadmin.Region/provinces')
        ->middleware(AdminPermissionMiddleware::class, 'admin.merchant.read');

    // 市列表（支持 GET/POST；参数：province_code）
    Route::post('cities', 'admin/shopadmin.Region/cities')
        ->middleware(AdminPermissionMiddleware::class, 'admin.region.read');

    // 区/县列表（支持 GET/POST；参数：city_code）
    Route::post('districts', 'admin/shopadmin.Region/districts')
        ->middleware(AdminPermissionMiddleware::class, 'admin.region.read');

    // 树形（支持 GET/POST；参数：depth/keyword/province_code/city_code）
    Route::post('tree', 'admin/shopadmin.Region/tree')
        ->middleware(AdminPermissionMiddleware::class, 'admin.region.read');

    // 清缓存（仅 POST）
    Route::post('clear_cache', 'admin/shopadmin.Region/clear_cache')
        ->middleware(AdminPermissionMiddleware::class, 'admin.region.cache.clear')
        ->middleware(AdminSensitiveOperationMiddleware::class, 'REGION_CACHE_CLEAR');

});
