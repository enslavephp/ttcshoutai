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

    // 注册：需要权限（shopadmin.auth.register）
    Route::post('register', 'auth.ShopAdminAuth/register')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.register');

    // 管理员列表：需要权限（shopadmin.auth.listAdmins）
    Route::post('list', 'auth.ShopAdminAuth/listAdmins')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.auth.listAdmins');

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

    Route::post('unbindAllPermissionsOfRole', 'rbac.Role/unbindAllPermissionsOfRole')
        ->middleware(ShopAdminPermissionMiddleware::class, 'shopadmin.role.update');

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
