<?php


//------------------------------------------------------------
// File: app/shop/validate/UsersValidate.php  （更新：大陆 11 位手机号；注册/登录场景）
namespace app\shop\validate;

use think\Validate;

class UsersValidate extends Validate
{
    // 基础规则（用于注册）；登录单独在控制器内 rule()
    protected $rule = [
        'telephone' => 'require|regex:/^1\\d{10}$/|unique:users',
        'password'  => 'require|min:6',
    ];

    protected $message = [
        'telephone.require' => '手机号不能为空',
        'telephone.regex'   => '手机号格式不正确，应为中国大陆 11 位手机号（无国家码）',
        'telephone.unique'  => '手机号已被注册',
        'password.require'  => '密码不能为空',
        'password.min'      => '密码长度不能少于6位',
    ];

    // 可选：定义场景
    protected $scene = [
        'register' => ['telephone','password'],
    ];
}
