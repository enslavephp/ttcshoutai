<?php
namespace app\shop\validate;

use think\Validate;

class UsersValidate extends Validate
{
    // 定义验证规则
    protected $rule = [
        'telephone' => 'require|regex:/^\d{10,15}$/|unique:users',
        'password'  => 'require|min:6', // 密码至少 6 位
    ];

    // 定义错误提示
    protected $message = [
        'telephone.require' => '手机号不能为空',
        'telephone.regex' => '手机号格式不正确，应为10到15位数字',
        'telephone.unique' => '手机号已被注册',

        'password.require' => '密码不能为空',
        'password.min' => '密码长度不能少于6位',
    ];
}

