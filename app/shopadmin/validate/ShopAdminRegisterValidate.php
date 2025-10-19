<?php
declare(strict_types=1);

namespace app\shopadmin\validate;

use think\Validate;

class ShopAdminRegisterValidate extends Validate
{
    protected $rule = [
        'username' => 'require|alphaDash|min:3|max:64',
        'password' => 'require|min:8|max:128',
        'email'    => 'email|max:254',
        'phone'    => 'require|regex:^1[3-9]\\d{9}$',
    ];

    protected $message = [
        'username.require'  => '用户名不能为空',
        'username.alphaDash'=> '用户名仅支持字母数字下划线和中划线',
        'username.min'      => '用户名至少3位',
        'username.max'      => '用户名过长',
        'password.require'  => '密码不能为空',
        'password.min'      => '密码至少8位',
        'password.max'      => '密码过长',
        'email.email'       => '邮箱格式不正确',
        'phone.regex'       => '手机号需 E.164 格式，例如 +8613800138000',
    ];
}
