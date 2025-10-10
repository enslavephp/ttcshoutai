<?php
declare(strict_types=1);

namespace app\admin\validate;

use think\Validate;

class AdminLoginValidate extends Validate
{
    protected $rule = [
        'username' => 'require|max:64',
        'password' => 'require|max:128',
    ];

    protected $message = [
        'username.require' => '用户名不能为空',
        'username.max'     => '用户名长度超限',
        'password.require' => '密码不能为空',
        'password.max'     => '密码长度超限',
    ];
}
