<?php
declare(strict_types=1);

namespace app\admin\validate;

use think\Validate;

class AdminChangePasswordValidate extends Validate
{
    protected $rule = [
        'old_password' => 'require|min:8|max:128',
        'new_password' => 'require|min:8|max:128|different:old_password',
    ];

    protected $message = [
        'old_password.require' => '旧密码不能为空',
        'old_password.min'     => '旧密码至少8位',
        'new_password.require' => '新密码不能为空',
        'new_password.min'     => '新密码至少8位',
        'new_password.different'=> '新密码不能与旧密码相同',
    ];
}
