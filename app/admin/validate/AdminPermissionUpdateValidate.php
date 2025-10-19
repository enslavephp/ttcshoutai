<?php
declare(strict_types=1);

namespace app\admin\validate;

use think\Validate;

class AdminPermissionUpdateValidate extends Validate
{
    protected $rule = [
        'id'            => 'require|integer',
        'code'          => ['regex' => '/^[A-Za-z0-9_.-]{1,64}$/'],
        'name'          => 'max:64',
        'description'   => 'max:255',
        'resource_type' => 'max:32',
        'resource_id'   => 'max:128',
        'action'        => 'max:32',
    ];

    protected $message = [
        'id.require'    => 'id 不能为空',
        'id.integer'    => 'id 格式错误',
        'code.regex'    => 'code 仅允许字母、数字、下划线(_)、中划线(-)、点号(.)，且不超过64位',
        'name.max'      => 'name 长度超限',
        'description.max'   => 'description 长度超限',
        'resource_type.max' => 'resource_type 长度超限',
        'resource_id.max'   => 'resource_id 长度超限',
        'action.max'        => 'action 长度超限',
    ];
}
