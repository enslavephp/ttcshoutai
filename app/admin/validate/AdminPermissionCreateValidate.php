<?php
declare(strict_types=1);

namespace app\admin\validate;

use think\Validate;

class AdminPermissionCreateValidate extends Validate
{
    protected $rule = [
        'code'          => ['require', 'regex' => '/^[A-Za-z0-9_.-]{1,64}$/'],
        'name'          => 'require|max:64',
        'description'   => 'max:255',
        'resource_type' => 'require|max:32',
        'resource_id'   => 'max:128',
        'action'        => 'require|max:32',
    ];

    protected $message = [
        'code.require'  => 'code 不能为空',
        'code.regex'    => 'code 仅允许字母、数字、下划线(_)、中划线(-)、点号(.)，且不超过64位',
        'name.require'  => 'name 不能为空',
        'name.max'      => 'name 长度超限',
        'description.max'   => 'description 长度超限',
        'resource_type.require' => 'resource_type 不能为空',
        'resource_type.max'     => 'resource_type 长度超限',
        'resource_id.max'       => 'resource_id 长度超限',
        'action.require'        => 'action 不能为空',
        'action.max'            => 'action 长度超限',
    ];
}
