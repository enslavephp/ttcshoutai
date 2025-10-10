<?php
namespace app\shop\validate;

use think\Validate;

class TagValidate extends Validate
{
    protected $rule = [
        'name'  => 'require|max:255|unique:tags',
        'weight' => 'integer',
    ];

    protected $message = [
        'name.require' => '标签名称必须填写',
        'name.max' => '标签名称不能超过255个字符',
        'name.unique' => '标签名称已存在',
        'weight.integer' => '权重必须为整数',
    ];

    protected $scene = [
        'create' => ['name', 'weight'],
        'update' => ['name', 'weight'],
    ];
}
