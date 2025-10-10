<?php
namespace app\shop\validate;

use think\Validate;

class CartValidate extends Validate
{
    // 验证规则
    protected $rule = [
        'product_id' => 'require|integer',
        'quantity'   => 'require|integer|gt:0',
        'cart_id'    => 'integer|gt:0',
    ];

    // 错误提示
    protected $message = [
        'product_id.require' => '商品 ID 不能为空',
        'product_id.integer' => '商品 ID 必须是整数',
        'quantity.require'   => '商品数量不能为空',
        'quantity.integer'   => '商品数量必须是整数',
        'quantity.gt'        => '商品数量必须大于 0',
        'cart_id.integer'    => '购物车条目 ID 必须是整数',
        'cart_id.gt'         => '购物车条目 ID 必须大于 0',
    ];

    // 验证场景
    protected $scene = [
        'add'    => ['product_id', 'quantity'],
        'update' => ['cart_id', 'quantity'],
        'remove' => ['cart_id'],
    ];
}

