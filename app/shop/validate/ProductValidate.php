<?php
namespace app\shop\validate;

use think\Validate;

class ProductValidate extends Validate
{
    // 定义验证规则
    protected $rule = [
        'name' => 'require|max:255',
        'sku' => 'require',  // 修改为自定义校验函数
        'shop_id' => 'require|integer|gt:0',  // 校验 shop_id 是否有效
        'price' => 'require|float|>=:0',
        'stock' => 'require|integer|>=:0',
        'categories' => 'array',
        'categories.*' => 'integer|exists:categories,id',
        'tags' => 'array',
        'tags.*' => 'integer|exists:tags,id',
        'image' => 'file|image|max:2048',  // 添加图片验证规则
        'delete_image' => 'in:0,1',        // 校验 delete_image 是否有效
    ];

    // 定义错误提示
    protected $message = [
        'name.require' => '商品名称不能为空',
        'name.max' => '商品名称长度不能超过255个字符',
        'sku.require' => '商品编码不能为空',
        'shop_id.require' => '商店 ID 不能为空',
        'shop_id.integer' => '商店 ID 必须为整数',
        'shop_id.gt' => '商店 ID 必须大于0',
        'price.require' => '价格不能为空',
        'price.float' => '价格必须是数字',
        'price.>=' => '价格不能为负数',
        'stock.require' => '库存不能为空',
        'stock.integer' => '库存必须是整数',
        'stock.>=' => '库存不能为负数',
        'categories.array' => '分类必须是数组',
        'categories.*.integer' => '分类ID必须是整数',
        'categories.*.exists' => '分类ID不存在',
        'tags.array' => '标签必须是数组',
        'tags.*.integer' => '标签ID必须是整数',
        'tags.*.exists' => '标签ID不存在',
        'image.file' => '图片必须是文件类型',
        'image.image' => '上传的文件必须是图片',
        'image.max' => '图片大小不能超过2MB',
        'delete_image.in' => '删除图片参数无效，必须为0或1',
    ];

    // 场景验证规则
    protected $scene = [
        // 更新时验证所有字段，包括图片
        'update' => ['name', 'sku', 'shop_id', 'price', 'stock', 'categories', 'tags', 'image', 'delete_image'],

        // 更新时不验证图片字段
        'update_without_image' => ['name', 'sku', 'shop_id', 'price', 'stock', 'categories', 'tags', 'delete_image'],

        // 新建时验证所有字段
        'create' => ['name', 'sku', 'shop_id', 'price', 'stock', 'categories', 'tags', 'image'],
    ];
}
