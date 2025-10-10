<?php
namespace app\shop\validate;

use app\shop\model\Shops;
use think\Validate;

class CategoryValidate extends Validate
{
    // 定义验证规则
    protected $rule = [
        'name'    => 'require|max:255|unique:categories', // 分类名称唯一性校验
        'image'   => 'file|image|max:2048',              // 图片校验
        'shop_id' => 'require|checkShopExists',           // 自定义规则校验商户
        'weight'  => 'integer|>=:0',                      // 权重必须是非负整数
    ];

    // 不验证图片字段的规则（用于更新时）
    protected $scene = [
        'update' => ['name', 'image', 'shop_id', 'weight'],
        'update_without_image' => ['name', 'shop_id', 'weight'], // 更新时不验证图片
    ];

    // 定义错误提示
    protected $message = [
        'name.require'    => '分类名称不能为空',
        'name.max'        => '分类名称不能超过255个字符',
        'name.unique'     => '分类名称已存在，请使用其他名称',
        'shop_id.require' => '商户 ID 不能为空',
        'shop_id.checkShopExists' => '商户 ID 不存在，请提供有效的商户',
        'weight.integer'  => '权重必须是整数',
        'weight.>='       => '权重不能为负数',
        'image.file'      => '图片必须是文件类型',
        'image.image'     => '上传文件必须是图片',
        'image.max'       => '图片大小不能超过2MB',
    ];

    protected $default = [
        'weight' => 99, // 设置默认权重
    ];

    // 自定义规则：校验商户是否存在
    protected function checkShopExists($value, $rule, $data = [])
    {
        return Shops::find($value) ? true : false;
    }
}