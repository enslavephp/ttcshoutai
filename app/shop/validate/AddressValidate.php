<?php
namespace app\shop\validate;

use think\Validate;

class AddressValidate extends Validate
{
    // 定义验证规则
    protected $rule = [
        'full_address'   => 'require|max:1024', // 必须提供完整地址，限制长度
        'full_address_name'        => 'require|max:255', // 必须提供详细地址，限制长度
        'address'        => 'require|max:255', // 必须提供详细地址，限制长度
        'tel'            => 'require|mobile',  // 必须是有效的手机号
//        'zipcode'        => 'number|length:6', // 邮政编码必须是6位数字
        'recipient_name' => 'require|max:255', // 收货人姓名
        'is_default'     => 'in:0,1',          // 是否默认地址只能是0或1
        'latitude'       => 'require|float|between:-90,90', // 纬度值在[-90, 90]之间
        'longitude'      => 'require|float|between:-180,180', // 经度值在[-180, 180]之间
    ];

    // 定义验证提示信息
    protected $message = [
        'full_address.require'   => '完整地址不能为空',
        'full_address.max'       => '完整地址不能超过1024个字符',
        'full_address_name.require'   => '完整地址名称不能为空',
        'full_address_name.max'       => '完整地址名称不能超过255个字符',
        'address.require'        => '详细地址不能为空',
        'address.max'            => '详细地址不能超过255个字符',
        'tel.require'            => '联系电话不能为空',
        'tel.mobile'             => '联系电话格式不正确',
//        'zipcode.number'         => '邮政编码必须是数字',
//        'zipcode.length'         => '邮政编码必须是6位数字',
        'recipient_name.require' => '收货人姓名不能为空',
        'recipient_name.max'     => '收货人姓名不能超过255个字符',
        'is_default.in'          => '默认地址标志必须是0或1',
        'latitude.require'       => '纬度不能为空',
        'latitude.float'         => '纬度必须是浮点数',
        'latitude.between'       => '纬度必须在-90到90之间',
        'longitude.require'      => '经度不能为空',
        'longitude.float'        => '经度必须是浮点数',
        'longitude.between'      => '经度必须在-180到180之间',
    ];

    // 场景验证
    protected $scene = [
//        , 'zipcode'
        'create' => ['user_id', 'full_address', 'full_address_name', 'address', 'tel', 'recipient_name', 'is_default', 'latitude', 'longitude'],
        'update' => ['id'],
    ];
}

