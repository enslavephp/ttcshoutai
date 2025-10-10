<?php
declare(strict_types=1);

namespace app\admin\validate;

use think\Validate;
use think\facade\Request;

class ShopAdminMerchantValidate extends Validate
{
    // 规则
    protected $rule = [
        'merchant_name'  => 'require|max:100|unique:shopadmin_merchant,merchant_name',
        'merchant_code'  => 'require|max:50|unique:shopadmin_merchant,merchant_code',
        'contact_person' => 'require|max:50',
        'contact_phone'  => 'require|regex:^1[3-9]\\d{9}$', // 仅大陆11位手机号
        'province'       => 'require|max:50',
        'city'           => 'require|max:50',
        'address'        => 'require|max:255',
        'status'         => 'in:0,1',
    ];

    // 提示
    protected $message = [
        'merchant_name.require'     => '商户名称不能为空',
        'merchant_name.max'         => '商户名称不能超过100个字符',
        'merchant_name.unique'      => '商户名称已存在',

        'merchant_code.require'     => '商户编码不能为空',
        'merchant_code.max'         => '商户编码不能超过50个字符',
        'merchant_code.unique'      => '商户编码已存在',

        'contact_person.require'    => '联系人不能为空',
        'contact_person.max'        => '联系人不能超过50个字符',

        'contact_phone.require'     => '联系电话不能为空',
        'contact_phone.regex'       => '联系电话格式不正确，需为11位大陆手机号，如：13800138000',

        'email.regex'               => '电子邮箱格式不正确',
        'email.max'                 => '电子邮箱不能超过100个字符',

        'province.require'          => '省份不能为空',
        'province.max'              => '省份不能超过50个字符',

        'city.require'              => '城市不能为空',
        'city.max'                  => '城市不能超过50个字符',

        'address.require'           => '详细地址不能为空',
        'address.max'               => '详细地址不能超过255个字符',

        'status.in'                 => '状态只能是 0 或 1',
    ];

    // 场景
    protected $scene = [
        'create' => ['merchant_name', 'merchant_code', 'contact_person', 'contact_phone', 'email', 'province', 'city', 'address', 'status'],
        'update' => ['merchant_name', 'merchant_code', 'contact_person', 'contact_phone', 'email', 'province', 'city', 'address', 'status'],
    ];

    // 为 update 场景动态忽略自身记录（避免把自己当重复）
    public function sceneUpdate()
    {
        $id = (int)(Request::post('id') ?? 0);
        return $this->only($this->scene['update'])
            ->append('merchant_name', "unique:shopadmin_merchant,merchant_name,{$id},id")
            ->append('merchant_code', "unique:shopadmin_merchant,merchant_code,{$id},id");
    }
}
