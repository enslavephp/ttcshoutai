<?php
declare(strict_types=1);

namespace app\shopadmin\validate;

use think\Validate;

class ShopAdminLoginValidate extends Validate
{
    protected $rule = [
        'username'       => 'require|max:64',
        'password'       => 'require|max:128',

        // 三选一的商户标识（格式放宽以兼容你的实际使用）
        'merchant_id'    => 'number',
        'merchant_code'  => 'max:64',
        'merchant_name'  => 'max:128',
    ];

    protected $message = [
        'username.require'      => '用户名不能为空',
        'username.max'          => '用户名长度超限',
        'password.require'      => '密码不能为空',
        'password.max'          => '密码长度超限',
        'merchant_id.number'    => 'merchant_id 必须是数字',
        'merchant_code.max'     => 'merchant_code 长度超限',
        'merchant_name.max'     => 'merchant_name 长度超限',
    ];

    /**
     * 覆写校验：强制至少提供一个商户标识
     */
    public function check($data, $rules = [], $scene = ''): bool
    {
        $ok = parent::check($data, $rules, $scene);
        if (!$ok) {
            return false;
        }

        if (
            empty($data['merchant_id']) &&
            empty($data['merchant_code']) &&
            empty($data['merchant_name'])
        ) {
            $this->error = '请提供商户标识：merchant_id / merchant_code / merchant_name 其一';
            return false;
        }

        return true;
    }
}
