<?php


//------------------------------------------------------------
// File: app/shop/validate/AddressValidate.php
namespace app\shop\validate;

use think\Validate;

class AddressValidate extends Validate
{
    protected $rule = [
        // 主键（仅更新场景）
        'id'             => 'integer',
        // 行政区划
        'province'       => 'max:50',
        'city'           => 'max:50',
        'district'       => 'max:50',
        // 详细地址
        'street_address' => 'max:255',
        'address_line'   => 'max:255',
        // 联系方式
        'recipient_name' => 'max:50',
        'tel'            => 'regex:/^1\\d{10}$/',
        'zipcode'        => 'regex:/^\\d{6}$/',
        // 默认标记
        'is_default'     => 'in:0,1',
        // 经纬度
        'latitude'       => 'number|between:-90,90',
        'longitude'      => 'number|between:-180,180',
    ];

    protected $message = [
        'id.integer'                => 'ID 格式错误',
        'province.max'              => '省份长度不能超过50',
        'city.max'                  => '城市长度不能超过50',
        'district.max'              => '区/县长度不能超过50',
        'street_address.max'        => '详细地址长度不能超过255',
        'address_line.max'          => '补充地址长度不能超过255',
        'recipient_name.max'        => '收货人姓名长度不能超过50',
        'tel.regex'                 => '联系电话格式不正确，应为中国大陆 11 位手机号（无国家码）',
        'zipcode.regex'             => '邮政编码应为 6 位数字',
        'is_default.in'             => '默认标记只能为 0 或 1',
        'latitude.number'           => '纬度必须为数字',
        'latitude.between'          => '纬度范围应在 -90 到 90',
        'longitude.number'          => '经度必须为数字',
        'longitude.between'         => '经度范围应在 -180 到 180',
    ];

    protected $scene = [
        // 创建：核心字段必填 + 经纬度必填
        'create' => [
            'province'       => 'require|max:50',
            'city'           => 'require|max:50',
            'district'       => 'require|max:50',
            'street_address' => 'require|max:255',
            'recipient_name' => 'require|max:50',
            'tel'            => 'require|regex:/^1\\d{10}$/',
            'zipcode',
            'is_default',
            'latitude'       => 'require|number|between:-90,90',
            'longitude'      => 'require|number|between:-180,180',
        ],
        // 更新：允许部分字段更新；若修改经纬度，必须成对出现
        'update' => [
            'id'             => 'require|integer',
            'province', 'city', 'district', 'street_address', 'address_line',
            'recipient_name', 'tel', 'zipcode', 'is_default',
            'latitude'  => 'number|between:-90,90',
            'longitude' => 'number|between:-180,180',
        ],
    ];

    // 额外的成对约束：更新时若出现一个坐标则必须另一个也出现
    public function sceneUpdate()
    {
        return $this->only(array_keys($this->rule))
            ->append('id', 'require|integer')
            ->remove('latitude', 'require')
            ->remove('longitude', 'require')
            ->checkPair();
    }

    protected function checkPair()
    {
        $this->extend('pairCoord', function ($value, $rule, $data) {
            $hasLat = array_key_exists('latitude', $data) && $data['latitude'] !== '';
            $hasLon = array_key_exists('longitude', $data) && $data['longitude'] !== '';
            return ($hasLat === $hasLon) ? true : '更新经纬度时必须同时提供 latitude 与 longitude';
        });
        $this->append('latitude', 'pairCoord');
        $this->append('longitude', 'pairCoord');
        return $this;
    }
}

