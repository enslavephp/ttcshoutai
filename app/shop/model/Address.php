<?php
namespace app\shop\model;
use think\Model;
class Address extends Model
{
    // 数据表名称
    protected $table = 'user_addresses';

    // 自动隐藏的字段
    protected $hidden = ['location'];
    // 主键
    protected $pk = 'id';

    // 自动写入时间戳字段
    protected $autoWriteTimestamp = true;

    // 定义时间戳字段名
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    // 数据转换类型
    protected $type = [
        'latitude'  => 'float',
        'longitude' => 'float',
    ];

    // 定义一对一关联用户（可选）
    public function user()
    {
        return $this->belongsTo(Users::class, 'user_id', 'id');
    }

    /**
     * 获取默认地址
     * @param int $userId
     * @return Address|null
     */
    public static function getDefaultAddress(int $userId)
    {
        return self::where('user_id', $userId)
            ->where('is_default', 1)
            ->find();
    }

    /**
     * 保存地址时，确保只有一个默认地址
     */
    public static function setDefaultAddress($userId, $addressId)
    {
        // 先将其他地址设置为非默认
        self::where('user_id', $userId)
            ->where('id', '<>', $addressId)
            ->update(['is_default' => 0]);

        // 设置当前地址为默认
        self::where('id', $addressId)->update(['is_default' => 1]);
    }
}
