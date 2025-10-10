<?php

namespace app\shop\model;

use think\Model;

class Shops extends Model
{
    // 指定主键
    protected $pk = 'shop_id';

    // 指定数据表
    protected $table = 'shops';

    // 设置自动写入时间戳
    protected $autoWriteTimestamp = 'datetime';
    /**
     * 获取启用状态的商户
     */
    public static function getEnabledShops()
    {
        return self::where('status', 1)->select()->toArray();
    }

    /**
     * 根据关键字搜索商户
     */
    public static function searchShops($keyword = null)
    {
        $query = self::order('created_at', 'desc');
        if ($keyword) {
            $query->whereLike('shop_name', "%$keyword%");
        }
        return $query->select()->toArray();
    }

    /**
     * 按分页获取商户列表
     */
    public static function getPaginatedShops($page = 1, $limit = 10)
    {
        return self::paginate([
            'list_rows' => $limit,
            'page'      => $page,
        ]);
    }
}