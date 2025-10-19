<?php
//------------------------------------------------------------
// File: app/shop/model/UserAddresses.php
namespace app\shop\model;


use think\Model;
use think\facade\Db;


class UserAddresses extends Model
{
    protected $table = 'user_addresses';


    protected $autoWriteTimestamp = 'datetime';
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';
    protected $dateFormat = 'Y-m-d H:i:s';


// 返回 JSON/数组时隐藏二进制 POINT 字段，避免 UTF-8 编码错误（Malformed UTF-8）
    protected $hidden = ['location'];


// 关系：所属用户
    public function user()
    {
        return $this->belongsTo(Users::class, 'user_id', 'id');
    }


    /**
     * 在写入时由经纬度拼接 POINT(longitude, latitude) 到 location 字段
     * - 符合“应用层/Model 拼接”的约定
     * - 注意经度在前、纬度在后
     */
    protected static function onBeforeInsert($model)
    {
        if (!is_null($model->longitude) && !is_null($model->latitude)) {
            $lng = (float) $model->longitude;
            $lat = (float) $model->latitude;
            $model->setAttr('location', Db::raw(sprintf('POINT(%F,%F)', $lng, $lat)));
        }
    }

    protected static function onBeforeUpdate($model)
    {
        $changed = method_exists($model, 'getChangedData') ? $model->getChangedData() : [];
        if (array_key_exists('longitude', $changed) || array_key_exists('latitude', $changed)) {
            $lng = (float) $model->longitude;
            $lat = (float) $model->latitude;
            $model->setAttr('location', Db::raw(sprintf('POINT(%F,%F)', $lng, $lat)));
        }
    }


    /**
     * 取某用户最新的“默认地址”一条（按 updated_at DESC, id DESC）
     */
    public static function latestDefaultByUser(int $userId)
    {
        return self::where('user_id', $userId)
            ->where('is_default', 1)
            ->order(['updated_at' => 'desc', 'id' => 'desc'])
            ->find();
    }


    /**
     * 取某用户最近编辑/使用的地址（不限定默认）
     */
    public static function latestByUser(int $userId)
    {
        return self::where('user_id', $userId)
            ->order(['updated_at' => 'desc', 'id' => 'desc'])
            ->find();
    }


    /**
     * 半径检索（公里）：经纬度列计算（哈弗辛）+ 使用 SPATIAL 索引做矩形预筛
     * 返回数组（含 distance_km 字段）
     */
    public static function findNearby(float $lat0, float $lon0, float $radiusKm = 5, int $limit = 50): array
    {
// 1) 预筛选矩形（快速缩小范围）
        $latDelta = $radiusKm / 111.32;
        $lonDelta = $radiusKm / (111.32 * cos(deg2rad($lat0)));
        $latMin = $lat0 - $latDelta; $latMax = $lat0 + $latDelta;
        $lonMin = $lon0 - $lonDelta; $lonMax = $lon0 + $lonDelta;


// 2) 用 location 的 SPATIAL 索引做 MBR 矩形预筛（WKT 经度在前、纬度在后）
        $poly = sprintf(
            'POLYGON((%F %F,%F %F,%F %F,%F %F,%F %F))',
            $lonMin, $latMin,
            $lonMin, $latMax,
            $lonMax, $latMax,
            $lonMax, $latMin,
            $lonMin, $latMin
        );

// 3) 哈弗辛公式精确距离（公里）
        $distanceExpr = '(
6371 * 2 * ASIN(
SQRT(
POW(SIN(RADIANS(:lat - latitude)/2), 2) +
COS(RADIANS(latitude)) * COS(RADIANS(:lat)) *
POW(SIN(RADIANS(:lon - longitude)/2), 2)
)
)
)';


        $query = self::whereBetween('latitude', [$latMin, $latMax])
            ->whereBetween('longitude', [$lonMin, $lonMax])
            ->whereRaw("MBRContains(ST_GeomFromText('{$poly}'), location)")
            ->field("id,user_id,province,city,district,street_address,latitude,longitude,{$distanceExpr} AS distance_km")
            ->bind(['lat' => $lat0, 'lon' => $lon0])
            ->order('distance_km', 'asc')
            ->limit($limit);


        $list = $query->select();
        return $list ? $list->toArray() : [];
    }
}