<?php
// app/common/Helper.php
namespace app\common;
use app\common\model\SysConfig;
use think\facade\Cache;

class Helper
{
    public static  function  getValue(string $key, $default = null, $relation = false)
    {
        $key = strtolower($key); // 统一小写，避免大小写重复
        $cacheKey = 'sys_config:' . $key;

        if (Cache::has($cacheKey)) {
            return Cache::get($cacheKey);
        }
        /** @var SysConfig|null $row */
        $row = SysConfig::where('config_key', $key)->find();
        if ($row) {
            $val = \app\common\Helper::castValue((string)$row->config_value, (string)$row->value_type);
            Cache::set($cacheKey, $val, 300); // 缓存 5 分钟，可按需调整/改用 Redis tag
            return $val;
        }

        return $default;
    }

    /** 应用层类型转换 */
    protected static function castValue(string $v, string $type)
    {
        switch ($type) {
            case 'int':  return (int)$v;
            case 'bool': return in_array(strtolower($v), ['1','true','on','yes'], true);
            case 'json': return json_decode($v, true) ?: [];
            default:     return $v;
        }
    }
}