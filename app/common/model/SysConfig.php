<?php
declare(strict_types=1);

namespace app\common\model;

use think\Model;
use think\facade\Cache;

class SysConfig extends Model
{
    protected $name = 'sys_config';
    protected $pk   = 'id';
    // 时间戳字段名与类型
    protected $autoWriteTimestamp = 'timestamp';
    protected $createTime = 'created_at';
    protected $updateTime = 'updated_at';

    /** 读取配置（DB → 缓存 → 默认值） */
    public function  getValue(string $key, $default = null, $relation = false)
    {
        $key = strtolower($key); // 统一小写，避免大小写重复
        $cacheKey = 'sys_config:' . $key;

        if (Cache::has($cacheKey)) {
            return Cache::get($cacheKey);
        }

        /** @var SysConfig|null $row */
        $row = self::where('config_key', $key)->find();
        if ($row) {
            $val = self::castValue((string)$row->config_value, (string)$row->value_type);
            Cache::set($cacheKey, $val, 300); // 缓存 5 分钟，可按需调整/改用 Redis tag
            return $val;
        }

        return $default;
    }

    /** 写入/更新配置（带缓存失效） */
    public static function setValue(string $key, $value, string $type = 'string'): bool
    {
        $key = strtolower($key);

        // 业务校验示例：限制 permission.level_order 只能 asc/desc
        if ($key === 'permission.level_order' && !in_array($value, ['asc','desc'], true)) {
            throw new \InvalidArgumentException('permission.level_order 仅支持 asc / desc');
        }

        $store = ($type === 'json')
            ? json_encode($value, JSON_UNESCAPED_UNICODE)
            : (string)$value;

        $exists = self::where('config_key', $key)->find();
        if ($exists) {
            $exists->save(['config_value' => $store, 'value_type' => $type]);
        } else {
            self::create([
                'config_key'   => $key,
                'config_value' => $store,
                'value_type'   => $type,
                'group_name'   => explode('.', $key)[0] ?? 'default',
            ]);
        }
        Cache::delete('sys_config:' . $key);
        return true;
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
