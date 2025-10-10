<?php
namespace app\common\infra;


use app\common\contracts\SimpleCacheInterface;
use think\facade\Cache;


class CacheFacadeAdapter implements SimpleCacheInterface
{
    public function get(string $key, $default = null)
    {
        return Cache::get($key, $default);
    }


    public function set(string $key, $value, int $ttl = 0): bool
    {
        return Cache::set($key, $value, $ttl > 0 ? $ttl : null);
    }


    public function has(string $key): bool
    {
        return Cache::has($key);
    }


    public function delete(string $key): bool
    {
        return (bool) Cache::delete($key);
    }


    public function pull(string $key)
    {
        $val = Cache::get($key);
        Cache::delete($key);
        return $val;
    }


    public function ttl(string $key): int
    {
// ThinkPHP 以 TTL API 的可用性为准，这里尝试兼容
        try {
            return Cache::ttl($key);
        } catch (\Throwable $e) {
            return -1; // 不支持 TTL 则返回 -1
        }
    }
}