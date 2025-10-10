<?php
namespace app\common\contracts;


interface SimpleCacheInterface
{
    public function get(string $key, $default = null);
    public function set(string $key, $value, int $ttl = 0): bool;
    public function has(string $key): bool;
    public function delete(string $key): bool; // 与 think\Cache 的 del/pull 行为对齐
    public function pull(string $key); // 取出并删除，若实现不支持，可 get+delete
    public function ttl(string $key): int; // 剩余过期秒数，不支持则返回 -1
}