<?php
namespace app\common;

use Swoole\Database\PDOConfig;
use Swoole\Database\PDOPool;

class DatabasePool
{
    private static $instance;
    private $pool;

    private function __construct()
    {
        // 配置数据库连接
        $config = (new PDOConfig())
            ->withHost(env('database.hostname', '127.0.0.1'))
            ->withPort(env('database.hostport', 3306))
            ->withDbname(env('database.database', 'test'))
            ->withCharset('utf8mb4')
            ->withUsername(env('database.username', 'root'))
            ->withPassword(env('database.password', '12345678'));

        // 创建连接池
        $this->pool = new PDOPool($config, 10); // 最大连接数为 10
    }

    // 单例模式，确保只有一个连接池实例
    public static function getInstance(): self
    {
        if (!self::$instance) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    // 获取连接
    public function getConnection()
    {
        return $this->pool->get();
    }

    // 释放连接
    public function releaseConnection($connection)
    {
        $this->pool->put($connection);
    }

    // 关闭连接池
    public function __destruct()
    {
        $this->pool->close();
    }
}
