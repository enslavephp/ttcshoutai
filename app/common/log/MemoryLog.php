<?php
namespace app\common\log;

use think\log\driver\File;

class MemoryLog extends File
{
    protected static $logs = [];

    // 重写记录方法
    public function save(array $log): bool
    {
        // 将日志保存到静态变量中
        self::$logs[] = $log;

        // 调用父类方法，将日志写入文件
        return parent::save($log);
    }

    // 获取全部日志
    public static function getLog()
    {
        return self::$logs;
    }
}
