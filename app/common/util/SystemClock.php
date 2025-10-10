<?php
namespace app\common\util;


use app\common\contracts\ClockInterface;


class SystemClock implements ClockInterface
{
    public function now(): int
    {
        return time();
    }
}