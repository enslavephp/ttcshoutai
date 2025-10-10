<?php
namespace app\common\util;


class Crypto
{
    public static function secureJti(int $bytes = 16): string
    {
        return bin2hex(random_bytes($bytes));
    }
}