<?php
namespace app\common\contracts;


interface ClockInterface
{
    public function now(): int; // unix timestamp
}