<?php
namespace app\common\service;


interface WeChatClientInterface
{
    /**
     * @return array{session_key:string, openid:string}
     */
    public function code2Session(string $code): array;
}