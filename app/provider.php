<?php
use app\ExceptionHandle;
use app\Request;
// app/provider.php
use app\common\service\WeChatClientInterface;
use app\common\service\WeChatClient;
// 容器Provider定义文件
return [
    'think\Request'          => Request::class,
    'think\exception\Handle' => ExceptionHandle::class,
    WeChatClientInterface::class => WeChatClient::class,
];
