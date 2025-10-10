<?php
namespace app;

use Swoole\Http\Server;
use app\common\DatabasePool;

class HttpServer
{
    public function start()
    {
        $server = new Server('127.0.0.1', 9501);

        $server->on('Request', function ($request, $response) {
            $dbPool = DatabasePool::getInstance();
            $connection = $dbPool->getConnection();

            try {
                $statement = $connection->query('SELECT * FROM users');
                $result = $statement->fetchAll(\PDO::FETCH_ASSOC);
                $response->end(json_encode($result));
            } finally {
                $dbPool->releaseConnection($connection);
            }
        });

        $server->start();
    }
}
