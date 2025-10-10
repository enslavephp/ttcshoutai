<?php
namespace app\shop\controller\userlogin;

use app\BaseController;

class Index extends BaseController
{
    public function index()
    {
        return 'shop';
    }

    public function hello($name = 'ThinkPHP6')
    {
        return 'hello,' . $name;
    }
}
