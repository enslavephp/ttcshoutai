<?php
namespace app\shop\controller\shop;

use app\shop\model\Shops;
use app\BaseController;


class Shop extends BaseController
{
    private $SHOP_STATUS;

    public function __construct()
    {
        $this->SHOP_STATUS = 1; // 默认显示正常运营的店铺
    }
    /**
     * 获取所有商户信息
     */
    public function index(\think\Request $request)
    {
        // 按条件筛选商户
        $conditions = [];
        if ($this->SHOP_STATUS !== null) {
            $conditions['status'] = $this->SHOP_STATUS;
        }
        $shop_data = Shops::where($conditions)->select()->toArray();

        return $this->jsonResponse('获取商家列表成功', 200, 'success', $shop_data);
    }
}
