<?php
declare(strict_types=1);

namespace app\admin\controller;

use app\BaseController;

use think\facade\Request;

class Config extends BaseController
{
    public function get()
    {
        $key = strtolower((string)Request::param('key', ''));
        if ($key === '') return $this->jsonResponse('缺少 key', 422, 'error');

        $val = \app\common\Helper::getValue($key, null);
        return $this->jsonResponse('OK', 200, 'success', ['key' => $key, 'value' => $val]);
    }

    public function set()
    {
        $key   = strtolower((string)Request::param('key', ''));
        $value = Request::param('value', null);

        if ($key === '') return $this->jsonResponse('缺少 key', 422, 'error');

        // 仅示例：针对特定键做白名单校验
        if ($key === 'permission.level_order' && !in_array($value, ['asc','desc'], true)) {
            return $this->jsonResponse('参数不合法（仅支持 asc/desc）', 422, 'error');
        }

        SysConfig::setValue($key, $value, is_array($value) ? 'json' : 'string');
        return $this->jsonResponse('OK', 200, 'success');
    }
}
