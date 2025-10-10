<?php
declare(strict_types=1);

namespace app\admin\controller\secure;

use app\BaseController;
use think\facade\Request;
use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\admin\service\AdminSensitiveOperationService;

/**
 * 敏感操作二次确认控制器
 * - 端点：POST /admin/secure/confirm/verify
 * - Header 需携带 admin access（6 小时）
 */
class Confirm extends BaseController
{
    private ?TokenService $tokenService = null;

    private function tokenSvc(): TokenService
    {
        if ($this->tokenService === null) {
            $this->tokenService = new TokenService(
                new CacheFacadeAdapter(),
                new \app\common\util\SystemClock(),
                config('jwt') ?: []
            );
        }
        return $this->tokenService;
    }

    /** 确认：把 pending_token 置为已确认 */
    public function verify()
    {
        // 认证
        $auth = Request::header('Authorization') ?: '';
        $raw  = stripos($auth, 'Bearer ') === 0 ? substr($auth, 7) : '';
        if (!$raw) return $this->jsonResponse('未登录', 401, 'error');

        try {
            $claims = $this->tokenSvc()->parse($raw);
        } catch (\Throwable $e) {
            return $this->jsonResponse('会话无效', 401, 'error');
        }
        if (($claims->realm ?? '') !== 'admin') {
            return $this->jsonResponse('非法领域', 403, 'error');
        }
        $adminId = (int)($claims->user_id ?? 0);
        if ($adminId <= 0) return $this->jsonResponse('会话异常', 401, 'error');

        // 参数
        $token = (string)(Request::post('confirmation_token') ?? Request::get('confirmation_token') ?? '');
        if ($token === '') {
            return $this->jsonResponse('缺少 confirmation_token', 422, 'error');
        }

        // 执行确认
        $svc = new AdminSensitiveOperationService();
        $ok  = $svc->confirm($adminId, $token);
        if (!$ok) {
            return $this->jsonResponse('确认失败或已过期', 400, 'error');
        }

        return $this->jsonResponse('确认成功', 200, 'success');
    }
}
