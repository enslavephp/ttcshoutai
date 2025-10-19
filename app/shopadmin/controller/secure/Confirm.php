<?php
declare(strict_types=1);

namespace app\shopadmin\controller\secure;

use app\BaseController;
use think\facade\Request;
use think\facade\Log;

use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;

use app\shopadmin\service\ShopAdminSensitiveOperationService;

/**
 * 【商户侧】敏感操作二次确认
 * Endpoint:
 *   POST /shopadmin/secure/confirm/initiate  发起确认，返回 confirmation_token
 *   POST /shopadmin/secure/confirm/verify    提交 token 确认
 *   POST /shopadmin/secure/confirm/check     校验 token 是否“已确认且有效”
 * Header: Authorization: Bearer <shopadmin access>  （realm=shopadmin）
 * 关键点：
 *  - 强制按 merchant_id 租户隔离
 *  - 严格绑定当前商户、当前管理员
 */
class Confirm extends BaseController
{
    private ?TokenService $tokenService = null;

    private function tokenSvc(): TokenService
    {
        if ($this->tokenService === null) {
            // 初始化 TokenService 用于生成和验证 JWT token
            $jwtSecret = (string)(\app\common\Helper::getValue('jwt.secret') ?? 'PLEASE_CHANGE_ME');
            $jwtCfg['secret'] = $jwtSecret;

            $this->tokenService = new TokenService(
                new CacheFacadeAdapter(),
                new SystemClock(),
                $jwtCfg
            );
        }
        return $this->tokenService;
    }

    /**
     * 解析并校验 shopadmin 会话
     * @return array [merchantId, adminId, errorResponse|null]
     */
    private function requireShopadminAuth(): array
    {
        $auth = Request::header('Authorization') ?: '';
        $raw  = stripos($auth, 'Bearer ') === 0 ? substr($auth, 7) : '';
        if (!$raw) return [0, 0, $this->jsonResponse('未登录', 401, 'error')];

        try {
            $claims = $this->tokenSvc()->parse($raw);
        } catch (\Throwable $e) {
            return [0, 0, $this->jsonResponse('会话无效', 401, 'error')];
        }

        if (($claims->realm ?? '') !== 'shopadmin') {
            return [0, 0, $this->jsonResponse('非法领域', 403, 'error')];
        }

        $merchantId = (int)($claims->merchant_id ?? 0);
        $adminId    = (int)($claims->user_id ?? 0);
        if ($merchantId <= 0 || $adminId <= 0) {
            return [0, 0, $this->jsonResponse('会话缺少租户标识', 401, 'error')];
        }
        return [$merchantId, $adminId, null];
    }

    /**
     * 发起确认：返回 confirmation_token
     * 入参（POST）：
     *  - operation_type   string   必填
     *  - operation_data   object|string  可选（字符串时按 JSON 尝试解码）
     *  - ttl_seconds      int      可选，默认 300，区间建议 60~3600
     */
    public function initiate()
    {
        [$merchantId, $adminId, $err] = $this->requireShopadminAuth();
        if ($err) return $err;

        $opType = (string)(Request::post('operation_type') ?? '');
        if ($opType === '') return $this->jsonResponse('缺少 operation_type', 422, 'error');

        $rawData = Request::post('operation_data');
        if (is_string($rawData) && $rawData !== '') {
            $decoded = json_decode($rawData, true);
            $opData  = is_array($decoded) ? $decoded : ['raw' => $rawData];
        } elseif (is_array($rawData)) {
            $opData = $rawData;
        } else {
            $opData = [];
        }

        $ttl = (int)(Request::post('ttl_seconds') ?? 300);
        $ttl = max(60, min(3600, $ttl)); // 企业缺省策略：1~60分钟

        try {
            $svc   = new ShopAdminSensitiveOperationService();
            $token = $svc->initiate($merchantId, $adminId, $opType, $opData, $ttl);
        } catch (\Throwable $e) {
            Log::error('shopadmin.secure.confirm.initiate failed: '.$e->getMessage());
            return $this->jsonResponse('发起失败', 500, 'error');
        }

        return $this->jsonResponse('已发起确认', 200, 'success', [
            'confirmation_token' => $token,
            'expires_in'         => $ttl
        ]);
    }

    /** 提交 token 确认 */
    public function verify()
    {
        [$merchantId, $adminId, $err] = $this->requireShopadminAuth();
        if ($err) return $err;

        $token = (string)(Request::post('confirmation_token') ?? Request::get('confirmation_token') ?? '');
        if ($token === '') return $this->jsonResponse('缺少 confirmation_token', 422, 'error');

        try {
            $svc = new ShopAdminSensitiveOperationService();
            $ok  = $svc->confirm($merchantId, $adminId, $token);
        } catch (\Throwable $e) {
            Log::error('shopadmin.secure.confirm.verify failed: '.$e->getMessage());
            return $this->jsonResponse('确认失败', 500, 'error');
        }

        if (!$ok) return $this->jsonResponse('确认失败或已过期', 400, 'error');
        return $this->jsonResponse('确认成功', 200, 'success');
    }

    /**
     * 二次校验：是否已确认
     * 入参（POST）：
     *  - operation_type   string 必填
     *  - confirmation_token string 必填
     */
    public function check()
    {
        [$merchantId, $adminId, $err] = $this->requireShopadminAuth();
        if ($err) return $err;

        $opType = (string)(Request::post('operation_type') ?? '');
        $token  = (string)(Request::post('confirmation_token') ?? '');
        if ($opType === '' || $token === '') {
            return $this->jsonResponse('缺少必要参数', 422, 'error');
        }

        try {
            $svc = new ShopAdminSensitiveOperationService();
            $ok  = $svc->verifyConfirmed($merchantId, $adminId, $opType, $token);
        } catch (\Throwable $e) {
            Log::error('shopadmin.secure.confirm.check failed: '.$e->getMessage());
            return $this->jsonResponse('校验失败', 500, 'error');
        }

        return $this->jsonResponse('OK', 200, 'success', ['confirmed' => $ok ? 1 : 0]);
    }
}
