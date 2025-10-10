<?php

namespace app\shop\controller\order;

use app\BaseController;
use app\shop\model\Order as OrderModel;
use app\shop\model\Users;
use think\Request;
use think\facade\Log;

class Wxpay extends BaseController
{
    /**
     * 创建微信预支付订单
     */
    public function createWxOrder(Request $request)
    {
        // 获取用户信息
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        // 获取订单信息
        $orderId = $request->post('order_id');
        $amount = $request->post('amount'); // 单位：元

        if (empty($orderId) || empty($amount)) {
            return $this->jsonResponse('订单 ID 和金额不能为空', 400, 'error');
        }

        try {
            // 使用统一的微信支付配置文件
            $config = config('wechat');
            $url = 'https://api.mch.weixin.qq.com/v3/pay/transactions/jsapi';

            // 查询用户的 openid
            $openid = Users::where('id', $userId)->value('open_id');
            if (empty($openid)) {
                return $this->jsonResponse('用户未绑定微信账号', 400, 'error');
            }

            // 构造请求数据
            $payload = [
                'appid'        => $config['app_id'],
                'mchid'        => $config['mch_id'],
                'description'  => '订单支付 - ' . $orderId,
                'out_trade_no' => $orderId . time(), // 确保订单号唯一
                'notify_url'   => $config['notify_url'],
                'amount'       => [
                    'total'    => intval($amount * 100), // 单位转换为分
                    'currency' => 'CNY',
                ],
                'payer'        => [
                    'openid' => $openid,
                ],
            ];

            // 发送请求
            $response = $this->postRequest($url, json_encode($payload), $config);
            if ($response['code'] !== 200) {
                throw new \Exception('微信支付请求失败: ' . $response['body']);
            }
            $responseBody = json_decode($response['body'], true);
            if (!isset($responseBody['prepay_id'])) {
                throw new \Exception('预支付订单创建失败');
            }
            $prepayId = $responseBody['prepay_id'];

            // 生成时间戳和随机字符串
            $timeStamp = (string)time();
            $nonceStr  = bin2hex(random_bytes(16));

            // 构造待签名数据（注意键值顺序需与前端一致）
            $signData = [
                'appId'     => $config['app_id'],
                'timeStamp' => $timeStamp,
                'nonceStr'  => $nonceStr,
                'package'   => "prepay_id=$prepayId",
                'signType'  => 'RSA',
            ];
            $signString = $this->buildSignString($signData);
            $paySign    = $this->generateRSASign($signString, $config['key_path']);

            return $this->jsonResponse('微信支付预订单创建成功', 200, 'success', [
                'timeStamp' => $timeStamp,
                'nonceStr'  => $nonceStr,
                'package'   => "prepay_id=$prepayId",
                'signType'  => 'RSA',
                'paySign'   => $paySign,
            ]);
        } catch (\Exception $e) {
            Log::error('微信支付订单创建失败', ['error' => $e->getMessage()]);
            return $this->jsonResponse('支付订单创建失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 构造签名字符串（按照 key 排序后以 & 拼接）
     */
    private function buildSignString($data)
    {
        ksort($data);
        $pairs = [];
        foreach ($data as $key => $value) {
            $pairs[] = $key . '=' . $value;
        }
        return implode('&', $pairs);
    }

    /**
     * 使用 RSA 签名
     */
    private function generateRSASign($string, $privateKeyPath)
    {
        $privateKey = file_get_contents($privateKeyPath);
        if (!$privateKey) {
            throw new \Exception('加载私钥失败');
        }
        $res = openssl_get_privatekey($privateKey);
        if (!$res) {
            throw new \Exception('无效的私钥');
        }
        openssl_sign($string, $signature, $res, OPENSSL_ALGO_SHA256);
        return base64_encode($signature);
    }

    /**
     * 微信支付异步通知处理
     */
    public function notify()
    {
        // 读取回调内容
        $content = file_get_contents('php://input');
        Log::info('微信支付回调通知', ['content' => $content]);

        try {
            $config = config('wechat'); // 统一使用微信配置
            $data = json_decode($content, true);
            if (!$data || !isset($data['resource'])) {
                throw new \Exception('回调数据解析失败');
            }

            // 解密通知数据（使用 APIv3 密钥）
            $decryptedData = $this->decryptCallback($data['resource'], $config['api_key_v3']);

            // 仅处理支付成功事件
            if ($data['event_type'] !== 'TRANSACTION.SUCCESS') {
                Log::warning('支付回调事件非成功状态', ['event_type' => $data['event_type']]);
                return response('', 204);
            }

            // 提取订单信息
            $outTradeNo   = $decryptedData['out_trade_no']   ?? null;
            $transactionId = $decryptedData['transaction_id'] ?? null;
            $successTime  = $decryptedData['success_time']   ?? null;

            if (!$outTradeNo || !$transactionId || !$successTime) {
                throw new \Exception('支付回调数据缺失关键字段');
            }

            // 更新订单状态（例如：2 表示已支付）
            $updated = OrderModel::where('order_no', $outTradeNo)->update([
                'status'         => 2,
                'transaction_id' => $transactionId,
                'paid_at'        => $successTime,
            ]);
            if (!$updated) {
                throw new \Exception("更新订单状态失败，订单号: $outTradeNo");
            }

            return response('', 200);
        } catch (\Exception $e) {
            Log::error('微信支付回调处理失败', [
                'error' => $e->getMessage(),
                'trace' => $e->getTrace(),
            ]);
            return response('', 500);
        }
    }

    /**
     * 解密微信支付通知数据
     *
     * @param array  $resource 微信回调中的加密数据资源
     * @param string $key      APIv3 密钥
     * @return array 解密后的数据数组
     */
    private function decryptCallback($resource, $key)
    {
        $ciphertext    = base64_decode($resource['ciphertext']);
        $nonce         = $resource['nonce'];
        $associatedData = $resource['associated_data'] ?? '';

        // 正确分离密文与 TAG（最后 16 字节为 TAG）
        $tag            = substr($ciphertext, -16);
        $ciphertextData = substr($ciphertext, 0, -16);

        $decrypted = openssl_decrypt(
            $ciphertextData,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $nonce,
            $tag,
            $associatedData
        );
        if (!$decrypted) {
            throw new \Exception('解密回调数据失败');
        }
        return json_decode($decrypted, true);
    }

    /**
     * 发送带有商户 API 证书的 POST 请求
     */
    private function postRequest($url, $body, $config)
    {
        $method = 'POST';
        $path   = parse_url($url, PHP_URL_PATH);
        $authorization = $this->generateAuthorizationHeader($method, $path, $body, $config);

        $ch = curl_init($url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Content-Type: application/json',
            'Accept: application/json',
            'User-Agent: MyWechatPayClient/1.0',
            "Authorization: $authorization",
        ]);
        // 配置商户证书
        curl_setopt($ch, CURLOPT_SSLCERT, $config['cert_path']);
        curl_setopt($ch, CURLOPT_SSLKEY, $config['key_path']);

        $responseBody = curl_exec($ch);
        $httpCode     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError    = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            throw new \Exception("CURL Error: " . $curlError);
        }

        return [
            'code' => $httpCode,
            'body' => $responseBody,
        ];
    }

    /**
     * 根据规范生成待签名字符串，并生成签名（用于 Authorization 头）
     */
    private function generateSignature($method, $path, $timestamp, $nonceStr, $body, $config)
    {
        $message = "$method\n$path\n$timestamp\n$nonceStr\n$body\n";
        $privateKey = file_get_contents($config['key_path']);
        if (!$privateKey) {
            throw new \Exception('加载私钥失败');
        }
        $res = openssl_get_privatekey($privateKey);
        if (!$res) {
            throw new \Exception('无效的私钥');
        }
        openssl_sign($message, $signature, $res, 'sha256WithRSAEncryption');
        return base64_encode($signature);
    }

    /**
     * 生成微信支付接口调用的 Authorization 头
     */
    private function generateAuthorizationHeader($method, $path, $body, $config)
    {
        $timestamp = time(); // 当前时间戳
        $nonceStr = bin2hex(random_bytes(16)); // 随机字符串
        $signature = $this->generateSignature($method, $path, $timestamp, $nonceStr, $body, $config);

        return sprintf(
            'WECHATPAY2-SHA256-RSA2048 mchid="%s",nonce_str="%s",timestamp="%d",serial_no="%s",signature="%s"',
            $config['mch_id'],
            $nonceStr,
            $timestamp,
            $config['serial_no'], // 商户证书序列号
            $signature
        );
    }
}
