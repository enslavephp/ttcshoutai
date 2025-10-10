<?php
namespace app\common\service;

class WeChatClient implements WeChatClientInterface
{
    private array $cfg;

    public function __construct(array $cfg = [])
    {
        $this->cfg = $cfg ?: config('wechat');
    }

    /**
     * @return array{session_key:string, openid:string}
     * @throws \RuntimeException
     */
    public function code2Session(string $code): array
    {
        $url = $this->cfg['api_url']
            . "?appid={$this->cfg['app_id']}&secret={$this->cfg['secret']}"
            . "&js_code={$code}&grant_type=authorization_code";

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT        => 5,
        ]);
        $resp = curl_exec($ch);
        if ($resp === false) {
            curl_close($ch);
            throw new \RuntimeException('wechat_network_error');
        }
        $http = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        if ($http !== 200) {
            throw new \RuntimeException('wechat_http_' . $http);
        }
        $data = json_decode($resp, true) ?: [];
        if (empty($data['session_key']) || empty($data['openid'])) {
            throw new \RuntimeException('wechat_bad_response');
        }
        return ['session_key' => $data['session_key'], 'openid' => $data['openid']];
    }
}