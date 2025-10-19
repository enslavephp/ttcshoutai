<?php
// File: app/shop/controller/user/Address.php
namespace app\shop\controller\user;

use app\BaseController;
use app\shop\validate\AddressValidate;
use app\shop\model\UserAddresses as AddressModel;
use think\facade\Db;
use think\facade\Log;
use think\Request;

class Address extends BaseController
{
    /**
     * 创建或更新地址（Model 内拼接 POINT，经纬度来自请求）
     */
    public function handleAddress(Request $request, $isUpdate = false)
    {
        // 登录校验
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = (int)$user['id'];

        // 参数与校验
        $data = $request->post();
        $validate = new AddressValidate();
        $scene = $isUpdate ? 'update' : 'create';
        if (!$validate->scene($scene)->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        // 更新场景：校验记录归属
        $address = null;
        if ($isUpdate) {
            $address = AddressModel::where('id', (int)$data['id'])->where('user_id', $userId)->find();
            if (!$address) {
                return $this->jsonResponse('地址不存在', 404, 'error');
            }
        }

        // 默认地址：若设置为默认，则将其他地址的 is_default 置 0（保持应用层单默认）
        if (isset($data['is_default']) && (int)$data['is_default'] === 1) {
            $this->setDefaultAddress($userId, $isUpdate ? (int)$data['id'] : null);
        }

        // 构建写库数据（不直接写 location；由 Model 事件拼接 POINT(lon,lat)）
        $addressData = $this->buildAddressData($data, $userId);

        Db::startTrans();
        try {
            if ($isUpdate) {
                $address->save($addressData);
            } else {
                AddressModel::create($addressData);
            }
            Db::commit();
            return $this->jsonResponse($isUpdate ? '地址更新成功' : '地址创建成功', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('保存地址失败', [
                'error' => $e->getMessage(),
                'user_id' => $userId,
                'data' => $data,
            ]);
            return $this->jsonResponse('保存地址失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 清理并设置默认地址（应用层保持单默认；DDL 层允许多个）
     */
    private function setDefaultAddress(int $userId, ?int $currentId = null): void
    {
        AddressModel::where('user_id', $userId)
            ->when($currentId !== null, function ($q) use ($currentId) {
                $q->where('id', '<>', $currentId);
            })
            ->update(['is_default' => 0]);
    }

    /**
     * 过滤和映射字段到 DDL 列
     */
    private function buildAddressData(array $data, int $userId): array
    {
        $latitude  = isset($data['latitude'])  ? (float)$data['latitude']  : null;
        $longitude = isset($data['longitude']) ? (float)$data['longitude'] : null;

        // 仅保留 DDL 中存在的字段
        $payload = [
            'user_id'        => $userId,
            // 行政区划
            'province'       => $data['province']       ?? null,
            'city'           => $data['city']           ?? null,
            'district'       => $data['district']       ?? null,
            // 详细地址
            'street_address' => $data['street_address'] ?? null,
            'address_line'   => $data['address_line']   ?? null,
            // 联系方式
            'recipient_name' => $data['recipient_name'] ?? null,
            'tel'            => $data['tel']            ?? null,
            'zipcode'        => $data['zipcode']        ?? null,
            // 默认标记
            'is_default'     => isset($data['is_default']) ? (int)$data['is_default'] : 0,
            // 经纬度（location 由模型事件自动生成）
            'latitude'       => $latitude,
            'longitude'      => $longitude,
        ];

        // 仅过滤掉 null，保留 0 或空字符串
        return array_filter($payload, static function ($v) { return $v !== null; });
    }

    /** 创建地址 */
    public function createAddress(Request $request)
    {
        return $this->handleAddress($request, false);
    }

    /** 更新地址 */
    public function updateAddress(Request $request)
    {
        return $this->handleAddress($request, true);
    }

    /** 删除地址（物理删除） */
    public function deleteAddress(Request $request)
    {
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = (int)$user['id'];

        $addressIds = $request->post('address_ids');
        if (empty($addressIds) || !is_array($addressIds)) {
            return $this->jsonResponse('地址ID不能为空或格式错误', 400, 'error');
        }

        $addresses = AddressModel::whereIn('id', $addressIds)->where('user_id', $userId)->select();
        if ($addresses->isEmpty()) {
            return $this->jsonResponse('地址不存在或没有权限删除', 404, 'error');
        }

        $defaultAddressDeleted = false;
        foreach ($addresses as $addr) {
            if ((int)$addr->is_default === 1) { $defaultAddressDeleted = true; break; }
        }

        Db::startTrans();
        try {
            AddressModel::whereIn('id', $addressIds)->where('user_id', $userId)->delete();

            if ($defaultAddressDeleted) {
                // 将剩余中最新的一条置为默认
                $newDefault = AddressModel::where('user_id', $userId)
                    ->order(['updated_at' => 'desc', 'id' => 'desc'])
                    ->find();
                if ($newDefault) {
                    $newDefault->is_default = 1;
                    $newDefault->save();
                }
            }

            Db::commit();
            return $this->jsonResponse('地址删除成功', 200, 'success');
        } catch (\Throwable $e) {
            Db::rollback();
            Log::error('地址删除失败', ['error' => $e->getMessage()]);
            return $this->jsonResponse('地址删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /** 获取当前用户的所有地址（默认优先，时间倒序） */
    public function getUserAddresses(Request $request)
    {
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = (int)$user['id'];

        try {
            $addresses = AddressModel::where('user_id', $userId)
                ->field('id,user_id,province,city,district,street_address,address_line,recipient_name,tel,zipcode,is_default,latitude,longitude,created_at,updated_at,ST_AsText(location) AS location_wkt')
                ->order(['is_default' => 'desc', 'updated_at' => 'desc', 'id' => 'desc'])
                ->select()->toArray();
// 前端用 location_wkt，如 "POINT(121.4737 31.2304)"

            return $this->jsonResponse('获取地址成功', 200, 'success', $addresses);
        } catch (\Throwable $e) {
            return $this->jsonResponse('获取地址失败: ' . $e->getMessage(), 500, 'error');
        }
    }
}