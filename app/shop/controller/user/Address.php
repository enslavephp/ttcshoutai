<?php

namespace app\shop\controller\user;

use app\BaseController;
use app\shop\validate\AddressValidate;
use app\shop\model\Address as AddressModel;
use think\facade\Db;
use think\facade\Log;
use think\Request;

class Address extends BaseController
{
    /**
     * 创建或更新地址
     */
    public function handleAddress(Request $request, $isUpdate = false)
    {
        // 获取用户信息
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        // 验证输入数据
        $data = $request->post();
        $validate = new AddressValidate();
        $scene = $isUpdate ? 'update' : 'create';
        if (!$validate->scene($scene)->check($data)) {
            return $this->jsonResponse($validate->getError(), 422, 'error');
        }

        // 查询待更新的地址
        $address = null;
        if ($isUpdate) {
            $address = AddressModel::where('id', $data['id'])->where('user_id', $userId)->find();
            if (!$address) {
                return $this->jsonResponse('地址不存在', 404, 'error');
            }
        }

        // 处理默认地址逻辑
        if (isset($data['is_default']) && $data['is_default'] == 1) {
            $this->setDefaultAddress($userId, $isUpdate ? $data['id'] : null);
        }

        // 动态构建更新数据
        $addressData = $this->buildAddressData($data, $userId);

        // 保存地址
        Db::startTrans();
        try {
            if ($isUpdate) {
                $address->save($addressData);
            } else {
                AddressModel::create($addressData);
            }
            Db::commit();
            return $this->jsonResponse($isUpdate ? '地址更新成功' : '地址创建成功', 200, 'success');
        } catch (\Exception $e) {
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
     * 清理并设置默认地址
     */
    private function setDefaultAddress($userId, $currentId = null)
    {
        // 先将其他默认地址设为 0，但保留当前地址为默认
        AddressModel::where('user_id', $userId)
            ->where('id', '<>', $currentId)
            ->update(['is_default' => 0]);
    }

    /**
     * 动态构建地址数据
     */
    private function buildAddressData($data, $userId)
    {
        // 经纬度处理
        $latitude = $data['latitude'] ?? null;
        $longitude = $data['longitude'] ?? null;
        $location = null;

        if ($latitude && $longitude) {
            $location = Db::raw("ST_GeomFromText('POINT($longitude $latitude)')");
        }

        // 动态过滤数据，保留有效字段
        $addressData = array_filter([
            'user_id'        => $userId,
            'full_address'   => $data['full_address'] ?? null,
            'full_address_name' => $data['full_address_name'] ?? null,
            'address'        => $data['address'] ?? null,
            'tel'            => $data['tel'] ?? null,
            'recipient_name' => $data['recipient_name'] ?? null,
            'is_default'     => $data['is_default'] ?? 0,
            'latitude'       => $latitude,
            'longitude'      => $longitude,
            'location'       => $location,
        ], fn($value) => $value !== null);

        return $addressData;
    }



    /**
     * 创建地址
     */
    public function createAddress(Request $request)
    {
        return $this->handleAddress($request, false);
    }

    /**
     * 更新地址
     */
    public function updateAddress(Request $request)
    {
        return $this->handleAddress($request, true);
    }
    /**
     * 删除地址
     */
    public function deleteAddress(Request $request)
    {
        // 获取用户信息
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        // 获取地址ID
        $addressIds = $request->post('address_ids');

        if (empty($addressIds) || !is_array($addressIds)) {
            return $this->jsonResponse('地址ID不能为空或格式错误', 400, 'error');
        }

        // 查找地址记录
        $addresses = AddressModel::whereIn('id', $addressIds)
            ->where('user_id', $userId)
            ->select();

        if ($addresses->isEmpty()) {
            return $this->jsonResponse('地址不存在或没有权限删除', 404, 'error');
        }

        // 检查是否有默认地址被删除
        $defaultAddressDeleted = false;
        foreach ($addresses as $address) {
            if ($address->is_default) {
                $defaultAddressDeleted = true;
                break;
            }
        }

        Db::startTrans();
        try {
            // 批量删除地址
            AddressModel::whereIn('id', $addressIds)->where('user_id', $userId)->delete();

            // 如果删除了默认地址，设置新的默认地址
            if ($defaultAddressDeleted) {
                AddressModel::where('user_id', $userId)
                    ->whereNotIn('id', $addressIds)
                    ->limit(1)
                    ->update(['is_default' => 1]);
            }

            Db::commit();
            return $this->jsonResponse('地址删除成功', 200, 'success');
        } catch (\Exception $e) {
            Db::rollback();
            Log::error('地址删除失败', ['error' => $e->getMessage()]);
            return $this->jsonResponse('地址删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }
    /**
     * 获取当前用户的所有地址
     */
    public function getUserAddresses(Request $request)
    {
        // 获取用户信息
        $user = $request->user ?? null;
        if (!$user || !isset($user['id'])) {
            return $this->jsonResponse('未登录用户，请先登录', 401, 'error');
        }
        $userId = $user['id'];

        try {
            // 查询当前用户的所有地址
            $addresses = AddressModel::where('user_id', $userId)
                ->order('is_default', 'desc') // 默认地址排在最前
                ->select()->toArray();
            return $this->jsonResponse('获取地址成功', 200, 'success', $addresses);
        } catch (\Exception $e) {
            return $this->jsonResponse('获取地址失败: ' . $e->getMessage(), 500, 'error');
        }
    }
}
