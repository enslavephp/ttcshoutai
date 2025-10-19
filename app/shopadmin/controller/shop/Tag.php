<?php
declare(strict_types=1);

namespace app\shopadmin\controller\shop;

use think\facade\Request;
use think\facade\Validate;
use think\facade\Log;
use think\facade\Db;
use app\shopadmin\model\Tag as TagModel;
use app\shopadmin\model\SkuTag as SkuTagModel;

/**
 * 标签管理（写）
 * - sort 越小越靠前
 * - 生效期 valid_from/valid_to（NULL=不限）
 * - 变更后刷新绑定该标签的 SKU 的 ES
 * - 已支持 created_by / updated_by 字段（表已添加）
 * - 与 shop_sku_tag 交互统一使用 ORM（SkuTagModel）
 * - 所有写操作包裹事务；try/catch 统一容错，失败自动回滚
 */
class Tag extends BaseShopAdmin
{
    /** 创建标签 */
    public function create()
    {
        try {
            [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $v = Validate::rule([
                'name'       => 'require|max:64',
                'sort'       => 'integer',
                'status'     => 'in:0,1',
                'valid_from' => 'date',
                'valid_to'   => 'date',
            ]);
            if (!$v->check($d)) return $this->jsonResponse($v->getError(), 422, 'error');

            $nameTrim = trim((string)$d['name']);
            // 重名校验（商户内）
            $dup = TagModel::where('merchant_id', $merchantId)->where('name', $nameTrim)->count();
            if ($dup > 0) return $this->jsonResponse('标签名称已存在', 409, 'error');

            $vf = isset($d['valid_from']) && trim((string)$d['valid_from']) !== '' ? date('Y-m-d H:i:s', strtotime($d['valid_from'])) : null;
            $vt = isset($d['valid_to'])   && trim((string)$d['valid_to'])   !== '' ? date('Y-m-d H:i:s', strtotime($d['valid_to']))   : null;
            if ($vf && $vt && strtotime($vf) >= strtotime($vt)) {
                return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
            }

            $tagId = 0;
            Db::transaction(function() use ($merchantId, $adminId, $nameTrim, $vf, $vt, $d, &$tagId) {
                $m = new TagModel();
                $m->save([
                    'merchant_id' => $merchantId,
                    'name'        => $nameTrim,
                    'sort'        => (int)($d['sort'] ?? 0),
                    'status'      => (int)($d['status'] ?? 1),
                    'valid_from'  => $vf,
                    'valid_to'    => $vt,
                    'created_by'  => $adminId, // 表已存在
                ]);
                $tagId = (int)$m->id;
            });

            // 新建标签通常尚未绑定 SKU，无需刷新 ES
            return $this->jsonResponse('创建成功', 200, 'success', ['tag_id' => $tagId]);
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            Log::error('tag.create: '.$msg);
            if (stripos($msg, 'uk_tag_name') !== false || stripos($msg, 'Duplicate') !== false) {
                return $this->jsonResponse('标签名称已存在', 409, 'error');
            }
            return $this->jsonResponse('创建失败', 500, 'error');
        }
    }

    /** 更新标签（仅更新传入字段；时间空串 => NULL；更新后刷新绑定 SKU 的 ES） */
    public function update()
    {
        try {
            [$merchantId, $adminId, $err] = $this->requireShopAdmin(); if ($err) return $err;

            $d = Request::post();
            $id = (int)($d['id'] ?? 0);
            if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

            /** @var TagModel|null $row */
            $row = TagModel::where('id', $id)->where('merchant_id', $merchantId)->find();
            if (!$row) return $this->jsonResponse('标签不存在', 404, 'error');

            $sets = [];
            if (array_key_exists('name', $d))   $sets['name'] = trim((string)$d['name']);
            if (array_key_exists('sort', $d))   $sets['sort'] = (int)$d['sort'];
            if (array_key_exists('status', $d)) $sets['status'] = (int)$d['status'];
            if (array_key_exists('valid_from', $d)) {
                $vf = trim((string)$d['valid_from']);
                $sets['valid_from'] = ($vf === '') ? null : date('Y-m-d H:i:s', strtotime($vf));
            }
            if (array_key_exists('valid_to', $d)) {
                $vt = trim((string)$d['valid_to']);
                $sets['valid_to'] = ($vt === '') ? null : date('Y-m-d H:i:s', strtotime($vt));
            }
            if (isset($sets['valid_from'], $sets['valid_to']) && $sets['valid_from'] && $sets['valid_to'] && strtotime((string)$sets['valid_from']) >= strtotime((string)$sets['valid_to'])) {
                return $this->jsonResponse('有效期起始必须早于结束', 400, 'error');
            }
            if (!$sets) return $this->jsonResponse('没有需要更新的字段', 400, 'error');

            // 同名校验（仅当 name 真的改动时）
            if (array_key_exists('name', $sets)) {
                $newName = (string)$sets['name'];
                if ($newName !== (string)$row->getAttr('name')) {
                    $dup = TagModel::where('merchant_id', $merchantId)
                        ->where('name', $newName)
                        ->where('id', '<>', $id)
                        ->count();
                    if ($dup > 0) return $this->jsonResponse('标签名称已存在', 409, 'error');
                }
            }

            Db::transaction(function() use ($row, $sets, $adminId) {
                $sets['updated_by'] = $adminId; // 表已存在
                $row->save($sets);
            });

            // 刷新绑定该标签的 SKU 的 ES（内部 try/catch）
            $this->esRefreshByTagSafe((int)$row->getAttr('merchant_id'), (int)$row->getAttr('id'));
            return $this->jsonResponse('OK', 200, '更新成功');
        } catch (\Throwable $e) {
            $msg = $e->getMessage();
            Log::error('tag.update: '.$msg, ['id' => $d['id'] ?? null]);
            if (stripos($msg, 'uk_tag_name') !== false || stripos($msg, 'Duplicate') !== false) {
                return $this->jsonResponse('标签名称已存在', 409, 'error');
            }
            return $this->jsonResponse('更新失败', 500, 'error');
        }
    }

    /** 删除（若仍有关联 SKU 则禁止） */
    public function delete()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $id = (int)(Request::post('id') ?? 0);
            if ($id <= 0) return $this->jsonResponse('缺少 id', 422, 'error');

            // 仍有关联 SKU 则禁止删除（使用 ORM）
            $cnt = SkuTagModel::where('merchant_id', $merchantId)->where('tag_id', $id)->count();
            if ($cnt > 0) return $this->jsonResponse('仍有关联 SKU，无法删除', 400, 'error');

            Db::transaction(function() use ($merchantId, $id) {
                TagModel::where('id', $id)->where('merchant_id', $merchantId)->delete();
            });
            return $this->jsonResponse('OK', 200, '删除成功');
        } catch (\Throwable $e) {
            Log::error('tag.delete: '.$e->getMessage(), ['id' => Request::post('id')]);
            return $this->jsonResponse('删除失败', 500, 'error');
        }
    }

    /** 列表（按状态、关键字、生效期；默认 sort 升序） */
    public function list()
    {
        try {
            [$merchantId, , $err] = $this->requireShopAdmin(); if ($err) return $err;

            $page      = max(1, (int)Request::param('page', 1));
            $pageSize  = max(1, min(200, (int)Request::param('page_size', 50)));
            $statusRaw = Request::param('status', null);
            $keyword   = trim((string)Request::param('keyword', ''));
            $validNow  = (int)Request::param('valid_now', 0) === 1;

            $q = TagModel::where('merchant_id', $merchantId);

            if ($statusRaw !== null && $statusRaw !== '') $q->where('status', (int)$statusRaw);
            if ($keyword !== '') {
                $kw = '%' . addcslashes($keyword, '%_') . '%';
                $q->whereLike('name', $kw);
            }
            if ($validNow) {
                $now = date('Y-m-d H:i:s');
                $q->where(function($w) use ($now){ $w->whereNull('valid_from')->whereOr('valid_from','<=',$now); });
                $q->where(function($w) use ($now){ $w->whereNull('valid_to')->whereOr('valid_to','>',$now); });
            }

            $q->field('id,merchant_id,name,sort,status,valid_from,valid_to,created_at,updated_at')
                ->order('sort','asc')->order('id','asc');

            $list = $q->paginate(['list_rows'=>$pageSize,'page'=>$page])->toArray();

            return $this->jsonResponse('OK', 200, 'success', [
                'items'     => $list['data'] ?? [],
                'total'     => $list['total'] ?? 0,
                'page'      => $list['current_page'] ?? $page,
                'page_size' => $list['per_page'] ?? $pageSize,
            ]);
        } catch (\Throwable $e) {
            Log::error('tag.list: '.$e->getMessage());
            return $this->jsonResponse('查询失败', 500, 'error');
        }
    }
}
