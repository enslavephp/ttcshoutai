<?php
declare(strict_types=1);

namespace app\admin\controller\shopadmin;

use app\BaseController;
use think\facade\Request;
use think\facade\Cache;
use app\admin\model\GeoRegion;

/**
 * 行政区划控制器（省 / 市 / 区县）
 * - 使用缓存加速；支持 refresh=1 强制刷新
 * - 若 GeoRegion 模型启用了 SoftDelete，TP6 默认查询会自动排除软删数据
 * - 统一去掉 Laravel 风格的 withoutTrashed()（TP6 无此方法）
 */
class Region extends BaseController
{
    private const CACHE_TTL = 86400;           // 每个键缓存 1 天
    private const CACHE_IDX = 'region:cache:index'; // 缓存键索引，便于清理

    /**
     * 省份列表（level=1）
     * GET/POST: ?refresh=1 可强制刷新缓存
     */
    public function provinces()
    {
        $refresh  = (int) Request::param('refresh', 0);
        $cacheKey = 'region:provinces';

        if ($refresh) {
            $this->deleteCacheKey($cacheKey);
        }

        $list = $this->rememberRegion($cacheKey, function () {
            return GeoRegion::where(['level' => 1, 'status' => 1])
                ->order('sort asc, code asc')
                ->field('code,name,pinyin,sort')
                ->select()
                ->toArray();
        });

        return $this->jsonResponse('OK', 200, 'success', ['list' => $list]);
    }

    /**
     * 市列表（传省 code）
     * 参数：province_code
     */
    public function cities()
    {
        $pcode = trim((string) Request::param('province_code', ''));
        if ($pcode === '') {
            return $this->jsonResponse('缺少参数：province_code', 422, 'error');
        }

        // 省是否存在
        $exists = GeoRegion::where(['code' => $pcode, 'level' => 1])->find();
        if (!$exists) {
            return $this->jsonResponse('省份不存在', 404, 'error');
        }

        $refresh  = (int) Request::param('refresh', 0);
        $cacheKey = "region:cities:{$pcode}";
        if ($refresh) {
            $this->deleteCacheKey($cacheKey);
        }

        $list = $this->rememberRegion($cacheKey, function () use ($pcode) {
            return GeoRegion::where(['level' => 2, 'status' => 1, 'parent_code' => $pcode])
                ->order('sort asc, code asc')
                ->field('code,name,pinyin,sort,parent_code')
                ->select()
                ->toArray();
        });

        return $this->jsonResponse('OK', 200, 'success', [
            'province_code' => $pcode,
            'list'          => $list,
        ]);
    }

    /**
     * 区/县列表（传市 code）
     * 参数：city_code
     */
    public function districts()
    {
        $ccode = trim((string) Request::param('city_code', ''));
        if ($ccode === '') {
            return $this->jsonResponse('缺少参数：city_code', 422, 'error');
        }

        // 市是否存在
        $exists = GeoRegion::where(['code' => $ccode, 'level' => 2])->find();
        if (!$exists) {
            return $this->jsonResponse('城市不存在', 404, 'error');
        }

        $refresh  = (int) Request::param('refresh', 0);
        $cacheKey = "region:districts:{$ccode}";
        if ($refresh) {
            $this->deleteCacheKey($cacheKey);
        }

        $list = $this->rememberRegion($cacheKey, function () use ($ccode) {
            return GeoRegion::where(['level' => 3, 'status' => 1, 'parent_code' => $ccode])
                ->order('sort asc, code asc')
                ->field('code,name,pinyin,sort,parent_code')
                ->select()
                ->toArray();
        });

        return $this->jsonResponse('OK', 200, 'success', [
            'city_code' => $ccode,
            'list'      => $list,
        ]);
    }

    /**
     * 树形数据：
     * - depth=1 仅省
     * - depth=2 省-市
     * - depth=3 省-市-区（默认）
     * 可选：keyword 模糊搜索（匹配 name/pinyin），仅返回匹配到的末级及其上级链路
     * 可选：province_code 限定某个省份
     * 可选：city_code     限定某个城市
     * 可选：refresh=1     刷新缓存
     */
    public function tree()
    {
        $depth   = max(1, min(3, (int) Request::param('depth', 3)));
        $keyword = trim((string) Request::param('keyword', ''));
        $pcode   = trim((string) Request::param('province_code', ''));
        $ccode   = trim((string) Request::param('city_code', ''));
        $refresh = (int) Request::param('refresh', 0);

        $cacheKey = 'region:tree:' . md5(json_encode([$depth, $keyword, $pcode, $ccode], JSON_UNESCAPED_UNICODE));
        if ($refresh) {
            $this->deleteCacheKey($cacheKey);
        }

        $data = $this->rememberRegion($cacheKey, function () use ($depth, $keyword, $pcode, $ccode) {
            // 1) 取集合
            if ($keyword !== '') {
                // 关键字匹配（任意层级）
                $matched = GeoRegion::where(['status' => 1])
                    ->where(function ($q) use ($keyword) {
                        $q->whereLike('name', "%{$keyword}%")
                            ->whereOr('pinyin', 'like', "%{$keyword}%");
                    })
                    ->field('code,name,level,parent_code,pinyin,sort')
                    ->select()->toArray();

                if (!$matched) {
                    return ['list' => []];
                }

                // 构建需要的 code 集合（匹配节点 + 其所有上级）
                $needCodes = array_column($matched, 'code');
                $parents   = array_filter(array_column($matched, 'parent_code'));
                $needCodes = array_values(array_unique(array_merge($needCodes, $parents)));

                $all   = [];
                $seen  = [];
                $pool  = $needCodes;

                while (!empty($pool)) {
                    $batch = GeoRegion::whereIn('code', array_values(array_unique($pool)))
                        ->field('code,name,level,parent_code,pinyin,sort')
                        ->select()->toArray();

                    foreach ($batch as $row) {
                        if (isset($seen[$row['code']])) { continue; }
                        $seen[$row['code']] = true;
                        $all[] = $row;
                        if (!empty($row['parent_code']) && !isset($seen[$row['parent_code']])) {
                            $pool[] = $row['parent_code'];
                        }
                    }

                    // 清空 pool（只保留新加入的父级）
                    $pool = array_values(array_filter(array_unique(array_map(
                        fn($r) => $r['parent_code'] ?? null,
                        $batch
                    ))));
                }

                // 去重合并匹配项
                $map = [];
                foreach (array_merge($matched, $all) as $item) {
                    $map[$item['code']] = $item;
                }
                $all = array_values($map);
            } else {
                // 无关键字，按 depth/pcode/ccode 取集合
                $query = GeoRegion::where(['status' => 1]);

                if ($pcode === '' && $ccode === '') {
                    $query->whereIn('level', range(1, $depth));
                } elseif ($pcode !== '') {
                    // 指定省 + 其下属层级（受 depth 限制）
                    $levels = $depth === 1 ? [1] : ($depth === 2 ? [1, 2] : [1, 2, 3]);
                    $query->whereIn('level', $levels)
                        ->where(function ($qq) use ($pcode) {
                            $qq->where('code', $pcode)->whereOr('parent_code', $pcode);
                        });
                } elseif ($ccode !== '') {
                    // 指定市 + 其下属层级
                    $levels = $depth === 2 ? [2] : [2, 3];
                    $query->whereIn('level', $levels)
                        ->where(function ($qq) use ($ccode) {
                            $qq->where('code', $ccode)->whereOr('parent_code', $ccode);
                        });
                }

                $all = $query->order('level asc, sort asc, code asc')
                    ->field('code,name,level,parent_code,pinyin,sort')
                    ->select()->toArray();
            }

            // 2) 构建树（最多到 depth）
            $byParent = [];
            foreach ($all as $row) {
                $parentKey = $row['parent_code'] ?? 'null';
                $byParent[$parentKey][] = $row;
            }

            // 省级：parent_code 为空
            $provinces = $byParent['null'] ?? [];

            // 递归构造
            $build = function (array $nodes, int $curLevel, int $maxDepth, array $byParent) use (&$build) {
                if ($curLevel >= $maxDepth) {
                    return array_map(function ($n) {
                        return [
                            'code'   => $n['code'],
                            'name'   => $n['name'],
                            'pinyin' => $n['pinyin'],
                            'level'  => $n['level'],
                            'sort'   => $n['sort'],
                        ];
                    }, $nodes);
                }
                return array_map(function ($n) use ($curLevel, $maxDepth, $byParent, $build) {
                    $children = $byParent[$n['code']] ?? [];
                    return [
                        'code'     => $n['code'],
                        'name'     => $n['name'],
                        'pinyin'   => $n['pinyin'],
                        'level'    => $n['level'],
                        'sort'     => $n['sort'],
                        'children' => $build($children, $curLevel + 1, $maxDepth, $byParent),
                    ];
                }, $nodes);
            };

            // 若指定 province_code / city_code，起点剪枝
            if ($pcode !== '') {
                $provinces = array_values(array_filter($provinces, fn($p) => $p['code'] === $pcode));
            }
            if ($ccode !== '') {
                // 起点为指定城市
                $city = null;
                foreach ($all as $row) {
                    if ($row['code'] === $ccode) { $city = $row; break; }
                }
                if ($city) {
                    $tree = $build([$city], $city['level'], max($city['level'], $depth), $byParent);
                    return ['list' => $tree];
                }
            }

            $tree = $build($provinces, 1, $depth, $byParent);
            return ['list' => $tree];
        });

        return $this->jsonResponse('OK', 200, 'success', $data);
    }

    /**
     * 清理区域缓存（含索引）
     */
    public function clear_cache()
    {
        $keys = Cache::get(self::CACHE_IDX, []);
        if (is_array($keys) && $keys) {
            foreach ($keys as $k) {
                Cache::delete($k);
            }
        }
        Cache::delete(self::CACHE_IDX);
        return $this->jsonResponse('区域缓存已清理', 200, 'success');
    }

    // ================= 私有工具方法 =================

    /**
     * 记忆缓存并维护索引
     * @param string   $key
     * @param \Closure $callback
     * @param int      $ttl
     * @return mixed
     */
    private function rememberRegion(string $key, \Closure $callback, int $ttl = self::CACHE_TTL)
    {
        $this->addCacheKey($key);
        return Cache::remember($key, $callback, $ttl);
    }

    /** 将缓存键加入索引 */
    private function addCacheKey(string $key): void
    {
        try {
            $keys = Cache::get(self::CACHE_IDX, []);
            if (!is_array($keys)) { $keys = []; }
            if (!in_array($key, $keys, true)) {
                $keys[] = $key;
                // 索引本身设更久一点，避免过早丢失
                Cache::set(self::CACHE_IDX, $keys, self::CACHE_TTL * 7);
            }
        } catch (\Throwable $e) {
            // 忽略索引失败，不影响主流程
        }
    }

    /** 删除缓存并从索引中移除 */
    private function deleteCacheKey(string $key): void
    {
        try {
            Cache::delete($key);
            $keys = Cache::get(self::CACHE_IDX, []);
            if (is_array($keys)) {
                $idx = array_search($key, $keys, true);
                if ($idx !== false) {
                    array_splice($keys, $idx, 1);
                    Cache::set(self::CACHE_IDX, $keys, self::CACHE_TTL * 7);
                }
            }
        } catch (\Throwable $e) {
            // 忽略
        }
    }
}
