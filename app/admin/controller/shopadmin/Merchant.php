<?php
declare(strict_types=1);

namespace app\admin\controller\shopadmin;

use app\BaseController;
use think\facade\Request;
use think\facade\Validate;
use think\facade\Db;
use think\facade\Filesystem;
use think\facade\Log;

use app\admin\model\ShopAdminMerchant;
use app\admin\validate\ShopAdminMerchantValidate;

use app\common\infra\CacheFacadeAdapter;
use app\common\service\TokenService;
use app\common\util\SystemClock;

/**
 * 商户域控制器（商户侧）
 * 软删：使用 deleted_at 字段；默认所有查询自动排除软删数据（TP6）
 *
 * 文件系统建议：config/filesystem.php
 * 'public' => ['type'=>'local','root'=>public_path().'uploads','url'=>'/uploads','visibility'=>'public']
 */
class Merchant extends BaseController
{
    /** @var TokenService */
    private TokenService $tokenService;

    public function __construct()
    {
        // 初始化 TokenService 用于生成和验证 JWT token
        $jwtSecret = (string)(\app\common\Helper::getValue('jwt.secret') ?? 'PLEASE_CHANGE_ME');
        $jwtCfg['secret'] = $jwtSecret;

        $this->tokenService = new TokenService(
            new CacheFacadeAdapter(),
            new SystemClock(),
            $jwtCfg
        );
    }

    /**
     * 创建商户 + 初始化系统内置角色 super_shopadmin + 主管理员账号 + 绑定关系
     * 入参（multipart/form-data）：
     *  - 商户：merchant_name, merchant_code, contact_person, contact_phone, province, city, address, status, merchant_level?, email?, district?, logo(file), business_license(file)
     *  - 主管理员：super_admin_username, super_admin_password, super_admin_email?, super_admin_phone?, super_admin_mfa?
     */
    public function create()
    {
        // ------- 文件入参 -------
        $logoFile    = Request::file('logo');
        $licenseFile = Request::file('business_license');
        if (!$logoFile || !$licenseFile) {
            return $this->jsonResponse('请上传商户Logo和营业执照文件', 422, 'error');
        }

        // 基础文件规则
        $ok = Validate::rule([
            'logo'             => 'file|fileExt:png,jpg,jpeg|fileSize:2097152',      // ≤2MB
            'business_license' => 'file|fileExt:png,jpg,jpeg,pdf|fileSize:5242880',  // ≤5MB
        ])->check([
            'logo'             => $logoFile,
            'business_license' => $licenseFile,
        ]);
        if (!$ok) {
            return $this->jsonResponse(Validate::getError() ?: '文件校验失败', 422, 'error');
        }

        // 深度校验（图片结构 / PDF 头）
        if (!$this->verifyImageFile($logoFile)) {
            return $this->jsonResponse('Logo图片格式异常或已损坏', 422, 'error');
        }
        if (!$this->verifyImageOrPdfFile($licenseFile)) {
            return $this->jsonResponse('营业执照文件不合法（仅支持图片或PDF）', 422, 'error');
        }

        // ------- 业务入参 & 校验 -------
        $data = Request::post();
        $required = [
            'merchant_name','merchant_code','contact_person','contact_phone',
            'province','city','address','status',
            'super_admin_username','super_admin_password'
        ];
        foreach ($required as $f) {
            if (!isset($data[$f]) || $data[$f] === '') {
                return $this->jsonResponse("缺少必要参数：{$f}", 422, 'error');
            }
        }

        $validator = new ShopAdminMerchantValidate();
        if (!$validator->scene('create')->check($data)) {
            return $this->jsonResponse($validator->getError() ?: '参数校验失败', 422, 'error');
        }

        $saUsername = strtolower(trim((string)$data['super_admin_username']));
        $saPassword = (string)$data['super_admin_password'];
        if (strlen($saUsername) < 3 || strlen($saUsername) > 64) {
            return $this->jsonResponse('super_admin_username 长度非法', 422, 'error');
        }
        if (strlen($saPassword) < 6) {
            return $this->jsonResponse('super_admin_password 至少6位', 422, 'error');
        }

        $merchantLevel = (int)($data['merchant_level'] ?? 1);
        if ($merchantLevel < 1 || $merchantLevel > 9) {
            return $this->jsonResponse('merchant_level 取值范围应为 1~9（9=超级商户）', 422, 'error');
        }

        // ------- 先保存文件；事务失败回滚文件 -------
        $savedRel = [];
        try {
            $logoRel = Filesystem::disk('public')->putFile('merchant_logos', $logoFile);
            $blRel   = Filesystem::disk('public')->putFile('business_licenses', $licenseFile);
            $savedRel = [$logoRel, $blRel];

            $logoUrl = Filesystem::disk('public')->url($logoRel);
            $blUrl   = Filesystem::disk('public')->url($blRel);
        } catch (\Throwable $e) {
            return $this->jsonResponse('文件保存失败: '.$e->getMessage(), 500, 'error');
        }

        // ------- 事务 -------
        $result = []; // <- 按引用变量需先声明
        try {
            Db::transaction(function () use ($data, $logoUrl, $blUrl, $merchantLevel, $saUsername, $saPassword, &$result) {
                // 3.1 商户
                $merchant = new ShopAdminMerchant();
                $merchant->save([
                    'merchant_name'    => $data['merchant_name'],
                    'merchant_code'    => $data['merchant_code'],
                    'contact_person'   => $data['contact_person'],
                    'contact_phone'    => $data['contact_phone'],
                    'email'            => $data['email'] ?? null,
                    'province'         => $data['province'],
                    'city'             => $data['city'],
                    'district'         => $data['district'] ?? null,
                    'address'          => $data['address'],
                    'logo_url'         => $logoUrl,
                    'business_license' => $blUrl,
                    'status'           => (int)$data['status'],
                    'merchant_level'   => $merchantLevel,
                ]);
                $merchantId = (int)$merchant->id;

                // 3.2 角色
                $roleId = Db::name('shopadmin_role')->insertGetId([
                    'merchant_id' => $merchantId,
                    'code'        => 'super_shopadmin',
                    'name'        => '主管理员',
                    'description' => '商户级超管，拥有该商户下的全域操作权（权限校验直通）',
                    'is_system'   => 1,
                    'level'       => 1,
                    'status'      => 1,
                    'valid_from'  => date('Y-m-d H:i:s'),
                    'created_at'  => date('Y-m-d H:i:s'),
                    'updated_at'  => date('Y-m-d H:i:s'),
                    'version'     => 1,
                ]);

                // 3.3 超管账号（bcrypt）
                $passwordHash = password_hash($saPassword, PASSWORD_BCRYPT);
                $adminId = Db::name('shopadmin_user')->insertGetId([
                    'merchant_id'            => $merchantId,
                    'username'               => $saUsername,
                    'password'               => $passwordHash,
                    'password_algo'          => 'bcrypt',
                    'password_meta'          => json_encode(['algo' => 'bcrypt'], JSON_UNESCAPED_UNICODE),
                    'phone'                  => $data['super_admin_phone'] ?? null,
                    'email'                  => $data['super_admin_email'] ?? null,
                    'status'                 => 1,
                    'login_failed_attempts'  => 0,
                    'mfa_enabled'            => (int)($data['super_admin_mfa'] ?? 0),
                    'is_primary_super_admin' => 1,
                    'created_at'             => date('Y-m-d H:i:s'),
                    'updated_at'             => date('Y-m-d H:i:s'),
                    'version'                => 1,
                ]);

                // 3.4 绑定
                Db::name('shopadmin_user_role')->insert([
                    'admin_id'    => $adminId,
                    'role_id'     => $roleId,
                    'merchant_id' => $merchantId,
                    'assigned_at' => date('Y-m-d H:i:s'),
                    'assigned_by' => null,
                    'valid_from'  => date('Y-m-d H:i:s'),
                    'valid_to'    => null,
                ]);

                // 3.5 子账号额度 +1
//                Db::name('shopadmin_merchant')
//                    ->where('id', $merchantId)
//                    ->inc('current_sub_accounts', 1)
//                    ->update();
//                一次性修正 SQL，把每个商户的 current_sub_accounts 纠正为实际子账号数（不含超管）：
//                UPDATE shopadmin_merchant m
//JOIN (
//    SELECT merchant_id, COUNT(*) AS sub_cnt
//  FROM shopadmin_user
//  WHERE is_primary_super_admin = 0
//  GROUP BY merchant_id
//) u ON u.merchant_id = m.id
//SET m.current_sub_accounts = u.sub_cnt;




                $result = [
                    'merchant_id' => $merchantId,
                    'role_id'     => $roleId,
                    'admin_id'    => $adminId,
                ];
            });

            return $this->jsonResponse('商户创建成功', 200, 'success', array_merge($result, [
                'merchant_level'        => $merchantLevel,
                'logo_url'              => $logoUrl,
                'business_license_url'  => $blUrl,
                'login_hint'            => '可使用商户名称/编码 + 账号 + 密码登录；超管将绕过权限校验'
            ]));
        } catch (\Throwable $e) {
            // 回滚文件
            foreach ($savedRel as $rel) { $this->deleteRelIfExists($rel); }
            $msg = $e->getMessage();
            if (strpos($msg,'Duplicate')!==false || strpos($msg,'1062')!==false) {
                return $this->jsonResponse('唯一约束冲突：商户/账号/编码已存在', 409, 'error');
            }
            return $this->jsonResponse('创建商户失败: '.$msg, 500, 'error');
        }
    }

    /**
     * 更新商户信息（有文件则更新；无则保持原值）—— 软删数据不可更新
     */
    public function update()
    {
        $data = Request::post();
        if (empty($data['id'])) {
            return $this->jsonResponse('缺少商户ID', 400, 'error');
        }

        $validator = new ShopAdminMerchantValidate();
        if (!$validator->scene('update')->check($data)) {
            return $this->jsonResponse($validator->getError() ?: '参数校验失败', 422, 'error');
        }

        // 文件可选
        $logoFile    = Request::file('logo');
        $licenseFile = Request::file('business_license');

        if ($logoFile) {
            $ok = Validate::rule(['logo'=>'file|fileExt:png,jpg,jpeg|fileSize:2097152'])
                ->check(['logo'=>$logoFile]);
            if (!$ok) return $this->jsonResponse(Validate::getError() ?: 'Logo校验失败', 422, 'error');
            if (!$this->verifyImageFile($logoFile)) {
                return $this->jsonResponse('Logo图片格式异常或已损坏', 422, 'error');
            }
        }
        if ($licenseFile) {
            $ok = Validate::rule(['bl'=>'file|fileExt:png,jpg,jpeg,pdf|fileSize:5242880'])
                ->check(['bl'=>$licenseFile]);
            if (!$ok) return $this->jsonResponse(Validate::getError() ?: '营业执照校验失败', 422, 'error');
            if (!$this->verifyImageOrPdfFile($licenseFile)) {
                return $this->jsonResponse('营业执照文件不合法（仅支持图片或PDF）', 422, 'error');
            }
        }

        // 先保存新文件，失败回滚；成功后 DB 成功再删旧文件
        $logoUrl = null; $logoRel = null;
        $blUrl   = null; $blRel   = null;
        try {
            if ($logoFile) {
                $logoRel = Filesystem::disk('public')->putFile('merchant_logos', $logoFile);
                $logoUrl = Filesystem::disk('public')->url($logoRel);
            }
            if ($licenseFile) {
                $blRel = Filesystem::disk('public')->putFile('business_licenses', $licenseFile);
                $blUrl = Filesystem::disk('public')->url($blRel);
            }
        } catch (\Throwable $e) {
            return $this->jsonResponse('文件保存失败: ' . $e->getMessage(), 500, 'error');
        }

        $levelPatch = null;
        if (isset($data['merchant_level']) && $data['merchant_level'] !== '') {
            $lv = (int)$data['merchant_level'];
            if ($lv < 1 || $lv > 9) {
                $this->deleteRelIfExists($logoRel);
                $this->deleteRelIfExists($blRel);
                return $this->jsonResponse('merchant_level 取值范围应为 1~9（9=超级商户）', 422, 'error');
            }
            $levelPatch = $lv;
        }

        $oldLogo = null; $oldBl = null; // <- 按引用变量需先声明
        try {
            Db::transaction(function () use ($data, $logoUrl, $blUrl, $levelPatch, $logoRel, $blRel, &$oldLogo, &$oldBl) {
                /** @var ShopAdminMerchant|null $merchant */
                // 默认查询已自动排除软删数据（这里不需要 withoutTrashed）
                $merchant = ShopAdminMerchant::find((int)$data['id']);
                if (!$merchant) {
                    $this->deleteRelIfExists($logoRel);
                    $this->deleteRelIfExists($blRel);
                    throw new \RuntimeException('商户不存在或已被删除');
                }

                $oldLogo = $merchant->logo_url;
                $oldBl   = $merchant->business_license;

                $payload = [
                    'merchant_name'    => $data['merchant_name']   ?? $merchant->merchant_name,
                    'merchant_code'    => $data['merchant_code']   ?? $merchant->merchant_code,
                    'contact_person'   => $data['contact_person']  ?? $merchant->contact_person,
                    'contact_phone'    => $data['contact_phone']   ?? $merchant->contact_phone,
                    'email'            => $data['email']           ?? $merchant->email,
                    'province'         => $data['province']        ?? $merchant->province,
                    'city'             => $data['city']            ?? $merchant->city,
                    'district'         => $data['district']        ?? $merchant->district,
                    'address'          => $data['address']         ?? $merchant->address,
                    'logo_url'         => $logoUrl                 ?: $merchant->logo_url,
                    'business_license' => $blUrl                   ?: $merchant->business_license,
                    'status'           => isset($data['status'])   ? (int)$data['status'] : $merchant->status,
                ];
                if ($levelPatch !== null) {
                    $payload['merchant_level'] = $levelPatch;
                }

                $merchant->save($payload);
            });

            // 成功后再删旧文件
            if ($logoUrl && $oldLogo && $oldLogo !== $logoUrl) {
                $this->deletePublicFileByUrl($oldLogo);
            }
            if ($blUrl && $oldBl && $oldBl !== $blUrl) {
                $this->deletePublicFileByUrl($oldBl);
            }

            return $this->jsonResponse('商户更新成功', 200, 'success');
        } catch (\Throwable $e) {
            $this->deleteRelIfExists($logoRel);
            $this->deleteRelIfExists($blRel);
            $msg = $e->getMessage();
            if ($msg === '商户不存在或已被删除') {
                return $this->jsonResponse($msg, 404, 'error');
            }
            if (strpos($msg,'Duplicate')!==false || strpos($msg,'1062')!==false) {
                return $this->jsonResponse('唯一约束冲突：商户/编码/电话等已存在', 409, 'error');
            }
            return $this->jsonResponse('更新商户失败: ' . $msg, 500, 'error');
        }
    }

    /**
     * 软删商户（delete）—— 只做软删与关联软删（不清理文件；可恢复）
     */
    public function delete()
    {
        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) {
            return $this->jsonResponse('缺少商户ID', 400, 'error');
        }

        try {
            Db::transaction(function () use ($id) {
                /** @var ShopAdminMerchant|null $merchant */
                // 默认排除软删；不存在即可能已软删/不存在
                $merchant = ShopAdminMerchant::find($id);
                if (!$merchant) {
                    throw new \RuntimeException('商户不存在或已被删除');
                }

                // 关联表可选择软删或禁用（这里演示禁用/软删由你表结构决定）
                Db::name('shopadmin_user')
                    ->where('merchant_id', $id)
                    ->update(['status' => 0]); // 禁用子账号（示例）

                // 软删商户
                $merchant->delete(); // 使用 SoftDelete trait
            });

            return $this->jsonResponse('商户删除成功（已软删）', 200, 'success');
        } catch (\Throwable $e) {
            if ($e->getMessage() === '商户不存在或已被删除') {
                return $this->jsonResponse('商户不存在或已被删除', 404, 'error');
            }
            return $this->jsonResponse('删除商户失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 物理删除（不可恢复）—— 清理关联与磁盘文件
     */
    public function delete_force()
    {
        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) {
            return $this->jsonResponse('缺少商户ID', 400, 'error');
        }

        try {
            Db::transaction(function () use ($id) {
                /** @var ShopAdminMerchant|null $merchant */
                $merchant = ShopAdminMerchant::withTrashed()->find($id);
                if (!$merchant) {
                    throw new \RuntimeException('商户不存在');
                }

                // 清理关联
                Db::name('shopadmin_user_role')->where('merchant_id', $id)->delete();
                Db::name('shopadmin_user')->where('merchant_id', $id)->delete();
                Db::name('shopadmin_role')->where('merchant_id', $id)->delete();

                // 文件
                if (!empty($merchant->logo_url)) $this->deletePublicFileByUrl($merchant->logo_url);
                if (!empty($merchant->business_license)) $this->deletePublicFileByUrl($merchant->business_license);

                // 物理删
                $merchant->force()->delete();
            });

            return $this->jsonResponse('商户已物理删除', 200, 'success');
        } catch (\Throwable $e) {
            return $this->jsonResponse('物理删除失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 恢复已软删商户
     */
    public function restore()
    {
        $id = (int)(Request::post('id') ?? 0);
        if ($id <= 0) return $this->jsonResponse('缺少商户ID', 400, 'error');

        try {
            Db::transaction(function () use ($id) {
                /** @var ShopAdminMerchant|null $merchant */
                $merchant = ShopAdminMerchant::onlyTrashed()->find($id);
                if (!$merchant) {
                    throw new \RuntimeException('商户不存在或未删除');
                }
                $merchant->restore();

                // 同步恢复子账号可选：这里演示把状态启用回来
                Db::name('shopadmin_user')
                    ->where('merchant_id', $id)
                    ->update(['status' => 1]);
            });

            return $this->jsonResponse('商户已恢复', 200, 'success');
        } catch (\Throwable $e) {
            return $this->jsonResponse('恢复失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    /**
     * 获取商户详情（默认不返回软删数据；include_deleted=1 可取到软删）
     */
    public function info()
    {
        $id = (int)(Request::post('id') ?? 0);
        $includeDeleted = (int)(Request::post('include_deleted') ?? 0);

        if ($id <= 0) {
            return $this->jsonResponse('缺少商户ID', 400, 'error');
        }

        $merchant = $includeDeleted
            ? ShopAdminMerchant::withTrashed()->find($id)
            : ShopAdminMerchant::find($id);

        if (!$merchant) {
            return $this->jsonResponse('商户不存在', 404, 'error');
        }
        return $this->jsonResponse('商户信息获取成功', 200, 'success', ['merchant' => $merchant]);
    }

    /**
     * 商户列表（分页/状态/关键词/等级/创建时间区间/排序）
     * 额外：
     * - include_deleted=1：包含软删
     * - only_deleted=1：仅软删
     */
    public function list()
    {
        $page   = max(1, (int)(Request::post('page') ?? Request::get('page') ?? 1));
        $limit  = min(100, max(1, (int)(Request::post('limit') ?? Request::get('limit') ?? 20)));
        $kw     = trim((string)(Request::post('keyword') ?? Request::get('keyword') ?? ''));
        $status = Request::post('status') ?? Request::get('status') ?? '';
        $level  = Request::post('level')  ?? Request::get('level')  ?? '';
        $includeDeleted = (int)(Request::post('include_deleted') ?? Request::get('include_deleted') ?? 0);
        $onlyDeleted    = (int)(Request::post('only_deleted')    ?? Request::get('only_deleted')    ?? 0);

        // 创建时间区间（闭开区间： [from, to) ）
        $createdFrom = trim((string)(Request::post('created_from') ?? Request::get('created_from') ?? ''));
        $createdTo   = trim((string)(Request::post('created_to')   ?? Request::get('created_to')   ?? ''));

        // 排序白名单
        $sortByRaw  = strtolower((string)(Request::post('sort_by')  ?? Request::get('sort_by')  ?? 'id'));
        $sortDirRaw = strtolower((string)(Request::post('sort_dir') ?? Request::get('sort_dir') ?? 'desc'));
        $sortMap = [
            'id'          => 'id',
            'create_time' => 'create_time',
            'update_time' => 'update_time',
            'level'       => 'merchant_level',
            'name'        => 'merchant_name',
            'code'        => 'merchant_code',
            'status'      => 'status',
        ];
        $sortCol = $sortMap[$sortByRaw] ?? 'id';
        $sortDir = $sortDirRaw === 'asc' ? 'asc' : 'desc';

        // 软删过滤策略
        if ($onlyDeleted) {
            $query = ShopAdminMerchant::onlyTrashed();
        } elseif ($includeDeleted) {
            $query = ShopAdminMerchant::withTrashed();
        } else {
            $query = ShopAdminMerchant::where([]);
        }

        // 关键词
        $query = $query->where(function ($q) use ($kw) {
            if ($kw !== '') {
                $q->where(function ($qq) use ($kw) {
                    $qq->whereLike('merchant_name', "%{$kw}%")
                        ->whereOr('merchant_code', 'like', "%{$kw}%")
                        ->whereOr('contact_person', 'like', "%{$kw}%");
                });
            }
        });

        if ($status !== '') {
            $query->where('status', (int)$status);
        }
        if ($level !== '') {
            $query->where('merchant_level', (int)$level);
        }
        if ($createdFrom !== '') {
            $query->where('create_time', '>=', $createdFrom);
        }
        if ($createdTo !== '') {
            $query->where('create_time', '<',  $createdTo);
        }

        try {
            $total = (clone $query)->count();
            $rows = $query->order($sortCol, $sortDir)->page($page, $limit)->select()->toArray();


            $hasMore = ($page * $limit) < $total;

            return $this->jsonResponse('商户列表获取成功', 200, 'success', [
                'list'           => $rows,
                'total'          => $total,
                'page'           => $page,
                'limit'          => $limit,
                'has_more'       => $hasMore,
                'sort_by'        => array_search($sortCol, $sortMap, true) ?: 'id',
                'sort_dir'       => $sortDir,
                'created_from'   => $createdFrom ?: null,
                'created_to'     => $createdTo ?: null,
                'level'          => $level !== '' ? (int)$level : null,
                'include_deleted'=> (bool)$includeDeleted,
                'only_deleted'   => (bool)$onlyDeleted,
            ]);
        } catch (\Throwable $e) {
            return $this->jsonResponse('获取商户列表失败: ' . $e->getMessage(), 500, 'error');
        }
    }

    // ========== 私有工具方法 ==========

    /** 通过 URL 删除 public 盘文件 */
    private function deletePublicFileByUrl(string $url): void
    {
        try {
            $disk = Filesystem::disk('public');
            $base = rtrim($disk->url(''), '/');
            $path = parse_url($url, PHP_URL_PATH);
            if (!is_string($path)) return;
            $path = ltrim($path, '/');
            $baseTrim = ltrim($base, '/');

            if ($baseTrim !== '' && str_starts_with($path, $baseTrim)) {
                $rel = ltrim(substr($path, strlen($baseTrim)), '/');
                if ($rel) $disk->delete($rel);
            }
        } catch (\Throwable $ignored) {}
    }

    /** 若提供了相对路径，则删除 public 盘文件 */
    private function deleteRelIfExists(?string $rel): void
    {
        if ($rel) {
            try { Filesystem::disk('public')->delete($rel); } catch (\Throwable $ignored) {}
        }
    }

    /** 检测图片文件是否有效（getimagesize） */
    private function verifyImageFile($uploadedFile): bool
    {
        try {
            $tmp = method_exists($uploadedFile, 'getPathname') ? $uploadedFile->getPathname() : null;
            if (!$tmp || !is_file($tmp)) return false;
            $info = @getimagesize($tmp);
            return $info !== false;
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * 检测图片或 PDF
     * - 若为图片：getimagesize 通过
     * - 若为 PDF：文件头应以 %PDF 开始
     */
    private function verifyImageOrPdfFile($uploadedFile): bool
    {
        try {
            $tmp = method_exists($uploadedFile, 'getPathname') ? $uploadedFile->getPathname() : null;
            if (!$tmp || !is_file($tmp)) return false;

            if (@getimagesize($tmp) !== false) return true;

            $fh = @fopen($tmp, 'rb');
            if (!$fh) return false;
            $head = @fread($fh, 4);
            @fclose($fh);
            return $head === '%PDF';
        } catch (\Throwable $e) {
            return false;
        }
    }
}
