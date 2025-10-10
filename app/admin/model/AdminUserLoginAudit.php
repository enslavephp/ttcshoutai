<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;

/**
 * 管理员登录审计（ORM）
 *
 * 字段：
 *  - id, admin_id, username, occurred_at, ip, user_agent, device_fingerprint, result, reason
 *
 * 说明：
 *  - occurred_at 由业务控制，不启用自动时间戳
 *  - ip 存二进制（BLOB/VARBINARY），此处不做类型转换
 */
class AdminUserLoginAudit extends Model
{
    protected $name = 'admin_user_login_audit';
    protected $pk   = 'id';

    protected $autoWriteTimestamp = false;

    protected $field = [
        'id','admin_id','username','occurred_at','ip','user_agent',
        'device_fingerprint','result','reason',
    ];

    protected $type = [
        'id'          => 'integer',
        'admin_id'    => 'integer',
        'occurred_at' => 'datetime',
    ];
}
