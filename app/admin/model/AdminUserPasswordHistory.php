<?php
declare(strict_types=1);

namespace app\admin\model;

use think\Model;

/**
 * 管理员密码历史（ORM）
 *
 * 字段：
 *  - id, admin_id, password, password_algo, password_meta
 *  - changed_at, changed_by, reason, client_info
 *
 * 说明：
 *  - 表内只有 changed_at，不走自动时间戳
 */
class AdminUserPasswordHistory extends Model
{
    protected $name = 'admin_user_password_history';
    protected $pk   = 'id';

    protected $autoWriteTimestamp = false;

    protected $field = [
        'id','admin_id','password','password_algo','password_meta',
        'changed_at','changed_by','reason','client_info',
    ];

    protected $type = [
        'id'          => 'integer',
        'admin_id'    => 'integer',
        'changed_by'  => 'integer',
        'changed_at'  => 'datetime',
    ];
}
