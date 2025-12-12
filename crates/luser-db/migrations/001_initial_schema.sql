-------------------------------------------
-- Luser Platform Database Schema
-- 版本: 1.0.0
-- 描述: 付费订阅视频平台核心表结构
-- 创建时间: 2025-12-12
-------------------------------------------
-- 启用扩展
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- 创建枚举类型
CREATE TYPE user_role AS ENUM ('user', 'creator', 'admin', 'super_admin');
CREATE TYPE user_status AS ENUM ('active', 'suspended', 'banned', 'deleted');
CREATE TYPE video_status AS ENUM ('uploading', 'processing', 'ready', 'failed', 'deleted');
CREATE TYPE subscription_status AS ENUM ('active', 'canceled', 'expired', 'paused');
CREATE TYPE transaction_type AS ENUM ('subscription', 'tip', 'purchase', 'withdrawal', 'refund');
CREATE TYPE transaction_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'refunded');
CREATE TYPE withdrawal_status AS ENUM ('pending', 'processing', 'completed', 'failed', 'canceled');
CREATE TYPE audit_action AS ENUM (
    'user_login', 'user_logout', 'user_register', 'user_update',
    'video_upload', 'video_update', 'video_delete', 'video_view',
    'subscription_create', 'subscription_cancel', 'subscription_renew',
    'payment_success', 'payment_failed', 'payment_refund',
    'withdrawal_request', 'withdrawal_process', 'withdrawal_complete',
    'config_update', 'admin_action', 'system_event'
);

-------------------------------------------
-- 用户表 (users)
-- 存储平台所有用户信息，包括普通用户和内容创作者
-------------------------------------------
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 用户名，用于登录和显示，唯一
    username VARCHAR(50) NOT NULL UNIQUE,
    -- 邮箱地址，用于登录和通知，唯一
    email VARCHAR(255) NOT NULL UNIQUE,
    -- 密码哈希，使用Argon2id算法加密存储
    password_hash VARCHAR(255) NOT NULL,
    -- 显示名称，可修改，用于前端显示
    nick_name VARCHAR(100),
    -- 头像URL
    avatar_url TEXT,
    -- 简介/个人描述
    bio TEXT,
    -- 用户角色：user(普通用户), creator(创作者), admin(管理员), super_admin(超级管理员)
    role user_role NOT NULL DEFAULT 'user',
    -- 创作者相关字段
    -- 是否为已验证创作者
    is_verified_creator BOOLEAN DEFAULT FALSE,
    -- 创作者标签/分类
    creator_category VARCHAR(50),
    -- 创作者等级，用于推荐和搜索排序
    creator_level INTEGER DEFAULT 1,
    -- 统计字段
    follower_count BIGINT DEFAULT 0,
    following_count BIGINT DEFAULT 0,
    total_earnings DECIMAL(12, 2) DEFAULT 0.00,
    -- 账户状态：active(活跃), suspended(停用), banned(封禁), deleted(删除)
    status  user_status NOT NULL DEFAULT 'active',
    -- 邮箱验证状态
    email_verified BOOLEAN DEFAULT FALSE,
    -- 上次登录时间
    last_login_at TIMESTAMP WITH TIME ZONE,
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),

     -- 约束
    CONSTRAINT chk_username_length CHECK (LENGTH(username) >= 3 AND LENGTH(username) <= 50),
    CONSTRAINT chk_username_format CHECK (username ~ '^[a-zA-Z0-9_]+$'),
    CONSTRAINT chk_email_format CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$'),
    CONSTRAINT chk_nick_name_length CHECK (nick_name IS NULL OR LENGTH(nick_name) <= 100),
    CONSTRAINT chk_creator_level CHECK (creator_level >= 1 AND creator_level <= 10)
);

COMMENT ON TABLE users IS '用户表：存储所有用户信息，包括普通用户和创作者';
COMMENT ON COLUMN users.id IS '用户唯一标识符';
COMMENT ON COLUMN users.username IS '用户名，用于登录，必须唯一';
COMMENT ON COLUMN users.email IS '邮箱地址，用于登录和接收通知';
COMMENT ON COLUMN users.role IS '用户角色：user-普通用户, creator-内容创作者, admin-管理员';
COMMENT ON COLUMN users.is_verified_creator IS '是否为平台验证的创作者';
COMMENT ON COLUMN users.creator_level IS '创作者等级，影响推荐权重和分成比例';
COMMENT ON COLUMN users.total_earnings IS '创作者总收益（人民币）';

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_status ON users(status);
CREATE INDEX idx_users_created_at ON users(created_at DESC);

-------------------------------------------
-- 云服务配置表 (cloud_service_configs)
-- 存储腾讯云、阿里云等云服务商的配置信息
-- 支持多配置切换和热更新
-------------------------------------------
CREATE TABLE cloud_service_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 配置名称，用于管理界面显示
    name VARCHAR(100) NOT NULL,
    -- 服务商类型：tencent_vod(腾讯云点播), aliyun_vod(阿里云点播)
    vendor VARCHAR(20) NOT NULL 
        CHECK (vendor IN ('tencent_vod', 'aliyun_vod')),
    -- 服务商API密钥ID
    secret_id VARCHAR(255) NOT NULL,
    -- 加密存储的密钥
    secret_key_encrypted TEXT NOT NULL,
    -- 服务区域，如：ap-guangzhou, cn-shanghai
    region VARCHAR(50) NOT NULL,
    -- 存储桶名称
    bucket VARCHAR(255),
    -- 应用ID（腾讯云VOD的SubAppId）
    app_id VARCHAR(100),
    -- 子应用ID（腾讯云）
    sub_app_id BIGINT,
    -- 转码模板名称
    transcoding_template VARCHAR(100),
    -- 水印模板ID
    watermark_template_id VARCHAR(100),
    -- 上传凭证过期时间（小时）
    upload_token_expire_hours INTEGER DEFAULT 24,
    -- 播放凭证过期时间（秒）
    play_token_expire_seconds INTEGER DEFAULT 3600,
    -- 是否启用DRM加密
    enable_drm BOOLEAN DEFAULT FALSE,
    -- 是否激活此配置（同一时间只能有一个激活配置）
    is_active BOOLEAN DEFAULT FALSE,
    -- 配置状态：enabled(启用), disabled(禁用), testing(测试中)
    status VARCHAR(20) DEFAULT 'enabled' 
        CHECK (status IN ('enabled', 'disabled', 'testing')),
    -- 元数据
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 同一服务商同一区域只能有一个配置
    UNIQUE(vendor, region)
);

COMMENT ON TABLE cloud_service_configs IS '云服务配置表：存储腾讯云、阿里云等点播服务配置';
COMMENT ON COLUMN cloud_service_configs.vendor IS '服务商类型：tencent_vod-腾讯云点播, aliyun_vod-阿里云点播';
COMMENT ON COLUMN cloud_service_configs.secret_key_encrypted IS '加密存储的API密钥，使用AES-GCM算法加密';
COMMENT ON COLUMN cloud_service_configs.is_active IS '是否激活此配置，激活的配置会被系统使用';
COMMENT ON COLUMN cloud_service_configs.upload_token_expire_hours IS '上传凭证过期时间，默认24小时';

CREATE INDEX idx_cloud_configs_vendor ON cloud_service_configs(vendor);
CREATE INDEX idx_cloud_configs_status ON cloud_service_configs(status);
CREATE INDEX idx_cloud_configs_is_active ON cloud_service_configs(is_active) WHERE is_active = true;

-------------------------------------------
-- 支付配置表 (payment_configs)
-- 存储支付宝、微信支付等支付渠道的配置
-------------------------------------------
CREATE TABLE payment_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 配置名称
    name VARCHAR(100) NOT NULL,
    -- 支付渠道：alipay(支付宝), wechatpay(微信支付)
    channel VARCHAR(20) NOT NULL 
        CHECK (channel IN ('alipay', 'wechatpay')),
    -- 应用ID
    app_id VARCHAR(100) NOT NULL,
    -- 商户号
    merchant_id VARCHAR(100),
    -- 加密存储的私钥
    private_key_encrypted TEXT NOT NULL,
    -- 加密存储的公钥（微信支付需要）
    public_key_encrypted TEXT,
    -- 回调通知地址
    notify_url VARCHAR(255) NOT NULL,
    -- 支付完成返回地址
    return_url VARCHAR(255),
    -- 是否沙箱环境
    sandbox BOOLEAN DEFAULT FALSE,
    -- 是否激活
    is_active BOOLEAN DEFAULT FALSE,
    -- 平台手续费率（百分比，如0.20表示20%）
    platform_fee_rate DECIMAL(5,4) DEFAULT 0.2000,
    -- 最小提现金额（元）
    min_withdraw_amount DECIMAL(10,2) DEFAULT 100.00,
    -- 最大提现金额（元）
    max_withdraw_amount DECIMAL(10,2) DEFAULT 50000.00,
    -- 配置状态
    status VARCHAR(20) DEFAULT 'enabled',
    -- 元数据
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 同一渠道同一应用只能有一个配置
    UNIQUE(channel, app_id)
);

COMMENT ON TABLE payment_configs IS '支付配置表：存储支付宝、微信支付等支付渠道配置';
COMMENT ON COLUMN payment_configs.channel IS '支付渠道：alipay-支付宝, wechatpay-微信支付';
COMMENT ON COLUMN payment_configs.platform_fee_rate IS '平台手续费率，例如0.20表示平台收取20%的费用';
COMMENT ON COLUMN payment_configs.sandbox IS '是否沙箱环境，用于测试支付流程';

CREATE INDEX idx_payment_configs_channel ON payment_configs(channel);
CREATE INDEX idx_payment_configs_is_active ON payment_configs(is_active) WHERE is_active = true;

-------------------------------------------
-- 视频表 (videos)
-- 存储用户上传的视频元数据
-------------------------------------------
CREATE TABLE videos (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 视频所属用户（创作者）
    user_id UUID NOT NULL REFERENCES users(id),
    -- 视频标题
    title VARCHAR(255) NOT NULL,
    -- 视频描述
    description TEXT,
    -- 视频标签，JSON数组格式
    tags JSONB DEFAULT '[]'::jsonb,
    -- 云服务商的视频ID
    vendor_video_id VARCHAR(100) NOT NULL,
    -- 使用的云服务商
    cloud_vendor VARCHAR(20) NOT NULL,
    -- 视频时长（秒，可带小数）
    duration_seconds DECIMAL(10,3),
    -- 文件大小（字节）
    file_size_bytes BIGINT,
    -- 视频格式
    format VARCHAR(20),
    -- 分辨率宽度
    width INTEGER,
    -- 分辨率高度
    height INTEGER,
    -- 码率（bps）
    bitrate INTEGER,
    -- 封面图URL
    cover_url TEXT,
    -- 视频状态：uploading(上传中), processing(处理中), ready(就绪), failed(失败), deleted(删除)
    status video_status NOT NULL DEFAULT 'uploading',
    -- 转码进度（0-100）
    transcode_progress INTEGER DEFAULT 0,
    -- 是否公开（所有人都可观看）
    is_public BOOLEAN DEFAULT FALSE,
    -- 是否需要订阅才能观看
    requires_subscription BOOLEAN DEFAULT TRUE,
    -- 单次购买价格（如果支持单次购买）
    price_amount DECIMAL(10,2),
    -- 货币代码
    price_currency VARCHAR(3) DEFAULT 'CNY',
    -- 统计字段
    view_count BIGINT DEFAULT 0,
    like_count BIGINT DEFAULT 0,
    comment_count BIGINT DEFAULT 0,
    share_count BIGINT DEFAULT 0,
    -- 收入统计（如果是付费视频）
    total_earnings DECIMAL(12, 2) DEFAULT 0.00,
    -- 敏感内容标记
    is_sensitive BOOLEAN DEFAULT FALSE,
    -- 需要年龄验证
    requires_age_verification BOOLEAN DEFAULT FALSE,
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 发布时间（当状态变为ready时设置）
    published_at TIMESTAMP WITH TIME ZONE,
    -- 约束
    CONSTRAINT chk_price_positive CHECK (price_amount IS NULL OR price_amount > 0),
    CONSTRAINT chk_progress_range CHECK (transcode_progress >= 0 AND transcode_progress <= 100)
);

COMMENT ON TABLE videos IS '视频表：存储视频元数据，不存储实际视频文件';
COMMENT ON COLUMN videos.vendor_video_id IS '云服务商（腾讯云/阿里云）的视频ID';
COMMENT ON COLUMN videos.cloud_vendor IS '视频存储的云服务商：tencent_vod, aliyun_vod';
COMMENT ON COLUMN videos.status IS '视频状态：uploading-上传中, processing-转码处理中, ready-可播放';
COMMENT ON COLUMN videos.requires_subscription IS '是否需要订阅才能观看，为false时所有人都可观看';

CREATE INDEX idx_videos_user_id ON videos(user_id);
CREATE INDEX idx_videos_status ON videos(status);
CREATE INDEX idx_videos_created_at ON videos(created_at DESC);
CREATE INDEX idx_videos_published_at ON videos(published_at DESC) WHERE status = 'ready';
CREATE INDEX idx_videos_tags ON videos USING GIN(tags);
CREATE INDEX idx_videos_is_public ON videos(is_public) WHERE is_public = true;

-------------------------------------------
-- 订阅表 (subscriptions)
-- 存储用户之间的订阅关系
-------------------------------------------
CREATE TABLE subscriptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 订阅者（粉丝）
    subscriber_id UUID NOT NULL REFERENCES users(id),
    -- 被订阅者（创作者）
    creator_id UUID NOT NULL REFERENCES users(id),
    -- 订阅套餐ID
    plan_id UUID NOT NULL REFERENCES subscription_plans(id),
    -- 订阅状态：active(活跃), canceled(已取消), expired(已过期), paused(已暂停)
    status subscription_status NOT NULL DEFAULT 'active',
    -- 当前周期开始时间
    current_period_start TIMESTAMP WITH TIME ZONE NOT NULL,
    -- 当前周期结束时间
    current_period_end TIMESTAMP WITH TIME ZONE NOT NULL,
    -- 取消时间（如果已取消）
    canceled_at TIMESTAMP WITH TIME ZONE,
    -- 订阅结束时间（如果已过期或取消）
    ended_at TIMESTAMP WITH TIME ZONE,
    -- 自动续费
    auto_renew BOOLEAN DEFAULT TRUE,
    -- 订阅价格（记录订阅时的价格）
    amount DECIMAL(10,2) NOT NULL,
    -- 货币
    currency VARCHAR(3) DEFAULT 'CNY',
    -- 支付渠道
    payment_channel VARCHAR(20),
    -- 第三方支付订单号
    payment_order_id VARCHAR(100),
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 一个用户不能重复订阅同一个创作者
    UNIQUE(subscriber_id, creator_id, status) WHERE status = 'active'
);

COMMENT ON TABLE subscriptions IS '订阅表：存储用户对创作者的订阅关系';
COMMENT ON COLUMN subscriptions.status IS '订阅状态：active-有效, canceled-用户已取消, expired-已过期';
COMMENT ON COLUMN subscriptions.auto_renew IS '是否自动续费，为true时到期自动扣费续订';

CREATE INDEX idx_subscriptions_subscriber_id ON subscriptions(subscriber_id);
CREATE INDEX idx_subscriptions_creator_id ON subscriptions(creator_id);
CREATE INDEX idx_subscriptions_status ON subscriptions(status);
CREATE INDEX idx_subscriptions_period_end ON subscriptions(current_period_end) WHERE status = 'active';

-------------------------------------------
-- 订阅套餐表 (subscription_plans)
-- 存储创作者创建的订阅套餐
-------------------------------------------
CREATE TABLE subscription_plans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 套餐所属创作者
    creator_id UUID NOT NULL REFERENCES users(id),
    -- 套餐名称
    name VARCHAR(100) NOT NULL,
    -- 套餐描述
    description TEXT,
    -- 套餐价格（元/月）
    amount_monthly DECIMAL(10,2) NOT NULL,
    -- 套餐价格（元/年），如果提供则优惠
    amount_yearly DECIMAL(10,2),
    -- 货币
    currency VARCHAR(3) DEFAULT 'CNY',
    -- 套餐等级，用于多个套餐时的排序
    tier INTEGER DEFAULT 1,
    -- 套餐权益，JSON格式
    benefits JSONB DEFAULT '[]'::jsonb,
    -- 是否启用
    is_active BOOLEAN DEFAULT TRUE,
    -- 最大订阅人数限制，NULL表示无限制
    max_subscribers INTEGER,
    -- 当前订阅人数
    current_subscribers INTEGER DEFAULT 0,
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 约束
    CONSTRAINT chk_amount_positive CHECK (amount_monthly > 0),
    CONSTRAINT chk_yearly_discount CHECK (amount_yearly IS NULL OR amount_yearly < amount_monthly * 12)
);

COMMENT ON TABLE subscription_plans IS '订阅套餐表：创作者可以创建多个订阅套餐供粉丝选择';
COMMENT ON COLUMN subscription_plans.tier IS '套餐等级，数字越大表示套餐越高级';
COMMENT ON COLUMN subscription_plans.benefits IS '套餐权益，JSON格式，如：["观看所有视频", "独家内容", "提前观看"]';

CREATE INDEX idx_subscription_plans_creator_id ON subscription_plans(creator_id);
CREATE INDEX idx_subscription_plans_is_active ON subscription_plans(is_active) WHERE is_active = true;

-------------------------------------------
-- 交易表 (transactions)
-- 存储所有支付交易记录
-------------------------------------------
CREATE TABLE transactions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 交易类型：subscription(订阅), tip(打赏), purchase(购买), withdrawal(提现), refund(退款)
    type transaction_type NOT NULL,
    -- 支付用户
    from_user_id UUID NOT NULL REFERENCES users(id),
    -- 收款用户（如果是提现，则to_user_id=from_user_id）
    to_user_id UUID NOT NULL REFERENCES users(id),
    -- 关联的业务ID（如订阅ID、视频ID）
    reference_id UUID,
    -- 交易金额（正数）
    amount DECIMAL(10,2) NOT NULL,
    -- 货币
    currency VARCHAR(3) DEFAULT 'CNY',
    -- 平台手续费
    platform_fee DECIMAL(10,2) DEFAULT 0.00,
    -- 支付渠道
    payment_channel VARCHAR(20),
    -- 第三方支付订单号
    payment_order_id VARCHAR(100),
    -- 第三方交易号
    payment_transaction_id VARCHAR(100),
    -- 交易状态：pending(待处理), processing(处理中), completed(已完成), failed(失败), refunded(已退款)
    status transaction_status NOT NULL DEFAULT 'pending',
    -- 失败原因
    failure_reason TEXT,
    -- 交易描述
    description VARCHAR(255),
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    completed_at TIMESTAMP WITH TIME ZONE,
    -- 约束
    CONSTRAINT chk_amount_positive CHECK (amount > 0),
    CONSTRAINT chk_fee_nonnegative CHECK (platform_fee >= 0)
);

COMMENT ON TABLE transactions IS '交易表：记录所有资金流动，包括订阅、打赏、提现等';
COMMENT ON COLUMN transactions.type IS '交易类型：subscription-订阅, tip-打赏, purchase-单次购买, withdrawal-提现';
COMMENT ON COLUMN transactions.platform_fee IS '平台收取的手续费金额';

CREATE INDEX idx_transactions_from_user_id ON transactions(from_user_id);
CREATE INDEX idx_transactions_to_user_id ON transactions(to_user_id);
CREATE INDEX idx_transactions_type ON transactions(type);
CREATE INDEX idx_transactions_status ON transactions(status);
CREATE INDEX idx_transactions_payment_order_id ON transactions(payment_order_id);
CREATE INDEX idx_transactions_created_at ON transactions(created_at DESC);

-------------------------------------------
-- 提现申请表 (withdrawal_requests)
-- 存储创作者的提现申请
-------------------------------------------
CREATE TABLE withdrawal_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 申请人（创作者）
    user_id UUID NOT NULL REFERENCES users(id),
    -- 提现金额
    amount DECIMAL(10,2) NOT NULL,
    -- 实际到账金额（扣除手续费后）
    net_amount DECIMAL(10,2),
    -- 手续费
    fee DECIMAL(10,2) DEFAULT 0.00,
    -- 提现渠道：alipay(支付宝), wechatpay(微信支付), bank(银行卡)
    channel VARCHAR(20) NOT NULL
        CHECK (channel IN ('alipay', 'wechatpay', 'bank')),
    -- 收款账户信息（加密存储）
    account_info_encrypted TEXT NOT NULL,
    -- 提现状态：pending(待处理), processing(处理中), completed(已完成), failed(失败), canceled(已取消)
    status withdrawal_status NOT NULL DEFAULT 'pending',
    -- 处理人（管理员）
    processed_by UUID REFERENCES users(id),
    -- 处理时间
    processed_at TIMESTAMP WITH TIME ZONE,
    -- 处理备注
    processing_notes TEXT,
    -- 失败原因
    failure_reason TEXT,
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 约束
    CONSTRAINT chk_amount_min CHECK (amount >= 100.00), -- 最小提现金额100元
    CONSTRAINT chk_net_amount CHECK (net_amount <= amount - fee)
);

COMMENT ON TABLE withdrawal_requests IS '提现申请表：创作者申请将收益提现到个人账户';
COMMENT ON COLUMN withdrawal_requests.account_info_encrypted IS '加密存储的收款账户信息，如支付宝账号、微信openid等';
COMMENT ON COLUMN withdrawal_requests.status IS '提现状态：pending-待审核, processing-打款中, completed-已完成';

CREATE INDEX idx_withdrawal_requests_user_id ON withdrawal_requests(user_id);
CREATE INDEX idx_withdrawal_requests_status ON withdrawal_requests(status);
CREATE INDEX idx_withdrawal_requests_created_at ON withdrawal_requests(created_at DESC);

-------------------------------------------
-- 视频观看记录表 (video_views)
-- 记录用户观看视频的行为
-------------------------------------------
CREATE TABLE video_views (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 观看用户（如果已登录）
    user_id UUID REFERENCES users(id),
    -- 观看的视频
    video_id UUID NOT NULL REFERENCES videos(id),
    -- 观看设备信息
    user_agent TEXT,
    -- IP地址（匿名化处理）
    ip_hash VARCHAR(64),
    -- 观看开始时间
    started_at TIMESTAMP WITH TIME ZONE NOT NULL,
    -- 观看结束时间
    ended_at TIMESTAMP WITH TIME ZONE,
    -- 观看时长（秒）
    watch_duration_seconds INTEGER,
    -- 是否完整观看（观看时长超过视频时长的80%）
    is_completed BOOLEAN DEFAULT FALSE,
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    -- 一个用户对同一个视频一天只记录一次完整观看
    UNIQUE(user_id, video_id, DATE(started_at)) WHERE is_completed = TRUE AND user_id IS NOT NULL
);

COMMENT ON TABLE video_views IS '视频观看记录表：用于统计视频观看数据和用户行为分析';
COMMENT ON COLUMN video_views.ip_hash IS 'IP地址的哈希值，用于匿名化识别用户';
COMMENT ON COLUMN video_views.is_completed IS '是否完整观看，用于计算完播率';

CREATE INDEX idx_video_views_video_id ON video_views(video_id);
CREATE INDEX idx_video_views_user_id ON video_views(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX idx_video_views_started_at ON video_views(started_at DESC);
CREATE INDEX idx_video_views_is_completed ON video_views(is_completed) WHERE is_completed = true;

-------------------------------------------
-- 系统配置表 (system_configs)
-- 存储平台全局配置
-------------------------------------------
CREATE TABLE system_configs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 配置键
    config_key VARCHAR(100) NOT NULL UNIQUE,
    -- 配置值（JSON格式）
    config_value JSONB NOT NULL,
    -- 配置类型：string, number, boolean, array, object
    value_type VARCHAR(20) NOT NULL DEFAULT 'string'
        CHECK (value_type IN ('string', 'number', 'boolean', 'array', 'object')),
    -- 配置描述
    description TEXT,
    -- 配置分组
    category VARCHAR(50) DEFAULT 'general',
    -- 是否可修改
    is_editable BOOLEAN DEFAULT TRUE,
    -- 是否需要重启生效
    requires_restart BOOLEAN DEFAULT FALSE,
    -- 元数据
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_by UUID REFERENCES users(id)
);

COMMENT ON TABLE system_configs IS '系统配置表：存储平台全局配置，支持热更新';
COMMENT ON COLUMN system_configs.config_key IS '配置键，如：site.name, video.upload.max_size';
COMMENT ON COLUMN system_configs.config_value IS '配置值，JSON格式，根据value_type解析';

CREATE INDEX idx_system_configs_category ON system_configs(category);
CREATE INDEX idx_system_configs_is_editable ON system_configs(is_editable);

-------------------------------------------
-- 审计日志表 (audit_logs)
-- 记录重要操作日志
-------------------------------------------
CREATE TABLE audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- 操作类型：user_login, user_logout, video_upload, video_delete, 
    -- subscription_create, payment_success, config_update, admin_action
    action_type audit_action NOT NULL,
    -- 操作用户
    user_id UUID REFERENCES users(id),
    -- 目标资源类型
    resource_type VARCHAR(50),
    -- 目标资源ID
    resource_id UUID,
    -- 操作详情（JSON格式）
    details JSONB,
    -- IP地址
    ip_address INET,
    -- 用户代理
    user_agent TEXT,
    -- 操作结果：success, failure
    result VARCHAR(20) DEFAULT 'success'
        CHECK (result IN ('success', 'failure')),
    -- 错误信息（如果操作失败）
    error_message TEXT,
    -- 元数据
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

COMMENT ON TABLE audit_logs IS '审计日志表：记录所有重要操作，用于安全审计和问题排查';
COMMENT ON COLUMN audit_logs.action_type IS '操作类型，如：user_login, video_upload, payment_success';
COMMENT ON COLUMN audit_logs.details IS '操作详情，JSON格式，包含请求参数和响应结果';

CREATE INDEX idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_action_type ON audit_logs(action_type);
CREATE INDEX idx_audit_logs_created_at ON audit_logs(created_at DESC);
CREATE INDEX idx_audit_logs_resource ON audit_logs(resource_type, resource_id);

-------------------------------------------
-- 触发器：更新时间戳
-------------------------------------------
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- 为用户表添加触发器
CREATE TRIGGER update_users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 为视频表添加触发器
CREATE TRIGGER update_videos_updated_at
    BEFORE UPDATE ON videos
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 为订阅表添加触发器
CREATE TRIGGER update_subscriptions_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- 为交易表添加触发器
CREATE TRIGGER update_transactions_updated_at
    BEFORE UPDATE ON transactions
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-------------------------------------------
-- 初始化数据
-------------------------------------------

-- 插入默认管理员用户（密码：Admin123!@#）
INSERT INTO users (id, username, email, password_hash, role, is_verified_creator, status, email_verified)
VALUES (
    '11111111-1111-1111-1111-111111111111',
    'admin',
    'admin@Luser.com',
    -- Argon2id hash of "Admin123!@#"
    '$argon2id$v=19$m=4096,t=3,p=1$c29tZXNhbHQ$QZ6xG4f2WYqjC9cZKjLp7Uj1gYdTKBZR1hYJjL6qH0w',
    'super_admin',
    TRUE,
    'active',
    TRUE
) ON CONFLICT (email) DO NOTHING;

-- 插入系统配置
INSERT INTO system_configs (config_key, config_value, value_type, description, category, is_editable)
VALUES 
    ('site.name', '"Luser Platform"', 'string', '网站名称', 'general', TRUE),
    ('site.description', '"付费订阅视频内容平台"', 'string', '网站描述', 'general', TRUE),
    ('video.upload.max_size_mb', '2048', 'number', '最大视频上传大小（MB）', 'video', TRUE),
    ('video.upload.allowed_formats', '["mp4", "mov", "avi", "mkv"]', 'array', '允许的视频格式', 'video', TRUE),
    ('video.transcode.quality_profiles', '[{"name": "360p", "width": 640, "height": 360}, {"name": "720p", "width": 1280, "height": 720}, {"name": "1080p", "width": 1920, "height": 1080}]', 'array', '转码质量配置', 'video', FALSE),
    ('payment.platform_fee_rate', '0.20', 'number', '平台手续费率（20%）', 'payment', FALSE),
    ('withdrawal.min_amount', '100.00', 'number', '最小提现金额（元）', 'payment', TRUE),
    ('withdrawal.max_amount_per_day', '50000.00', 'number', '单日最大提现金额（元）', 'payment', TRUE),
    ('security.login.max_attempts', '5', 'number', '最大登录尝试次数', 'security', TRUE),
    ('security.login.lockout_minutes', '30', 'number', '登录失败锁定时间（分钟）', 'security', TRUE)
ON CONFLICT (config_key) DO NOTHING;