-- Honeypot API keys: 蜜罐/金丝雀 Key 支持。
-- is_honeypot=true 的 Key 在认证中间件层被整体拦截：不进入正常转发/计费链路，
-- 而是记录完整请求并返回注入了指纹采集指令的合成/转发响应。
-- 正常 Key 完全不受影响（所有逻辑以 is_honeypot 标记为门禁）。

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS is_honeypot BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS honeypot_config JSONB DEFAULT NULL;

-- 蜜罐命中事件：完整请求快照 + 抽取到的情报
CREATE TABLE IF NOT EXISTS honeypot_events (
    id BIGSERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    api_key_id BIGINT NOT NULL,
    source VARCHAR(20) NOT NULL DEFAULT 'gateway',
    method VARCHAR(10) NOT NULL DEFAULT '',
    path TEXT NOT NULL DEFAULT '',
    client_ip VARCHAR(64) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    model TEXT NOT NULL DEFAULT '',
    is_stream BOOLEAN NOT NULL DEFAULT FALSE,
    headers JSONB DEFAULT NULL,
    body TEXT NOT NULL DEFAULT '',
    body_truncated BOOLEAN NOT NULL DEFAULT FALSE,
    intel JSONB DEFAULT NULL,
    injected_payload TEXT NOT NULL DEFAULT '',
    response_mode VARCHAR(20) NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_honeypot_events_key_created ON honeypot_events (api_key_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_honeypot ON api_keys (is_honeypot) WHERE is_honeypot;
