-- 蜜罐事件增加平台返回的完整响应文本，用于管理页展示"对话-响应"记录
ALTER TABLE honeypot_events ADD COLUMN IF NOT EXISTS response_text TEXT NOT NULL DEFAULT '';
