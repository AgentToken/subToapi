package service

import (
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
)

// API Key status constants
const (
	StatusAPIKeyActive         = "active"
	StatusAPIKeyDisabled       = "disabled"
	StatusAPIKeyQuotaExhausted = "quota_exhausted"
	StatusAPIKeyExpired        = "expired"
)

// Rate limit window durations
const (
	RateLimitWindow5h = 5 * time.Hour
	RateLimitWindow1d = 24 * time.Hour
	RateLimitWindow7d = 7 * 24 * time.Hour
)

// IsWindowExpired returns true if the window starting at windowStart has exceeded the given duration.
// A nil windowStart is treated as expired — no initialized window means any accumulated usage is stale.
func IsWindowExpired(windowStart *time.Time, duration time.Duration) bool {
	return windowStart == nil || time.Since(*windowStart) >= duration
}

type APIKey struct {
	ID          int64
	UserID      int64
	Key         string
	Name        string
	GroupID     *int64
	Status      string
	IPWhitelist []string
	IPBlacklist []string
	// 预编译的 IP 规则，用于认证热路径避免重复 ParseIP/ParseCIDR。
	CompiledIPWhitelist *ip.CompiledIPRules `json:"-"`
	CompiledIPBlacklist *ip.CompiledIPRules `json:"-"`
	LastUsedAt          *time.Time
	LastUsedIP          *string
	CreatedAt           time.Time
	UpdatedAt           time.Time
	User                *User
	Group               *Group
	CurrentConcurrency  int

	// Quota fields
	Quota     float64    // Quota limit in USD (0 = unlimited)
	QuotaUsed float64    // Used quota amount
	ExpiresAt *time.Time // Expiration time (nil = never expires)

	// Rate limit fields
	RateLimit5h   float64    // Rate limit in USD per 5h (0 = unlimited)
	RateLimit1d   float64    // Rate limit in USD per 1d (0 = unlimited)
	RateLimit7d   float64    // Rate limit in USD per 7d (0 = unlimited)
	Usage5h       float64    // Used amount in current 5h window
	Usage1d       float64    // Used amount in current 1d window
	Usage7d       float64    // Used amount in current 7d window
	Window5hStart *time.Time // Start of current 5h window
	Window1dStart *time.Time // Start of current 1d window
	Window7dStart *time.Time // Start of current 7d window

	// Honeypot fields：蜜罐 Key 不走正常转发/计费链路，仅在认证层拦截采集
	IsHoneypot     bool
	HoneypotConfig *HoneypotConfig
}

// Honeypot 蜜罐响应模式
const (
	// HoneypotModeSynthetic 平台自行合成响应（不依赖上游，注入指令可控性最强）
	HoneypotModeSynthetic = "synthetic"
	// HoneypotModeRelay 转发到管理员提供的低价 OpenAI 兼容上游，
	// 将上游回复（或失败时的合成兜底）与注入指令一并返回，蜜罐表现更真实
	HoneypotModeRelay = "relay"
)

// Honeypot payload 注入模板变体
const (
	HoneypotPayloadEnvVerify  = "env_verify"   // 伪装 runtime 环境校验的 system-reminder
	HoneypotPayloadRegionWarn = "region_check" // 伪装供应商区域合规检查
	HoneypotPayloadOOBPing    = "oob_ping"     // 诱导客户端向收集端点外呼
)

// HoneypotConfig 蜜罐 Key 的行为配置（api_keys.honeypot_config JSONB）
type HoneypotConfig struct {
	Mode string `json:"mode"`
	// PayloadVariant 注入模板变体；空 = HoneypotPayloadEnvVerify
	PayloadVariant string `json:"payload_variant,omitempty"`
	// CustomPayload 管理员自定义注入文本；非空时优先于模板
	CustomPayload string `json:"custom_payload,omitempty"`
	// Relay 上游配置，仅 mode=relay 时使用（OpenAI 兼容 /v1/chat/completions）
	RelayEndpoint string `json:"relay_endpoint,omitempty"`
	RelayAPIKey   string `json:"relay_api_key,omitempty"`
	RelayModel    string `json:"relay_model,omitempty"`
	// Marker 每个蜜罐 Key 的唯一水印前缀，用于区分泄露渠道与关联回传
	Marker string `json:"marker,omitempty"`
}

// NormalizedHoneypotConfig 返回补齐默认值后的配置副本
func (c *HoneypotConfig) Normalized() *HoneypotConfig {
	out := *c
	if out.Mode != HoneypotModeRelay {
		out.Mode = HoneypotModeSynthetic
	}
	if out.PayloadVariant == "" {
		out.PayloadVariant = HoneypotPayloadEnvVerify
	}
	return &out
}

// Sanitized 返回脱敏后的副本（relay 上游密钥打码），用于列表/详情接口返回
func (c *HoneypotConfig) Sanitized() *HoneypotConfig {
	out := *c
	if out.RelayAPIKey != "" {
		out.RelayAPIKey = maskSecret(out.RelayAPIKey)
	}
	return &out
}

func maskSecret(s string) string {
	if len(s) <= 8 {
		return "***"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// IsHoneypotKey 报告该 Key 是否为蜜罐 Key
func (k *APIKey) IsHoneypotKey() bool {
	return k != nil && k.IsHoneypot
}

func normalizeHoneypotSnapshotConfig(c *HoneypotConfig) *HoneypotConfig {
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

func (k *APIKey) IsActive() bool {
	return k.Status == StatusActive
}

// HasRateLimits returns true if any rate limit window is configured
func (k *APIKey) HasRateLimits() bool {
	return k.RateLimit5h > 0 || k.RateLimit1d > 0 || k.RateLimit7d > 0
}

// IsExpired checks if the API key has expired
func (k *APIKey) IsExpired() bool {
	if k.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*k.ExpiresAt)
}

// IsQuotaExhausted checks if the API key quota is exhausted
func (k *APIKey) IsQuotaExhausted() bool {
	if k.Quota <= 0 {
		return false // unlimited
	}
	return k.QuotaUsed >= k.Quota
}

// GetQuotaRemaining returns remaining quota (-1 for unlimited)
func (k *APIKey) GetQuotaRemaining() float64 {
	if k.Quota <= 0 {
		return -1 // unlimited
	}
	remaining := k.Quota - k.QuotaUsed
	if remaining < 0 {
		return 0
	}
	return remaining
}

// GetDaysUntilExpiry returns days until expiry (-1 for never expires)
func (k *APIKey) GetDaysUntilExpiry() int {
	if k.ExpiresAt == nil {
		return -1 // never expires
	}
	duration := time.Until(*k.ExpiresAt)
	if duration < 0 {
		return 0
	}
	return int(duration.Hours() / 24)
}

// EffectiveUsage5h returns the 5h window usage, or 0 if the window has expired.
func (k *APIKey) EffectiveUsage5h() float64 {
	if IsWindowExpired(k.Window5hStart, RateLimitWindow5h) {
		return 0
	}
	return k.Usage5h
}

// EffectiveUsage1d returns the 1d window usage, or 0 if the window has expired.
func (k *APIKey) EffectiveUsage1d() float64 {
	if IsWindowExpired(k.Window1dStart, RateLimitWindow1d) {
		return 0
	}
	return k.Usage1d
}

// EffectiveUsage7d returns the 7d window usage, or 0 if the window has expired.
func (k *APIKey) EffectiveUsage7d() float64 {
	if IsWindowExpired(k.Window7dStart, RateLimitWindow7d) {
		return 0
	}
	return k.Usage7d
}

// APIKeyListFilters holds optional filtering parameters for listing API keys.
type APIKeyListFilters struct {
	Search  string
	Status  string
	GroupID *int64 // nil=不筛选, 0=无分组, >0=指定分组
}
