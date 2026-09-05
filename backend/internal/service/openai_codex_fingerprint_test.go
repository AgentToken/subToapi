package service

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

const testCodexFingerprintSeed = "11111111-1111-4111-8111-111111111111"

func newTestOAuthAccount(id int64, extra map[string]any) *Account {
	if codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(extra)) {
		if extra == nil {
			extra = make(map[string]any)
		}
		if _, exists := extra[codexFingerprintSeedExtraKey]; !exists {
			extra[codexFingerprintSeedExtraKey] = testCodexFingerprintSeed
		}
	}
	return &Account{
		ID:       id,
		Platform: PlatformOpenAI,
		Type:     AccountTypeOAuth,
		Extra:    extra,
	}
}

// --- deriveStableUUIDv4 ---

func TestDeriveStableUUIDv4_Deterministic(t *testing.T) {
	a := deriveStableUUIDv4("test-seed-1")
	b := deriveStableUUIDv4("test-seed-1")
	assert.Equal(t, a, b, "同一种子应返回相同结果")
}

func TestDeriveStableUUIDv4_DifferentSeeds(t *testing.T) {
	a := deriveStableUUIDv4("seed-a")
	b := deriveStableUUIDv4("seed-b")
	assert.NotEqual(t, a, b, "不同种子应返回不同结果")
}

func TestDeriveStableUUIDv4_ValidFormat(t *testing.T) {
	result := deriveStableUUIDv4("test-seed")
	parsed, err := uuid.Parse(result)
	require.NoError(t, err, "应返回合法 UUID 格式")
	assert.Equal(t, uuid.Version(4), parsed.Version(), "应为 UUIDv4")
	assert.Equal(t, uuid.RFC4122, parsed.Variant(), "应为 RFC4122 变体")
}

// --- GetCodexFingerprintMode ---

func TestGetCodexFingerprintMode(t *testing.T) {
	tests := []struct {
		name     string
		account  *Account
		expected codexFingerprintMode
	}{
		{"nil 账号", nil, codexFingerprintOff},
		{"非 OAuth 账号", &Account{Platform: PlatformOpenAI, Type: "api_key"}, codexFingerprintOff},
		{"OpenAI setup token", &Account{Platform: PlatformOpenAI, Type: AccountTypeSetupToken, Extra: map[string]any{codexFingerprintModeExtraKey: "session"}}, codexFingerprintSession},
		{"Anthropic setup token", &Account{Platform: PlatformAnthropic, Type: AccountTypeSetupToken, Extra: map[string]any{codexFingerprintModeExtraKey: "session"}}, codexFingerprintOff},
		// 收敛是显式 opt-in：缺省/空/非法一律 off（#5610）。存量账号普遍没有这个
		// extra 键，升级不得把它们静默切进收敛。
		{"无 extra 默认 off", newTestOAuthAccount(1, nil), codexFingerprintOff},
		{"空值默认 off", newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: ""}), codexFingerprintOff},
		{"非法值默认 off", newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: "invalid"}), codexFingerprintOff},
		{"显式 off", newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: "off"}), codexFingerprintOff},
		{"device", newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: "device"}), codexFingerprintDevice},
		{"session", newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: "session"}), codexFingerprintSession},
		{"full", newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: "full"}), codexFingerprintFull},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.account.GetCodexFingerprintMode())
		})
	}
}

// --- resolveConvergedInstallationID ---

func TestResolveConvergedInstallationID_UsesDeviceID(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{"openai_device_id": "real-device-id"})
	assert.Equal(t, "real-device-id", resolveConvergedInstallationID(account, testCodexFingerprintSeed))
}

func TestResolveConvergedInstallationID_DerivesFromSeed(t *testing.T) {
	account := newTestOAuthAccount(42, nil)
	result := resolveConvergedInstallationID(account, testCodexFingerprintSeed)
	_, err := uuid.Parse(result)
	require.NoError(t, err, "派生值应为合法 UUID")
	assert.Equal(t, result, resolveConvergedInstallationID(account, testCodexFingerprintSeed), "确定性")
}

func TestResolveConvergedInstallationID_DifferentSeeds(t *testing.T) {
	account := newTestOAuthAccount(1, nil)
	a := resolveConvergedInstallationID(account, testCodexFingerprintSeed)
	b := resolveConvergedInstallationID(account, "22222222-2222-4222-8222-222222222222")
	assert.NotEqual(t, a, b)
}

// --- resolveConvergedThreadID ---

func TestResolveConvergedThreadID_PerClientSession(t *testing.T) {
	a := resolveConvergedThreadID(testCodexFingerprintSeed, "session-aaa")
	b := resolveConvergedThreadID(testCodexFingerprintSeed, "session-bbb")
	assert.NotEqual(t, a, b, "不同客户端 session 应得到不同 thread_id")
}

func TestResolveConvergedThreadID_Deterministic(t *testing.T) {
	a := resolveConvergedThreadID(testCodexFingerprintSeed, "session-aaa")
	b := resolveConvergedThreadID(testCodexFingerprintSeed, "session-aaa")
	assert.Equal(t, a, b, "同一客户端 session 应得到相同 thread_id")
}

func TestResolveConvergedThreadID_EmptySession(t *testing.T) {
	assert.Equal(t, "", resolveConvergedThreadID(testCodexFingerprintSeed, ""))
}

// --- off 模式：resolveCodexFingerprintIDsFromRequest 返回 nil ---

func TestResolveCodexFingerprintIDsFromRequest_ExplicitOff(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: "off"})
	ids := resolveCodexFingerprintIDsFromRequest(account, nil)
	assert.Nil(t, ids, "显式 off 模式应返回 nil")
}

// 未显式配置的存量账号不得被收敛（#5610）：默认返回 nil，出站身份保持
// v0.1.175 之前的客户端原值。
func TestResolveCodexFingerprintIDsFromRequest_DefaultIsOff(t *testing.T) {
	account := newTestOAuthAccount(1, nil)
	assert.Nil(t, resolveCodexFingerprintIDsFromRequest(account, nil), "无 extra 应视为 off")
}

// 管理员显式 opt-in 的账号行为不变。
func TestResolveCodexFingerprintIDsFromRequest_ExplicitOptInHonored(t *testing.T) {
	for _, mode := range []string{"device", "session", "full"} {
		t.Run(mode, func(t *testing.T) {
			account := newTestOAuthAccount(1, map[string]any{codexFingerprintModeExtraKey: mode})
			ids := resolveCodexFingerprintIDsFromRequest(account, nil)
			require.NotNil(t, ids, "显式配置必须生效")
			assert.Equal(t, codexFingerprintMode(mode), ids.mode)
			assert.NotEmpty(t, ids.installationID)
		})
	}
}

func TestResolveCodexFingerprintIDsFromRequest_EnabledModesRequireValidSeed(t *testing.T) {
	for _, tt := range []struct {
		name  string
		extra map[string]any
	}{
		{name: "missing", extra: map[string]any{codexFingerprintModeExtraKey: "device"}},
		{name: "missing with device override", extra: map[string]any{codexFingerprintModeExtraKey: "device", "openai_device_id": "real-device"}},
		{name: "blank", extra: map[string]any{codexFingerprintModeExtraKey: "session", codexFingerprintSeedExtraKey: ""}},
		{name: "uppercase", extra: map[string]any{codexFingerprintModeExtraKey: "full", codexFingerprintSeedExtraKey: "11111111-1111-4111-8111-AAAAAAAAAAAA"}},
		{name: "nil uuid", extra: map[string]any{codexFingerprintModeExtraKey: "device", codexFingerprintSeedExtraKey: "00000000-0000-0000-0000-000000000000"}},
		{name: "non string", extra: map[string]any{codexFingerprintModeExtraKey: "session", codexFingerprintSeedExtraKey: 123}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			account := &Account{ID: 1, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: tt.extra}
			require.Nil(t, resolveCodexFingerprintIDsFromRequest(account, nil))
		})
	}
}

// --- applyCodexFingerprintHeaders: off 模式 ---

func TestApplyCodexFingerprintHeaders_OffMode(t *testing.T) {
	h := http.Header{}
	h.Set("x-codex-installation-id", "original-install-id")
	h.Set("x-codex-window-id", "original-window-id")

	applyCodexFingerprintHeaders(h, nil)

	assert.Equal(t, "original-install-id", h.Get("x-codex-installation-id"), "nil ids 不改写")
	assert.Equal(t, "original-window-id", h.Get("x-codex-window-id"), "nil ids 不改写")
}

// --- applyCodexFingerprintHeaders: device 模式 ---

func TestApplyCodexFingerprintHeaders_DeviceMode(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "device",
		"openai_device_id":           "converged-device",
	})
	turnMetadata := `{"installation_id":"user-install","session_id":"user-session","sandbox":"seccomp"}`
	h := http.Header{}
	h.Set("x-codex-installation-id", "user-install")
	h.Set("x-codex-window-id", "user-window:0")
	h.Set("x-codex-turn-metadata", turnMetadata)

	ids := resolveCodexFingerprintIDsFromRequest(account, nil)
	applyCodexFingerprintHeaders(h, ids)

	assert.Equal(t, "converged-device", h.Get("x-codex-installation-id"), "installation_id 应收敛")
	assert.Equal(t, "user-window:0", h.Get("x-codex-window-id"), "device 模式不改写 window_id")

	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(h.Get("x-codex-turn-metadata")), &meta))
	assert.Equal(t, "converged-device", meta["installation_id"])
	assert.Equal(t, "user-session", meta["session_id"], "device 模式不改写 session_id")
	assert.Equal(t, "seccomp", meta["sandbox"], "非指纹字段保留原样")
}

// --- applyCodexFingerprintHeaders: session 模式 ---

func TestApplyCodexFingerprintHeaders_SessionMode(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "session",
	})
	clientHeaders := http.Header{}
	clientHeaders.Set("session-id", "client-session-aaa")

	turnMetadata := `{"installation_id":"user-install","session_id":"user-session","thread_id":"user-thread","turn_id":"user-turn","window_id":"user-thread:0","sandbox":"seccomp","thread_source":"user"}`
	h := http.Header{}
	h.Set("x-codex-installation-id", "user-install")
	h.Set("x-codex-window-id", "user-thread:0")
	h.Set("x-codex-turn-metadata", turnMetadata)
	h.Set("x-client-request-id", "user-thread")

	ids := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	applyCodexFingerprintHeaders(h, ids)

	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	convergedInstall := resolveConvergedInstallationID(account, seed)
	convergedSession := resolveConvergedSessionID(seed)
	convergedThread := resolveConvergedThreadID(seed, "client-session-aaa")

	assert.Equal(t, convergedInstall, h.Get("x-codex-installation-id"))
	assert.Equal(t, convergedSession, h.Get("session-id"))
	assert.Equal(t, convergedSession, h.Get("session_id"), "下划线形式也应被改写")
	assert.Equal(t, convergedThread, h.Get("thread-id"))
	assert.Equal(t, convergedThread, h.Get("x-client-request-id"))
	assert.Equal(t, convergedThread+":0", h.Get("x-codex-window-id"))

	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(h.Get("x-codex-turn-metadata")), &meta))
	assert.Equal(t, convergedInstall, meta["installation_id"])
	assert.Equal(t, convergedSession, meta["session_id"])
	assert.Equal(t, convergedThread, meta["thread_id"])
	assert.NotEqual(t, "user-turn", meta["turn_id"], "turn_id 应被新生成的值替换")
	assert.Equal(t, "seccomp", meta["sandbox"], "sandbox 保留原样")
	assert.Equal(t, "user", meta["thread_source"], "thread_source 保留原样")
}

// --- session 模式：不同客户端得到不同 thread ---

func TestApplyCodexFingerprintHeaders_SessionMode_DifferentClients(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "session",
	})

	makeTurnMeta := func() string {
		return `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0"}`
	}

	clientA := http.Header{}
	clientA.Set("session-id", "client-A")
	idsA := resolveCodexFingerprintIDsFromRequest(account, clientA)
	hA := http.Header{}
	hA.Set("x-codex-turn-metadata", makeTurnMeta())
	applyCodexFingerprintHeaders(hA, idsA)

	clientB := http.Header{}
	clientB.Set("session-id", "client-B")
	idsB := resolveCodexFingerprintIDsFromRequest(account, clientB)
	hB := http.Header{}
	hB.Set("x-codex-turn-metadata", makeTurnMeta())
	applyCodexFingerprintHeaders(hB, idsB)

	assert.Equal(t, hA.Get("session-id"), hB.Get("session-id"), "session_id 应相同")
	assert.NotEqual(t, hA.Get("thread-id"), hB.Get("thread-id"), "不同客户端 thread_id 应不同")
	assert.NotEqual(t, hA.Get("x-codex-window-id"), hB.Get("x-codex-window-id"), "不同客户端 window_id 应不同")
	assert.Equal(t, hA.Get("x-codex-installation-id"), hB.Get("x-codex-installation-id"))
}

// --- full 模式 ---

func TestApplyCodexFingerprintHeaders_FullMode(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "full",
	})
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	convergedSession := resolveConvergedSessionID(seed)

	clientA := http.Header{}
	clientA.Set("session-id", "client-A")
	idsA := resolveCodexFingerprintIDsFromRequest(account, clientA)
	hA := http.Header{}
	hA.Set("x-codex-turn-metadata", `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0"}`)
	applyCodexFingerprintHeaders(hA, idsA)

	clientB := http.Header{}
	clientB.Set("session-id", "client-B")
	idsB := resolveCodexFingerprintIDsFromRequest(account, clientB)
	hB := http.Header{}
	hB.Set("x-codex-turn-metadata", `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0"}`)
	applyCodexFingerprintHeaders(hB, idsB)

	assert.Equal(t, hA.Get("thread-id"), hB.Get("thread-id"), "full 模式 thread_id 应相同")
	assert.Equal(t, convergedSession, hA.Get("thread-id"), "full 模式 thread_id 应等于 session_id")
	assert.Equal(t, hA.Get("x-codex-window-id"), hB.Get("x-codex-window-id"), "full 模式 window_id 应相同")
}

// --- H1 修复验证：头和体的 turn_id 一致性 ---

func TestFingerprintIDs_HeaderAndBody_TurnID_Consistent(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "session",
	})
	clientHeaders := http.Header{}
	clientHeaders.Set("session-id", "client-session-xyz")

	ids := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	require.NotNil(t, ids)

	// 头改写
	h := http.Header{}
	h.Set("x-codex-turn-metadata", `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0"}`)
	applyCodexFingerprintHeaders(h, ids)

	// 体改写（使用同一份 ids）
	reqBody := map[string]any{
		"client_metadata": map[string]any{
			"x-codex-installation-id": "x",
			"session_id":              "x",
			"turn_id":                 "x",
			"x-codex-turn-metadata":   `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0"}`,
		},
	}
	applyCodexFingerprintClientMetadata(reqBody, ids)

	// 从头 turn-metadata JSON 提取 turn_id
	var headerMeta map[string]any
	require.NoError(t, json.Unmarshal([]byte(h.Get("x-codex-turn-metadata")), &headerMeta))
	headerTurnID, ok := headerMeta["turn_id"].(string)
	require.True(t, ok, "头 turn-metadata 应包含 string 类型的 turn_id")

	// 从体 client_metadata 提取 turn_id
	cm, ok := reqBody["client_metadata"].(map[string]any)
	require.True(t, ok, "请求体应包含 client_metadata")
	bodyTurnID, ok := cm["turn_id"].(string)
	require.True(t, ok, "体 client_metadata 应包含 string 类型的 turn_id")

	// 从体内嵌 turn-metadata JSON 提取 turn_id
	embeddedRaw, ok := cm["x-codex-turn-metadata"].(string)
	require.True(t, ok, "体 client_metadata 应包含 x-codex-turn-metadata 字符串")
	var bodyMeta map[string]any
	require.NoError(t, json.Unmarshal([]byte(embeddedRaw), &bodyMeta))
	bodyEmbeddedTurnID, ok := bodyMeta["turn_id"].(string)
	require.True(t, ok, "体内嵌 turn-metadata 应包含 string 类型的 turn_id")

	assert.Equal(t, headerTurnID, bodyTurnID, "头和体的 turn_id 必须一致")
	assert.Equal(t, headerTurnID, bodyEmbeddedTurnID, "头和体内嵌 turn-metadata 的 turn_id 必须一致")
	assert.Equal(t, ids.turnID, headerTurnID, "所有 turn_id 都应来自同一份 ids")
	assert.Equal(t, headerMeta["turn_started_at_unix_ms"], bodyMeta["turn_started_at_unix_ms"], "头和体的 timestamp 必须一致")
	assert.Equal(t, float64(ids.turnStartedAtUnixMs), headerMeta["turn_started_at_unix_ms"])
}

func TestFingerprintIDs_MalformedEmbeddedMetadataRebuiltConsistently(t *testing.T) {
	account := newTestOAuthAccount(2, map[string]any{codexFingerprintModeExtraKey: "session"})
	clientHeaders := make(http.Header)
	clientHeaders.Set("session-id", "client-session-malformed")
	ids := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	require.NotNil(t, ids)

	h := make(http.Header)
	h.Set("x-codex-turn-metadata", "{malformed")
	applyCodexFingerprintHeaders(h, ids)

	reqBody := map[string]any{
		"client_metadata": map[string]any{
			"session_id":            "client-session-malformed",
			"x-codex-turn-metadata": "[malformed",
		},
	}
	require.True(t, applyCodexFingerprintClientMetadata(reqBody, ids))

	var headerMeta map[string]any
	require.NoError(t, json.Unmarshal([]byte(h.Get("x-codex-turn-metadata")), &headerMeta))
	clientMetadata, ok := reqBody["client_metadata"].(map[string]any)
	require.True(t, ok)
	bodyRaw, ok := clientMetadata["x-codex-turn-metadata"].(string)
	require.True(t, ok)
	var bodyMeta map[string]any
	require.NoError(t, json.Unmarshal([]byte(bodyRaw), &bodyMeta))

	for _, key := range []string{"installation_id", "session_id", "thread_id", "turn_id", "window_id", "turn_started_at_unix_ms"} {
		assert.Equal(t, headerMeta[key], bodyMeta[key], "rebuilt metadata field %s must match", key)
	}
}

// --- applyCodexFingerprintClientMetadata ---

func TestApplyCodexFingerprintClientMetadata_OffMode(t *testing.T) {
	reqBody := map[string]any{
		"client_metadata": map[string]any{
			"x-codex-installation-id": "original",
		},
	}
	modified := applyCodexFingerprintClientMetadata(reqBody, nil)
	assert.False(t, modified, "nil ids 不改写")
}

func TestApplyCodexFingerprintClientMetadata_DeviceMode(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "device",
		"openai_device_id":           "converged-device",
	})
	ids := resolveCodexFingerprintIDsFromRequest(account, nil)
	require.NotNil(t, ids)

	embeddedMeta := `{"installation_id":"x","session_id":"user-session","sandbox":"seccomp"}`
	reqBody := map[string]any{
		"client_metadata": map[string]any{
			"x-codex-installation-id": "original-install",
			"session_id":              "user-session",
			"x-codex-turn-metadata":   embeddedMeta,
		},
	}

	modified := applyCodexFingerprintClientMetadata(reqBody, ids)
	require.True(t, modified)

	cm, ok := reqBody["client_metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "converged-device", cm["x-codex-installation-id"])
	assert.Equal(t, "user-session", cm["session_id"], "device 模式不改 session_id")

	turnMetaStr, ok := cm["x-codex-turn-metadata"].(string)
	require.True(t, ok)
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(turnMetaStr), &meta))
	assert.Equal(t, "converged-device", meta["installation_id"])
	assert.Equal(t, "seccomp", meta["sandbox"], "非指纹字段保留原样")
}

func TestApplyCodexFingerprintClientMetadata_SessionMode(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "session",
	})
	clientHeaders := http.Header{}
	clientHeaders.Set("session-id", "client-session-aaa")

	ids := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	require.NotNil(t, ids)

	embeddedMeta := `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0","sandbox":"seccomp"}`
	reqBody := map[string]any{
		"client_metadata": map[string]any{
			"x-codex-installation-id": "original-install",
			"session_id":              "original-session",
			"x-codex-turn-metadata":   embeddedMeta,
		},
	}

	modified := applyCodexFingerprintClientMetadata(reqBody, ids)
	require.True(t, modified)

	cm, ok := reqBody["client_metadata"].(map[string]any)
	require.True(t, ok)
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	convergedInstall := resolveConvergedInstallationID(account, seed)
	convergedSession := resolveConvergedSessionID(seed)
	convergedThread := resolveConvergedThreadID(seed, "client-session-aaa")

	assert.Equal(t, convergedInstall, cm["x-codex-installation-id"])
	assert.Equal(t, convergedSession, cm["session_id"])
	assert.Equal(t, convergedThread, cm["thread_id"])
	assert.Equal(t, convergedThread+":0", cm["x-codex-window-id"])

	turnMetaStr, ok := cm["x-codex-turn-metadata"].(string)
	require.True(t, ok)
	var meta map[string]any
	require.NoError(t, json.Unmarshal([]byte(turnMetaStr), &meta))
	assert.Equal(t, convergedInstall, meta["installation_id"])
	assert.Equal(t, convergedSession, meta["session_id"])
	assert.Equal(t, "seccomp", meta["sandbox"], "非指纹字段保留原样")
}

func TestApplyCodexFingerprintClientMetadata_FullMode(t *testing.T) {
	account := newTestOAuthAccount(1, map[string]any{
		codexFingerprintModeExtraKey: "full",
	})
	clientHeaders := http.Header{}
	clientHeaders.Set("session-id", "any-client")

	ids := resolveCodexFingerprintIDsFromRequest(account, clientHeaders)
	require.NotNil(t, ids)

	reqBody := map[string]any{
		"client_metadata": map[string]any{
			"session_id":            "x",
			"thread_id":             "x",
			"x-codex-turn-metadata": `{"installation_id":"x","session_id":"x","thread_id":"x","turn_id":"x","window_id":"x:0"}`,
		},
	}

	modified := applyCodexFingerprintClientMetadata(reqBody, ids)
	require.True(t, modified)

	cm, ok := reqBody["client_metadata"].(map[string]any)
	require.True(t, ok)
	seed, ok := codexFingerprintSeed(account.Extra)
	require.True(t, ok)
	convergedSession := resolveConvergedSessionID(seed)

	assert.Equal(t, convergedSession, cm["session_id"])
	assert.Equal(t, convergedSession, cm["thread_id"], "full 模式 thread_id 应等于 session_id")
}

// --- extractClientSessionID ---

func TestExtractClientSessionID(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected string
	}{
		{"连字符形式优先", func() http.Header {
			h := http.Header{}
			h.Set("session-id", "hyphen-form")
			h.Set("session_id", "underscore-form")
			return h
		}(), "hyphen-form"},
		{"回退到下划线形式", func() http.Header {
			h := http.Header{}
			h.Set("session_id", "underscore-form")
			return h
		}(), "underscore-form"},
		{"都没有", http.Header{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractClientSessionID(tt.headers))
		})
	}
}

// --- 透传路径：raw 字节版 client_metadata 改写 ---

// rawVsMapClientMetadata 用同一份 ids 分别跑 map 版与 raw 字节版，
// 返回两侧最终的 client_metadata 解码结果。
func rawVsMapClientMetadata(t *testing.T, body []byte, ids *codexFingerprintIDs) (map[string]any, map[string]any) {
	t.Helper()

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))
	applyCodexFingerprintClientMetadata(decoded, ids)
	mapCM, _ := decoded["client_metadata"].(map[string]any)

	rawBody, changed, err := applyCodexFingerprintClientMetadataRaw(body, ids)
	require.NoError(t, err)
	require.True(t, changed)
	var rawDecoded map[string]any
	require.NoError(t, json.Unmarshal(rawBody, &rawDecoded))
	rawCM, _ := rawDecoded["client_metadata"].(map[string]any)
	return mapCM, rawCM
}

func cloneCodexFingerprintIDsForTest(ids *codexFingerprintIDs) *codexFingerprintIDs {
	if ids == nil {
		return nil
	}
	cloned := *ids
	cloned.originalBodySessionID = ""
	cloned.originalBodySessionIDCaptured = false
	return &cloned
}

func applyMapAndRawFingerprintBodiesForTest(t *testing.T, body []byte, ids *codexFingerprintIDs) (map[string]any, map[string]any) {
	t.Helper()

	mapIDs := cloneCodexFingerprintIDsForTest(ids)
	rawIDs := cloneCodexFingerprintIDsForTest(ids)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(body, &decoded))
	applyCodexFingerprintClientMetadata(decoded, mapIDs)

	rawBody, _, err := applyCodexFingerprintClientMetadataRaw(body, rawIDs)
	require.NoError(t, err)
	var rawDecoded map[string]any
	require.NoError(t, json.Unmarshal(rawBody, &rawDecoded))
	return decoded, rawDecoded
}

func TestApplyCodexFingerprintPromptCacheKey_MapRawEquivalence(t *testing.T) {
	for _, mode := range []codexFingerprintMode{codexFingerprintSession, codexFingerprintFull} {
		t.Run(string(mode)+"/default", func(t *testing.T) {
			account := newTestOAuthAccount(4300, map[string]any{codexFingerprintModeExtraKey: string(mode)})
			ids := resolveCodexFingerprintIDs(account, "header-session", mode)
			require.NotNil(t, ids)

			body := []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"body-session","client_metadata":{"session_id":" body-session ","trace":"keep"},"input":[]}`)
			mapBody, rawBody := applyMapAndRawFingerprintBodiesForTest(t, body, ids)

			require.Equal(t, mapBody["prompt_cache_key"], rawBody["prompt_cache_key"])
			require.Equal(t, ids.sessionID, mapBody["prompt_cache_key"])
			mapCM, _ := mapBody["client_metadata"].(map[string]any)
			rawCM, _ := rawBody["client_metadata"].(map[string]any)
			require.Equal(t, ids.sessionID, mapCM["session_id"])
			require.Equal(t, mapCM["session_id"], rawCM["session_id"])
			require.Equal(t, "keep", rawCM["trace"])
		})
	}

	t.Run("explicit override", func(t *testing.T) {
		account := newTestOAuthAccount(4301, map[string]any{codexFingerprintModeExtraKey: "session"})
		ids := resolveCodexFingerprintIDs(account, "header-session", codexFingerprintSession)
		require.NotNil(t, ids)

		body := []byte(`{"model":"gpt-5.6-sol","prompt_cache_key":"explicit-cache","client_metadata":{"session_id":"body-session"},"input":[]}`)
		mapBody, rawBody := applyMapAndRawFingerprintBodiesForTest(t, body, ids)

		require.Equal(t, "explicit-cache", mapBody["prompt_cache_key"])
		require.Equal(t, "explicit-cache", rawBody["prompt_cache_key"])
		mapCM, _ := mapBody["client_metadata"].(map[string]any)
		rawCM, _ := rawBody["client_metadata"].(map[string]any)
		require.Equal(t, ids.sessionID, mapCM["session_id"])
		require.Equal(t, ids.sessionID, rawCM["session_id"])
	})
}

func TestApplyCodexFingerprintPromptCacheKey_Negatives(t *testing.T) {
	sessionAccount := newTestOAuthAccount(4310, map[string]any{codexFingerprintModeExtraKey: "session"})
	sessionIDs := resolveCodexFingerprintIDs(sessionAccount, "header-session", codexFingerprintSession)
	require.NotNil(t, sessionIDs)
	deviceAccount := newTestOAuthAccount(4311, map[string]any{codexFingerprintModeExtraKey: "device"})
	deviceIDs := resolveCodexFingerprintIDs(deviceAccount, "header-session", codexFingerprintDevice)
	require.NotNil(t, deviceIDs)

	tests := []struct {
		name          string
		body          []byte
		ids           *codexFingerprintIDs
		wantExists    bool
		wantCacheKey  any
		wantRawString string
	}{
		{
			name:       "missing key is not injected",
			body:       []byte(`{"client_metadata":{"session_id":"body-session"}}`),
			ids:        sessionIDs,
			wantExists: false,
		},
		{
			name:         "empty key preserved",
			body:         []byte(`{"prompt_cache_key":"","client_metadata":{"session_id":"body-session"}}`),
			ids:          sessionIDs,
			wantExists:   true,
			wantCacheKey: "",
		},
		{
			name:         "whitespace-different key is an explicit override",
			body:         []byte(`{"prompt_cache_key":" body-session ","client_metadata":{"session_id":"body-session"}}`),
			ids:          sessionIDs,
			wantExists:   true,
			wantCacheKey: " body-session ",
		},
		{
			name:         "non-string key preserved",
			body:         []byte(`{"prompt_cache_key":123,"client_metadata":{"session_id":"body-session"}}`),
			ids:          sessionIDs,
			wantExists:   true,
			wantCacheKey: float64(123),
		},
		{
			name:         "missing source metadata preserves key",
			body:         []byte(`{"prompt_cache_key":"body-session"}`),
			ids:          sessionIDs,
			wantExists:   true,
			wantCacheKey: "body-session",
		},
		{
			name:         "non-string source session preserves key",
			body:         []byte(`{"prompt_cache_key":"123","client_metadata":{"session_id":123}}`),
			ids:          sessionIDs,
			wantExists:   true,
			wantCacheKey: "123",
		},
		{
			name:         "non-object source metadata preserves key",
			body:         []byte(`{"prompt_cache_key":"body-session","client_metadata":"bad"}`),
			ids:          sessionIDs,
			wantExists:   true,
			wantCacheKey: "body-session",
		},
		{
			name:         "device mode preserves key",
			body:         []byte(`{"prompt_cache_key":"body-session","client_metadata":{"session_id":"body-session"}}`),
			ids:          deviceIDs,
			wantExists:   true,
			wantCacheKey: "body-session",
		},
		{
			name:          "off mode preserves body",
			body:          []byte(`{"prompt_cache_key":"body-session","client_metadata":{"session_id":"body-session"}}`),
			ids:           nil,
			wantExists:    true,
			wantCacheKey:  "body-session",
			wantRawString: `{"prompt_cache_key":"body-session","client_metadata":{"session_id":"body-session"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mapBody map[string]any
			require.NoError(t, json.Unmarshal(tt.body, &mapBody))
			changedMap := applyCodexFingerprintClientMetadata(mapBody, cloneCodexFingerprintIDsForTest(tt.ids))

			rawBody, changedRaw, err := applyCodexFingerprintClientMetadataRaw(tt.body, cloneCodexFingerprintIDsForTest(tt.ids))
			require.NoError(t, err)
			if tt.ids == nil {
				require.False(t, changedMap)
				require.False(t, changedRaw)
				require.JSONEq(t, tt.wantRawString, string(rawBody))
				return
			}
			require.True(t, changedMap)
			require.True(t, changedRaw)

			rawDecoded := map[string]any{}
			require.NoError(t, json.Unmarshal(rawBody, &rawDecoded))
			_, mapExists := mapBody["prompt_cache_key"]
			_, rawExists := rawDecoded["prompt_cache_key"]
			require.Equal(t, tt.wantExists, mapExists)
			require.Equal(t, tt.wantExists, rawExists)
			if tt.wantExists {
				require.Equal(t, tt.wantCacheKey, mapBody["prompt_cache_key"])
				require.Equal(t, tt.wantCacheKey, rawDecoded["prompt_cache_key"])
			}
		})
	}
}

func TestApplyCodexFingerprintClientMetadataRaw_MatchesMapVariant(t *testing.T) {
	embedded := `{\"installation_id\":\"real-install\",\"session_id\":\"real-session\",\"sandbox\":\"seatbelt\"}`
	bodies := map[string]string{
		"no_client_metadata": `{"model":"gpt-5.6-sol","input":[],"stream":true}`,
		"object_with_extras": `{"model":"gpt-5.6-sol","client_metadata":{"session_id":"client-session","traceparent":"00-abc-def-01","x-codex-turn-metadata":"` + embedded + `"},"stream":true}`,
		"non_object_value":   `{"model":"gpt-5.6-sol","client_metadata":"bogus","stream":true}`,
	}
	for _, mode := range []codexFingerprintMode{codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull} {
		account := newTestOAuthAccount(4242, map[string]any{codexFingerprintModeExtraKey: string(mode)})
		ids := resolveCodexFingerprintIDs(account, "client-sess-raw", mode)
		require.NotNil(t, ids)
		for name, body := range bodies {
			t.Run(string(mode)+"/"+name, func(t *testing.T) {
				mapCM, rawCM := rawVsMapClientMetadata(t, []byte(body), ids)
				assert.Equal(t, mapCM, rawCM, "raw 字节版与 map 版的 client_metadata 结果必须逐点一致")
			})
		}
	}
}

func TestApplyCodexFingerprintClientMetadataRaw_PreservesUnrelatedFields(t *testing.T) {
	account := newTestOAuthAccount(4243, map[string]any{codexFingerprintModeExtraKey: "session"})
	ids := resolveCodexFingerprintIDs(account, "client-sess-preserve", codexFingerprintSession)
	require.NotNil(t, ids)

	body := []byte(`{"model":"gpt-5.6-sol","input":[{"type":"message","role":"user","content":"hi"}],"stream":true,"prompt_cache_key":"pck-1"}`)
	out, changed, err := applyCodexFingerprintClientMetadataRaw(body, ids)
	require.NoError(t, err)
	require.True(t, changed)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(out, &decoded))
	assert.Equal(t, "gpt-5.6-sol", decoded["model"])
	assert.Equal(t, "pck-1", decoded["prompt_cache_key"])
	assert.Equal(t, true, decoded["stream"])
	cm, _ := decoded["client_metadata"].(map[string]any)
	require.NotNil(t, cm)
	assert.Equal(t, ids.sessionID, cm["session_id"])
	assert.Equal(t, ids.turnID, cm["turn_id"])
}

func TestApplyCodexFingerprintClientMetadataRaw_Noop(t *testing.T) {
	body := []byte(`{"model":"gpt-5.6-sol"}`)
	out, changed, err := applyCodexFingerprintClientMetadataRaw(body, nil)
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Equal(t, body, out)

	out, changed, err = applyCodexFingerprintClientMetadataRaw(nil, &codexFingerprintIDs{mode: codexFingerprintSession, installationID: "x"})
	require.NoError(t, err)
	assert.False(t, changed)
	assert.Nil(t, out)
}

// --- context 暂存与出站头应用（透传/非透传共用 seam）---

func newFingerprintStageTestContext(t *testing.T) *gin.Context {
	t.Helper()
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/responses", nil)
	return c
}

func TestStageCodexFingerprintIDs_NilOverwritesPreviousAccount(t *testing.T) {
	c := newFingerprintStageTestContext(t)
	accountA := newTestOAuthAccount(1001, map[string]any{codexFingerprintModeExtraKey: "session"})
	idsA := resolveCodexFingerprintIDs(accountA, "sess-x", codexFingerprintSession)
	require.NotNil(t, idsA)
	stageCodexFingerprintIDs(c, idsA)

	// failover 切到 off 模式账号：无条件覆写为 nil，上一账号 IDs 不得残留
	stageCodexFingerprintIDs(c, nil)

	h := http.Header{}
	h.Set("session_id", "isolated-session")
	accountB := newTestOAuthAccount(1002, map[string]any{"codex_fingerprint_mode": "off"})
	applyStagedCodexFingerprintHeaders(c, accountB, h)
	assert.Equal(t, "isolated-session", h.Get("session_id"), "off 账号不得应用上一账号的收敛 ID")
	assert.Empty(t, h.Get("x-codex-installation-id"))
}

func TestApplyStagedCodexFingerprintRejectsDifferentOAuthAccount(t *testing.T) {
	c := newFingerprintStageTestContext(t)
	accountA := newTestOAuthAccount(1003, map[string]any{codexFingerprintModeExtraKey: "session"})
	idsA := resolveCodexFingerprintIDs(accountA, "sess-a", codexFingerprintSession)
	require.NotNil(t, idsA)
	stageCodexFingerprintIDs(c, idsA)

	accountB := newTestOAuthAccount(1004, map[string]any{codexFingerprintModeExtraKey: "session"})
	h := make(http.Header)
	h.Set("session-id", "account-b-session")
	applyStagedCodexFingerprintHeaders(c, accountB, h)
	assert.Equal(t, "account-b-session", h.Get("session-id"))
	assert.Empty(t, h.Get("x-codex-installation-id"))

	body := map[string]any{"client_metadata": map[string]any{"session_id": "account-b-session"}}
	assert.False(t, applyStagedCodexFingerprintClientMetadata(c, accountB, body))
	clientMetadata, ok := body["client_metadata"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "account-b-session", clientMetadata["session_id"])
}

func TestApplyStagedCodexFingerprintHeaders_SkipsNonOAuthAccount(t *testing.T) {
	c := newFingerprintStageTestContext(t)
	oauthIDs := resolveCodexFingerprintIDs(newTestOAuthAccount(1003, map[string]any{codexFingerprintModeExtraKey: "session"}), "sess-y", codexFingerprintSession)
	require.NotNil(t, oauthIDs)
	stageCodexFingerprintIDs(c, oauthIDs)

	h := http.Header{}
	apiKeyAccount := &Account{ID: 1004, Platform: PlatformOpenAI, Type: AccountTypeAPIKey}
	applyStagedCodexFingerprintHeaders(c, apiKeyAccount, h)
	assert.Empty(t, h.Get("x-codex-installation-id"), "stale 收敛 ID 不得应用到非 OAuth 账号")
}

func TestBuildUpstreamRequestOpenAIPassthrough_AppliesStagedFingerprint(t *testing.T) {
	svc := &OpenAIGatewayService{}
	// 收敛是显式 opt-in（#5610）：显式开启后验证透传路径的出站头收敛。
	account := newTestOAuthAccount(2001, map[string]any{
		"openai_oauth_passthrough": true,
		"codex_fingerprint_mode":   "session",
	})

	c := newFingerprintStageTestContext(t)
	c.Request.Header.Set("session_id", "real-client-session")
	c.Request.Header.Set("User-Agent", "codex_cli_rs/0.144.1 (Ubuntu 22.4.0; x86_64) xterm-256color")
	c.Request.Header.Set("originator", "codex_cli_rs")
	c.Request.Header.Set("x-codex-turn-metadata", `{"installation_id":"real-install","session_id":"real-session","sandbox":"seatbelt"}`)

	// 复刻 forwardOpenAIPassthrough 的解析+暂存 seam（默认 session 模式）
	ids := resolveCodexFingerprintIDsFromRequest(account, c.Request.Header)
	require.NotNil(t, ids)
	stageCodexFingerprintIDs(c, ids)

	body := []byte(`{"model":"gpt-5.6-sol","input":[],"stream":true}`)
	req, err := svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, account, body, "test-token")
	require.NoError(t, err)

	assert.Equal(t, ids.sessionID, req.Header.Get("session_id"), "session 模式下出站 session_id 应为账号级收敛值")
	assert.Equal(t, ids.installationID, req.Header.Get("x-codex-installation-id"))
	assert.Equal(t, ids.windowID, req.Header.Get("x-codex-window-id"))
	assert.Equal(t, ids.threadID, req.Header.Get("x-client-request-id"))
	turnMetadata := req.Header.Get("x-codex-turn-metadata")
	require.NotEmpty(t, turnMetadata)
	assert.Contains(t, turnMetadata, ids.sessionID, "turn-metadata JSON 中的 session_id 应被收敛")
	assert.Contains(t, turnMetadata, `"sandbox":"seatbelt"`, "turn-metadata 未指定字段应原样保留")
}

func TestBuildUpstreamRequestOpenAIPassthrough_OffModeKeepsIsolatedSession(t *testing.T) {
	svc := &OpenAIGatewayService{}
	account := newTestOAuthAccount(2002, map[string]any{
		"openai_oauth_passthrough": true,
		"codex_fingerprint_mode":   "off",
	})

	c := newFingerprintStageTestContext(t)
	c.Request.Header.Set("session_id", "real-client-session")
	c.Request.Header.Set("originator", "codex_cli_rs")

	ids := resolveCodexFingerprintIDsFromRequest(account, c.Request.Header)
	require.Nil(t, ids)
	stageCodexFingerprintIDs(c, ids)

	body := []byte(`{"model":"gpt-5.6-sol","input":[],"stream":true}`)
	req, err := svc.buildUpstreamRequestOpenAIPassthrough(context.Background(), c, account, body, "test-token")
	require.NoError(t, err)

	assert.NotEmpty(t, req.Header.Get("session_id"))
	assert.NotEqual(t, resolveConvergedSessionID(testCodexFingerprintSeed), req.Header.Get("session_id"), "off 模式不得收敛 session_id")
	assert.Empty(t, req.Header.Get("x-codex-window-id"))
}

func TestApplyCodexFingerprintClientMetadataRaw_NonObjectBodyUntouched(t *testing.T) {
	account := newTestOAuthAccount(4244, map[string]any{codexFingerprintModeExtraKey: "session"})
	ids := resolveCodexFingerprintIDs(account, "client-sess-nonobj", codexFingerprintSession)
	require.NotNil(t, ids)

	for _, body := range []string{`[1,2,3]`, `"plain string"`, `not json at all`} {
		out, changed, err := applyCodexFingerprintClientMetadataRaw([]byte(body), ids)
		require.NoError(t, err)
		assert.False(t, changed, "非 JSON 对象 body 不应被改写: %s", body)
		assert.Equal(t, []byte(body), out)
	}
}

// --- off 模式 installation 兜底（#5786 全载体缺失） ---

func TestDecideCodexInstallationBackfill_OffModeBackfillsCanonical(t *testing.T) {
	account := newTestOAuthAccount(4901, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})

	backfill := decideCodexInstallationBackfill(account, nil, nil)
	require.NotNil(t, backfill, "客户端与账号都无 installation 时应兜底")
	assert.Equal(t, account.ID, backfill.accountID)
	assert.Equal(t, resolveConvergedInstallationID(account, testCodexFingerprintSeed), backfill.installationID)
}

func TestDecideCodexInstallationBackfill_DeviceIDPreferred(t *testing.T) {
	deviceAccount := newTestOAuthAccount(4903, map[string]any{
		codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
		"openai_device_id":           "real-device-id",
	})
	backfill := decideCodexInstallationBackfill(deviceAccount, nil, nil)
	require.NotNil(t, backfill)
	assert.Equal(t, "real-device-id", backfill.installationID, "显式 device_id 优先于 seed 派生")
}

func TestDecideCodexInstallationBackfill_ClientCarriersSuppress(t *testing.T) {
	account := newTestOAuthAccount(4904, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	canonical := accountCodexCanonicalInstallationID(account)
	require.NotEmpty(t, canonical)

	// 头侧载体
	h := http.Header{}
	h.Set("x-codex-installation-id", "client-install")
	assert.Nil(t, decideCodexInstallationBackfill(account, h, nil), "客户端已带 installation 头时不得兜底")

	h2 := http.Header{}
	h2.Set("x-codex-turn-metadata", `{"installation_id":"tm-install","turn_id":"t1"}`)
	assert.Nil(t, decideCodexInstallationBackfill(account, h2, nil), "turn metadata 头已带 installation 时不得兜底")

	// 体侧载体
	assert.Nil(t, decideCodexInstallationBackfill(account, nil, map[string]any{
		"x-codex-installation-id": "body-install",
	}), "client_metadata 平铺键已带 installation 时不得兜底")

	assert.Nil(t, decideCodexInstallationBackfill(account, nil, map[string]any{
		"x-codex-turn-metadata": `{"installation_id":"embedded-install"}`,
	}), "内嵌 turn metadata 已带 installation 时不得兜底")
}

func TestDecideCodexInstallationBackfill_NoSeedNoDevice(t *testing.T) {
	account := newTestOAuthAccount(4905, nil)
	assert.Nil(t, decideCodexInstallationBackfill(account, nil, nil), "无 seed 且无 device_id 时不兜底")
}

func TestApplyCodexInstallationBackfillToRequestBody_Additive(t *testing.T) {
	canonical := "00000000-0000-4000-8000-0000000000aa"

	// 无 client_metadata：创建并写入
	body := map[string]any{"model": "gpt-5.6-sol"}
	assert.True(t, applyCodexInstallationBackfillToRequestBody(body, canonical))
	cm, cmOk := body["client_metadata"].(map[string]any)
	require.True(t, cmOk)
	assert.Equal(t, canonical, cm["x-codex-installation-id"])
	assert.NotContains(t, cm, openAIWSTurnMetadataHeader, "不应凭空创建内嵌 turn metadata")

	// 已有内嵌 turn metadata：补 installation_id，保留其他字段
	body2 := map[string]any{"client_metadata": map[string]any{
		openAIWSTurnMetadataHeader: `{"turn_id":"t1","thread_id":"th1"}`,
	}}
	assert.True(t, applyCodexInstallationBackfillToRequestBody(body2, canonical))
	metadataRaw, metadataRawOk := body2["client_metadata"].(map[string]any)[openAIWSTurnMetadataHeader].(string)
	require.True(t, metadataRawOk)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(metadataRaw), &metadata))
	assert.Equal(t, canonical, metadata["installation_id"])
	assert.Equal(t, "t1", metadata["turn_id"], "既有 turn metadata 字段必须保留")

	// 已有值：不覆盖
	body3 := map[string]any{"client_metadata": map[string]any{"x-codex-installation-id": "client-install"}}
	assert.False(t, applyCodexInstallationBackfillToRequestBody(body3, canonical))
	body3cm, body3cmOk := body3["client_metadata"].(map[string]any)
	require.True(t, body3cmOk)
	assert.Equal(t, "client-install", body3cm["x-codex-installation-id"])
}

func TestApplyCodexInstallationBackfillToRequestBodyRaw_ParityWithMap(t *testing.T) {
	canonical := "00000000-0000-4000-8000-0000000000bb"

	body := []byte(`{"model":"gpt-5.6-sol","input":[],"client_metadata":{"x-codex-turn-metadata":"{\"turn_id\":\"t2\"}"}}`)
	out, changed, err := applyCodexInstallationBackfillToRequestBodyRaw(body, canonical)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, canonical, gjson.GetBytes(out, "client_metadata.x-codex-installation-id").String())
	embedded := gjson.GetBytes(out, "client_metadata."+openAIWSTurnMetadataHeader).String()
	assert.Equal(t, canonical, codexJSONObjectStringField(embedded, "installation_id"))
	assert.Equal(t, "t2", codexJSONObjectStringField(embedded, "turn_id"))

	// 客户端已带平铺值：不改写
	body2 := []byte(`{"client_metadata":{"x-codex-installation-id":"client-install"}}`)
	out2, changed2, err := applyCodexInstallationBackfillToRequestBodyRaw(body2, canonical)
	require.NoError(t, err)
	assert.False(t, changed2)
	assert.Equal(t, "client-install", gjson.GetBytes(out2, "client_metadata.x-codex-installation-id").String())

	// 非 JSON 对象：原样保留
	for _, raw := range []string{`[1,2,3]`, `"s"`, `not json`} {
		outRaw, changedRaw, err := applyCodexInstallationBackfillToRequestBodyRaw([]byte(raw), canonical)
		require.NoError(t, err)
		assert.False(t, changedRaw)
		assert.Equal(t, []byte(raw), outRaw)
	}
}

func TestApplyStagedCodexInstallationBackfillHeaders(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	account := newTestOAuthAccount(4906, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	canonical := accountCodexCanonicalInstallationID(account)
	require.NotEmpty(t, canonical)

	stageCodexInstallationBackfill(c, &codexInstallationBackfill{accountID: account.ID, installationID: canonical})
	h := http.Header{}
	applyStagedCodexInstallationBackfillHeaders(c, account, h, nil)
	assert.Equal(t, canonical, h.Get("x-codex-installation-id"))

	// 已有头值不覆盖
	h2 := http.Header{}
	h2.Set("x-codex-installation-id", "client-install")
	applyStagedCodexInstallationBackfillHeaders(c, account, h2, nil)
	assert.Equal(t, "client-install", h2.Get("x-codex-installation-id"))

	// 已存在的 turn metadata 头被补齐
	h3 := http.Header{}
	h3.Set(openAIWSTurnMetadataHeader, `{"turn_id":"t3"}`)
	applyStagedCodexInstallationBackfillHeaders(c, account, h3, nil)
	assert.Equal(t, canonical, codexJSONObjectStringField(h3.Get(openAIWSTurnMetadataHeader), "installation_id"))
	assert.Equal(t, "t3", codexJSONObjectStringField(h3.Get(openAIWSTurnMetadataHeader), "turn_id"))

	// 账号不匹配的 stale 决策不得应用
	other := newTestOAuthAccount(4907, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	h4 := http.Header{}
	applyStagedCodexInstallationBackfillHeaders(c, other, h4, nil)
	assert.Empty(t, h4.Get("x-codex-installation-id"), "failover 后 stale 决策不得泄漏到其他账号")
}

func TestApplyStagedCodexInstallationBackfillHeaders_BodyToHeaderSync(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	account := newTestOAuthAccount(4909, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})

	// 无 staged 决策但体侧已携带（如 device_id 注入或客户端仅带体值）：头与体取同一值
	h := http.Header{}
	body := []byte(`{"client_metadata":{"x-codex-installation-id":"body-install"}}`)
	applyStagedCodexInstallationBackfillHeaders(c, account, h, body)
	assert.Equal(t, "body-install", h.Get("x-codex-installation-id"), "头缺失时应与体侧取同一值")

	// 体侧无 installation：不写头
	h2 := http.Header{}
	applyStagedCodexInstallationBackfillHeaders(c, account, h2, []byte(`{"model":"gpt-5.6-sol"}`))
	assert.Empty(t, h2.Get("x-codex-installation-id"))

	// 头已存在时不被体侧覆盖
	h3 := http.Header{}
	h3.Set("x-codex-installation-id", "header-install")
	applyStagedCodexInstallationBackfillHeaders(c, account, h3, body)
	assert.Equal(t, "header-install", h3.Get("x-codex-installation-id"))
}

func TestStageCodexInstallationBackfill_NilOverwrite(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	account := newTestOAuthAccount(4908, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})

	stageCodexInstallationBackfill(c, &codexInstallationBackfill{accountID: account.ID, installationID: "abc"})
	stageCodexInstallationBackfill(c, nil)
	assert.Nil(t, stagedCodexInstallationBackfill(c, account), "无条件覆写 nil 后不得读到旧决策")
}

func TestApplyCodexWSInstallationBackfillHeaders(t *testing.T) {
	account := newTestOAuthAccount(4910, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	canonical := accountCodexCanonicalInstallationID(account)
	require.NotEmpty(t, canonical)

	newWSHookContext := func(t *testing.T) *gin.Context {
		t.Helper()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		stageCodexInstallationBackfill(c, nil)
		return c
	}

	// 客户端未携带任何载体：补齐 canonical
	c := newWSHookContext(t)
	h := http.Header{}
	applyCodexWSInstallationBackfillHeaders(c, account, h)
	assert.Equal(t, canonical, h.Get("x-codex-installation-id"))

	// 客户端已带头值：不改写
	c2 := newWSHookContext(t)
	h2 := http.Header{}
	h2.Set("x-codex-installation-id", "client-install")
	applyCodexWSInstallationBackfillHeaders(c2, account, h2)
	assert.Equal(t, "client-install", h2.Get("x-codex-installation-id"))

	// 客户端 turn metadata 头已带 installation：整体保留
	c3 := newWSHookContext(t)
	h3 := http.Header{}
	h3.Set(openAIWSTurnMetadataHeader, `{"installation_id":"tm-install"}`)
	applyCodexWSInstallationBackfillHeaders(c3, account, h3)
	assert.Empty(t, h3.Get("x-codex-installation-id"), "客户端已携带 installation 载体时不得兜底")

	// 已存在 turn metadata 头缺 installation：补齐且保留其他字段
	c4 := newWSHookContext(t)
	h4 := http.Header{}
	h4.Set(openAIWSTurnMetadataHeader, `{"turn_id":"t4"}`)
	applyCodexWSInstallationBackfillHeaders(c4, account, h4)
	assert.Equal(t, canonical, h4.Get("x-codex-installation-id"))
	assert.Equal(t, canonical, codexJSONObjectStringField(h4.Get(openAIWSTurnMetadataHeader), "installation_id"))
	assert.Equal(t, "t4", codexJSONObjectStringField(h4.Get(openAIWSTurnMetadataHeader), "turn_id"))

	// 无 seed 且无 device_id：不兜底
	bare := newTestOAuthAccount(4911, nil)
	c5 := newWSHookContext(t)
	h5 := http.Header{}
	applyCodexWSInstallationBackfillHeaders(c5, bare, h5)
	assert.Empty(t, h5.Get("x-codex-installation-id"))
}

func TestApplyStagedCodexInstallationBackfillHeaders_CompactPath(t *testing.T) {
	account := newTestOAuthAccount(4912, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	canonical := accountCodexCanonicalInstallationID(account)
	require.NotEmpty(t, canonical)

	newCompactContext := func(t *testing.T) *gin.Context {
		t.Helper()
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses/compact", nil)
		return c
	}

	// compact 路径：头与体都缺失 → 头侧补齐 canonical
	c := newCompactContext(t)
	h := http.Header{}
	applyStagedCodexInstallationBackfillHeaders(c, account, h, []byte(`{"model":"gpt-5.6-sol"}`))
	assert.Equal(t, canonical, h.Get("x-codex-installation-id"))

	// compact 路径：体侧已携带 → 头与体取同一值，不用 canonical
	c2 := newCompactContext(t)
	h2 := http.Header{}
	applyStagedCodexInstallationBackfillHeaders(c2, account, h2, []byte(`{"client_metadata":{"x-codex-installation-id":"body-install"}}`))
	assert.Equal(t, "body-install", h2.Get("x-codex-installation-id"))

	// compact 路径：头已存在 → 不覆盖
	c3 := newCompactContext(t)
	h3 := http.Header{}
	h3.Set("x-codex-installation-id", "client-install")
	applyStagedCodexInstallationBackfillHeaders(c3, account, h3, []byte(`{}`))
	assert.Equal(t, "client-install", h3.Get("x-codex-installation-id"))

	// 非 compact 路径：无 staged 决策且体侧缺失时不得头侧兜底（保持原语义）
	c4, _ := gin.CreateTestContext(httptest.NewRecorder())
	c4.Request = httptest.NewRequest(http.MethodPost, "/backend-api/codex/responses", nil)
	h4 := http.Header{}
	applyStagedCodexInstallationBackfillHeaders(c4, account, h4, []byte(`{"model":"gpt-5.6-sol"}`))
	assert.Empty(t, h4.Get("x-codex-installation-id"))
}

// --- smart 指纹收敛模式（#5786 smart 策略） ---

func TestCodexFingerprintMode_SmartAccepted(t *testing.T) {
	account := newTestOAuthAccount(4920, map[string]any{
		codexFingerprintModeExtraKey: "smart",
		codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
	})
	assert.Equal(t, codexFingerprintSmart, account.GetCodexFingerprintMode())
	assert.True(t, codexFingerprintModeRequiresSeed(codexFingerprintSmart))
	assert.Nil(t, resolveCodexFingerprintIDs(account, "client-sess-smart", codexFingerprintSmart), "smart 不做静态收敛")
}

func TestResolveCodexSmartInstallationBackfill(t *testing.T) {
	ctx := context.Background()
	newSmartAccount := func() *Account {
		return newTestOAuthAccount(4921, map[string]any{
			codexFingerprintModeExtraKey: "smart",
			codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
		})
	}

	// 非 smart 账号：不解析
	offAccount := newTestOAuthAccount(4922, map[string]any{codexFingerprintSeedExtraKey: testCodexFingerprintSeed})
	svc := &OpenAIGatewayService{}
	assert.Nil(t, svc.resolveCodexSmartInstallationBackfill(ctx, offAccount, "sess-1", ""))

	// 会话缺失：不猜（规则 4）
	smartAccount := newSmartAccount()
	assert.Nil(t, svc.resolveCodexSmartInstallationBackfill(ctx, smartAccount, "", ""))

	// 无 seed 且无 device_id：无 canonical 来源（直接构造，绕过测试辅助的 seed 注入）
	bareSmart := &Account{ID: 4923, Platform: PlatformOpenAI, Type: AccountTypeOAuth, Extra: map[string]any{codexFingerprintModeExtraKey: "smart"}}
	assert.Nil(t, svc.resolveCodexSmartInstallationBackfill(ctx, bareSmart, "sess-1", ""))

	// 正常解析：返回权威绑定决策
	backfill := svc.resolveCodexSmartInstallationBackfill(ctx, smartAccount, "sess-1", "")
	require.NotNil(t, backfill)
	assert.True(t, backfill.authoritative)
	assert.Equal(t, smartAccount.ID, backfill.accountID)
	assert.Equal(t, resolveConvergedInstallationID(smartAccount, testCodexFingerprintSeed), backfill.installationID, "客户端未携带时绑定 canonical")
}

func TestResolveCodexSmartInstallationBackfill_ClientBindingWins(t *testing.T) {
	ctx := context.Background()
	store := newTestBindingStore(t, newFakeBindingGatewayCache())
	svc := &OpenAIGatewayService{codexSessionBindings: store}
	account := newTestOAuthAccount(4924, map[string]any{
		codexFingerprintModeExtraKey: "smart",
		codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
	})

	// 首次观测：客户端自带 installation → legacy/client 绑定
	first := svc.resolveCodexSmartInstallationBackfill(ctx, account, "sess-legacy", "client-own-install")
	require.NotNil(t, first)
	assert.Equal(t, "client-own-install", first.installationID)

	// 后续请求：客户端换值或缺失都固定使用绑定值
	second := svc.resolveCodexSmartInstallationBackfill(ctx, account, "sess-legacy", "client-rotated")
	require.NotNil(t, second)
	assert.Equal(t, "client-own-install", second.installationID)

	third := svc.resolveCodexSmartInstallationBackfill(ctx, account, "sess-legacy", "")
	require.NotNil(t, third)
	assert.Equal(t, "client-own-install", third.installationID)
}

func TestApplyCodexSmartInstallationToRequestBody_Authoritative(t *testing.T) {
	canonical := "00000000-0000-4000-8000-0000000000cc"

	// 无 client_metadata：创建并写入
	body := map[string]any{"model": "gpt-5.6-sol"}
	assert.True(t, applyCodexSmartInstallationToRequestBody(body, canonical))
	createdMetadata, createdMetadataOk := body["client_metadata"].(map[string]any)
	require.True(t, createdMetadataOk)
	assert.Equal(t, canonical, createdMetadata["x-codex-installation-id"])

	// 客户端既有值被权威覆盖（规则 3）
	body2 := map[string]any{"client_metadata": map[string]any{
		"x-codex-installation-id":  "client-old",
		openAIWSTurnMetadataHeader: `{"installation_id":"client-old","turn_id":"t5"}`,
	}}
	assert.True(t, applyCodexSmartInstallationToRequestBody(body2, canonical))
	cm, cmOk := body2["client_metadata"].(map[string]any)
	require.True(t, cmOk)
	assert.Equal(t, canonical, cm["x-codex-installation-id"])
	metadataRaw, metadataRawOk := cm[openAIWSTurnMetadataHeader].(string)
	require.True(t, metadataRawOk)
	var metadata map[string]any
	require.NoError(t, json.Unmarshal([]byte(metadataRaw), &metadata))
	assert.Equal(t, canonical, metadata["installation_id"])
	assert.Equal(t, "t5", metadata["turn_id"], "非身份字段保留")
}

func TestApplyCodexSmartInstallationToRequestBodyRaw_Authoritative(t *testing.T) {
	canonical := "00000000-0000-4000-8000-0000000000dd"

	body := []byte(`{"client_metadata":{"x-codex-installation-id":"client-old","x-codex-turn-metadata":"{\"installation_id\":\"client-old\"}"}}`)
	out, changed, err := applyCodexSmartInstallationToRequestBodyRaw(body, canonical)
	require.NoError(t, err)
	assert.True(t, changed)
	assert.Equal(t, canonical, gjson.GetBytes(out, "client_metadata.x-codex-installation-id").String())
	assert.Equal(t, canonical, codexJSONObjectStringField(gjson.GetBytes(out, "client_metadata."+openAIWSTurnMetadataHeader).String(), "installation_id"))

	// 非 JSON 对象：原样保留
	outRaw, changedRaw, err := applyCodexSmartInstallationToRequestBodyRaw([]byte(`[1]`), canonical)
	require.NoError(t, err)
	assert.False(t, changedRaw)
	assert.Equal(t, []byte(`[1]`), outRaw)
}

func TestApplyStagedCodexInstallationBackfillHeaders_SmartAuthoritative(t *testing.T) {
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	account := newTestOAuthAccount(4925, map[string]any{
		codexFingerprintModeExtraKey: "smart",
		codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
	})
	bound := "bound-install"
	stageCodexInstallationBackfill(c, &codexInstallationBackfill{accountID: account.ID, installationID: bound, authoritative: true})

	// 头已携带客户端值：权威绑定覆盖（规则 3）
	h := http.Header{}
	h.Set("x-codex-installation-id", "client-own")
	h.Set(openAIWSTurnMetadataHeader, `{"installation_id":"client-own","turn_id":"t6"}`)
	applyStagedCodexInstallationBackfillHeaders(c, account, h, nil)
	assert.Equal(t, bound, h.Get("x-codex-installation-id"))
	assert.Equal(t, bound, codexJSONObjectStringField(h.Get(openAIWSTurnMetadataHeader), "installation_id"))
	assert.Equal(t, "t6", codexJSONObjectStringField(h.Get(openAIWSTurnMetadataHeader), "turn_id"))
}

func TestCaptureCodexClientInstallationIdentity(t *testing.T) {
	// 头优先
	h := http.Header{}
	h.Set("session-id", "sess-header")
	h.Set("x-codex-installation-id", "install-header")
	sessionID, installation := captureCodexClientInstallationIdentity(h, nil)
	assert.Equal(t, "sess-header", sessionID)
	assert.Equal(t, "install-header", installation)

	// 头缺失时回退 body
	metadata := map[string]any{"session_id": "sess-body", "x-codex-installation-id": "install-body"}
	sessionID, installation = captureCodexClientInstallationIdentity(nil, metadata)
	assert.Equal(t, "sess-body", sessionID)
	assert.Equal(t, "install-body", installation)

	// 内嵌 turn metadata 兜底
	h2 := http.Header{}
	h2.Set("session-id", "sess-h")
	sessionID, installation = captureCodexClientInstallationIdentity(h2, map[string]any{
		openAIWSTurnMetadataHeader: `{"installation_id":"install-embedded"}`,
	})
	assert.Equal(t, "sess-h", sessionID)
	assert.Equal(t, "install-embedded", installation)
}

func TestForwardPassthroughSmartBinding_EndToEnd(t *testing.T) {
	ctx := context.Background()
	store := newTestBindingStore(t, newFakeBindingGatewayCache())
	svc := &OpenAIGatewayService{}
	svc.codexSessionBindings = store
	account := newTestOAuthAccount(4926, map[string]any{
		codexFingerprintModeExtraKey: "smart",
		codexFingerprintSeedExtraKey: testCodexFingerprintSeed,
	})

	bound := accountCodexCanonicalInstallationID(account)
	require.NotEmpty(t, bound)

	// 第一次：客户端未携带 installation → 绑定 canonical。
	// 按 forwardOpenAIPassthrough 的生产顺序：捕获→解析→体投影→暂存→出站头。
	c := newFingerprintStageTestContext(t)
	c.Request.Header.Set("session-id", "real-client-session")
	body1 := []byte(`{"model":"gpt-5.6-sol","instructions":"x","input":[],"stream":true}`)
	sess1, inst1 := captureCodexClientInstallationIdentityRaw(c.Request.Header, gjson.ParseBytes(body1))
	backfill1 := svc.resolveCodexSmartInstallationBackfill(ctx, account, sess1, inst1)
	require.NotNil(t, backfill1)
	assert.True(t, backfill1.authoritative)
	assert.Equal(t, bound, backfill1.installationID)
	stageCodexInstallationBackfill(c, backfill1)
	req1, err := svc.buildUpstreamRequestOpenAIPassthrough(ctx, c, account, body1, "test-token")
	require.NoError(t, err)
	assert.Equal(t, bound, req1.Header.Get("x-codex-installation-id"))

	// 第二次：客户端携带不同 installation → 仍固定使用绑定值（不重新读取下游）
	c2 := newFingerprintStageTestContext(t)
	c2.Request.Header.Set("session-id", "real-client-session")
	c2.Request.Header.Set("x-codex-installation-id", "client-rotated")
	body2 := []byte(`{"model":"gpt-5.6-sol","instructions":"x","input":[],"stream":true,"client_metadata":{"x-codex-installation-id":"client-rotated"}}`)
	sess2, inst2 := captureCodexClientInstallationIdentityRaw(c2.Request.Header, gjson.ParseBytes(body2))
	assert.Equal(t, "client-rotated", inst2, "捕获的是客户端原始值")
	backfill2 := svc.resolveCodexSmartInstallationBackfill(ctx, account, sess2, inst2)
	require.NotNil(t, backfill2)
	assert.Equal(t, bound, backfill2.installationID, "同一会话固定使用首次绑定值")
	stageCodexInstallationBackfill(c2, backfill2)
	req2, err := svc.buildUpstreamRequestOpenAIPassthrough(ctx, c2, account, body2, "test-token")
	require.NoError(t, err)
	assert.Equal(t, bound, req2.Header.Get("x-codex-installation-id"), "权威绑定覆盖客户端轮换后的 installation")
}
