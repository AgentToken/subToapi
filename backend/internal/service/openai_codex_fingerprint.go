package service

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

// codexFingerprintIDsContextKey 是暂存在 gin context 的收敛 ID 集合键。
// 由 Forward（非透传）或 forwardOpenAIPassthrough（透传）解析后写入，请求
// 构造器读取用于出站头改写——请求体与出站头必须共享同一份 IDs，保证
// turn_id 等随机字段一致。
const codexFingerprintIDsContextKey = "codex_fingerprint_ids"

// stageCodexFingerprintIDs 将本 attempt 解析出的收敛 ID 暂存到 gin context。
// 必须无条件覆写（含 nil）：failover 从收敛账号切到 off 账号时，上一账号的
// IDs 不得残留并被误应用到新账号的出站头（typed-nil 由应用侧 nil 守卫吸收）。
func stageCodexFingerprintIDs(c *gin.Context, ids *codexFingerprintIDs) {
	if c != nil {
		c.Set(codexFingerprintIDsContextKey, ids)
	}
}

func stagedCodexFingerprintIDs(c *gin.Context, account *Account) *codexFingerprintIDs {
	if c == nil || account == nil || !account.UsesOpenAICodexProtocol() {
		return nil
	}
	value, ok := c.Get(codexFingerprintIDsContextKey)
	if !ok {
		return nil
	}
	ids, ok := value.(*codexFingerprintIDs)
	if !ok || ids == nil || ids.accountID != account.ID {
		return nil
	}
	return ids
}

// applyStagedCodexFingerprintHeaders 读取 context 暂存的收敛 ID 并改写出站头。
// 非透传与透传两个请求构造器共用本函数，防止应用语义漂移。仅解析该
// snapshot 的 OAuth 账号可读取，避免 stale context 跨账号 failover 泄漏。
func applyStagedCodexFingerprintHeaders(c *gin.Context, account *Account, h http.Header) {
	applyCodexFingerprintHeaders(h, stagedCodexFingerprintIDs(c, account))
}

func applyStagedCodexFingerprintClientMetadata(c *gin.Context, account *Account, reqBody map[string]any) bool {
	return applyCodexFingerprintClientMetadata(reqBody, stagedCodexFingerprintIDs(c, account))
}

// codexFingerprintMode 控制 OAuth 账号出站请求的设备指纹收敛强度。
// 多人共享同一 OAuth 账号时，每个用户的 Codex 客户端会携带各自不同的
// installation_id / session_id / thread_id，上游据此判定设备数和会话数。
// 收敛模式将这些标识改写为账号级恒定值，减少上游可见的设备/会话指纹。
type codexFingerprintMode string

const (
	// codexFingerprintOff 不做任何收敛，原样透传客户端标识。
	// 这是默认值：收敛是显式 opt-in 的（见 GetCodexFingerprintMode）。
	codexFingerprintOff codexFingerprintMode = "off"
	// codexFingerprintDevice 仅收敛 installation_id 为账号级恒定值。
	// 上游看到 1 台设备 + 多会话（每用户各自的 session）。
	codexFingerprintDevice codexFingerprintMode = "device"
	// codexFingerprintSession 收敛 installation_id + session_id，
	// thread_id 按客户端原始 session-id 确定性派生（每个真实 Codex 会话一个独立线程）。
	// 上游看到 1 台设备 + 1 会话 + N 线程，最接近正常用户 spawn 子代理的模式。
	codexFingerprintSession codexFingerprintMode = "session"
	// codexFingerprintFull 收敛所有标识：installation_id + session_id + thread_id。
	// 上游看到 1 台设备 + 1 会话 + 1 线程，最激进。
	codexFingerprintFull codexFingerprintMode = "full"
)

const (
	codexFingerprintModeExtraKey = "codex_fingerprint_mode"
	codexFingerprintSeedExtraKey = "codex_fingerprint_seed"
)

func canonicalCodexFingerprintSeed(value any) (string, bool) {
	raw, ok := value.(string)
	if !ok {
		return "", false
	}
	trimmed := strings.TrimSpace(raw)
	parsed, err := uuid.Parse(trimmed)
	if err != nil || parsed == uuid.Nil || trimmed != parsed.String() {
		return "", false
	}
	return trimmed, true
}

func newCodexFingerprintSeed() string {
	return uuid.NewString()
}

func stripCodexFingerprintSeed(extra map[string]any) map[string]any {
	if extra == nil {
		return nil
	}
	stripped := maps.Clone(extra)
	delete(stripped, codexFingerprintSeedExtraKey)
	return stripped
}

func codexFingerprintModeFromExtra(extra map[string]any) codexFingerprintMode {
	if extra == nil {
		return codexFingerprintOff
	}
	raw, _ := extra[codexFingerprintModeExtraKey].(string)
	switch codexFingerprintMode(strings.TrimSpace(raw)) {
	case codexFingerprintOff, codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return codexFingerprintMode(strings.TrimSpace(raw))
	default:
		return codexFingerprintOff
	}
}

func codexFingerprintModeRequiresSeed(mode codexFingerprintMode) bool {
	switch mode {
	case codexFingerprintDevice, codexFingerprintSession, codexFingerprintFull:
		return true
	default:
		return false
	}
}

func codexFingerprintSeed(extra map[string]any) (string, bool) {
	if extra == nil {
		return "", false
	}
	return canonicalCodexFingerprintSeed(extra[codexFingerprintSeedExtraKey])
}

func prepareCodexFingerprintExtraForCreate(platform, accountType string, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	// OAuth 账号一律持 seed：off 模式的 installation 兜底（#5786）也依赖
	// 账号级持久化种子，不随收敛开关有无而缺位。setup_token 仅在启用收敛时
	// 需要 seed，其身份 namespace 优先走 token 指纹，保持既有行为。
	needsSeed := false
	switch {
	case platform == PlatformOpenAI && accountType == AccountTypeOAuth:
		needsSeed = true
	case platform == PlatformOpenAI && accountType == AccountTypeSetupToken:
		needsSeed = codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(prepared))
	}
	if !needsSeed {
		return prepared
	}
	if _, ok := codexFingerprintSeed(prepared); ok {
		return prepared
	}
	if prepared == nil {
		prepared = make(map[string]any, 1)
	}
	prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	return prepared
}

func prepareCodexFingerprintExtraForUpdate(account *Account, extra map[string]any) map[string]any {
	prepared := stripCodexFingerprintSeed(extra)
	if account == nil || !account.IsOpenAIOAuthLike() {
		return prepared
	}
	if seed, ok := codexFingerprintSeed(account.Extra); ok {
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = seed
		return prepared
	}
	if account.IsOpenAIOAuth() {
		// OAuth 账号无 seed 时补种，保证 off 模式 installation 兜底可用。
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
		return prepared
	}
	if codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(prepared)) {
		if prepared == nil {
			prepared = make(map[string]any, 1)
		}
		prepared[codexFingerprintSeedExtraKey] = newCodexFingerprintSeed()
	}
	return prepared
}

func sanitizedCodexFingerprintExtraUpdates(updates map[string]any) map[string]any {
	if updates == nil {
		return nil
	}
	sanitized := maps.Clone(updates)
	delete(sanitized, codexFingerprintSeedExtraKey)
	return sanitized
}

// ShouldEnsureCodexFingerprintSeedForExtraUpdates reports whether a JSONB key-level
// extra update is enabling Codex fingerprint convergence and therefore must atomically
// preserve or create the system-managed per-account seed in the repository update.
func ShouldEnsureCodexFingerprintSeedForExtraUpdates(updates map[string]any) bool {
	if updates == nil {
		return false
	}
	return codexFingerprintModeRequiresSeed(codexFingerprintModeFromExtra(updates))
}

// GetCodexFingerprintMode 从账号 extra JSON 读取指纹收敛模式。
//
// **收敛是显式 opt-in**：未设置、空值或非法值一律按 off 处理，只有管理员
// 明确配置 device / session / full 才收敛。
//
// 历史：v0.1.175（#5553）把缺省值当作 session，导致升级后存量 OAuth 账号
// （普遍没有这个 extra 键）的每个非透传请求都被静默改写 installation /
// session / thread / turn / window 五类标识；#5555、#5556、#5582 报告的额度
// 缩水都卡在该版本边界，并有"回退 v0.1.173 即恢复"与"新账号开收敛后降额"
// 的 A/B 实测。上游的配额判定策略不可观测，因此这里取兼容安全的一侧：
// 不显式 opt-in 就保持 v0.1.175 之前的客户端身份（#5610）。
func (a *Account) GetCodexFingerprintMode() codexFingerprintMode {
	if a == nil || !a.IsOpenAIOAuthLike() {
		return codexFingerprintOff
	}
	return codexFingerprintModeFromExtra(a.Extra)
}

// deriveStableUUIDv4 从种子确定性派生一个 UUIDv4 格式的字符串。
// 同一种子永远返回同一值。
func deriveStableUUIDv4(seed string) string {
	h := sha256.Sum256([]byte(seed))
	b := h[:16]
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 1
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		binary.BigEndian.Uint32(b[0:4]),
		binary.BigEndian.Uint16(b[4:6]),
		binary.BigEndian.Uint16(b[6:8]),
		binary.BigEndian.Uint16(b[8:10]),
		b[10:16])
}

// resolveConvergedInstallationID 返回账号级恒定的 installation_id。
// 优先使用管理员配置的真实 device_id，无则从系统管理的账号随机种子确定性派生。
func resolveConvergedInstallationID(account *Account, seed string) string {
	if account == nil {
		return ""
	}
	if deviceID := account.GetOpenAIDeviceID(); deviceID != "" {
		return deviceID
	}
	if seed == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-install-id:v2:" + seed)
}

// resolveConvergedSessionID 返回账号级恒定的 session_id。
func resolveConvergedSessionID(seed string) string {
	if seed == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-session-id:v2:" + seed)
}

// resolveConvergedThreadID 按客户端原始 session-id 确定性派生 thread_id。
// 每个真实 Codex 会话（不同客户端启动实例）获得一个独立线程，
// 模拟正常用户 spawn 子代理或开多窗口的模式。
func resolveConvergedThreadID(seed, clientSessionID string) string {
	if seed == "" || clientSessionID == "" {
		return ""
	}
	return deriveStableUUIDv4("sub2api:codex-thread-id:v2:" + seed + ":" + clientSessionID)
}

// codexFingerprintIDs 收敛后的完整 ID 集合。
// 由 resolveCodexFingerprintIDs 一次性生成，同一个实例在头改写和体改写之间共享，
// 确保所有载体中的 turn_id 等随机字段一致。体改写时还会补记原始
// client_metadata.session_id，用于识别 root prompt_cache_key 的默认值。
type codexFingerprintIDs struct {
	accountID                     int64
	mode                          codexFingerprintMode
	installationID                string
	sessionID                     string
	threadID                      string
	turnID                        string
	windowID                      string
	turnStartedAtUnixMs           int64
	originalBodySessionID         string
	originalBodySessionIDCaptured bool
}

// resolveCodexFingerprintIDs 按收敛模式计算出站 ID 集合。
// clientSessionID 是客户端原始的 session-id 头值（连字符形式），用于 session 模式下
// 的 thread_id 派生——每个真实 Codex 会话得到一个独立线程。
// 返回 nil 表示 off 模式，不需要改写。
// 注意：包含随机生成的 turn_id，调用方必须只调用一次并共享结果给头改写和体改写。
func resolveCodexFingerprintIDs(account *Account, clientSessionID string, mode codexFingerprintMode) *codexFingerprintIDs {
	if account == nil || mode == codexFingerprintOff {
		return nil
	}
	seed, ok := codexFingerprintSeed(account.Extra)
	if !ok {
		return nil
	}

	ids := &codexFingerprintIDs{
		accountID:           account.ID,
		mode:                mode,
		turnStartedAtUnixMs: time.Now().UnixMilli(),
	}

	ids.installationID = resolveConvergedInstallationID(account, seed)
	if ids.installationID == "" {
		return nil
	}

	switch mode {
	case codexFingerprintDevice:
		return ids

	case codexFingerprintSession:
		ids.sessionID = resolveConvergedSessionID(seed)
		ids.threadID = resolveConvergedThreadID(seed, clientSessionID)
		if ids.threadID == "" {
			ids.threadID = ids.sessionID
		}
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = ids.threadID + ":0"
		return ids

	case codexFingerprintFull:
		ids.sessionID = resolveConvergedSessionID(seed)
		ids.threadID = ids.sessionID
		ids.turnID = uuid.Must(uuid.NewV7()).String()
		ids.windowID = ids.threadID + ":0"
		return ids
	}

	return nil
}

// extractClientSessionID 从请求头中提取客户端原始的会话标识。
// 优先取 session-id（连字符形式，Codex CLI 标准），回退到 session_id（下划线形式）。
// 返回的值尚未被 isolateOpenAISessionID 改写，是客户端的真实标识。
func extractClientSessionID(h http.Header) string {
	if v := strings.TrimSpace(h.Get("session-id")); v != "" {
		return v
	}
	return strings.TrimSpace(h.Get("session_id"))
}

// resolveCodexFingerprintIDsFromRequest 从客户端原始请求头中提取 session-id，
// 结合账号配置一次性解析收敛 ID 集合。调用方应将返回的 ids 同时传给
// applyCodexFingerprintHeaders 和 applyCodexFingerprintClientMetadata。
func resolveCodexFingerprintIDsFromRequest(account *Account, clientHeaders http.Header) *codexFingerprintIDs {
	if account == nil {
		return nil
	}
	mode := account.GetCodexFingerprintMode()
	if mode == codexFingerprintOff {
		return nil
	}
	clientSessionID := ""
	if clientHeaders != nil {
		clientSessionID = extractClientSessionID(clientHeaders)
	}
	return resolveCodexFingerprintIDs(account, clientSessionID, mode)
}

// applyCodexFingerprintHeaders 按预计算的收敛 ID 改写出站 HTTP 头中的设备指纹。
// 在 buildUpstreamRequest 的白名单透传之后、enforceCodexIdentityHeaders 之前调用。
func applyCodexFingerprintHeaders(h http.Header, ids *codexFingerprintIDs) {
	if h == nil || ids == nil {
		return
	}

	// 所有非 off 模式都收敛 installation_id
	h.Set("x-codex-installation-id", ids.installationID)

	if ids.mode == codexFingerprintDevice {
		rewriteCodexTurnMetadataFields(h, map[string]any{
			"installation_id": ids.installationID,
		})
		return
	}

	// session / full 模式：改写所有相关头
	h.Set("x-codex-window-id", ids.windowID)
	h.Set("x-client-request-id", ids.threadID)
	// 连字符形式和下划线形式都改写，保证一致
	h.Set("session-id", ids.sessionID)
	h.Set("session_id", ids.sessionID)
	h.Set("thread-id", ids.threadID)

	rewriteCodexTurnMetadataFields(h, map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	})
}

// rewriteCodexTurnMetadataFields 解析 x-codex-turn-metadata 头中的 JSON，
// 替换指定字段后回写。合法对象保留未指定字段（如 sandbox、thread_source）；
// 非法/非对象值重建为最小合法 metadata，避免 flat 与 embedded identity 分裂。
func rewriteCodexTurnMetadataFields(h http.Header, fields map[string]any) {
	raw := strings.TrimSpace(h.Get("x-codex-turn-metadata"))
	if raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any, len(fields))
	}
	for k, v := range fields {
		metadata[k] = v
	}
	rebuilt, err := json.Marshal(metadata)
	if err != nil {
		return
	}
	h.Set("x-codex-turn-metadata", string(rebuilt))
}

// applyCodexFingerprintClientMetadata 按预计算的收敛 ID 改写请求体中的 client_metadata。
// 使用与头改写相同的 ids 实例，确保 turn_id 等随机字段一致。
func applyCodexFingerprintClientMetadata(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil || ids == nil {
		return false
	}

	captureCodexFingerprintOriginalBodySessionID(ids, reqBody["client_metadata"])
	existing, _ := reqBody["client_metadata"].(map[string]any)
	if existing == nil {
		existing = make(map[string]any)
	}

	modified := false
	if applyCodexFingerprintToClientMetadataMap(existing, ids) {
		reqBody["client_metadata"] = existing
		modified = true
	}
	if applyCodexFingerprintPromptCacheKey(reqBody, ids) {
		modified = true
	}
	return modified
}

// applyCodexFingerprintToClientMetadataMap 是 client_metadata 改写的共享核心，
// map 版（非透传，body 已解码）与 raw 字节版（透传热路径）都经由它，保证两条
// 路径的收敛语义永不漂移。
func applyCodexFingerprintToClientMetadataMap(existing map[string]any, ids *codexFingerprintIDs) bool {
	if existing == nil || ids == nil {
		return false
	}

	modified := false

	if ids.installationID != "" {
		existing["x-codex-installation-id"] = ids.installationID
		modified = true
	}

	if ids.mode == codexFingerprintDevice {
		rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
			"installation_id": ids.installationID,
		})
		return modified
	}

	// session / full 模式
	existing["session_id"] = ids.sessionID
	existing["thread_id"] = ids.threadID
	existing["turn_id"] = ids.turnID
	existing["x-codex-window-id"] = ids.windowID

	rewriteClientMetadataEmbeddedTurnMetadata(existing, map[string]any{
		"installation_id":         ids.installationID,
		"session_id":              ids.sessionID,
		"thread_id":               ids.threadID,
		"turn_id":                 ids.turnID,
		"window_id":               ids.windowID,
		"turn_started_at_unix_ms": ids.turnStartedAtUnixMs,
	})
	return true
}

func captureCodexFingerprintOriginalBodySessionID(ids *codexFingerprintIDs, clientMetadata any) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if clientMetadata == nil {
		return
	}
	switch metadata := clientMetadata.(type) {
	case map[string]any:
		if sessionID, ok := metadata["session_id"].(string); ok {
			ids.originalBodySessionID = strings.TrimSpace(sessionID)
		}
	case map[string]string:
		ids.originalBodySessionID = strings.TrimSpace(metadata["session_id"])
	}
}

func captureCodexFingerprintOriginalBodySessionIDRaw(ids *codexFingerprintIDs, value gjson.Result) {
	if ids == nil || ids.originalBodySessionIDCaptured {
		return
	}
	ids.originalBodySessionIDCaptured = true
	if value.Exists() && value.Type == gjson.String {
		ids.originalBodySessionID = strings.TrimSpace(value.String())
	}
}

func shouldRewriteCodexFingerprintPromptCacheKey(ids *codexFingerprintIDs, promptCacheKey string) bool {
	if ids == nil || !ids.originalBodySessionIDCaptured || ids.originalBodySessionID == "" || ids.sessionID == "" {
		return false
	}
	if ids.mode != codexFingerprintSession && ids.mode != codexFingerprintFull {
		return false
	}
	return promptCacheKey == ids.originalBodySessionID
}

func applyCodexFingerprintPromptCacheKey(reqBody map[string]any, ids *codexFingerprintIDs) bool {
	if reqBody == nil {
		return false
	}
	promptCacheKey, ok := reqBody["prompt_cache_key"].(string)
	if !ok || strings.TrimSpace(promptCacheKey) == "" || !shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey) {
		return false
	}
	if promptCacheKey == ids.sessionID {
		return false
	}
	reqBody["prompt_cache_key"] = ids.sessionID
	return true
}

// applyCodexFingerprintClientMetadataRaw 在原始 JSON 字节上改写 client_metadata，
// 供透传路径使用——透传是热路径，禁止对可能高达数十 MB 的 body 做全量
// Unmarshal（见 forwardOpenAIPassthrough 的轻量提取注释）。实现为：gjson 提取
// client_metadata 小对象单独解码，经共享核心改写后 sjson 一次性拼回，body
// 其余字节原样保留；root prompt_cache_key 仅在可证明是 body session 默认值时
// 做标量改写。语义与 applyCodexFingerprintClientMetadata 逐点一致（含
// "非对象值整体替换为收敛集合"的行为）。
func applyCodexFingerprintClientMetadataRaw(body []byte, ids *codexFingerprintIDs) ([]byte, bool, error) {
	if len(body) == 0 || ids == nil {
		return body, false, nil
	}
	// 非 JSON 对象的 body（数组/标量/畸形）没有 client_metadata 语义，
	// sjson 在这类根上写字段会改写整体结构，直接放行保持原样。
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
		return body, false, nil
	}

	existing := map[string]any{}
	if cm := gjson.GetBytes(body, "client_metadata"); cm.IsObject() {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.GetBytes(body, "client_metadata.session_id"))
		if err := json.Unmarshal([]byte(cm.Raw), &existing); err != nil {
			return body, false, fmt.Errorf("decode client_metadata for fingerprint: %w", err)
		}
	} else {
		captureCodexFingerprintOriginalBodySessionIDRaw(ids, gjson.Result{})
	}

	next := body
	modified := false
	if applyCodexFingerprintToClientMetadataMap(existing, ids) {
		raw, err := json.Marshal(existing)
		if err != nil {
			return body, false, fmt.Errorf("encode converged client_metadata: %w", err)
		}
		var setErr error
		next, setErr = sjson.SetRawBytes(body, "client_metadata", raw)
		if setErr != nil {
			return body, false, fmt.Errorf("splice converged client_metadata: %w", setErr)
		}
		modified = true
	}
	promptCacheKey := gjson.GetBytes(body, "prompt_cache_key")
	if promptCacheKey.Exists() && promptCacheKey.Type == gjson.String && strings.TrimSpace(promptCacheKey.String()) != "" && shouldRewriteCodexFingerprintPromptCacheKey(ids, promptCacheKey.String()) {
		rewritten, err := sjson.SetBytes(next, "prompt_cache_key", ids.sessionID)
		if err != nil {
			return body, false, fmt.Errorf("splice converged prompt_cache_key: %w", err)
		}
		next = rewritten
		modified = true
	}
	return next, modified, nil
}

// rewriteClientMetadataEmbeddedTurnMetadata 改写 client_metadata 中内嵌的
// x-codex-turn-metadata JSON 字符串里的指定字段。非法/非对象值会重建，
// 避免 flat client_metadata 与 embedded metadata 暴露两套身份。
func rewriteClientMetadataEmbeddedTurnMetadata(clientMetadata map[string]any, fields map[string]any) {
	raw, ok := clientMetadata["x-codex-turn-metadata"].(string)
	if !ok || raw == "" {
		return
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		metadata = make(map[string]any, len(fields))
	}
	for k, v := range fields {
		metadata[k] = v
	}
	if rebuilt, err := json.Marshal(metadata); err == nil {
		clientMetadata["x-codex-turn-metadata"] = string(rebuilt)
	}
}

// ---- off 模式 installation 兜底（#5786「全载体缺失」） ----
//
// off 表示不主动收敛、尽量透传：客户端携带的 installation 一律原样保留。
// 但当下游请求的所有载体（独立头、turn metadata 头、body client_metadata
// 平铺键与内嵌 turn metadata）都没有 installation 时，新版官方 Codex 的
// 主模型请求不会产生这种形态（官方 ≥0.119.0-alpha.16 总是携带，见
// openai/codex@5d1671ca）。此时补齐账号级 canonical installation，取值与
// 收敛模式的 resolveConvergedInstallationID 完全一致（显式 openai_device_id
// 优先，其次持久化 seed 派生），因此模式切换不会改变 installation 身份。
// 客户端已携带任一载体时整体保留、绝不半改半放，避免单请求内身份分裂。

const codexInstallationBackfillContextKey = "codex_installation_backfill"

// codexInstallationBackfill 记录单个 attempt 的兜底决策。installationID 为空
// 表示决策为"不补齐"（客户端已携带或账号无 canonical 取值）。
type codexInstallationBackfill struct {
	accountID      int64
	installationID string
}

// stageCodexInstallationBackfill 将本 attempt 的兜底决策暂存到 gin context。
// 必须无条件覆写（含 nil），防止 failover 后残留上一账号的决策。
func stageCodexInstallationBackfill(c *gin.Context, backfill *codexInstallationBackfill) {
	if c != nil {
		c.Set(codexInstallationBackfillContextKey, backfill)
	}
}

// stagedCodexInstallationBackfill 读取当前账号在本 attempt 的兜底决策。
// 与 stagedCodexFingerprintIDs 相同的账号绑定守卫：决策只对产生它的账号生效。
func stagedCodexInstallationBackfill(c *gin.Context, account *Account) *codexInstallationBackfill {
	if c == nil || account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	value, ok := c.Get(codexInstallationBackfillContextKey)
	if !ok {
		return nil
	}
	backfill, ok := value.(*codexInstallationBackfill)
	if !ok || backfill == nil || backfill.accountID != account.ID {
		return nil
	}
	return backfill
}

// accountCodexCanonicalInstallationID 返回账号级 canonical installation，
// 与收敛模式共用同一取值来源。仅 OAuth 账号参与（setup_token 不持 seed，
// namespace 走 token 指纹，保持既有行为）。
func accountCodexCanonicalInstallationID(account *Account) string {
	if account == nil || !account.IsOpenAIOAuth() {
		return ""
	}
	seed, ok := codexFingerprintSeed(account.Extra)
	if !ok {
		return ""
	}
	return resolveConvergedInstallationID(account, seed)
}

// decideCodexInstallationBackfill 针对 map 形态的请求体做兜底决策，
// 仅在指纹收敛未启用（fpIDs == nil，即 off 模式）时调用。
func decideCodexInstallationBackfill(account *Account, clientHeaders http.Header, clientMetadata any) *codexInstallationBackfill {
	if account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	installationID := accountCodexCanonicalInstallationID(account)
	if installationID == "" {
		return nil
	}
	if clientHeadersCarryCodexInstallation(clientHeaders) || clientBodyCarriesCodexInstallationMap(clientMetadata) {
		return nil
	}
	return &codexInstallationBackfill{accountID: account.ID, installationID: installationID}
}

// decideCodexInstallationBackfillRaw 是透传热路径的决策版本，语义与 map 版一致。
func decideCodexInstallationBackfillRaw(account *Account, clientHeaders http.Header, body []byte) *codexInstallationBackfill {
	if account == nil || !account.IsOpenAIOAuth() {
		return nil
	}
	installationID := accountCodexCanonicalInstallationID(account)
	if installationID == "" {
		return nil
	}
	if clientHeadersCarryCodexInstallation(clientHeaders) || clientBodyCarriesCodexInstallationRaw(gjson.ParseBytes(body)) {
		return nil
	}
	return &codexInstallationBackfill{accountID: account.ID, installationID: installationID}
}

// clientHeadersCarryCodexInstallation 检查下游请求头侧的全部 installation 载体。
func clientHeadersCarryCodexInstallation(h http.Header) bool {
	if h == nil {
		return false
	}
	if strings.TrimSpace(h.Get("x-codex-installation-id")) != "" {
		return true
	}
	return codexJSONObjectStringField(h.Get(openAIWSTurnMetadataHeader), "installation_id") != ""
}

// clientBodyCarriesCodexInstallationMap 检查 map 形态请求体的 installation 载体。
// 非字符串的既有值保守视为已携带（整体保留，不改写）。
func clientBodyCarriesCodexInstallationMap(clientMetadata any) bool {
	switch metadata := clientMetadata.(type) {
	case map[string]any:
		if v, ok := metadata["x-codex-installation-id"]; ok {
			if s, isStr := v.(string); !isStr || strings.TrimSpace(s) != "" {
				return true
			}
		}
		if raw, ok := metadata[openAIWSTurnMetadataHeader].(string); ok {
			if codexJSONObjectStringField(raw, "installation_id") != "" {
				return true
			}
		}
	case map[string]string:
		if v, ok := metadata["x-codex-installation-id"]; ok && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

// clientBodyCarriesCodexInstallationRaw 检查原始 JSON 请求体的 installation 载体。
func clientBodyCarriesCodexInstallationRaw(root gjson.Result) bool {
	if !root.IsObject() {
		return false
	}
	clientMetadata := root.Get("client_metadata")
	if clientMetadata.Exists() && !clientMetadata.IsObject() {
		// 非对象形态保守视为已携带，整体保留。
		return true
	}
	if inst := clientMetadata.Get("x-codex-installation-id"); inst.Exists() {
		if inst.Type != gjson.String || strings.TrimSpace(inst.String()) != "" {
			return true
		}
	}
	if tm := clientMetadata.Get(openAIWSTurnMetadataHeader); tm.Exists() && tm.Type == gjson.String {
		if codexJSONObjectStringField(tm.String(), "installation_id") != "" {
			return true
		}
	}
	return false
}

// codexJSONObjectStringField 从 JSON 对象字符串中读取指定字符串字段，
// 解析失败或非对象时返回空。
func codexJSONObjectStringField(raw, key string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		return ""
	}
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

// applyCodexInstallationBackfillToRequestBody 将 canonical installation 补齐进
// map 请求体的全部适用载体：平铺 client_metadata 键 + 已存在的内嵌 turn
// metadata。不创建内嵌 turn metadata（避免伪造完整 turn 状态），不覆盖已有值。
func applyCodexInstallationBackfillToRequestBody(reqBody map[string]any, installationID string) bool {
	if reqBody == nil || installationID == "" {
		return false
	}
	existing, _ := reqBody["client_metadata"].(map[string]any)
	if existing == nil {
		existing = make(map[string]any, 1)
	}
	modified := false
	const key = "x-codex-installation-id"
	if v, ok := existing[key].(string); !ok || strings.TrimSpace(v) == "" {
		existing[key] = installationID
		modified = true
	}
	if raw, ok := existing[openAIWSTurnMetadataHeader].(string); ok && strings.TrimSpace(raw) != "" {
		var metadata map[string]any
		if err := json.Unmarshal([]byte(raw), &metadata); err == nil && metadata != nil {
			if v, ok := metadata["installation_id"].(string); !ok || strings.TrimSpace(v) == "" {
				metadata["installation_id"] = installationID
				if rebuilt, err := json.Marshal(metadata); err == nil {
					existing[openAIWSTurnMetadataHeader] = string(rebuilt)
					modified = true
				}
			}
		}
	}
	if modified {
		reqBody["client_metadata"] = existing
	}
	return modified
}

// applyCodexInstallationBackfillToRequestBodyRaw 在原始 JSON 字节上补齐
// canonical installation，语义与 map 版逐点一致；透传热路径禁全量 Unmarshal，
// 仅对 client_metadata 小对象做外科手术。
func applyCodexInstallationBackfillToRequestBodyRaw(body []byte, installationID string) ([]byte, bool, error) {
	if len(body) == 0 || installationID == "" {
		return body, false, nil
	}
	root := gjson.ParseBytes(body)
	if !root.IsObject() {
		return body, false, nil
	}
	if cm := root.Get("client_metadata"); cm.Exists() && !cm.IsObject() {
		// 非对象 client_metadata 没有 installation 载体语义，整体保留。
		return body, false, nil
	}
	next := body
	modified := false
	const key = "client_metadata.x-codex-installation-id"
	if inst := root.Get(key); !inst.Exists() || inst.Type != gjson.String || strings.TrimSpace(inst.String()) == "" {
		setBody, err := sjson.SetBytes(next, key, installationID)
		if err != nil {
			return body, false, fmt.Errorf("backfill client_metadata installation: %w", err)
		}
		next = setBody
		modified = true
	}
	embeddedKey := "client_metadata." + openAIWSTurnMetadataHeader
	if embedded := gjson.GetBytes(next, embeddedKey); embedded.Exists() && embedded.Type == gjson.String && strings.TrimSpace(embedded.String()) != "" {
		if codexJSONObjectStringField(embedded.String(), "installation_id") == "" {
			var metadata map[string]any
			if err := json.Unmarshal([]byte(embedded.String()), &metadata); err == nil && metadata != nil {
				metadata["installation_id"] = installationID
				if rebuilt, err := json.Marshal(metadata); err == nil {
					setBody, err := sjson.SetBytes(next, embeddedKey, string(rebuilt))
					if err != nil {
						return body, false, fmt.Errorf("backfill embedded turn metadata installation: %w", err)
					}
					next = setBody
					modified = true
				}
			}
		}
	}
	return next, modified, nil
}

// fillCodexTurnMetadataInstallation 向已存在的 turn metadata 头补
// installation_id（不创建、不覆盖既有值），返回是否修改。
func fillCodexTurnMetadataInstallation(h http.Header, installationID string) bool {
	if h == nil || installationID == "" {
		return false
	}
	raw := strings.TrimSpace(h.Get(openAIWSTurnMetadataHeader))
	if raw == "" {
		return false
	}
	var metadata map[string]any
	if err := json.Unmarshal([]byte(raw), &metadata); err != nil || metadata == nil {
		return false
	}
	if v, ok := metadata["installation_id"].(string); ok && strings.TrimSpace(v) != "" {
		return false
	}
	metadata["installation_id"] = installationID
	rebuilt, err := json.Marshal(metadata)
	if err != nil {
		return false
	}
	h.Set(openAIWSTurnMetadataHeader, string(rebuilt))
	return true
}

// applyStagedCodexInstallationBackfillHeaders 在出站头构建末端消费兜底决策，
// 并做"体→头"同步：头缺失而体侧已携带 installation（客户端自身值、真实
// device_id 注入路径，或 off 兜底补齐的 canonical 取值）时，头与体取同一值，
// 避免同一请求载体分裂。收敛模式（device/session/full）自行覆盖 installation
// 头，不受本函数影响。
func applyStagedCodexInstallationBackfillHeaders(c *gin.Context, account *Account, h http.Header, reqBody []byte) {
	if h == nil || account == nil || !account.IsOpenAIOAuth() {
		return
	}
	installationID := ""
	if backfill := stagedCodexInstallationBackfill(c, account); backfill != nil {
		installationID = backfill.installationID
	}
	if installationID == "" && len(reqBody) > 0 {
		if inst := gjson.GetBytes(reqBody, "client_metadata.x-codex-installation-id"); inst.Type == gjson.String && strings.TrimSpace(inst.String()) != "" {
			installationID = inst.String()
		}
	}
	if installationID == "" && isOpenAIResponsesCompactPath(c) {
		// compact 路径在 body 阶段跳过兜底决策（legacy compact 形态不参与
		// 体改写），这里按头侧兜底：体侧也没有 installation 时补齐 canonical
		//（#5786：官方 compact 同样通过头携带安装身份）。
		if len(reqBody) == 0 || !clientBodyCarriesCodexInstallationRaw(gjson.ParseBytes(reqBody)) {
			installationID = accountCodexCanonicalInstallationID(account)
		}
	}
	if installationID == "" {
		return
	}
	if strings.TrimSpace(h.Get("x-codex-installation-id")) == "" {
		h.Set("x-codex-installation-id", installationID)
	}
	fillCodexTurnMetadataInstallation(h, installationID)
}

// applyCodexWSInstallationBackfillHeaders 为 WebSocket 握手头做 off 模式
// installation 兜底（#5786 全载体缺失）。与 HTTP 路径同规则：客户端升级请求
// 未携带任何 installation 载体（此时出站头也不会有——身份层只改写已有值，
// 收敛模式会自行写入 installation 头）时，补齐账号 canonical 取值。
func applyCodexWSInstallationBackfillHeaders(account *Account, h http.Header) {
	if h == nil || account == nil || !account.IsOpenAIOAuth() {
		return
	}
	if clientHeadersCarryCodexInstallation(h) {
		return
	}
	installationID := accountCodexCanonicalInstallationID(account)
	if installationID == "" {
		return
	}
	h.Set("x-codex-installation-id", installationID)
	fillCodexTurnMetadataInstallation(h, installationID)
}
