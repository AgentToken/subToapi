package middleware

import (
	"context"
	"crypto/rand"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/pkg/ip"
	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"go.uber.org/zap"
)

// honeypotBodyLimit 读取请求体的上限（多读 1 字节用于判断截断）
const honeypotBodyLimit = 256*1024 + 1

// honeypotAuthInterceptor 包级注入点：两个 API Key 认证中间件（anthropic/google
// 错误风格）都会在鉴权通过后调用 honeypotInterceptFromAuth。拦截器在 DI 装配时
// 通过 NewHoneypotInterceptor 写入，之后只读（与 SetIngressRejectRecorder 同模式）。
var honeypotAuthInterceptor atomic.Pointer[HoneypotInterceptor]

// SetHoneypotAuthInterceptor 注册蜜罐拦截器（启动时调用一次）
func SetHoneypotAuthInterceptor(h *HoneypotInterceptor) {
	if h != nil {
		honeypotAuthInterceptor.Store(h)
	}
}

// honeypotInterceptFromAuth 认证中间件的蜜罐钩子。
// 返回 true 表示请求已被蜜罐接管（响应已写出，调用方应直接 return）。
func honeypotInterceptFromAuth(c *gin.Context, apiKey *service.APIKey) bool {
	h := honeypotAuthInterceptor.Load()
	if h == nil || !apiKey.IsHoneypotKey() {
		return false
	}
	// 管理员显式停用蜜罐 Key 时按真实禁用语义返回，让盗用者看到 Key 失效
	if apiKey.Status == service.StatusAPIKeyDisabled {
		AbortWithError(c, http.StatusUnauthorized, "API_KEY_DISABLED", "API key is disabled")
		return true
	}
	h.Intercept(c, apiKey)
	return true
}

// HoneypotInterceptor 蜜罐请求拦截器：
// 记录完整请求 → 抽取回传情报 → 返回注入了指纹采集指令的响应。
type HoneypotInterceptor struct {
	svc *service.HoneypotService
	cfg *config.Config
}

// NewHoneypotInterceptor 创建蜜罐拦截器并注册为认证中间件的钩子
func NewHoneypotInterceptor(svc *service.HoneypotService, cfg *config.Config) *HoneypotInterceptor {
	h := &HoneypotInterceptor{svc: svc, cfg: cfg}
	SetHoneypotAuthInterceptor(h)
	return h
}

// honeypotClientFormat 客户端协议格式
type honeypotClientFormat int

const (
	honeypotFormatAnthropic honeypotClientFormat = iota
	honeypotFormatOpenAI
)

// Intercept 执行蜜罐拦截主流程（调用方负责不再调用 c.Next()）
func (h *HoneypotInterceptor) Intercept(c *gin.Context, apiKey *service.APIKey) {
	hpCfg := (&service.HoneypotConfig{}).Normalized()
	if apiKey.HoneypotConfig != nil {
		hpCfg = apiKey.HoneypotConfig.Normalized()
	}

	method := c.Request.Method
	path := c.Request.URL.Path
	body, bodyTruncated := h.readBody(c)
	model := gjson.GetBytes(body, "model").String()
	stream := gjson.GetBytes(body, "stream").Bool()
	maxTokens := int(gjson.GetBytes(body, "max_tokens").Int())
	isChat := method == http.MethodPost &&
		(strings.Contains(path, "messages") || strings.Contains(path, "completions") ||
			strings.Contains(path, "responses") || strings.Contains(path, "generate_content"))
	format := honeypotFormatOpenAI
	if strings.Contains(path, "messages") && !strings.Contains(path, "chat/completions") {
		format = honeypotFormatAnthropic
	}

	clientIP := ip.GetSecurityClientIP(c, h.cfg.TrustForwardedIPForAPIKeyACL())
	intel := service.ExtractIntel(string(body))
	// 命中即告警级别日志，方便运维第一时间发现盗用者活跃
	logger.FromContext(c.Request.Context()).Warn("honeypot.request_intercepted",
		zap.Int64("api_key_id", apiKey.ID),
		zap.String("client_ip", clientIP),
		zap.String("path", path),
		zap.String("model", model),
		zap.Bool("has_env_report", intel["env_report"] != nil))

	// 组装注入 payload 与响应文本
	collectorURL := h.collectorURL(c, hpCfg.Marker)
	payload := service.BuildInjectionPayload(hpCfg, collectorURL)

	responseMode := service.HoneypotModeSynthetic
	var assistantText string
	if isChat && hpCfg.Mode == service.HoneypotModeRelay {
		relayCtx, cancel := context.WithTimeout(c.Request.Context(), 110*time.Second)
		result, err := h.svc.FetchRelayCompletion(relayCtx, hpCfg, service.LastUserTextFromMessages(body), maxTokens)
		cancel()
		if err == nil && strings.TrimSpace(result.Text) != "" {
			responseMode = service.HoneypotModeRelay
			assistantText = strings.TrimSpace(result.Text) + "\n\n" + payload
		} else {
			responseMode = "relay_fallback"
			assistantText = payload
		}
	} else {
		assistantText = payload
	}

	// 先写响应（保活优先），事件异步落库
	switch {
	case method == http.MethodGet && strings.Contains(path, "models"):
		h.writeModelsList(c, format, model)
	case isChat && stream:
		h.writeChatStream(c, format, model, assistantText)
	case isChat:
		h.writeChatJSON(c, format, model, assistantText)
	default:
		h.writeChatJSON(c, format, model, assistantText)
	}
	c.Abort()

	event := &service.HoneypotEvent{
		APIKeyID:        apiKey.ID,
		Source:          service.HoneypotEventSourceGateway,
		Method:          method,
		Path:            path,
		ClientIP:        clientIP,
		UserAgent:       c.Request.UserAgent(),
		Model:           model,
		IsStream:        stream,
		Headers:         honeypotHeaderSnapshot(c),
		Body:            string(body),
		BodyTruncated:   bodyTruncated,
		Intel:           intel,
		InjectedPayload: payload,
		ResponseMode:    responseMode,
	}
	svc := h.svc
	go svc.RecordEvent(context.Background(), event)
}

func (h *HoneypotInterceptor) readBody(c *gin.Context) ([]byte, bool) {
	if c.Request.Body == nil {
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(c.Request.Body, honeypotBodyLimit))
	_ = c.Request.Body.Close()
	if err != nil {
		return nil, false
	}
	if len(raw) >= honeypotBodyLimit {
		return raw[:honeypotBodyLimit-1], true
	}
	return raw, false
}

// collectorURL 根据请求 Host 拼 OOB 收集端点绝对地址
func (h *HoneypotInterceptor) collectorURL(c *gin.Context, marker string) string {
	scheme := "https"
	if proto := c.GetHeader("X-Forwarded-Proto"); proto == "http" {
		scheme = "http"
	} else if c.Request.TLS != nil {
		scheme = "https"
	}
	host := c.Request.Host
	if host == "" {
		return ""
	}
	return scheme + "://" + host + service.HoneypotOOBRoutePath + marker
}

// honeypotHeaderSnapshot 采集请求头快照（剔除凭据类头），
// x-stainless-* 等头能直接暴露盗用者的 SDK 与语言。
func honeypotHeaderSnapshot(c *gin.Context) map[string]any {
	sensitive := map[string]bool{
		"authorization": true, "x-api-key": true, "x-goog-api-key": true,
		"cookie": true, "set-cookie": true, "proxy-authorization": true,
	}
	out := make(map[string]any)
	count := 0
	for name, values := range c.Request.Header {
		if sensitive[strings.ToLower(name)] || count >= 40 {
			continue
		}
		joined := strings.Join(values, ", ")
		if len(joined) > 512 {
			joined = joined[:512]
		}
		out[name] = joined
		count++
	}
	return out
}

// ── 响应写出 ─────────────────────────────────────────────────────

func (h *HoneypotInterceptor) writeChatStream(c *gin.Context, format honeypotClientFormat, model, text string) {
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")
	c.Status(http.StatusOK)

	deltas := chunkText(text, 120)
	if format == honeypotFormatAnthropic {
		msgID := honeypotGenerateMsgID()
		h.sseEvent(c, "message_start", `{"type":"message_start","message":{"model":`+strconv.Quote(model)+`,"id":`+strconv.Quote(msgID)+`,"type":"message","role":"assistant","content":[],"stop_reason":null,"stop_sequence":null,"stop_details":null,"usage":{"input_tokens":`+strconv.Itoa(estTokens(text))+`,"cache_creation_input_tokens":0,"cache_read_input_tokens":0,"output_tokens":0}}}`)
		h.sseEvent(c, "content_block_start", `{"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}`)
		for _, d := range deltas {
			h.sseEvent(c, "content_block_delta", `{"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":`+strconv.Quote(d)+`}}`)
			sleepRealistic()
		}
		h.sseEvent(c, "content_block_stop", `{"index":0,"type":"content_block_stop"}`)
		h.sseEvent(c, "message_delta", `{"type":"message_delta","delta":{"stop_reason":"end_turn","stop_sequence":null,"stop_details":null},"usage":{"output_tokens":`+strconv.Itoa(estTokens(text))+`}}`)
		h.sseEvent(c, "message_stop", `{"type":"message_stop"}`)
		return
	}

	chatID := honeypotGenerateChatID()
	created := time.Now().Unix()
	roleChunk := `{"id":` + strconv.Quote(chatID) + `,"object":"chat.completion.chunk","created":` + strconv.FormatInt(created, 10) + `,"model":` + strconv.Quote(model) + `,"choices":[{"index":0,"delta":{"role":"assistant","content":""},"finish_reason":null}]}`
	h.sseData(c, roleChunk)
	for _, d := range deltas {
		chunk := `{"id":` + strconv.Quote(chatID) + `,"object":"chat.completion.chunk","created":` + strconv.FormatInt(created, 10) + `,"model":` + strconv.Quote(model) + `,"choices":[{"index":0,"delta":{"content":` + strconv.Quote(d) + `},"finish_reason":null}]}`
		h.sseData(c, chunk)
		sleepRealistic()
	}
	finalChunk := `{"id":` + strconv.Quote(chatID) + `,"object":"chat.completion.chunk","created":` + strconv.FormatInt(created, 10) + `,"model":` + strconv.Quote(model) + `,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}]}`
	h.sseData(c, finalChunk)
	h.sseData(c, "[DONE]")
}

func (h *HoneypotInterceptor) writeChatJSON(c *gin.Context, format honeypotClientFormat, model, text string) {
	if format == honeypotFormatAnthropic {
		response := gin.H{
			"model":         model,
			"id":            honeypotGenerateMsgID(),
			"type":          "message",
			"role":          "assistant",
			"content":       []gin.H{{"type": "text", "text": text}},
			"stop_reason":   "end_turn",
			"stop_sequence": nil,
			"stop_details":  nil,
			"usage": gin.H{
				"input_tokens":                estTokens(text),
				"cache_creation_input_tokens": 0,
				"cache_read_input_tokens":     0,
				"cache_creation": gin.H{
					"ephemeral_5m_input_tokens": 0,
					"ephemeral_1h_input_tokens": 0,
				},
				"output_tokens": estTokens(text),
			},
		}
		c.JSON(http.StatusOK, response)
		return
	}
	response := gin.H{
		"id":      honeypotGenerateChatID(),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []gin.H{{
			"index":         0,
			"message":       gin.H{"role": "assistant", "content": text},
			"finish_reason": "stop",
		}},
		"usage": gin.H{
			"prompt_tokens":     estTokens(text),
			"completion_tokens": estTokens(text),
			"total_tokens":      estTokens(text) * 2,
		},
	}
	c.JSON(http.StatusOK, response)
}

func (h *HoneypotInterceptor) writeModelsList(c *gin.Context, format honeypotClientFormat, requested string) {
	if requested == "" {
		if format == honeypotFormatAnthropic {
			requested = "claude-sonnet-4-5-20250929"
		} else {
			requested = "gpt-4o"
		}
	}
	models := []string{requested}
	if format == honeypotFormatAnthropic {
		models = append(models, "claude-opus-4-1-20250805", "claude-haiku-4-5-20251001")
	} else {
		models = append(models, "gpt-4o-mini", "gpt-4.1")
	}
	if format == honeypotFormatAnthropic {
		data := make([]gin.H, 0, len(models))
		for _, m := range models {
			data = append(data, gin.H{"type": "model", "id": m, "display_name": m, "created_at": time.Now().Format(time.RFC3339)})
		}
		c.JSON(http.StatusOK, gin.H{"data": data, "has_more": false, "first_id": models[0], "last_id": models[len(models)-1]})
		return
	}
	data := make([]gin.H, 0, len(models))
	for _, m := range models {
		data = append(data, gin.H{"id": m, "object": "model", "created": time.Now().Unix(), "owned_by": "owner"})
	}
	c.JSON(http.StatusOK, gin.H{"object": "list", "data": data})
}

func (h *HoneypotInterceptor) sseEvent(c *gin.Context, event, data string) {
	_, _ = c.Writer.WriteString("event: " + event + "\ndata: " + data + "\n\n")
	c.Writer.Flush()
}

func (h *HoneypotInterceptor) sseData(c *gin.Context, data string) {
	_, _ = c.Writer.WriteString("data: " + data + "\n\n")
	c.Writer.Flush()
}

// ── 小工具 ───────────────────────────────────────────────────────

// chunkText 把文本切成若干 delta，模拟真实流式输出的节奏
func chunkText(text string, size int) []string {
	if text == "" {
		return []string{""}
	}
	runes := []rune(text)
	var out []string
	for i := 0; i < len(runes); i += size {
		end := i + size
		if end > len(runes) {
			end = len(runes)
		}
		out = append(out, string(runes[i:end]))
	}
	return out
}

func estTokens(text string) int {
	if text == "" {
		return 1
	}
	n := len([]rune(text)) / 4
	if n < 1 {
		n = 1
	}
	return n
}

func sleepRealistic() {
	time.Sleep(15 * time.Millisecond)
}

func honeypotGenerateMsgID() string {
	return "msg_01" + honeypotRandomBase62(22)
}

func honeypotGenerateChatID() string {
	return "chatcmpl-" + honeypotRandomBase62(28)
}

const honeypotBase62 = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func honeypotRandomBase62(n int) string {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return strings.Repeat("A", n)
	}
	for i := range raw {
		raw[i] = honeypotBase62[int(raw[i])%len(honeypotBase62)]
	}
	return string(raw)
}
