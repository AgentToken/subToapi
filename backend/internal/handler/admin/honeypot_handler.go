package admin

import (
	"errors"
	"strconv"

	"github.com/Wei-Shaw/sub2api/internal/handler/dto"
	"github.com/Wei-Shaw/sub2api/internal/pkg/response"
	pkgmiddleware "github.com/Wei-Shaw/sub2api/internal/server/middleware"
	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// AdminHoneypotHandler 蜜罐 Key 管理端点
type AdminHoneypotHandler struct {
	honeypotService *service.HoneypotService
	apiKeyService   *service.APIKeyService
}

// NewAdminHoneypotHandler 创建蜜罐管理 handler
func NewAdminHoneypotHandler(honeypotService *service.HoneypotService, apiKeyService *service.APIKeyService) *AdminHoneypotHandler {
	return &AdminHoneypotHandler{
		honeypotService: honeypotService,
		apiKeyService:   apiKeyService,
	}
}

// honeypotConfigRequest 创建/更新/转换共用的蜜罐配置
type honeypotConfigRequest struct {
	Mode           string `json:"mode"`
	PayloadVariant string `json:"payload_variant"`
	CustomPayload  string `json:"custom_payload"`
	RelayEndpoint  string `json:"relay_endpoint"`
	RelayAPIKey    string `json:"relay_api_key"`
	RelayModel     string `json:"relay_model"`
}

func (r *honeypotConfigRequest) toConfig() *service.HoneypotConfig {
	return &service.HoneypotConfig{
		Mode:           r.Mode,
		PayloadVariant: r.PayloadVariant,
		CustomPayload:  r.CustomPayload,
		RelayEndpoint:  r.RelayEndpoint,
		RelayAPIKey:    r.RelayAPIKey,
		RelayModel:     r.RelayModel,
	}
}

// CreateKey 创建蜜罐 Key
// POST /api/v1/admin/honeypot/keys
func (h *AdminHoneypotHandler) CreateKey(c *gin.Context) {
	var req struct {
		Name   string                `json:"name"`
		Config honeypotConfigRequest `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	// 蜜罐 Key 挂在创建者名下（管理员），仅作属主占位，不走正常转发/计费
	subject, ok := pkgmiddleware.GetAuthSubjectFromContext(c)
	if !ok {
		response.Unauthorized(c, "Authentication required")
		return
	}
	key, rawKey, err := h.honeypotService.CreateKey(c.Request.Context(), subject.UserID, service.CreateHoneypotKeyRequest{
		Name:   req.Name,
		Config: req.Config.toConfig(),
	})
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	resp := gin.H{
		"api_key": honeypotKeyResp(key),
		// 明文只在创建响应里出现一次
		"key": rawKey,
	}
	response.Success(c, resp)
}

// ListKeys 蜜罐 Key 列表
// GET /api/v1/admin/honeypot/keys
func (h *AdminHoneypotHandler) ListKeys(c *gin.Context) {
	keys, err := h.honeypotService.ListKeys(c.Request.Context())
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	items := make([]gin.H, 0, len(keys))
	for i := range keys {
		k := keys[i]
		ownerEmail := ""
		ownerName := ""
		if k.User != nil {
			ownerEmail = k.User.Email
			ownerName = k.User.Username
		}
		items = append(items, gin.H{
			"id":            k.ID,
			"name":          k.Name,
			"key_masked":    maskAPIKey(k.Key),
			"status":        k.Status,
			"config":        k.HoneypotConfig,
			"event_count":   k.EventCount,
			"last_event_at": k.LastEventAt,
			"created_at":    k.CreatedAt,
			"owner_email":   ownerEmail,
			"owner_name":    ownerName,
		})
	}
	response.Success(c, gin.H{"items": items, "total": len(items)})
}

// UpdateKey 更新蜜罐 Key（状态/配置）
// PUT /api/v1/admin/honeypot/keys/:id
func (h *AdminHoneypotHandler) UpdateKey(c *gin.Context) {
	keyID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid API key ID")
		return
	}
	var req struct {
		Status *string                `json:"status"`
		Config *honeypotConfigRequest `json:"config"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	updates := service.UpdateHoneypotKeyRequest{Status: req.Status}
	if req.Config != nil {
		updates.Config = req.Config.toConfig()
	}
	key, err := h.honeypotService.UpdateKey(c.Request.Context(), keyID, updates)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{"api_key": honeypotKeyResp(key)})
}

// ConvertKey 将已泄露的真实 Key 原地转为蜜罐
// POST /api/v1/admin/honeypot/convert
func (h *AdminHoneypotHandler) ConvertKey(c *gin.Context) {
	var req struct {
		KeyID            int64                 `json:"key_id" binding:"required"`
		Config           honeypotConfigRequest `json:"config"`
		IssueReplacement bool                  `json:"issue_replacement"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.BadRequest(c, "Invalid request: "+err.Error())
		return
	}
	result, err := h.honeypotService.ConvertKey(c.Request.Context(), req.KeyID, service.ConvertToHoneypotRequest{
		Config:           req.Config.toConfig(),
		IssueReplacement: req.IssueReplacement,
	})
	if err != nil {
		if errors.Is(err, service.ErrAPIKeyNotFound) {
			response.NotFound(c, "API key not found")
			return
		}
		response.ErrorFrom(c, err)
		return
	}
	resp := gin.H{"api_key": honeypotKeyResp(result.APIKey)}
	if result.ReplacementKey != nil {
		resp["replacement_api_key"] = dto.APIKeyFromService(result.ReplacementKey)
		// 补发 Key 的明文只在本次返回
		resp["replacement_key"] = result.ReplacementRaw
	}
	response.Success(c, resp)
}

// ListEvents 蜜罐命中事件
// GET /api/v1/admin/honeypot/events?api_key_id=&page=&page_size=
func (h *AdminHoneypotHandler) ListEvents(c *gin.Context) {
	var apiKeyID *int64
	if raw := c.Query("api_key_id"); raw != "" {
		id, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			response.BadRequest(c, "Invalid api_key_id")
			return
		}
		apiKeyID = &id
	}
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("page_size", "50"))
	events, total, err := h.honeypotService.ListEvents(c.Request.Context(), apiKeyID, page, pageSize)
	if err != nil {
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, gin.H{
		"items":     events,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetEvent 蜜罐事件详情（含解析后的逐轮对话记录）
// GET /api/v1/admin/honeypot/events/:id
func (h *AdminHoneypotHandler) GetEvent(c *gin.Context) {
	eventID, err := strconv.ParseInt(c.Param("id"), 10, 64)
	if err != nil {
		response.BadRequest(c, "Invalid event ID")
		return
	}
	detail, err := h.honeypotService.GetEventDetail(c.Request.Context(), eventID)
	if err != nil {
		if errors.Is(err, service.ErrHoneypotEventNotFound) {
			response.NotFound(c, "Honeypot event not found")
			return
		}
		response.ErrorFrom(c, err)
		return
	}
	response.Success(c, detail)
}

func honeypotKeyResp(k *service.APIKey) gin.H {
	cfg := k.HoneypotConfig
	if cfg != nil {
		cfg = cfg.Sanitized()
	}
	return gin.H{
		"id":          k.ID,
		"name":        k.Name,
		"key_masked":  honeypotMaskKey(k.Key),
		"status":      k.Status,
		"is_honeypot": true,
		"config":      cfg,
		"created_at":  k.CreatedAt,
	}
}

func honeypotMaskKey(key string) string {
	if len(key) <= 12 {
		return key[:3] + "***"
	}
	return key[:10] + "..." + key[len(key)-4:]
}
