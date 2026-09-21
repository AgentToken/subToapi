package handler

import (
	"io"
	"net/http"

	"github.com/Wei-Shaw/sub2api/internal/service"

	"github.com/gin-gonic/gin"
)

// honeypotOOBBodyLimit OOB 回传体上限
const honeypotOOBBodyLimit = 64 * 1024

// HoneypotHandler 蜜罐公网回调（OOB 收集端点）
type HoneypotHandler struct {
	honeypotService *service.HoneypotService
}

// NewHoneypotHandler 创建蜜罐 OOB handler
func NewHoneypotHandler(honeypotService *service.HoneypotService) *HoneypotHandler {
	return &HoneypotHandler{honeypotService: honeypotService}
}

// CollectOOB 接收注入指令诱导的外呼回传。
// 路由：ANY /hp/collect/:marker （公开无鉴权；marker 即蜜罐水印）
func (h *HoneypotHandler) CollectOOB(c *gin.Context) {
	body := ""
	if c.Request.Body != nil {
		raw, err := io.ReadAll(io.LimitReader(c.Request.Body, honeypotOOBBodyLimit))
		if err == nil {
			body = string(raw)
		}
	}
	// 回显 204 即可：客户端（curl 等）只需要请求成功
	marker := c.Param("marker")
	h.honeypotService.RecordOOBHit(
		c.Request.Context(),
		marker,
		c.ClientIP(),
		c.Request.Method,
		c.Request.URL.Path,
		body,
	)
	c.Status(http.StatusNoContent)
}
