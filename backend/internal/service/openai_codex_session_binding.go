package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Wei-Shaw/sub2api/internal/pkg/logger"
	"go.uber.org/zap"
)

// codexSessionInstallationBindingTTL 是绑定在缓存后端的存活时长。绑定一经创建
// 不可变；过期后（会话长期不活跃）按首次观测规则确定性重建——source=client
// 与 source=canonical 的重建值都与原值一致，除非 seed/显式 device_id 变更。
const codexSessionInstallationBindingTTL = 30 * 24 * time.Hour

// codexSessionBindingMaxCachedEntries 限制单实例内存热缓存条目数，超出时
// 淘汰最久未见的绑定（缓存淘汰不影响后端持久化值）。
const codexSessionBindingMaxCachedEntries = 100_000

// codexSessionBindingSource 标识绑定的来源（对应 #5786 的 binding_source）：
//   - client：首次观测到客户端自带 installation（即 issue 中的 legacy binding，
//     旧 session 保持其历史身份）；
//   - canonical：客户端未携带 installation，绑定账号级 canonical installation。
const (
	codexSessionBindingSourceClient    = "client"
	codexSessionBindingSourceCanonical = "canonical"
)

// CodexSessionInstallationBinding 是一个 (账号, 客户端会话) 的 installation
// 身份绑定快照（#5786 smart 策略要求的持久化 binding）。
type CodexSessionInstallationBinding struct {
	InstallationID string `json:"installation_id"`
	Source         string `json:"source"`
	FirstSeenUnix  int64  `json:"first_seen_unix"`
	LastSeenUnix   int64  `json:"last_seen_unix"`
}

// CodexSessionInstallationBindingStore 管理 (账号, 客户端会话) → installation
// 的持久化绑定。Resolve 首次观测时建立绑定，后续永远返回既有绑定值：
// 同一 session 生命周期内的 installation 保持稳定，不随收敛模式或 seed 变化。
type CodexSessionInstallationBindingStore interface {
	// Resolve 返回绑定 installation；首次观测时以 clientInstallation（非空，
	// 即 legacy/client 绑定）或 canonicalInstallation 建立。两个 installation
	// 来源都为空时返回 ok=false。
	Resolve(ctx context.Context, accountID int64, clientSessionID, clientInstallation, canonicalInstallation string) (CodexSessionInstallationBinding, bool)
}

type defaultCodexSessionInstallationBindingStore struct {
	cache GatewayCache

	mu    sync.RWMutex
	hot   map[string]CodexSessionInstallationBinding
	clock func() time.Time
}

// NewCodexSessionInstallationBindingStore 构建绑定存储：内存热缓存 + GatewayCache
// 持久化（Redis 部署下跨实例、跨重启一致；无 Redis 时退化为单实例内存，
// 绑定值仍按首次观测规则确定性重建）。
func NewCodexSessionInstallationBindingStore(cache GatewayCache) CodexSessionInstallationBindingStore {
	return &defaultCodexSessionInstallationBindingStore{
		cache: cache,
		hot:   make(map[string]CodexSessionInstallationBinding, 256),
		clock: time.Now,
	}
}

// hashCodexSessionBindingClientSession 将客户端原始 session 标识脱敏为哈希，
// 避免在缓存后端存储明文客户端会话标识。
func hashCodexSessionBindingClientSession(clientSessionID string) string {
	sum := sha256.Sum256([]byte("codex-session-binding:v1:" + clientSessionID))
	return hex.EncodeToString(sum[:16])
}

func codexSessionBindingCacheKey(accountID int64, sessionHash string) string {
	return fmt.Sprintf("%d:%s", accountID, sessionHash)
}

func (s *defaultCodexSessionInstallationBindingStore) Resolve(ctx context.Context, accountID int64, clientSessionID, clientInstallation, canonicalInstallation string) (CodexSessionInstallationBinding, bool) {
	clientSessionID = strings.TrimSpace(clientSessionID)
	if accountID <= 0 || clientSessionID == "" {
		return CodexSessionInstallationBinding{}, false
	}
	sessionHash := hashCodexSessionBindingClientSession(clientSessionID)
	cacheKey := codexSessionBindingCacheKey(accountID, sessionHash)

	now := s.clock().Unix()
	if binding, ok := s.fromHot(cacheKey, now); ok {
		return binding, true
	}

	if binding, ok := s.fromPersistentCache(ctx, cacheKey); ok {
		s.storeHot(cacheKey, binding)
		return binding, true
	}

	// 首次观测：绑定来源按 #5786 规则——客户端自带 installation 时保留其
	// 历史身份（legacy/client binding），否则绑定账号 canonical installation。
	source := codexSessionBindingSourceCanonical
	installationID := canonicalInstallation
	if clientInstallation != "" {
		source = codexSessionBindingSourceClient
		installationID = clientInstallation
	}
	if installationID == "" {
		return CodexSessionInstallationBinding{}, false
	}
	binding := CodexSessionInstallationBinding{
		InstallationID: installationID,
		Source:         source,
		FirstSeenUnix:  now,
		LastSeenUnix:   now,
	}
	s.storeHot(cacheKey, binding)
	s.persist(ctx, cacheKey, binding)
	return binding, true
}

func (s *defaultCodexSessionInstallationBindingStore) fromHot(cacheKey string, nowUnix int64) (CodexSessionInstallationBinding, bool) {
	s.mu.RLock()
	binding, ok := s.hot[cacheKey]
	s.mu.RUnlock()
	if !ok {
		return CodexSessionInstallationBinding{}, false
	}
	// 内存条目不过期（绑定不可变），仅做容量上限维护；LastSeen 只在内存
	// 中滚动更新，避免热路径写缓存后端。
	s.mu.Lock()
	binding.LastSeenUnix = nowUnix
	s.hot[cacheKey] = binding
	if len(s.hot) > codexSessionBindingMaxCachedEntries {
		s.pruneLocked(nowUnix)
	}
	s.mu.Unlock()
	return binding, true
}

func (s *defaultCodexSessionInstallationBindingStore) fromPersistentCache(ctx context.Context, cacheKey string) (CodexSessionInstallationBinding, bool) {
	if s.cache == nil {
		return CodexSessionInstallationBinding{}, false
	}
	payload, err := s.cache.GetCodexSessionInstallationBinding(ctx, cacheKey)
	if err != nil {
		logger.L().Debug("codex session binding cache read failed", zap.String("error", err.Error()))
		return CodexSessionInstallationBinding{}, false
	}
	if len(payload) == 0 {
		return CodexSessionInstallationBinding{}, false
	}
	var binding CodexSessionInstallationBinding
	if err := json.Unmarshal(payload, &binding); err != nil || binding.InstallationID == "" || binding.Source == "" {
		return CodexSessionInstallationBinding{}, false
	}
	return binding, true
}

func (s *defaultCodexSessionInstallationBindingStore) persist(ctx context.Context, cacheKey string, binding CodexSessionInstallationBinding) {
	if s.cache == nil {
		return
	}
	payload, err := json.Marshal(binding)
	if err != nil {
		return
	}
	if err := s.cache.SetCodexSessionInstallationBinding(ctx, cacheKey, payload, codexSessionInstallationBindingTTL); err != nil {
		logger.L().Debug("codex session binding cache write failed", zap.String("error", err.Error()))
	}
}

func (s *defaultCodexSessionInstallationBindingStore) storeHot(cacheKey string, binding CodexSessionInstallationBinding) {
	s.mu.Lock()
	if s.hot == nil {
		s.hot = make(map[string]CodexSessionInstallationBinding, 256)
	}
	s.hot[cacheKey] = binding
	if len(s.hot) > codexSessionBindingMaxCachedEntries {
		s.pruneLocked(s.clock().Unix())
	}
	s.mu.Unlock()
}

// pruneLocked 控制内存热缓存上限（调用方需持有写锁）：优先淘汰超过
// 1 小时未见的绑定；仍超限时直接丢弃多余条目（绑定值在缓存后端或重建
// 规则中仍然可得）。
func (s *defaultCodexSessionInstallationBindingStore) pruneLocked(nowUnix int64) {
	staleBefore := nowUnix - int64(time.Hour.Seconds())
	for key, binding := range s.hot {
		if binding.LastSeenUnix < staleBefore {
			delete(s.hot, key)
		}
	}
	for key := range s.hot {
		if len(s.hot) <= codexSessionBindingMaxCachedEntries {
			return
		}
		delete(s.hot, key)
	}
}
