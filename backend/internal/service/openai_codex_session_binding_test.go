package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBindingGatewayCache 是带真实存取语义的 GatewayCache 测试替身（其余方法不参与）。
type fakeBindingGatewayCache struct {
	GatewayCache
	mu    sync.Mutex
	store map[string][]byte
}

func newFakeBindingGatewayCache() *fakeBindingGatewayCache {
	return &fakeBindingGatewayCache{store: map[string][]byte{}}
}

func (c *fakeBindingGatewayCache) SetCodexSessionInstallationBinding(_ context.Context, key string, payload []byte, _ time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.store[key] = append([]byte(nil), payload...)
	return nil
}

func (c *fakeBindingGatewayCache) GetCodexSessionInstallationBinding(_ context.Context, key string) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	payload, ok := c.store[key]
	if !ok {
		return nil, nil
	}
	return append([]byte(nil), payload...), nil
}

func newTestBindingStore(cache GatewayCache) CodexSessionInstallationBindingStore {
	store := NewCodexSessionInstallationBindingStore(cache).(*defaultCodexSessionInstallationBindingStore)
	base := time.Unix(1_700_000_000, 0)
	store.clock = func() time.Time { return base }
	return store
}

func TestCodexSessionBinding_ClientInstallationBindsAsClient(t *testing.T) {
	store := newTestBindingStore(newFakeBindingGatewayCache())

	binding, ok := store.Resolve(context.Background(), 71, "sess-aaa", "client-install-1", "canonical-install")
	require.True(t, ok)
	assert.Equal(t, "client-install-1", binding.InstallationID)
	assert.Equal(t, codexSessionBindingSourceClient, binding.Source)
}

func TestCodexSessionBinding_NoClientInstallationBindsCanonical(t *testing.T) {
	store := newTestBindingStore(newFakeBindingGatewayCache())

	binding, ok := store.Resolve(context.Background(), 71, "sess-bbb", "", "canonical-install")
	require.True(t, ok)
	assert.Equal(t, "canonical-install", binding.InstallationID)
	assert.Equal(t, codexSessionBindingSourceCanonical, binding.Source)
}

func TestCodexSessionBinding_ImmutableAfterFirstObservation(t *testing.T) {
	store := newTestBindingStore(newFakeBindingGatewayCache())
	ctx := context.Background()

	first, ok := store.Resolve(ctx, 71, "sess-ccc", "client-first", "canonical-install")
	require.True(t, ok)

	// 客户端随后更换 installation（或来源在 client/canonical 间变化）：绑定值不变。
	second, ok := store.Resolve(ctx, 71, "sess-ccc", "client-rotated", "canonical-install")
	require.True(t, ok)
	assert.Equal(t, first.InstallationID, second.InstallationID)

	third, ok := store.Resolve(ctx, 71, "sess-ccc", "", "canonical-install")
	require.True(t, ok)
	assert.Equal(t, first.InstallationID, third.InstallationID)
}

func TestCodexSessionBinding_SessionAndAccountScoped(t *testing.T) {
	store := newTestBindingStore(newFakeBindingGatewayCache())
	ctx := context.Background()

	a, ok := store.Resolve(ctx, 71, "sess-a", "client-x", "canonical-a")
	require.True(t, ok)
	b, ok := store.Resolve(ctx, 71, "sess-b", "client-y", "canonical-a")
	require.True(t, ok)
	assert.Equal(t, "client-x", a.InstallationID)
	assert.Equal(t, "client-y", b.InstallationID, "不同会话各自绑定各自的值")

	// 同账号下客户端未携带 installation 的会话都绑定账号 canonical。
	b2, ok := store.Resolve(ctx, 71, "sess-b2", "", "canonical-a")
	require.True(t, ok)
	assert.Equal(t, "canonical-a", b2.InstallationID)

	c, ok := store.Resolve(ctx, 72, "sess-a", "", "canonical-b")
	require.True(t, ok)
	assert.Equal(t, "canonical-b", c.InstallationID, "同会话标识跨账号隔离：账号 72 独立绑定")

	again, ok := store.Resolve(ctx, 71, "sess-a", "", "canonical-a")
	require.True(t, ok)
	assert.Equal(t, "client-x", again.InstallationID, "账号 71 的既有绑定不受其他账号影响")
}

func TestCodexSessionBinding_PersistsAcrossStoreInstances(t *testing.T) {
	cache := newFakeBindingGatewayCache()
	ctx := context.Background()

	first := newTestBindingStore(cache)
	binding, ok := first.Resolve(ctx, 71, "sess-persist", "client-persist", "canonical")
	require.True(t, ok)

	// 模拟重启：新实例从缓存后端恢复既有绑定，而不是重新按首次观测建绑。
	second := newTestBindingStore(cache)
	restored, ok := second.Resolve(ctx, 71, "sess-persist", "", "canonical")
	require.True(t, ok)
	assert.Equal(t, binding.InstallationID, restored.InstallationID)
	assert.Equal(t, codexSessionBindingSourceClient, restored.Source)
}

func TestCodexSessionBinding_InvalidInputs(t *testing.T) {
	store := newTestBindingStore(newFakeBindingGatewayCache())
	ctx := context.Background()

	_, ok := store.Resolve(ctx, 71, "", "client", "canonical")
	assert.False(t, ok, "缺少 session 时不建绑定（#5786 规则 4：不猜）")

	_, ok = store.Resolve(ctx, 0, "sess", "client", "canonical")
	assert.False(t, ok, "缺少账号时不建绑定")

	_, ok = store.Resolve(ctx, 71, "sess", "", "")
	assert.False(t, ok, "两个 installation 来源都为空时不建绑定")
}
