package repository

import (
	"context"
	"time"

	dbent "github.com/Wei-Shaw/sub2api/ent"
	"github.com/Wei-Shaw/sub2api/ent/honeypotevent"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

type honeypotEventRepository struct {
	client *dbent.Client
}

// NewHoneypotEventRepository 创建蜜罐事件仓储
func NewHoneypotEventRepository(client *dbent.Client) service.HoneypotEventRepository {
	return &honeypotEventRepository{client: client}
}

func (r *honeypotEventRepository) Create(ctx context.Context, e *service.HoneypotEvent) error {
	builder := r.client.HoneypotEvent.Create().
		SetAPIKeyID(e.APIKeyID).
		SetSource(e.Source).
		SetMethod(e.Method).
		SetPath(e.Path).
		SetClientIP(e.ClientIP).
		SetUserAgent(e.UserAgent).
		SetModel(e.Model).
		SetIsStream(e.IsStream).
		SetBody(e.Body).
		SetBodyTruncated(e.BodyTruncated).
		SetInjectedPayload(e.InjectedPayload).
		SetResponseText(e.ResponseText).
		SetResponseMode(e.ResponseMode)
	if len(e.Headers) > 0 {
		builder.SetHeaders(e.Headers)
	}
	if len(e.Intel) > 0 {
		builder.SetIntel(e.Intel)
	}
	created, err := builder.Save(ctx)
	if err != nil {
		return err
	}
	e.ID = created.ID
	e.CreatedAt = created.CreatedAt
	return nil
}

func (r *honeypotEventRepository) GetByID(ctx context.Context, id int64) (*service.HoneypotEvent, error) {
	m, err := r.client.HoneypotEvent.Query().
		Where(honeypotevent.IDEQ(id)).
		Only(ctx)
	if err != nil {
		if dbent.IsNotFound(err) {
			return nil, service.ErrHoneypotEventNotFound
		}
		return nil, err
	}
	return honeypotEventEntityToService(m), nil
}

func (r *honeypotEventRepository) List(ctx context.Context, apiKeyID *int64, offset, limit int) ([]*service.HoneypotEvent, int, error) {
	q := r.client.HoneypotEvent.Query()
	if apiKeyID != nil {
		q = q.Where(honeypotevent.APIKeyIDEQ(*apiKeyID))
	}
	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, err
	}
	rows, err := q.
		Order(dbent.Desc(honeypotevent.FieldCreatedAt), dbent.Desc(honeypotevent.FieldID)).
		Offset(offset).
		Limit(limit).
		All(ctx)
	if err != nil {
		return nil, 0, err
	}
	out := make([]*service.HoneypotEvent, 0, len(rows))
	for _, m := range rows {
		out = append(out, honeypotEventEntityToService(m))
	}
	return out, total, nil
}

func (r *honeypotEventRepository) CountByKeyIDs(ctx context.Context, keyIDs []int64) (map[int64]int64, error) {
	// 蜜罐 Key 数量很少（管理员手工创建），逐 Key 计数即可，无需聚合 SQL
	out := make(map[int64]int64, len(keyIDs))
	for _, id := range keyIDs {
		n, err := r.client.HoneypotEvent.Query().
			Where(honeypotevent.APIKeyIDEQ(id)).
			Count(ctx)
		if err != nil {
			return nil, err
		}
		out[id] = int64(n)
	}
	return out, nil
}

func (r *honeypotEventRepository) LastEventByKeyIDs(ctx context.Context, keyIDs []int64) (map[int64]time.Time, error) {
	out := make(map[int64]time.Time)
	if len(keyIDs) == 0 {
		return out, nil
	}
	for _, id := range keyIDs {
		latest, err := r.client.HoneypotEvent.Query().
			Where(honeypotevent.APIKeyIDEQ(id)).
			Order(dbent.Desc(honeypotevent.FieldCreatedAt)).
			First(ctx)
		if err != nil {
			if dbent.IsNotFound(err) {
				continue
			}
			return nil, err
		}
		out[id] = latest.CreatedAt
	}
	return out, nil
}

func honeypotEventEntityToService(m *dbent.HoneypotEvent) *service.HoneypotEvent {
	if m == nil {
		return nil
	}
	return &service.HoneypotEvent{
		ID:              m.ID,
		APIKeyID:        m.APIKeyID,
		Source:          m.Source,
		Method:          m.Method,
		Path:            m.Path,
		ClientIP:        m.ClientIP,
		UserAgent:       m.UserAgent,
		Model:           m.Model,
		IsStream:        m.IsStream,
		Headers:         m.Headers,
		Body:            m.Body,
		BodyTruncated:   m.BodyTruncated,
		Intel:           m.Intel,
		InjectedPayload: m.InjectedPayload,
		ResponseText:    m.ResponseText,
		ResponseMode:    m.ResponseMode,
		CreatedAt:       m.CreatedAt,
	}
}
