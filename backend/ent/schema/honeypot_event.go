package schema

import (
	"github.com/Wei-Shaw/sub2api/ent/schema/mixins"

	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// HoneypotEvent holds one intercepted request on a honeypot API key.
// 记录盗用者请求的完整快照（头/体/IP/UA）以及从回传内容中抽取的情报。
type HoneypotEvent struct {
	ent.Schema
}

func (HoneypotEvent) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "honeypot_events"},
	}
}

func (HoneypotEvent) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixins.TimeMixin{},
	}
}

func (HoneypotEvent) Fields() []ent.Field {
	return []ent.Field{
		field.Int64("api_key_id"),
		// gateway = 正常网关请求被拦截; oob = 注入指令诱导的外呼回传
		field.String("source").MaxLen(20).Default("gateway"),
		field.String("method").MaxLen(10).Default(""),
		field.String("path").Default(""),
		field.String("client_ip").MaxLen(64).Default(""),
		field.Text("user_agent").Optional(),
		field.String("model").Default(""),
		field.Bool("is_stream").Default(false),
		field.JSON("headers", map[string]any{}).Optional(),
		field.Text("body").Optional(),
		field.Bool("body_truncated").Default(false),
		// 从请求/回传内容中抽取的结构化情报（env_report、git 身份等）
		field.JSON("intel", map[string]any{}).Optional(),
		field.Text("injected_payload").Optional(),
		field.String("response_mode").MaxLen(20).Default(""),
	}
}

func (HoneypotEvent) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("api_key_id", "created_at"),
	}
}
