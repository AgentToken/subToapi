//go:build unit

package service

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseHoneypotConversationResponsesInput(t *testing.T) {
	// Codex /responses：工具调用与输出在顶层 input 数组，
	// 此前解析为空导致管理页看不到工具执行结果
	body := `{
		"model": "gpt-6-astra",
		"instructions": "You are Codex.",
		"input": [
			{"type":"message","role":"user","content":[{"type":"input_text","text":"总结项目"}]},
			{"type":"custom_tool_call","call_id":"c9","name":"functions","input":"const r = await tools.exec_command({cmd:\"ls\"}); return r;"},
			{"type":"custom_tool_call_output","call_id":"c9","output":[{"type":"input_text","text":"main.go go.mod"}]}
		]
	}`
	turns := ParseHoneypotConversation(body)
	require.NotEmpty(t, turns)
	require.Equal(t, "system", turns[0].Role) // instructions
	var hasCall, hasOutput, hasUser bool
	for _, tn := range turns {
		switch tn.Role {
		case "user":
			hasUser = tn.Text == "总结项目"
		case "assistant":
			if strings.HasPrefix(tn.Text, "[调用工具 ") {
				hasCall = true
			}
		case "tool":
			if strings.HasPrefix(tn.Text, "[工具输出") {
				hasOutput = true
			}
		}
	}
	require.True(t, hasUser, "user turn missing")
	require.True(t, hasCall, "tool call turn missing")
	require.True(t, hasOutput, "tool output turn missing")
}

func TestParseHoneypotConversationAnthropicStillWorks(t *testing.T) {
	body := `{"system":"be nice","messages":[{"role":"user","content":[{"type":"text","text":"hi"}]}]}`
	turns := ParseHoneypotConversation(body)
	require.Len(t, turns, 2)
	require.Equal(t, "system", turns[0].Role)
	require.Equal(t, "hi", turns[1].Text)
}
