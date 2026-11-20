package llmpresets

import (
	"strings"
	"testing"
)

// 预设清单完整性：12 条、id 唯一、格式枚举合法、自定义中转 base_url 留空。
func TestPresetsWellFormed(t *testing.T) {
	all := All()
	if len(all) != 12 {
		t.Fatalf("预设数量 = %d，期望 12", len(all))
	}
	seen := map[string]bool{}
	for _, p := range all {
		if seen[p.ID] {
			t.Fatalf("预设 id 重复: %s", p.ID)
		}
		seen[p.ID] = true
		switch p.Format {
		case "openai", "anthropic", "openai-responses":
		default:
			t.Fatalf("预设 %s format 非法: %q", p.ID, p.Format)
		}
		switch p.Category {
		case "official", "aggregate", "custom":
		default:
			t.Fatalf("预设 %s category 非法: %q", p.ID, p.Category)
		}
	}
	if _, ok := seen["custom-relay"]; !ok {
		t.Fatal("缺 custom-relay 模板")
	}
	if _, ok := seen["opencode"]; !ok {
		t.Fatal("缺 opencode 预设")
	}
	custom, _ := Get("custom-relay")
	if custom.BaseURL != "" {
		t.Fatalf("自定义中转 base_url 应留空，得 %q", custom.BaseURL)
	}
	// 真实配置口径：OpenCode 走 anthropic 协议 + zen 网关
	oc, _ := Get("opencode")
	if oc.Format != "anthropic" || !strings.Contains(oc.BaseURL, "opencode.ai") {
		t.Fatalf("OpenCode 预设与实际用法不符: %+v", oc)
	}
}

// 元数据推断：精确 / 带日期后缀前缀 / 厂商前缀 / 预设兜底 / 未命中。
func TestLookupMeta(t *testing.T) {
	cases := []struct {
		model  string
		wantK  int
		source string
	}{
		{"deepseek-v4.1-flash", 256, SourceMeta},
		{"DeepSeek-V4.1-Flash", 256, SourceMeta},       // 大小写不敏感
		{"claude-opus-4-8-20261101", 200, SourceMeta},  // 日期后缀前缀命中
		{"anthropic/claude-opus-4-5", 200, SourceMeta}, // 厂商前缀剥除
		{"gpt-4o", 128, SourceMeta},
	}
	for _, c := range cases {
		e, src := LookupMeta(c.model)
		if e.ContextK != c.wantK || src != c.source {
			t.Fatalf("LookupMeta(%q) = %dK/%s，期望 %dK/%s", c.model, e.ContextK, src, c.wantK, c.source)
		}
	}
	if _, src := LookupMeta("totally-unknown-model-xyz"); src != SourceNone {
		t.Fatalf("未知模型应 none，得 %s", src)
	}
	if e, _ := LookupMeta(""); e.ContextK != 0 {
		t.Fatal("空模型名应零值")
	}
	// 内嵌快照没有、但预设条目有的模型 → preset 来源
	if _, src := LookupMeta("nvidia/nemotron-3-ultra-550b-a55b:free"); src == SourceMeta {
		t.Fatalf("快照外模型不应来自 meta")
	}
}
