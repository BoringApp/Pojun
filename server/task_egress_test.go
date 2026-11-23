package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixedEgressInput() taskEgressInput {
	return taskEgressInput{
		CapturedAt:       time.Date(2026, 11, 23, 12, 34, 56, 0, time.UTC),
		BuildVersion:     "0.4.98",
		CaptureEnabled:   true,
		CaptureEffective: true,
		CAPresent:        true,
		PoolConfigured:   true,
		PoolAvailable:    2,
		PoolStrategy:     "round_robin",
		Roles: map[string]string{
			"worker":    "http://127.0.0.1:8788",
			"planner":   "http://127.0.0.1:8788",
			"mainagent": "http://127.0.0.1:8788",
		},
	}
}

func TestBuildTaskEgressSnapshotCaptureOn(t *testing.T) {
	snap := buildTaskEgressSnapshot(fixedEgressInput())
	if snap.SchemaVersion != 1 || snap.Source != "task_agent_build" {
		t.Fatalf("schema/source = %d/%q", snap.SchemaVersion, snap.Source)
	}
	if !snap.Capture.Enabled || !snap.Capture.Effective || !snap.Capture.CAPresent {
		t.Fatalf("capture 状态错误: %+v", snap.Capture)
	}
	if snap.Egress.Kind != egressKindRecordingProxy {
		t.Fatalf("worker kind = %q, want recording_proxy", snap.Egress.Kind)
	}
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindProxyPool {
		t.Fatalf("upstream = %+v, want proxy_pool", snap.Upstream)
	}
	if !snap.RolesUniform {
		t.Fatal("捕获开启时三角色应一致")
	}
	if got := snap.CapturedAt; got != "2026-11-23T12:34:56Z" {
		t.Fatalf("captured_at = %q", got)
	}
	if snap.Observed.Known || snap.Observed.Reason != "not_observable_at_capture" {
		t.Fatalf("observed = %+v, want explicit unknown", snap.Observed)
	}
}

// 捕获开关打开但 traffic 子系统不可用：不能冒充「已录制」，角色按捕获关闭的实际
// 注入值分类。
func TestBuildTaskEgressSnapshotCaptureDeclaredNotEffective(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = true
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = false
	in.PoolAvailable = 0
	in.Roles = map[string]string{"worker": "", "planner": "", "mainagent": ""}
	snap := buildTaskEgressSnapshot(in)
	if !snap.Capture.Enabled || snap.Capture.Effective {
		t.Fatalf("capture = %+v, want enabled && !effective", snap.Capture)
	}
	if snap.Egress.Kind != egressKindDirect {
		t.Fatalf("kind = %q, want direct", snap.Egress.Kind)
	}
	if snap.Upstream != nil {
		t.Fatalf("未生效的记录代理不应有 upstream: %+v", snap.Upstream)
	}
}

func TestBuildTaskEgressSnapshotPoolRolesDiverge(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.Roles = map[string]string{
		"worker":    "http://alice:s3cr3t@10.0.0.5:8080",
		"planner":   "http://bob@10.0.0.6:8080",
		"mainagent": "socks5://10.0.0.7:1080",
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.RolesUniform {
		t.Fatal("三个不同上游应标记 roles_uniform=false")
	}
	if snap.Egress.Kind != egressKindProxyPool || !snap.Egress.HasAuth {
		t.Fatalf("worker route = %+v", snap.Egress)
	}
	if snap.Egress.Address != "http://10.0.0.5:8080" {
		t.Fatalf("worker address 未脱敏: %q", snap.Egress.Address)
	}
	blob, _ := json.Marshal(snap)
	for _, banned := range []string{"alice", "bob", "s3cr3t"} {
		if strings.Contains(string(blob), banned) {
			t.Fatalf("快照泄漏凭据片段 %q: %s", banned, blob)
		}
	}
}

func TestBuildTaskEgressSnapshotStrictBlock(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = true
	in.PoolAvailable = 0
	in.StrictEgress = true
	in.GlobalProxy = ""
	in.Roles = map[string]string{
		"worker": strictEgressBlockProxy, "planner": strictEgressBlockProxy, "mainagent": strictEgressBlockProxy,
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindStrictBlock {
		t.Fatalf("kind = %q, want strict_block", snap.Egress.Kind)
	}
	if snap.Egress.Address != "" {
		t.Fatalf("严格阻断不应展示哨兵地址: %q", snap.Egress.Address)
	}
}

func TestBuildTaskEgressSnapshotGlobalAndDirect(t *testing.T) {
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = false
	in.PoolAvailable = 0
	in.GlobalProxy = "http://user:pw@10.0.0.9:3128"
	in.Roles = map[string]string{
		"worker": "http://user:pw@10.0.0.9:3128", "planner": "http://user:pw@10.0.0.9:3128", "mainagent": "http://user:pw@10.0.0.9:3128",
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindGlobalProxy || !snap.Egress.HasAuth || snap.Egress.Address != "http://10.0.0.9:3128" {
		t.Fatalf("global route = %+v", snap.Egress)
	}

	in.GlobalProxy = ""
	in.Roles = map[string]string{"worker": "", "planner": "", "mainagent": ""}
	snap = buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindDirect || snap.Egress.Address != "" {
		t.Fatalf("direct route = %+v", snap.Egress)
	}
}

// 捕获开 + 池全熔断 + 严格出口 + 直连兜底：上游是直连（仍录制），不是严格阻断。
func TestBuildTaskEgressUpstreamStrictFallback(t *testing.T) {
	in := fixedEgressInput()
	in.PoolAvailable = 0
	in.StrictEgress = true
	in.DirectRecordFallback = true
	snap := buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindDirect {
		t.Fatalf("upstream = %+v, want direct", snap.Upstream)
	}
	in.DirectRecordFallback = false
	snap = buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindStrictBlock {
		t.Fatalf("upstream = %+v, want strict_block", snap.Upstream)
	}
}

func TestBuildTaskEgressSnapshotGlobalWithExhaustedPoolStrict(t *testing.T) {
	// 捕获关闭 + 严格出口 + 池全熔断 + 有全局代理：Agent 侧仍走全局代理
	// （ProxyAddr 的严格分支只在没有全局代理时才返回哨兵）。
	in := fixedEgressInput()
	in.CaptureEnabled = false
	in.CaptureEffective = false
	in.CAPresent = false
	in.PoolConfigured = true
	in.PoolAvailable = 0
	in.StrictEgress = true
	in.GlobalProxy = "http://10.0.0.9:3128"
	in.Roles = map[string]string{
		"worker": "http://10.0.0.9:3128", "planner": "http://10.0.0.9:3128", "mainagent": "http://10.0.0.9:3128",
	}
	snap := buildTaskEgressSnapshot(in)
	if snap.Egress.Kind != egressKindGlobalProxy {
		t.Fatalf("kind = %q, want global_proxy", snap.Egress.Kind)
	}
	if snap.Upstream != nil {
		t.Fatalf("捕获关闭不应有 upstream: %+v", snap.Upstream)
	}

	// 捕获开启时同样的策略组合：MITM 钩子在严格分支直接返回哨兵，
	// 即使配置了全局代理也不会回退到它。
	in.CaptureEffective = true
	in.CAPresent = true
	in.Roles = map[string]string{
		"worker": "http://127.0.0.1:8788", "planner": "http://127.0.0.1:8788", "mainagent": "http://127.0.0.1:8788",
	}
	snap = buildTaskEgressSnapshot(in)
	if snap.Upstream == nil || snap.Upstream.Kind != egressKindStrictBlock {
		t.Fatalf("upstream = %+v, want strict_block", snap.Upstream)
	}
}

func TestRedactEgressProxy(t *testing.T) {
	cases := []struct {
		raw      string
		wantAddr string
		wantHost string
		wantPort string
		wantAuth bool
		wantOK   bool
	}{
		{"http://alice:s3cr3t@10.0.0.1:8080", "http://10.0.0.1:8080", "10.0.0.1", "8080", true, true},
		{"socks5h://bob@[::1]:1080", "socks5h://[::1]:1080", "::1", "1080", true, true},
		{"http://user:pass@host:1/path?token=abc#frag", "http://host:1", "host", "1", true, true},
		{"http://10.0.0.1:8080", "http://10.0.0.1:8080", "10.0.0.1", "8080", false, true},
		{"http://proxy.example", "http://proxy.example", "proxy.example", "", false, true},
		{"", "", "", "", false, true},
		{"://bad", "", "", "", false, false},
		{"not a url", "", "", "", false, false},
	}
	for _, c := range cases {
		ep := redactEgressProxy(c.raw)
		if ep.Address != c.wantAddr || ep.Host != c.wantHost || ep.Port != c.wantPort ||
			ep.HasAuth != c.wantAuth || ep.ParseOK != c.wantOK {
			t.Fatalf("redactEgressProxy(%q) = %+v, want addr=%q host=%q port=%q auth=%v ok=%v",
				c.raw, ep, c.wantAddr, c.wantHost, c.wantPort, c.wantAuth, c.wantOK)
		}
		for _, banned := range []string{"alice", "bob", "s3cr3t", "pass", "token=abc", "not a url", "/path"} {
			if strings.Contains(ep.Address, banned) {
				t.Fatalf("输出泄漏 %q: %q", banned, ep.Address)
			}
		}
	}
}

// 回归守卫：agentsForTask 必须保持三次 ProxyAddr()/ProxyCACert() 调用
// （worker/planner/mainagent 各一次）。新增第四次会推进 round_robin/random
// 的池游标，改变三角色实际拿到的出口分配，属于行为回归。
func TestAgentsForTaskCallsProxyAddrExactlyThreeTimes(t *testing.T) {
	src, err := os.ReadFile("task_llm.go")
	if err != nil {
		t.Fatalf("读 task_llm.go: %v", err)
	}
	body := string(src)
	start := strings.Index(body, "func (s *Server) agentsForTask(")
	if start < 0 {
		t.Fatal("找不到 agentsForTask")
	}
	body = body[start:]
	if end := strings.Index(body, "\nfunc "); end > 0 {
		body = body[:end]
	}
	if got := strings.Count(body, "s.m.ProxyAddr()"); got != 3 {
		t.Fatalf("agentsForTask 内 ProxyAddr() 调用 %d 次，必须恰好 3 次", got)
	}
	if got := strings.Count(body, "s.m.ProxyCACert()"); got != 3 {
		t.Fatalf("agentsForTask 内 ProxyCACert() 调用 %d 次，必须恰好 3 次", got)
	}
}

func TestTaskEgressUA(t *testing.T) {
	ua := taskEgressUA()
	if ua.TaskLevelOverride != "none" || ua.Observation != "declaration_only" {
		t.Fatalf("ua 语义 = %q/%q", ua.TaskLevelOverride, ua.Observation)
	}
	if len(ua.Surfaces) == 0 {
		t.Fatal("UA 声明表为空")
	}
	byID := map[string]TaskEgressUASurface{}
	for _, s := range ua.Surfaces {
		byID[s.ID] = s
	}
	if got := byID["http_request"]; got.Class != "platform_fixed" || got.Value == "" {
		t.Fatalf("http_request = %+v", got)
	}
	for _, id := range []string{"http_probe", "api_contract", "diff_responses"} {
		got := byID[id]
		if got.Class != "runtime_default" {
			t.Fatalf("%s class = %q, want runtime_default", id, got.Class)
		}
		if got.Value != "" {
			t.Fatalf("%s 不应声明固定 UA: %q", id, got.Value)
		}
	}
}

// Handler 语义：401/404/200 built=false/200 built=true；快照原样透传。
func TestTaskEgressHandler(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("database unavailable (%v) — skipping", err)
	}
	if m.pg == nil {
		t.Skip("postgres unavailable — skipping")
	}
	td := t.TempDir()
	s := New(context.Background(), m, td, td, td)
	h := s.Handler()
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}
	task, err := m.CreateTask("egress handler", "goal", nil, 0, 0)
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	taskID, _ := strconv.ParseInt(task.ID, 10, 64)
	t.Cleanup(func() { _ = m.pg.DeleteTask(taskID) })

	do := func(path, token string) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	if code, _ := do("/api/tasks/"+task.ID+"/egress", ""); code != http.StatusUnauthorized {
		t.Fatalf("no auth code = %d, want 401", code)
	}
	if code, _ := do("/api/tasks/999999999/egress", tok); code != http.StatusNotFound {
		t.Fatalf("unknown task code = %d, want 404", code)
	}
	code, out := do("/api/tasks/"+task.ID+"/egress", tok)
	if code != http.StatusOK || out["built"] != false || out["reason"] != "not_built" {
		t.Fatalf("not-built response = %d %v", code, out)
	}

	snap := buildTaskEgressSnapshot(taskEgressInput{
		CapturedAt:       time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC),
		CaptureEnabled:   false,
		CaptureEffective: false,
		Roles: map[string]string{
			"worker":    "http://user:pw@10.0.0.5:8080",
			"planner":   "http://user:pw@10.0.0.5:8080",
			"mainagent": "http://user:pw@10.0.0.5:8080",
		},
		PoolConfigured: true,
		PoolAvailable:  1,
		PoolStrategy:   "sticky_host",
	})
	raw, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if err := m.pg.SetTaskEgressSnapshot(taskID, raw); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}
	code, out = do("/api/tasks/"+task.ID+"/egress", tok)
	if code != http.StatusOK || out["built"] != true {
		t.Fatalf("built response = %d %v", code, out)
	}
	snapshot, _ := out["snapshot"].(map[string]any)
	egress, _ := snapshot["egress"].(map[string]any)
	if egress["kind"] != "proxy_pool" || egress["address"] != "http://10.0.0.5:8080" {
		t.Fatalf("egress = %v", egress)
	}
	body, _ := json.Marshal(out)
	if bytes.Contains(body, []byte("user:pw")) || bytes.Contains(body, []byte("pw@")) {
		t.Fatalf("响应泄漏代理凭据: %s", body)
	}
}
