package eval

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/chu0119/pojun/db"
)

func TestScenarioValidate(t *testing.T) {
	sc := &Scenario{ID: "x", Name: "x", Goal: "g", Expected: []ExpectedFinding{{VulnClass: "RCE"}}}
	if err := sc.Validate(); err != nil {
		t.Fatal(err)
	}
	bad := *sc
	bad.Expected = nil
	if err := bad.Validate(); err == nil {
		t.Fatal("empty expected must be rejected")
	}
	if got := (ExpectedFinding{}).minEvidence(); got != defaultMinEvidenceRunes {
		t.Fatalf("default min evidence = %d", got)
	}
	if got := (ExpectedFinding{MinEvidenceRunes: -1}).minEvidence(); got != 0 {
		t.Fatalf("disabled min evidence = %d", got)
	}
}

func TestLoadScenariosRejectsDuplicateID(t *testing.T) {
	dir := t.TempDir()
	body := `{"id":"dup","name":"n","goal":"g","expected":[{"vulnclass":"RCE"}]}`
	for _, name := range []string{"a.json", "b.json"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := LoadScenarios(dir); err == nil || !strings.Contains(err.Error(), "重复") {
		t.Fatalf("duplicate id should fail: %v", err)
	}
}

func TestCompareRuns(t *testing.T) {
	a := &RunResult{ScenarioID: "s", TaskID: 1, Pass: true, RequiredFound: 2, UnexpectedN: 0,
		Expected:    []ExpectedResult{{VulnClass: "RCE", Matched: true}, {VulnClass: "XSS", Matched: true}},
		TokensInput: 100, TokensOutput: 50, CostUSD: 1, DurationMinutes: 10, StagesSeen: 2}
	b := &RunResult{ScenarioID: "s", TaskID: 2, Pass: false, RequiredFound: 1, UnexpectedN: 3,
		Expected:    []ExpectedResult{{VulnClass: "RCE", Matched: true}},
		TokensInput: 200, TokensOutput: 100, CostUSD: 2, DurationMinutes: 12, StagesSeen: 1}
	cmp, err := CompareRuns(a, b)
	if err != nil {
		t.Fatal(err)
	}
	if !cmp.Regressed || cmp.Improved {
		t.Fatalf("regression flags: %+v", cmp)
	}
	if cmp.RequiredFoundDelta != -1 || cmp.UnexpectedDelta != 3 || cmp.TokensDelta != 150 {
		t.Fatalf("deltas: %+v", cmp)
	}
	if len(cmp.NewlyMissing) != 1 || cmp.NewlyMissing[0] != "XSS" {
		t.Fatalf("newly missing: %v", cmp.NewlyMissing)
	}
	md := cmp.Markdown()
	for _, want := range []string{"退步", "XSS", "Token"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q:\n%s", want, md)
		}
	}
}

func TestScoreTask(t *testing.T) {
	dsn := os.Getenv("POJUN_PG_DSN")
	if dsn == "" {
		t.Skip("POJUN_PG_DSN not set")
	}
	d, err := db.Open(dsn)
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	defer d.Close()

	task, err := d.CreateTask("bench scoring fixture", "find the bugs", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })
	longEvidence := strings.Repeat("evidence ", 30) // 270 bytes / 270 runes
	if _, err := d.Exec(`INSERT INTO findings(task_id,vulnclass,name,severity,summary,evidence,status,asset_ids)
VALUES ($1,'SQL注入','sqli','high','s','`+longEvidence+`','pending','[]')`, task.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO findings(task_id,vulnclass,name,severity,summary,evidence,status,asset_ids)
VALUES ($1,'XSS','xss','low','s','short','pending','[]')`, task.ID); err != nil {
		t.Fatal(err)
	}

	sc := &Scenario{
		ID: "fixture", Name: "fixture", Goal: "g",
		Expected: []ExpectedFinding{
			{VulnClass: "注入", MinEvidenceRunes: 120},                  // required, long evidence
			{VulnClass: "XSS", Optional: true, MinEvidenceRunes: 120}, // optional, short evidence
			{VulnClass: "RCE", Optional: true, MinEvidenceRunes: -1},  // optional, absent
		},
	}
	res, err := ScoreTask(context.Background(), d, sc, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Pass {
		t.Fatalf("optional misses must not fail: %s", res.PassReason)
	}
	if res.RequiredFound != 1 || res.RequiredTotal != 1 || res.ExpectedFound != 2 {
		t.Fatalf("counts: required=%d/%d expected=%d", res.RequiredFound, res.RequiredTotal, res.ExpectedFound)
	}
	if res.EvidenceCompleteness != 0.5 {
		t.Fatalf("evidence completeness = %v, want 0.5", res.EvidenceCompleteness)
	}
	if res.UnexpectedN != 0 {
		t.Fatalf("unexpected = %d, want 0", res.UnexpectedN)
	}

	// 新增一条未预期的发现 + 必得项缺失 → fail，并列出缺失项。
	if _, err := d.Exec(`INSERT INTO findings(task_id,vulnclass,name,severity,summary,evidence,status,asset_ids)
VALUES ($1,'信息泄露','leak','medium','s','`+longEvidence+`','pending','[]')`, task.ID); err != nil {
		t.Fatal(err)
	}
	sc2 := &Scenario{ID: "fixture2", Name: "fixture2", Goal: "g", Expected: []ExpectedFinding{{VulnClass: "RCE"}}}
	res2, err := ScoreTask(context.Background(), d, sc2, task.ID)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Pass || !strings.Contains(res2.PassReason, "RCE") {
		t.Fatalf("missing required should fail: %+v", res2.PassReason)
	}
	if res2.UnexpectedN != 3 {
		t.Fatalf("unexpected = %d, want 3", res2.UnexpectedN)
	}
}
