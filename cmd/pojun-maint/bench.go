package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/chu0119/pojun/db"
	"github.com/chu0119/pojun/eval"
)

// runBench 是 P1-4 评测 harness 的离线入口。
//
//	pojun-maint bench score --config ... --scenario eval/scenarios/dvwa.json --task 18 [--out run.json]
//	pojun-maint bench validate --scenario eval/scenarios
//	pojun-maint bench compare --a run-a.json --b run-b.json [--out diff.json] [--markdown diff.md]
//
// score 只读任务数据：不重跑 agent、不改 DB、不发网络请求。
func runBench(args []string) {
	if len(args) == 0 {
		benchUsage()
		os.Exit(2)
	}
	sub := args[0]
	fs := flag.NewFlagSet("bench "+sub, flag.ExitOnError)
	cfgPath := fs.String("config", "/opt/pojun/config.json", "POJUN config.json 路径")
	scenarioPath := fs.String("scenario", "", "场景 manifest 文件或目录")
	taskID := fs.Int64("task", 0, "score: 要评分的任务 ID")
	outPath := fs.String("out", "", "输出 JSON 文件")
	aPath := fs.String("a", "", "compare: 基线 RunResult JSON")
	bPath := fs.String("b", "", "compare: 新 RunResult JSON")
	mdPath := fs.String("markdown", "", "compare: 额外输出 Markdown 报告")
	_ = fs.Parse(args[1:])

	switch sub {
	case "validate":
		if strings.TrimSpace(*scenarioPath) == "" {
			fail(fmt.Errorf("--scenario 必填（目录）"))
		}
		scs, err := eval.LoadScenarios(*scenarioPath)
		if err != nil {
			fail(err)
		}
		for _, sc := range scs {
			fmt.Printf("OK  %-40s required=%d optional=%d stages=%d\n",
				sc.ID, sc.RequiredCount(), len(sc.Expected)-sc.RequiredCount(), len(sc.Stages))
		}
		fmt.Printf("共 %d 个场景，全部通过校验\n", len(scs))

	case "score":
		if strings.TrimSpace(*scenarioPath) == "" || *taskID <= 0 {
			fail(fmt.Errorf("score 需要 --scenario 与 --task"))
		}
		sc, err := eval.LoadScenario(*scenarioPath)
		if err != nil {
			fail(err)
		}
		dsn, err := loadDSN(*cfgPath)
		if err != nil {
			fail(err)
		}
		pg, err := db.OpenReadOnly(dsn)
		if err != nil {
			fail(fmt.Errorf("连接数据库失败：%w", err))
		}
		defer pg.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		res, err := eval.ScoreTask(ctx, pg, sc, *taskID)
		if err != nil {
			fail(err)
		}
		printRunResult(res)
		if *outPath != "" {
			if err := eval.WriteJSON(*outPath, res); err != nil {
				fail(err)
			}
			fmt.Printf("已写入 %s\n", *outPath)
		}

	case "compare":
		if strings.TrimSpace(*aPath) == "" || strings.TrimSpace(*bPath) == "" {
			fail(fmt.Errorf("compare 需要 --a 与 --b"))
		}
		a, err := eval.ReadRunResult(*aPath)
		if err != nil {
			fail(err)
		}
		b, err := eval.ReadRunResult(*bPath)
		if err != nil {
			fail(err)
		}
		cmp, err := eval.CompareRuns(a, b)
		if err != nil {
			fail(err)
		}
		md := cmp.Markdown()
		fmt.Print(md)
		if *outPath != "" {
			if err := eval.WriteJSON(*outPath, cmp); err != nil {
				fail(err)
			}
			fmt.Printf("已写入 %s\n", *outPath)
		}
		if *mdPath != "" {
			if err := os.WriteFile(*mdPath, []byte(md), 0o644); err != nil {
				fail(err)
			}
			fmt.Printf("已写入 %s\n", *mdPath)
		}
		if cmp.Regressed {
			os.Exit(1) // 回归时给 CI/脚本一个非零退出码
		}

	default:
		benchUsage()
		os.Exit(2)
	}
}

func printRunResult(r *eval.RunResult) {
	fmt.Printf("场景: %s (%s)\n", r.ScenarioID, r.ScenarioName)
	fmt.Printf("任务: #%d  状态=%s  目标=%d/%d\n", r.TaskID, r.Status, r.GoalsMet, r.GoalsTotal)
	fmt.Printf("结果: %s  %s\n", passText(r.Pass), r.PassReason)
	fmt.Printf("必得项: %d/%d  预期命中(含可选): %d/%d  额外发现: %d  额外率: %.1f%%\n",
		r.RequiredFound, r.RequiredTotal, r.ExpectedFound, len(r.Expected), r.UnexpectedN, r.ExtraRate*100)
	fmt.Printf("证据完整度: %.1f%%  阶段覆盖: %d/%d\n", r.EvidenceCompleteness*100, r.StagesSeen, r.StageTotal)
	fmt.Printf("Token: in=%d out=%d  成本: $%.4f (known=%v)  耗时: %.1f 分钟  附件: %d\n",
		r.TokensInput, r.TokensOutput, r.CostUSD, r.CostKnown, r.DurationMinutes, r.Artifacts)
	if len(r.BudgetNote) > 0 {
		fmt.Printf("预算提示: %s\n", strings.Join(r.BudgetNote, "；"))
	}
	for _, e := range r.Expected {
		mark := "✗"
		if e.Matched {
			mark = "✓"
		}
		opt := ""
		if e.Optional {
			opt = " (optional)"
		}
		fmt.Printf("  %s %s%s  证据=%d/%d\n", mark, e.VulnClass, opt, e.EvidenceRunes, e.MinEvidenceRunes)
	}
}

func passText(v bool) string {
	if v {
		return "PASS"
	}
	return "FAIL"
}

func benchUsage() {
	fmt.Fprintln(os.Stderr, `usage:
  pojun-maint bench score    --config <config.json> --scenario <scenario.json> --task <id> [--out run.json]
  pojun-maint bench validate --scenario <scenarios-dir>
  pojun-maint bench compare  --a <baseline.json> --b <new.json> [--out diff.json] [--markdown diff.md]`)
}
