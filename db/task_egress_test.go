package db

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// 回归守卫：egress_snapshot 绝不进 taskCols——ListTasks/GetTask 会扫描全部活任务，
// 把回执 JSONB 塞进热路径会让每个任务都多一次解析。
func TestTaskEgressSnapshotNotInTaskCols(t *testing.T) {
	if strings.Contains(taskCols, "egress_snapshot") {
		t.Fatal("taskCols 不得包含 egress_snapshot（任务列表热路径）")
	}
}

func TestTaskEgressSnapshotRoundTrip(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()

	task, err := d.CreateTaskWithOptions("egress snapshot test", "round trip", TaskCreateOptions{})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() { _ = d.DeleteTask(task.ID) })

	// Never built → task exists, column NULL.
	raw, found, err := d.GetTaskEgressSnapshot(task.ID)
	if err != nil || !found || len(raw) != 0 {
		t.Fatalf("initial get = (%q, %v, %v), want (empty, true, nil)", raw, found, err)
	}

	snap := []byte(`{"schema_version":1,"captured_at":"2026-11-23T12:00:00Z","egress":{"kind":"direct","address":"","has_auth":false,"parse_ok":true},"ua":{"surfaces":[]}}`)
	if err := d.SetTaskEgressSnapshot(task.ID, snap); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}
	got, found, err := d.GetTaskEgressSnapshot(task.ID)
	if err != nil || !found {
		t.Fatalf("get after set = (%v, %v)", found, err)
	}
	var want, have any
	if err := json.Unmarshal(snap, &want); err != nil {
		t.Fatalf("unmarshal want: %v", err)
	}
	if err := json.Unmarshal(got, &have); err != nil {
		t.Fatalf("unmarshal got: %v", err)
	}
	if !reflect.DeepEqual(want, have) {
		t.Fatalf("round trip mismatch:\nwant %s\ngot  %s", snap, got)
	}

	// Soft-deleted (archived) tasks must be invisible.
	if _, err := d.Exec(`UPDATE tasks SET deleted_at=now() WHERE id=$1`, task.ID); err != nil {
		t.Fatalf("soft delete: %v", err)
	}
	if _, found, err := d.GetTaskEgressSnapshot(task.ID); err != nil || found {
		t.Fatalf("deleted task get = (found=%v, err=%v), want (false, nil)", found, err)
	}
}

// 归档必须显式清空出口回执：归档 stub 会一直留在 tasks 行里，若不清空，
// 恢复后任务页会展示归档前的陈旧「已构建」回执；restoreTaskStub 的显式
// 列清单不含该列，因此恢复后保持 NULL，直到下一次 Agent 装配重新写入。
func TestTaskArchiveClearsEgressSnapshot(t *testing.T) {
	d, err := Open(testDSN(t))
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	defer d.Close()
	if err := d.EnsureLLMRecordsTable(); err != nil {
		t.Fatal(err)
	}
	if err := d.EnsureLLMUsageTable(); err != nil {
		t.Fatal(err)
	}

	task, err := d.CreateTaskWithOptions("archive clears egress", "goal", TaskCreateOptions{})
	if err != nil {
		t.Fatalf("create task: %v", err)
	}
	t.Cleanup(func() {
		_, _ = d.Exec(`DELETE FROM task_archives WHERE task_id=$1`, task.ID)
		_ = d.DeleteTask(task.ID)
	})
	raw := []byte(`{"schema_version":1,"captured_at":"2026-11-23T12:00:00Z","egress":{"kind":"direct","has_auth":false,"parse_ok":true},"ua":{"surfaces":[]}}`)
	if err := d.SetTaskEgressSnapshot(task.ID, raw); err != nil {
		t.Fatalf("set snapshot: %v", err)
	}
	// 归档前置条件：任务已暂停或处于终态（与任务页归档按钮同一约束）。
	if err := d.SetPaused(task.ID, true); err != nil {
		t.Fatalf("pause task: %v", err)
	}

	archive, err := d.QueueTaskArchive(task.ID)
	if err != nil {
		t.Fatalf("queue archive: %v", err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatalf("claim archive: %v", err)
	}
	snap, err := d.SnapshotTaskArchive(task.ID)
	if err != nil {
		t.Fatalf("snapshot archive: %v", err)
	}
	if err := d.CompleteTaskArchive(archive.ID, snap, "/tmp/test-egress.tar", "abc", 1, 1); err != nil {
		t.Fatalf("complete archive: %v", err)
	}
	var isNull bool
	if err := d.QueryRow(`SELECT egress_snapshot IS NULL FROM tasks WHERE id=$1`, task.ID).Scan(&isNull); err != nil {
		t.Fatalf("read archived stub: %v", err)
	}
	if !isNull {
		t.Fatal("归档后 egress_snapshot 必须为 NULL")
	}

	if _, err := d.QueueTaskArchiveRestore(archive.ID); err != nil {
		t.Fatalf("queue restore: %v", err)
	}
	if _, err := d.ClaimTaskArchiveJob(t.Context()); err != nil {
		t.Fatalf("claim restore: %v", err)
	}
	if _, err := d.RestoreTaskArchive(archive.ID, snap, 600); err != nil {
		t.Fatalf("restore archive: %v", err)
	}
	if err := d.QueryRow(`SELECT egress_snapshot IS NULL FROM tasks WHERE id=$1`, task.ID).Scan(&isNull); err != nil {
		t.Fatalf("read restored stub: %v", err)
	}
	if !isNull {
		t.Fatal("恢复后不得回填归档前的 egress_snapshot")
	}
}
