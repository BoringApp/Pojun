package db

import (
	"database/sql"
	"errors"
)

// SetTaskEgressSnapshot writes the task's build-time egress receipt (issue #39).
// raw must already be redacted by the caller: this column is read by API handlers,
// diagnostics bundles and DB dumps, so no proxy credential may ever reach it.
//
// The column is intentionally absent from taskCols/scanTask: list endpoints do not
// need to parse it, and UpdateTask's RETURNING should not carry it either.
func (d *DB) SetTaskEgressSnapshot(taskID int64, raw []byte) error {
	_, err := d.Exec(
		`UPDATE tasks SET egress_snapshot=$2::jsonb WHERE id=$1 AND deleted_at IS NULL`,
		taskID, string(raw),
	)
	return err
}

// GetTaskEgressSnapshot returns the raw receipt JSON for a live task.
// found=false means the task row does not exist (or is deleted/archived);
// a NULL column returns (nil, true, nil) — the task exists but was never built.
func (d *DB) GetTaskEgressSnapshot(taskID int64) (raw []byte, found bool, err error) {
	var s sql.NullString
	err = d.QueryRow(
		`SELECT egress_snapshot::text FROM tasks WHERE id=$1 AND deleted_at IS NULL`,
		taskID,
	).Scan(&s)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if !s.Valid || s.String == "" {
		return nil, true, nil
	}
	return []byte(s.String), true, nil
}
