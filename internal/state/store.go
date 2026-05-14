package state

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/maestroi/hardener/internal/model"
)

// FileStore implements StateManager using the local filesystem.
// Layout: <stateDir>/runs/<run-id>/{plan,applied,rollback}.json
type FileStore struct {
	dir string
}

// NewFileStore creates a FileStore rooted at dir, creating subdirectories as needed.
func NewFileStore(dir string) (*FileStore, error) {
	for _, sub := range []string{"runs", "backups", "locks", "scans"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0750); err != nil {
			return nil, fmt.Errorf("creating state dir %s/%s: %w", dir, sub, err)
		}
	}
	return &FileStore{dir: dir}, nil
}

func (s *FileStore) StateDir() string { return s.dir }

func (s *FileStore) runDir(runID string) string {
	return filepath.Join(s.dir, "runs", runID)
}

func (s *FileStore) InitRun(ctx context.Context, profileName string, dryRun bool) (*model.Run, error) {
	_ = ctx
	run := &model.Run{
		ID:          fmt.Sprintf("%d", time.Now().UnixNano()),
		StartedAt:   time.Now().UTC(),
		ProfileName: profileName,
		StateDir:    s.dir,
		DryRun:      dryRun,
		Status:      model.RunPlanning,
	}

	runDir := s.runDir(run.ID)
	if err := os.MkdirAll(filepath.Join(runDir, "logs"), 0750); err != nil {
		return nil, fmt.Errorf("creating run dir: %w", err)
	}

	if err := s.writeJSON(filepath.Join(runDir, "run.json"), run); err != nil {
		return nil, err
	}

	if err := s.appendJSONL(filepath.Join(s.dir, "history.jsonl"), run); err != nil {
		return nil, err
	}

	manifest := &model.RollbackManifest{
		RunID:     run.ID,
		CreatedAt: run.StartedAt,
		Entries:   []model.RollbackEntry{},
	}
	if err := s.writeJSON(filepath.Join(runDir, "rollback.json"), manifest); err != nil {
		return nil, err
	}

	return run, nil
}

func (s *FileStore) SavePlan(ctx context.Context, runID string, actions []*model.PlannedAction) error {
	_ = ctx
	path := filepath.Join(s.runDir(runID), "plan.json")
	return s.writeJSON(path, actions)
}

func (s *FileStore) RecordApplied(ctx context.Context, runID string, action *model.AppliedAction) error {
	_ = ctx
	path := filepath.Join(s.runDir(runID), "applied.json")

	var actions []*model.AppliedAction
	if data, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(data, &actions)
	}
	actions = append(actions, action)
	return s.writeJSON(path, actions)
}

func (s *FileStore) AppendRollbackEntry(ctx context.Context, runID string, entry model.RollbackEntry) error {
	manifest, err := s.LoadRollbackManifest(ctx, runID)
	if err != nil {
		return err
	}
	manifest.Entries = append(manifest.Entries, entry)
	path := filepath.Join(s.runDir(runID), "rollback.json")
	return s.writeJSON(path, manifest)
}

func (s *FileStore) CompleteRun(ctx context.Context, runID string, status model.RunStatus) error {
	run, err := s.GetRun(ctx, runID)
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	run.FinishedAt = &now
	run.Status = status
	return s.writeJSON(filepath.Join(s.runDir(runID), "run.json"), run)
}

func (s *FileStore) GetRun(ctx context.Context, runID string) (*model.Run, error) {
	_ = ctx
	data, err := os.ReadFile(filepath.Join(s.runDir(runID), "run.json"))
	if err != nil {
		return nil, fmt.Errorf("run %s not found: %w", runID, err)
	}
	var run model.Run
	if err := json.Unmarshal(data, &run); err != nil {
		return nil, fmt.Errorf("parsing run %s: %w", runID, err)
	}
	return &run, nil
}

func (s *FileStore) ListRuns(ctx context.Context) ([]*model.Run, error) {
	_ = ctx
	entries, err := os.ReadDir(filepath.Join(s.dir, "runs"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var runs []*model.Run
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		run, err := s.GetRun(ctx, e.Name())
		if err != nil {
			continue
		}
		runs = append(runs, run)
	}
	sort.Slice(runs, func(i, j int) bool {
		return runs[i].StartedAt.Before(runs[j].StartedAt)
	})
	return runs, nil
}

func (s *FileStore) SaveScan(ctx context.Context, result *model.ScanResult) error {
	_ = ctx
	name := fmt.Sprintf("%d.json", result.Timestamp.UnixNano())
	path := filepath.Join(s.dir, "scans", name)
	return s.writeJSON(path, result)
}

func (s *FileStore) LatestScan(ctx context.Context) (*model.ScanResult, error) {
	scans, err := s.ListScans(ctx)
	if err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, ErrNoScans
	}
	return scans[len(scans)-1], nil
}

func (s *FileStore) ListScans(ctx context.Context) ([]*model.ScanResult, error) {
	_ = ctx
	dir := filepath.Join(s.dir, "scans")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var results []*model.ScanResult
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		result := new(model.ScanResult)
		if err := json.Unmarshal(data, result); err != nil {
			continue
		}
		results = append(results, result)
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Timestamp.Before(results[j].Timestamp)
	})
	return results, nil
}

func (s *FileStore) LoadRollbackManifest(ctx context.Context, runID string) (*model.RollbackManifest, error) {
	_ = ctx
	data, err := os.ReadFile(filepath.Join(s.runDir(runID), "rollback.json"))
	if err != nil {
		return nil, fmt.Errorf("rollback manifest for run %s: %w", runID, err)
	}
	var manifest model.RollbackManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("parsing rollback manifest: %w", err)
	}
	return &manifest, nil
}

func (s *FileStore) LoadPlan(ctx context.Context, runID string) ([]*model.PlannedAction, error) {
	_ = ctx
	path := filepath.Join(s.runDir(runID), "plan.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("plan for run %s: %w", runID, err)
	}
	var actions []*model.PlannedAction
	if err := json.Unmarshal(data, &actions); err != nil {
		return nil, fmt.Errorf("parsing plan for run %s: %w", runID, err)
	}
	return actions, nil
}

func (s *FileStore) LoadApplied(ctx context.Context, runID string) ([]*model.AppliedAction, error) {
	_ = ctx
	path := filepath.Join(s.runDir(runID), "applied.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("applied actions for run %s: %w", runID, err)
	}
	var actions []*model.AppliedAction
	if err := json.Unmarshal(data, &actions); err != nil {
		return nil, fmt.Errorf("parsing applied actions for run %s: %w", runID, err)
	}
	return actions, nil
}

func (s *FileStore) writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling to %s: %w", path, err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0640); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return os.Rename(tmp, path)
}

func (s *FileStore) appendJSONL(path string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = fmt.Fprintf(f, "%s\n", data)
	return err
}
