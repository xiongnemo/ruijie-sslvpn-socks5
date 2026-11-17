package userdirs

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

const legacyConfig = "vpn:\n  server: https://gateway.test:443\n  username: unit-test-user\n  password: unit-test-only\n"

// snapshot records every file and directory under the roots, with contents,
// so a test can prove that nothing changed.
func snapshot(t *testing.T, roots ...string) string {
	t.Helper()
	var lines []string
	for _, root := range roots {
		filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				t.Fatal(err)
			}
			line := path
			if !d.IsDir() {
				b, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				line += "=" + string(b)
			}
			lines = append(lines, line)
			return nil
		})
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func mustNotExist(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("%s still exists (%v)", path, err)
	}
}

func migrate(t *testing.T, env Env, o MigrateOptions) (string, error) {
	t.Helper()
	var out bytes.Buffer
	o.Out = &out
	err := env.Migrate(o)
	return out.String(), err
}

func TestMigrateDryRunTouchesNothing(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, legacyConfig)
	before := snapshot(t, home, wd)
	out, err := migrate(t, env, MigrateOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if after := snapshot(t, home, wd); after != before {
		t.Fatalf("dry run changed files:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	newPath := filepath.Join(home, ".config", "rj-socks", "config.yaml")
	for _, want := range []string{"dry run", "current directory " + wd, legacy + " -> " + newPath} {
		if !strings.Contains(out, want) {
			t.Errorf("plan lacks %q:\n%s", want, out)
		}
	}
}

func TestMigrateMovesConfig(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, legacyConfig)
	if err := os.Chmod(legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := migrate(t, env, MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(home, ".config", "rj-socks", "config.yaml")
	if readFile(t, newPath) != legacyConfig {
		t.Fatal("moved configuration differs")
	}
	mustNotExist(t, legacy)
	if !strings.Contains(out, "move "+legacy+" -> "+newPath) {
		t.Errorf("output lacks the move:\n%s", out)
	}
	if strings.Contains(out, "unit-test-only") {
		t.Fatal("migrate printed the configuration's contents")
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(newPath); info.Mode().Perm() != 0o600 {
			t.Errorf("moved configuration has mode %v, want 0600", info.Mode().Perm())
		}
		if info, _ := os.Stat(filepath.Dir(newPath)); info.Mode().Perm() != 0o700 {
			t.Errorf("configuration directory has mode %v, want 0700", info.Mode().Perm())
		}
	}
	// The working directory is not rj-socks' to remove.
	if _, err := os.Stat(wd); err != nil {
		t.Fatal("migrate removed the working directory")
	}

	// Idempotent: a second run has nothing to do and succeeds.
	out, err = migrate(t, env, MigrateOptions{})
	if err != nil || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("second run: %v\n%s", err, out)
	}
}

func TestMigrateMergesIntoExistingDirectory(t *testing.T) {
	xdg := t.TempDir()
	env, _, wd := testEnv(t, map[string]string{"XDG_CONFIG_HOME": xdg})
	other := filepath.Join(xdg, "rj-socks", "notes.txt")
	writeFile(t, other, "keep me")
	writeFile(t, filepath.Join(wd, "config.yaml"), legacyConfig)
	if _, err := migrate(t, env, MigrateOptions{}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(xdg, "rj-socks", "config.yaml")) != legacyConfig || readFile(t, other) != "keep me" {
		t.Fatal("merging into the existing directory lost a file")
	}
}

func TestMigrateConflictKeepsBoth(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy, newPath := filepath.Join(wd, "config.yaml"), filepath.Join(home, ".config", "rj-socks", "config.yaml")
	writeFile(t, legacy, legacyConfig)
	writeFile(t, newPath, legacyConfig+"# edited since\n")
	out, err := migrate(t, env, MigrateOptions{})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("conflict returned %v, want ErrConflict", err)
	}
	if readFile(t, legacy) != legacyConfig || readFile(t, newPath) != legacyConfig+"# edited since\n" {
		t.Fatal("a conflicting copy was changed")
	}
	if !strings.Contains(out, "conflict") {
		t.Errorf("conflict not reported:\n%s", out)
	}
}

func TestMigrateIdenticalRemovesLegacy(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy, newPath := filepath.Join(wd, "config.yaml"), filepath.Join(home, ".config", "rj-socks", "config.yaml")
	writeFile(t, legacy, legacyConfig)
	writeFile(t, newPath, legacyConfig)
	out, err := migrate(t, env, MigrateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, legacy)
	if readFile(t, newPath) != legacyConfig || !strings.Contains(out, "remove "+legacy) {
		t.Fatalf("identical copy not handled:\n%s", out)
	}
}

func TestMigrateRewritesReferences(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, "ca: gateway.pem\n")
	var gotDir string
	rewrite := func(data []byte, dir string) ([]byte, []PathRewrite, error) {
		gotDir = dir
		abs := filepath.Join(dir, "gateway.pem")
		return bytes.Replace(data, []byte("gateway.pem"), []byte(abs), 1), []PathRewrite{{Key: "ca", Old: "gateway.pem", New: abs}}, nil
	}
	plan, err := migrate(t, env, MigrateOptions{DryRun: true, Rewrite: rewrite})
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(home, ".config", "rj-socks", "config.yaml")
	if !strings.Contains(plan, "rewrite ca in "+newPath+": gateway.pem -> "+filepath.Join(wd, "gateway.pem")) {
		t.Fatalf("plan lacks the rewrite:\n%s", plan)
	}
	if readFile(t, legacy) != "ca: gateway.pem\n" {
		t.Fatal("dry run rewrote the file")
	}
	if _, err := migrate(t, env, MigrateOptions{Rewrite: rewrite}); err != nil {
		t.Fatal(err)
	}
	if gotDir != wd {
		t.Fatalf("rewrite got directory %s, want %s", gotDir, wd)
	}
	if got := readFile(t, newPath); got != "ca: "+filepath.Join(wd, "gateway.pem")+"\n" {
		t.Fatalf("reference not rewritten: %q", got)
	}
	mustNotExist(t, legacy)

	// The rewritten file counts as identical to its legacy original.
	writeFile(t, legacy, "ca: gateway.pem\n")
	if _, err := migrate(t, env, MigrateOptions{Rewrite: rewrite}); err != nil {
		t.Fatal(err)
	}
	mustNotExist(t, legacy)
}

func TestMigrateFailedRewriteStillMoves(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	writeFile(t, filepath.Join(wd, "config.yaml"), legacyConfig)
	out, err := migrate(t, env, MigrateOptions{Rewrite: func([]byte, string) ([]byte, []PathRewrite, error) {
		return nil, nil, errors.New("unit test refusal")
	}})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(home, ".config", "rj-socks", "config.yaml")) != legacyConfig || !strings.Contains(out, "skip rewriting") {
		t.Fatalf("failed rewrite was not reported or blocked the move:\n%s", out)
	}
}

func TestMigrateFrom(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	other := filepath.Join(wd, "vpn", "office.yaml")
	writeFile(t, other, legacyConfig)
	writeFile(t, filepath.Join(wd, "config.yaml"), "not this one")
	out, err := migrate(t, env, MigrateOptions{From: filepath.Join("vpn", "office.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(home, ".config", "rj-socks", "config.yaml")) != legacyConfig {
		t.Fatal("-from file was not moved")
	}
	mustNotExist(t, other)
	if readFile(t, filepath.Join(wd, "config.yaml")) != "not this one" || strings.Contains(out, "current directory") {
		t.Fatalf("-from still looked in the current directory:\n%s", out)
	}
	out, err = migrate(t, env, MigrateOptions{From: other})
	if err != nil || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("missing -from file: %v\n%s", err, out)
	}
}

func TestMigrateFromNewLocationIsNoop(t *testing.T) {
	env, home, _ := testEnv(t, nil)
	newPath := filepath.Join(home, ".config", "rj-socks", "config.yaml")
	writeFile(t, newPath, legacyConfig)
	env.WorkDir = func() (string, error) { return filepath.Dir(newPath), nil }
	out, err := migrate(t, env, MigrateOptions{})
	if err != nil || !strings.Contains(out, "nothing to migrate") {
		t.Fatalf("migrating the new location onto itself: %v\n%s", err, out)
	}
	if readFile(t, newPath) != legacyConfig {
		t.Fatal("configuration changed")
	}
}

func TestMigrateCopiesAcrossVolumes(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	legacy := filepath.Join(wd, "config.yaml")
	writeFile(t, legacy, legacyConfig)
	mtime := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	if err := os.Chtimes(legacy, mtime, mtime); err != nil {
		t.Fatal(err)
	}
	rename = func(string, string) error { return errors.New("invalid cross-device link (unit test)") }
	t.Cleanup(func() { rename = os.Rename })
	if _, err := migrate(t, env, MigrateOptions{}); err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(home, ".config", "rj-socks", "config.yaml")
	if readFile(t, newPath) != legacyConfig {
		t.Fatal("copied configuration differs")
	}
	mustNotExist(t, legacy)
	if info, _ := os.Stat(newPath); !info.ModTime().Equal(mtime) {
		t.Errorf("copy has mtime %v, want %v", info.ModTime(), mtime)
	}
	leftovers, _ := filepath.Glob(filepath.Join(filepath.Dir(newPath), ".rj-socks-migrate-*"))
	if len(leftovers) != 0 {
		t.Fatalf("copy left temporary files: %v", leftovers)
	}
}
