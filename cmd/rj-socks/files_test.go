package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/xiongnemo/ruijie-sslvpn-socks5/internal/userdirs"
)

func testEnv(t *testing.T) (env userdirs.Env, home, wd string) {
	t.Helper()
	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(name, t.TempDir())
	}
	home, wd = t.TempDir(), t.TempDir()
	return userdirs.Env{
		Getenv:  func(string) string { return "" },
		HomeDir: func() (string, error) { return home, nil },
		WorkDir: func() (string, error) { return wd, nil },
	}, home, wd
}

func write(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestChooseConfig(t *testing.T) {
	env, home, wd := testEnv(t)
	newPath, legacy := filepath.Join(home, ".config", "rj-socks", "config.yaml"), filepath.Join(wd, "config.yaml")
	write(t, legacy, "legacy")

	var stderr bytes.Buffer
	got, err := chooseConfig(env, "", false, &stderr)
	if err != nil || got != legacy {
		t.Fatalf("chooseConfig() = %s, %v; want the legacy file", got, err)
	}
	if want := `rj-socks: 正在使用旧位置的配置 ` + legacy + `；运行 "rj-socks migrate" 可将其移到 ` + newPath + "\n"; stderr.String() != want {
		t.Fatalf("stderr = %q, want %q", stderr.String(), want)
	}

	// An explicit -config wins over both locations and prints nothing,
	// including the old spelling "-config config.yaml".
	write(t, newPath, "new")
	for _, explicit := range []string{"config.yaml", filepath.Join(t.TempDir(), "x.yaml")} {
		stderr.Reset()
		if got, err := chooseConfig(env, explicit, true, &stderr); err != nil || got != explicit || stderr.Len() != 0 {
			t.Fatalf("explicit -config %s: got %s, %v, stderr %q", explicit, got, err, stderr.String())
		}
	}

	stderr.Reset()
	if got, err := chooseConfig(env, "", false, &stderr); err != nil || got != newPath || stderr.Len() != 0 {
		t.Fatalf("new location: got %s, %v, stderr %q", got, err, stderr.String())
	}
}

func TestRunMigrateRewritesCAFile(t *testing.T) {
	env, home, wd := testEnv(t)
	legacy := filepath.Join(wd, "office", "config.yaml")
	write(t, legacy, "vpn:\n  server: https://gateway.test:443\n  tls:\n    ca_file: gateway.pem # pinned CA\n")
	newPath := filepath.Join(home, ".config", "rj-socks", "config.yaml")
	ca := filepath.Join(wd, "office", "gateway.pem")

	// Both the documented single-dash flags and GNU-style double dashes work.
	var stdout bytes.Buffer
	if err := runMigrate([]string{"--dry-run", "--from", legacy}, env, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "改写 "+newPath+" 中的 vpn.tls.ca_file：gateway.pem -> "+ca) {
		t.Fatalf("plan lacks the ca_file rewrite:\n%s", stdout.String())
	}
	if _, err := os.Stat(newPath); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the new configuration")
	}

	stdout.Reset()
	if err := runMigrate([]string{"-from", legacy}, env, &stdout); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(newPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), ca) || !strings.Contains(string(b), "# pinned CA") {
		t.Fatalf("moved configuration lacks the absolute CA path or its comment:\n%s", b)
	}
	if err := runMigrate([]string{"unexpected"}, env, &stdout); err == nil {
		t.Fatal("a stray argument was accepted")
	}
}
