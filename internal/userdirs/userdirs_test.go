package userdirs

import (
	"os"
	"path/filepath"
	"testing"
)

// testEnv points every variable that could reach a real home at temporary
// directories, then returns an injected environment rooted in a fresh home
// and working directory. vars overrides the injected variables.
func testEnv(t *testing.T, vars map[string]string) (env Env, home, wd string) {
	t.Helper()
	for _, name := range []string{"HOME", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"} {
		t.Setenv(name, t.TempDir())
	}
	home, wd = t.TempDir(), t.TempDir()
	env = Env{
		Getenv:  func(name string) string { return vars[name] },
		HomeDir: func() (string, error) { return home, nil },
		WorkDir: func() (string, error) { return wd, nil },
	}
	return env, home, wd
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestConfigHomeHonorsOnlyAbsoluteXDG(t *testing.T) {
	absolute := t.TempDir()
	for _, test := range []struct {
		name, xdg string
		want      func(home string) string
	}{
		{"unset", "", func(home string) string { return filepath.Join(home, ".config") }},
		{"absolute", absolute, func(string) string { return absolute }},
		{"relative", filepath.Join("relative", "config"), func(home string) string { return filepath.Join(home, ".config") }},
		{"dot", ".", func(home string) string { return filepath.Join(home, ".config") }},
	} {
		t.Run(test.name, func(t *testing.T) {
			env, home, _ := testEnv(t, map[string]string{"XDG_CONFIG_HOME": test.xdg})
			got, err := env.ConfigHome()
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want(home) {
				t.Fatalf("ConfigHome() = %s, want %s", got, test.want(home))
			}
			file, err := env.ConfigFile()
			if err != nil {
				t.Fatal(err)
			}
			if file != filepath.Join(test.want(home), "rj-socks", "config.yaml") {
				t.Fatalf("ConfigFile() = %s", file)
			}
		})
	}
}

func TestConfigHomeWithoutHome(t *testing.T) {
	env, _, _ := testEnv(t, nil)
	env.HomeDir = func() (string, error) { return "", nil }
	if _, err := env.ConfigHome(); err == nil {
		t.Fatal("an empty home directory was accepted")
	}
	// An absolute XDG_CONFIG_HOME needs no home.
	xdg := t.TempDir()
	env.Getenv = func(name string) string { return map[string]string{"XDG_CONFIG_HOME": xdg}[name] }
	if got, err := env.ConfigHome(); err != nil || got != xdg {
		t.Fatalf("ConfigHome() = %s, %v", got, err)
	}
}

func TestResolveConfig(t *testing.T) {
	for _, setting := range []string{"XDG unset", "XDG absolute", "XDG relative"} {
		for _, test := range []struct {
			name              string
			atNew, atLegacy   bool
			wantNew, wantWarn bool
		}{
			{"neither", false, false, true, false},
			{"new only", true, false, true, false},
			{"legacy only", false, true, false, true},
			{"both", true, true, true, false},
		} {
			t.Run(setting+"/"+test.name, func(t *testing.T) {
				vars, base := map[string]string{}, ""
				switch setting {
				case "XDG absolute":
					base = t.TempDir()
					vars["XDG_CONFIG_HOME"] = base
				case "XDG relative":
					vars["XDG_CONFIG_HOME"] = "rel"
				}
				env, home, wd := testEnv(t, vars)
				if base == "" {
					base = filepath.Join(home, ".config")
				}
				newPath := filepath.Join(base, "rj-socks", "config.yaml")
				legacy := filepath.Join(wd, "config.yaml")
				if test.atNew {
					writeFile(t, newPath, "new")
				}
				if test.atLegacy {
					writeFile(t, legacy, "legacy")
				}
				got, err := env.ResolveConfig()
				if err != nil {
					t.Fatal(err)
				}
				want := legacy
				if test.wantNew {
					want = newPath
				}
				if got.Path != want || got.Legacy != test.wantWarn || got.New != newPath {
					t.Fatalf("ResolveConfig() = %+v, want path %s legacy %t", got, want, test.wantWarn)
				}
				if !test.atNew {
					if _, err := os.Stat(filepath.Dir(newPath)); !os.IsNotExist(err) {
						t.Fatal("resolving created the new directory; it must wait for the first write")
					}
				}
			})
		}
	}
}

func TestResolveConfigIgnoresEmptyNewDirectory(t *testing.T) {
	env, home, wd := testEnv(t, nil)
	if err := os.MkdirAll(filepath.Join(home, ".config", "rj-socks"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(wd, "config.yaml"), "legacy")
	got, err := env.ResolveConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Legacy || got.Path != filepath.Join(wd, "config.yaml") {
		t.Fatalf("an empty new directory hid the legacy configuration: %+v", got)
	}
	// A directory named config.yaml is not a configuration either.
	if err := os.MkdirAll(filepath.Join(home, ".config", "rj-socks", "config.yaml"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got, _ := env.ResolveConfig(); !got.Legacy {
		t.Fatalf("a directory at the new path hid the legacy configuration: %+v", got)
	}
}

func TestLegacyNotice(t *testing.T) {
	c := ConfigChoice{Path: filepath.FromSlash("/work/config.yaml"), Legacy: true, New: filepath.FromSlash("/home/u/.config/rj-socks/config.yaml")}
	want := `rj-socks: 正在使用旧位置的配置 ` + c.Path + `；运行 "rj-socks migrate" 可将其移到 ` + c.New
	if got := c.LegacyNotice(); got != want {
		t.Fatalf("LegacyNotice() = %q, want %q", got, want)
	}
}
