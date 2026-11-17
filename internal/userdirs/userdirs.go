// Package userdirs places rj-socks' per-user files in the XDG Base Directory
// layout, the same on Linux, macOS and Windows, and finds the configuration
// that older versions read from the working directory.
//
// rj-socks keeps a single per-user file: config.yaml, which holds the VPN
// credentials and the certificate pins saved by "always trust". It writes no
// session, cookie, log or pid file.
package userdirs

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Tool is the command name, and the directory name under each XDG base.
const Tool = "rj-socks"

// ConfigName is the configuration file name, in the XDG directory and in the
// working directory where versions before the XDG layout looked for it.
const ConfigName = "config.yaml"

// Env is the part of the process environment the resolver reads. Tests inject
// their own so nothing ever touches the real home or working directory.
type Env struct {
	Getenv  func(string) string
	HomeDir func() (string, error)
	WorkDir func() (string, error)
}

// OS reads the real process environment.
func OS() Env {
	return Env{Getenv: os.Getenv, HomeDir: os.UserHomeDir, WorkDir: os.Getwd}
}

// ConfigHome is $XDG_CONFIG_HOME, or ~/.config when that is unset or not an
// absolute path (the XDG spec says relative values are invalid). ~ is
// os.UserHomeDir: $HOME on Unix, %USERPROFILE% on Windows.
func (e Env) ConfigHome() (string, error) {
	if dir := e.Getenv("XDG_CONFIG_HOME"); dir != "" && filepath.IsAbs(dir) {
		return filepath.Clean(dir), nil
	}
	home, err := e.HomeDir()
	if err == nil && home == "" {
		err = errors.New("home directory is empty")
	}
	if err != nil {
		return "", fmt.Errorf("locate the home directory: %w", err)
	}
	return filepath.Join(home, ".config"), nil
}

// ConfigDir is $XDG_CONFIG_HOME/rj-socks.
func (e Env) ConfigDir() (string, error) {
	base, err := e.ConfigHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, Tool), nil
}

// ConfigFile is $XDG_CONFIG_HOME/rj-socks/config.yaml.
func (e Env) ConfigFile() (string, error) {
	dir, err := e.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, ConfigName), nil
}

// LegacyConfigFile is config.yaml in the working directory, the default of
// every release before the XDG layout.
func (e Env) LegacyConfigFile() (string, error) {
	wd, err := e.WorkDir()
	if err != nil {
		return "", fmt.Errorf("locate the working directory: %w", err)
	}
	return filepath.Join(wd, ConfigName), nil
}

// ConfigChoice is the configuration file a run uses.
type ConfigChoice struct {
	// Path is the file to load.
	Path string
	// Legacy reports that Path is the old working-directory default; the
	// caller tells the user once, on stderr, and points at "rj-socks migrate".
	Legacy bool
	// New is the XDG location, where migrate moves a legacy file.
	New string
}

// ResolveConfig picks the configuration file when -config is not given: the
// XDG file if it exists, else ./config.yaml if that exists, else the XDG path,
// which nothing creates until migrate or the user writes it.
func (e Env) ResolveConfig() (ConfigChoice, error) {
	newPath, err := e.ConfigFile()
	if err != nil {
		return ConfigChoice{}, err
	}
	if fileExists(newPath) {
		return ConfigChoice{Path: newPath, New: newPath}, nil
	}
	legacy, err := e.LegacyConfigFile()
	if err != nil {
		return ConfigChoice{}, err
	}
	if fileExists(legacy) {
		return ConfigChoice{Path: legacy, Legacy: true, New: newPath}, nil
	}
	return ConfigChoice{Path: newPath, New: newPath}, nil
}

// LegacyNotice is the one line printed to stderr when a run falls back to the
// old location.
func (c ConfigChoice) LegacyNotice() string {
	return fmt.Sprintf("%s: 正在使用旧位置的配置 %s；运行 \"%s migrate\" 可将其移到 %s", Tool, c.Path, Tool, c.New)
}

// fileExists reports whether path names something other than a directory. A
// file that exists but cannot be inspected counts, so loading it reports the
// real error instead of silently falling through to another file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return !errors.Is(err, fs.ErrNotExist)
	}
	return !info.IsDir()
}
