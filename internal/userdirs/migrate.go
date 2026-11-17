package userdirs

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// ErrConflict means migrate found a different file at the new location and
// kept both copies.
var ErrConflict = errors.New("migration left conflicts; both copies were kept")

// PathRewrite is one path inside the configuration that migrate changes so
// the file still works from its new directory.
type PathRewrite struct {
	Key, Old, New string
}

// MigrateOptions controls Migrate.
type MigrateOptions struct {
	// From is the legacy configuration file. Empty means config.yaml in the
	// working directory.
	From string
	// DryRun prints the plan and changes nothing.
	DryRun bool
	// Rewrite returns the configuration with paths that were relative to
	// oldDir made absolute, and what it changed. nil rewrites nothing.
	Rewrite func(data []byte, oldDir string) ([]byte, []PathRewrite, error)
	// Out receives the plan and every action.
	Out io.Writer
}

// rename is os.Rename; tests replace it to exercise the cross-volume path.
var rename = os.Rename

// Migrate moves a legacy configuration file to $XDG_CONFIG_HOME/rj-socks.
// It never overwrites: a different file at the new location is a conflict,
// reported as ErrConflict after both copies are left in place; an identical
// one makes the legacy copy redundant, so it is removed. Running it again
// finds nothing to do.
func (e Env) Migrate(o MigrateOptions) error {
	out := o.Out
	if out == nil {
		out = io.Discard
	}
	say := func(format string, args ...any) { fmt.Fprintf(out, format+"\n", args...) }
	if o.DryRun {
		say("dry run: nothing will be changed")
	}

	src := o.From
	if src == "" {
		wd, err := e.WorkDir()
		if err != nil {
			return fmt.Errorf("locate the working directory: %w", err)
		}
		src = filepath.Join(wd, ConfigName)
		say("looking for %s in the current directory %s (use -from to name another file)", ConfigName, wd)
	} else if !filepath.IsAbs(src) {
		wd, err := e.WorkDir()
		if err != nil {
			return fmt.Errorf("locate the working directory: %w", err)
		}
		src = filepath.Join(wd, src)
	}
	src = filepath.Clean(src)
	dst, err := e.ConfigFile()
	if err != nil {
		return err
	}

	srcInfo, err := os.Stat(src)
	switch {
	case errors.Is(err, os.ErrNotExist):
		say("nothing to migrate: %s does not exist", src)
		return nil
	case err != nil:
		return err
	case srcInfo.IsDir():
		return fmt.Errorf("%s is a directory, not a configuration file", src)
	}
	dstInfo, err := os.Stat(dst)
	dstExists := err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if dstExists && os.SameFile(srcInfo, dstInfo) {
		say("nothing to migrate: %s is already the new location", src)
		return nil
	}

	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	rewritten, rewrites := data, []PathRewrite(nil)
	if o.Rewrite != nil {
		if rewritten, rewrites, err = o.Rewrite(data, filepath.Dir(src)); err != nil {
			// The move still helps; the user fixes the paths by hand.
			say("skip rewriting paths in %s: %v; make any relative paths in it absolute after the move", src, err)
			rewritten, rewrites = data, nil
		}
	}

	if dstExists {
		if dstInfo.IsDir() {
			return fmt.Errorf("%s is a directory, not a configuration file", dst)
		}
		current, err := os.ReadFile(dst)
		if err != nil {
			return err
		}
		if bytes.Equal(current, data) || bytes.Equal(current, rewritten) {
			say("remove %s: the same configuration is already at %s", src, dst)
			if !o.DryRun {
				if err := os.Remove(src); err != nil {
					return err
				}
			}
			return nil
		}
		say("conflict: %s and %s differ; both kept. Keep the one you want at %s and delete the other, or pass -config to choose", src, dst, dst)
		return ErrConflict
	}

	say("move %s -> %s", src, dst)
	for _, r := range rewrites {
		say("rewrite %s in %s: %s -> %s", r.Key, dst, r.Old, r.New)
	}
	if o.DryRun {
		say("dry run complete; run without -dry-run to apply")
		return nil
	}
	// Created on first write. The directory holds VPN credentials.
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	// The file holds the VPN password: keep its mode but drop group and other
	// access; this only ever tightens.
	mode := srcInfo.Mode().Perm() & 0o600
	if len(rewrites) == 0 {
		err = moveFile(src, dst, mode)
	} else {
		err = replaceFile(src, dst, rewritten, mode)
	}
	if err != nil {
		return err
	}
	say("done; rj-socks now reads %s", dst)
	return nil
}

// moveFile renames src to dst, or, when rename fails (across volumes), copies
// it preserving mtime, verifies size and SHA-256, then removes src. Either way
// dst ends up with mode. The caller has checked that dst does not exist.
func moveFile(src, dst string, mode os.FileMode) error {
	renameErr := rename(src, dst)
	if renameErr == nil {
		return os.Chmod(dst, mode)
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	if err := writeVerified(src, dst, data, mode); err != nil {
		return fmt.Errorf("move %s: rename failed (%v), copy failed: %w", src, renameErr, err)
	}
	return os.Remove(src)
}

// replaceFile writes data, the rewritten configuration, to dst, verifies it,
// then removes src.
func replaceFile(src, dst string, data []byte, mode os.FileMode) error {
	if err := writeVerified(src, dst, data, mode); err != nil {
		return fmt.Errorf("write %s: %w", dst, err)
	}
	return os.Remove(src)
}

// writeVerified writes data beside dst with mode and src's mtime, renames it
// into place and checks size and SHA-256 by reading it back.
func writeVerified(src, dst string, data []byte, mode os.FileMode) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	// CreateTemp makes the file 0600, so the secret is never readable by others.
	f, err := os.CreateTemp(filepath.Dir(dst), "."+Tool+"-migrate-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(tmp, mode)
	}
	if err == nil {
		err = os.Chtimes(tmp, info.ModTime(), info.ModTime())
	}
	if err != nil {
		return err
	}
	if _, err := os.Lstat(dst); err == nil {
		return fmt.Errorf("%s appeared during the migration; not overwriting it", dst)
	}
	if err := os.Rename(tmp, dst); err != nil {
		return err
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		return err
	}
	if len(got) != len(data) || sha256.Sum256(got) != sha256.Sum256(data) {
		os.Remove(dst)
		return fmt.Errorf("%s does not match what was written", dst)
	}
	return nil
}
