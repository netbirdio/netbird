//go:build !android

package dns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/netbirdio/netbird/util"
)

func TestMain(m *testing.M) {
	_ = util.InitLog("debug", "console")
	code := m.Run()
	os.Exit(code)
}

func Test_newRepairtmp(t *testing.T) {
	type args struct {
		resolvConfContent  string
		touchedConfContent string
		wantChange         bool
	}
	tests := []args{
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 8.8.8.8
searchdomain netbird.cloud something`,
			wantChange: true,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something somethingelse`,
			wantChange: false,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 10.0.0.1
searchdomain netbird.cloud something`,
			wantChange: false,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
searchdomain something`,
			wantChange: true,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 10.0.0.1`,
			wantChange: true,
		},
		{
			resolvConfContent: `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`,

			touchedConfContent: `
nameserver 8.8.8.8`,
			wantChange: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run("test", func(t *testing.T) {
			t.Parallel()
			workDir := t.TempDir()
			operationFile := workDir + "/resolv.conf"
			err := os.WriteFile(operationFile, []byte(tt.resolvConfContent), 0755)
			if err != nil {
				t.Fatalf("failed to write out resolv.conf: %s", err)
			}

			var changed bool
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			updateFn := func([]string, string, *resolvConf) error {
				changed = true
				cancel()
				return nil
			}

			r := newRepair(operationFile, updateFn)
			r.watchFileChanges([]string{"netbird.cloud"}, "10.0.0.1")

			err = os.WriteFile(operationFile, []byte(tt.touchedConfContent), 0755)
			if err != nil {
				t.Fatalf("failed to write out resolv.conf: %s", err)
			}

			<-ctx.Done()

			r.stopWatchFileChanges()

			if changed != tt.wantChange {
				t.Errorf("unexpected result: want: %v, got: %v", tt.wantChange, changed)
			}
		})
	}
}

func Test_newRepairSymlink(t *testing.T) {
	resolvConfContent := `
nameserver 10.0.0.1
nameserver 8.8.8.8
searchdomain netbird.cloud something`

	modifyContent := `nameserver 8.8.8.8`

	tmpResolvConf := filepath.Join(t.TempDir(), "resolv.conf")
	err := os.WriteFile(tmpResolvConf, []byte(resolvConfContent), 0644)
	if err != nil {
		t.Fatal(err)
	}

	tmpLink := filepath.Join(t.TempDir(), "symlink")
	err = os.Symlink(tmpResolvConf, tmpLink)
	if err != nil {
		t.Fatal(err)
	}

	var changed bool
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	updateFn := func([]string, string, *resolvConf) error {
		changed = true
		cancel()
		return nil
	}

	r := newRepair(tmpLink, updateFn)
	r.watchFileChanges([]string{"netbird.cloud"}, "10.0.0.1")

	err = os.WriteFile(tmpLink, []byte(modifyContent), 0755)
	if err != nil {
		t.Fatalf("failed to write out resolv.conf: %s", err)
	}

	<-ctx.Done()

	r.stopWatchFileChanges()

	if changed != true {
		t.Errorf("unexpected result: want: %v, got: %v", true, false)
	}
}
