package cmd

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/wiretrustee/wiretrustee/client/internal"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/util"
)

func TestUpDaemon_Start(t *testing.T) {
	config := &mgmt.Config{}
	_, err := util.ReadJson("../testdata/management.json", config)
	if err != nil {
		t.Fatal(err)
	}
	testDir := t.TempDir()
	config.Datadir = testDir
	err = util.CopyFileContents("../testdata/store.json", filepath.Join(testDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}

	_, signalLis := startSignal(t)
	signalAddr = signalLis.Addr().String()
	config.Signal.URI = signalAddr

	_, mgmLis := startManagement(t, config)
	mgmAddr = mgmLis.Addr().String()
}

func TestUpDaemon(t *testing.T) {
	tempDir := t.TempDir()
	confPath := tempDir + "/config.json"

	stopCh = make(chan int, 1)
	cleanupCh = make(chan struct{}, 1)

	ctx := internal.CtxInitState(context.Background())
	state := internal.CtxGetState(ctx)

	_, cliLis := startClientDaemon(t, ctx, "http://"+mgmAddr, confPath, stopCh, cleanupCh)

	cliAddr = cliLis.Addr().String()

	daemonAddr = "tcp://" + cliAddr
	rootCmd.SetArgs([]string{
		"login",
		"--daemon-addr", "tcp://" + cliAddr,
		"--setup-key", "A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
		"--log-file", "",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)
	if status, err := state.Status(); err != nil && status != internal.StatusIdle {
		t.Errorf("wrong status after login: %s, %v", internal.StatusIdle, err)
		return
	}

	rootCmd.SetArgs([]string{
		"up",
		"--daemon-addr", "tcp://" + cliAddr,
		"--log-file", "",
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)
	if status, err := state.Status(); err != nil && status != internal.StatusConnected {
		t.Errorf("wrong status after connect: %s, %v", status, err)
		return
	}

	rootCmd.SetArgs([]string{
		"status",
		"--daemon-addr", "tcp://" + cliAddr,
	})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	time.Sleep(time.Second * 3)

	rootCmd.SetErr(nil)
	rootCmd.SetArgs([]string{"down", "--daemon-addr", "tcp://" + cliAddr})
	if err := rootCmd.Execute(); err != nil {
		t.Errorf("expected no error while running up command, got %v", err)
		return
	}
	// we can't check status here, because context already canceled
}
