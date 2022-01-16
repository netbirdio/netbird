package cmd

import (
	"github.com/wiretrustee/wiretrustee/iface"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/util"
	"net/url"
	"path/filepath"
	"testing"
	"time"
)

var signalAddr string

func TestUp_Start(t *testing.T) {
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

	_, mgmLis := startManagement(config, t)
	mgmAddr = mgmLis.Addr().String()

}

func TestUp(t *testing.T) {

	//defer iface.Close("wt0")

	tempDir := t.TempDir()
	confPath := tempDir + "/config.json"
	mgmtURL, err := url.Parse("http://" + mgmAddr)
	if err != nil {
		t.Fatal(err)
	}

	rootCmd.SetArgs([]string{
		"up",
		"--config",
		confPath,
		"--setup-key",
		"A2C8E62B-38F5-4553-B31E-DD66C696CEBB",
		"--management-url",
		mgmtURL.String(),
		"--log-level",
		"debug",
		"--log-file",
		"console",
	})
	go func() {
		err = rootCmd.Execute()
		if err != nil {
			t.Errorf("expected no error while running up command, got %v", err)
		}
	}()

	timeout := 15 * time.Second
	timeoutChannel := time.After(timeout)
	for {
		select {
		case <-timeoutChannel:
			t.Fatalf("expected wireguard interface %s to be created before %s", iface.WgInterfaceDefault, timeout.String())
		default:
		}
		e, err := iface.Exists(iface.WgInterfaceDefault)
		if err != nil {
			continue
		}
		if err != nil {
			continue
		}
		if *e {
			break
		}
	}
}
