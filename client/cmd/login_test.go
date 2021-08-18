package cmd

import (
	"fmt"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/iface"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/util"
	"path/filepath"
	"testing"
)

var mgmAddr string

func TestLogin_Start(t *testing.T) {
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
	_, listener := startManagement(config, t)
	mgmAddr = listener.Addr().String()
}

func TestLogin(t *testing.T) {

	tempDir := t.TempDir()
	confPath := tempDir + "/config.json"
	mgmtURL := fmt.Sprintf("http://%s", mgmAddr)
	rootCmd.SetArgs([]string{
		"login",
		"--config",
		confPath,
		"--setup-key",
		"a2c8e62b-38f5-4553-b31e-dd66c696cebb",
		"--management-url",
		mgmtURL,
	})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}

	// validate generated config
	actualConf := &internal.Config{}
	_, err = util.ReadJson(confPath, actualConf)
	if err != nil {
		t.Errorf("expected proper config file written, got broken %v", err)
	}

	if actualConf.ManagementURL.String() != mgmtURL {
		t.Errorf("expected management URL %s got %s", mgmtURL, actualConf.ManagementURL.String())
	}

	if actualConf.WgIface != iface.WgInterfaceDefault {
		t.Errorf("expected WgIface %s got %s", iface.WgInterfaceDefault, actualConf.WgIface)
	}

	if len(actualConf.PrivateKey) == 0 {
		t.Errorf("expected non empty Private key, got empty")
	}
}
