package cmd

import (
	"bytes"
	"fmt"
	"github.com/wiretrustee/wiretrustee/client/internal"
	"github.com/wiretrustee/wiretrustee/iface"
	mgmtProto "github.com/wiretrustee/wiretrustee/management/proto"
	mgmt "github.com/wiretrustee/wiretrustee/management/server"
	"github.com/wiretrustee/wiretrustee/util"
	"google.golang.org/grpc"
	"io/ioutil"
	"net"
	"path/filepath"
	"testing"
)

var serverAddr string

func Test_Start(t *testing.T) {
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
	serverAddr = listener.Addr().String()
}

func TestLogin_NoExistingConfig(t *testing.T) {

	tempDir := t.TempDir()
	confPath := tempDir + "/config.json"
	mgmtURL := fmt.Sprintf("http://%s", serverAddr)
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
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
	_, err = ioutil.ReadAll(b)
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

func startManagement(config *mgmt.Config, t *testing.T) (*grpc.Server, net.Listener) {
	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	store, err := mgmt.NewStore(config.Datadir)
	if err != nil {
		t.Fatal(err)
	}

	accountManager := mgmt.NewManager(store)
	mgmtServer, err := mgmt.NewServer(config, accountManager)
	if err != nil {
		t.Fatal(err)
	}
	mgmtProto.RegisterManagementServiceServer(s, mgmtServer)
	go func() {
		if err := s.Serve(lis); err != nil {
			t.Error(err)
			return
		}
	}()

	return s, lis
}
