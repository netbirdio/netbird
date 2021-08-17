package cmd

import (
	"bytes"
	"fmt"
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
	_, err := util.ReadJson("../../management/server/testdata/management.json", config)
	if err != nil {
		t.Fatal(err)
	}
	testDir := t.TempDir()
	config.Datadir = testDir
	err = util.CopyFileContents("../../management/server/testdata/store.json", filepath.Join(testDir, "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	_, listener := startManagement(config, t)
	serverAddr = listener.Addr().String()
}

func TestLogin_NoExistingConfig(t *testing.T) {

	tempDir := t.TempDir()

	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{
		"login",
		"--config",
		tempDir + "/config.json",
		"--setup-key",
		"a2c8e62b-38f5-4553-b31e-dd66c696cebb",
		tempDir + "/config.json",
		"--management-url",
		fmt.Sprintf("http://%s", serverAddr),
	})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
	_, err = ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
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
