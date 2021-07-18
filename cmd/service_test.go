package cmd

import (
	"bytes"
	"github.com/kardianos/service"
	"io/ioutil"
	"os"
	"testing"
)

func Test_ServiceInstallCMD(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{
		"service",
		"install",
		"--config",
		"/tmp/config.json",
	})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	expectedMSG := "Wiretrustee service has been installed"
	if string(out) != expectedMSG {
		t.Fatalf("expected \"%s\" got \"%s\"", expectedMSG, string(out))
	}
}

func Test_ServiceStartCMD(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{"service", "start"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	expectedMSG := "Wiretrustee service has been started"
	if string(out) != expectedMSG {
		t.Fatalf("expected \"%s\" got \"%s\"", expectedMSG, string(out))
	}
}

func Test_ServiceRunCMD(t *testing.T) {
	configFilePath := "/tmp/config.json"
	err := os.Remove(configFilePath)
	if err != nil {
		t.Fatal(err)
	}
	rootCmd.SetArgs([]string{
		"init",
		"--stunURLs",
		"stun:stun.wiretrustee.com:3468",
		"--signalAddr",
		"signal.wiretrustee.com:10000",
		"--turnURLs",
		"foo:bar@turn:stun.wiretrustee.com:3468",
		"--wgInterface",
		"utun99",
		"--wgLocalAddr",
		"10.100.100.1/24",
		"--config",
		configFilePath,
	})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}

	rootCmd.ResetFlags()
	rootCmd.SetArgs([]string{"service", "start"})
	err = rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
	s, err := newSVC(&program{}, newSVCConfig())
	if err != nil {
		t.Fatal(err)
	}
	status, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}

	if status != service.StatusRunning {
		t.Fatalf("expected running status of \"%d\" got \"%d\"", service.StatusRunning, status)
	}
}

func Test_ServiceStopCMD(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{"service", "stop"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}

	expectedMSG := "Wiretrustee service has been stopped"
	if string(out) != expectedMSG {
		t.Fatalf("expected \"%s\" got \"%s\"", expectedMSG, string(out))
	}
}

func Test_ServiceUninstallCMD(t *testing.T) {
	b := bytes.NewBufferString("")
	rootCmd.SetOut(b)
	rootCmd.SetErr(b)
	rootCmd.SetArgs([]string{"service", "uninstall"})
	err := rootCmd.Execute()
	if err != nil {
		t.Fatal(err)
	}
	out, err := ioutil.ReadAll(b)
	if err != nil {
		t.Fatal(err)
	}
	expectedMSG := "Wiretrustee has been uninstalled"
	if string(out) != expectedMSG {
		t.Fatalf("expected \"%s\" got \"%s\"", expectedMSG, string(out))
	}
}
