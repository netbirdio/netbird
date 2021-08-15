package cmd

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/kardianos/service"
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
	if _, err := os.Stat(configFilePath); err == nil {
		e := os.Remove(configFilePath)
		if e != nil {
			t.Fatal(err)
		}
	}
	rootCmd.SetArgs([]string{
		"--config",
		configFilePath,
	})
	err := rootCmd.Execute()
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

/*func Test_ServiceStopCMD(t *testing.T) {
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
}*/

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
