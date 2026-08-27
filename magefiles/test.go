package main

import (
	"errors"
	"strings"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

var defaultcli = []string{"test", "-tags=integration", "-timeout=20m"}

type Integrationtest mg.Namespace

func (i Integrationtest) All(gotestflags *string) error {
	var errs []error
	if err := i.Api(gotestflags); err != nil {
		errs = append(errs, err)
	}
	if err := i.NmapDb(gotestflags); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (Integrationtest) NmapDb(gotestflags *string) error {
	cli := defaultcli
	if gotestflags != nil {
		cli = append(cli, strings.Split(*gotestflags, " ")...)
	}
	cli = append(cli, "./integration_tests/management/network_map_db/...")

	return sh.RunV("go", cli...)
}

func (Integrationtest) NmapDbPostgres(gotestflags *string) error {
	cli := defaultcli
	if gotestflags != nil {
		cli = append(cli, strings.Split(*gotestflags, " ")...)
	}
	cli = append(cli, "./integration_tests/management/network_map_db/...")

	return sh.RunWithV(map[string]string{"NETBIRD_STORE_ENGINE": "postgres"}, "go", cli...)
}

func (Integrationtest) NmapDbSqlite(gotestflags *string) error {
	cli := defaultcli
	if gotestflags != nil {
		cli = append(cli, strings.Split(*gotestflags, " ")...)
	}
	cli = append(cli, "./integration_tests/management/network_map_db/...")
	return sh.RunWithV(map[string]string{"NETBIRD_STORE_ENGINE": "sqlite"}, "go", cli...)
}

func (Integrationtest) RegenerateNmapGoldenData(gotestflags *string) error {
	cli := defaultcli
	if gotestflags != nil {
		cli = append(cli, strings.Split(*gotestflags, " ")...)
	}
	cli = append(cli, "./integration_tests/management/network_map_db/...")
	return sh.RunWithV(map[string]string{"NMAP_UPDATE_GOLDEN_DATA": "true", "NETBIRD_STORE_ENGINE": "sqlite"}, "go", cli...)
}

func (Integrationtest) Api(gotestflags *string) error {
	cli := defaultcli
	if gotestflags != nil {
		cli = append(cli, strings.Split(*gotestflags, " ")...)
	}
	cli = append(cli, "./management/server/http/...")
	return sh.RunV("go", cli...)
}
