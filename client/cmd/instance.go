//go:build !ios && !android

package cmd

import (
	"context"
	"fmt"
	"io"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/netbirdio/netbird/client/internal/instance"
	"github.com/netbirdio/netbird/client/proto"
)

const instanceQueryTimeout = 2 * time.Second

var instanceCmd = &cobra.Command{
	Use:   "instance",
	Short: "Show the NetBird installations on this machine",
}

var instanceListCmd = &cobra.Command{
	Use:   "list",
	Short: "List the default installation and every named installation",
	Long: "Lists the default installation, when its service exists, and every named installation " +
		"with its label, colour, role, service state, version and program folder. Management URL " +
		"and overlay IP are shown for installations whose daemon answers.",
	RunE: func(cmd *cobra.Command, _ []string) error {
		rows, err := installationRows(cmd.Context())
		if err != nil {
			return err
		}
		return writeInstallationRows(cmd.OutOrStdout(), rows)
	},
}

func init() {
	instanceCmd.AddCommand(instanceListCmd)
	rootCmd.AddCommand(instanceCmd)
}

// installationRow is one line of `netbird instance list`.
type installationRow struct {
	name, label, colour, role, service, version, folder, management, ip string
}

func installationRows(ctx context.Context) ([]installationRow, error) {
	var rows []installationRow

	def := instance.Default()
	if state, ok := serviceState(def.ServiceName()); ok {
		row := installationRow{name: "default", role: string(def.Role()), service: state}
		fillFromDaemon(ctx, &row, def.DaemonAddr())
		rows = append(rows, row)
	}

	recs, err := instance.ListRecords()
	if err != nil {
		return nil, err
	}
	for _, rec := range recs {
		inst, err := instance.For(string(rec.Name))
		if err != nil {
			continue
		}
		inst, _ = rec.Apply(inst)
		state, ok := serviceState(inst.ServiceName())
		if !ok {
			state = "not installed"
		}
		row := installationRow{
			name:    string(inst.Name()),
			label:   inst.Label(),
			colour:  rec.Color,
			role:    string(inst.Role()),
			service: state,
			version: rec.Version,
			folder:  rec.InstallDir,
		}
		fillFromDaemon(ctx, &row, inst.DaemonAddr())
		rows = append(rows, row)
	}
	return rows, nil
}

// fillFromDaemon adds what only the running daemon knows. A daemon that does not
// answer in time leaves the fields empty.
func fillFromDaemon(ctx context.Context, row *installationRow, addr string) {
	ctx, cancel := context.WithTimeout(ctx, instanceQueryTimeout)
	defer cancel()

	conn, err := DialClientGRPCServer(ctx, addr)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()

	resp, err := proto.NewDaemonServiceClient(conn).Status(ctx, &proto.StatusRequest{GetFullPeerStatus: true})
	if err != nil {
		return
	}
	row.management = resp.GetFullStatus().GetManagementState().GetURL()
	row.ip = resp.GetFullStatus().GetLocalPeerState().GetIP()
	if row.version == "" {
		row.version = resp.GetDaemonVersion()
	}
}

func writeInstallationRows(out io.Writer, rows []installationRow) error {
	if len(rows) == 0 {
		_, err := fmt.Fprintln(out, "No NetBird installation found.")
		return err
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	if _, err := fmt.Fprintln(w, "NAME\tLABEL\tCOLOUR\tROLE\tSERVICE\tVERSION\tFOLDER\tMANAGEMENT\tIP"); err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
			r.name, dash(r.label), dash(r.colour), r.role, r.service, dash(r.version), dash(r.folder),
			dash(r.management), dash(r.ip)); err != nil {
			return err
		}
	}
	return w.Flush()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
