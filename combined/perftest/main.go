package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/netbirdio/netbird/client/embed"
)

const (
	echoPort       = 9000
	connectTimeout = 120 * time.Second
	startTimeout   = 60 * time.Second
	stopTimeout    = 30 * time.Second
)

type peerInfo struct {
	client   *embed.Client
	tunnelIP string
	name     string
}

type pairStats struct {
	from     string
	to       string
	sent     int64
	received int64
	lost     int64
	rtts     []time.Duration
}

func (s *pairStats) summary() (avgRTT, minRTT, maxRTT time.Duration, lossPercent float64) {
	if len(s.rtts) == 0 {
		return 0, 0, 0, 100
	}
	minRTT = s.rtts[0]
	maxRTT = s.rtts[0]
	var total time.Duration
	for _, rtt := range s.rtts {
		total += rtt
		if rtt < minRTT {
			minRTT = rtt
		}
		if rtt > maxRTT {
			maxRTT = rtt
		}
	}
	avgRTT = total / time.Duration(len(s.rtts))
	if s.sent > 0 {
		lossPercent = float64(s.lost) / float64(s.sent) * 100
	}
	return
}

func main() {
	managementURL := flag.String("management-url", "", "Management server URL (required)")
	setupKey := flag.String("setup-key", "", "Reusable setup key (required)")
	numPeers := flag.Int("peers", 5, "Number of peers to spawn")
	forceRelay := flag.Bool("force-relay", false, "Force relay connections (NB_FORCE_RELAY=true)")
	duration := flag.Duration("duration", 30*time.Second, "Traffic test duration")
	packetSize := flag.Int("packet-size", 512, "UDP packet size in bytes")
	logLevel := flag.String("log-level", "panic", "Client log level (trace, debug, info, warn, error, panic)")
	flag.Parse()

	if *managementURL == "" || *setupKey == "" {
		fmt.Fprintln(os.Stderr, "Error: --management-url and --setup-key are required")
		flag.Usage()
		os.Exit(1)
	}

	if *numPeers < 2 {
		fmt.Fprintln(os.Stderr, "Error: --peers must be at least 2")
		os.Exit(1)
	}

	// Minimum packet size: 8 bytes for timestamp + 8 bytes for sequence number
	if *packetSize < 16 {
		fmt.Fprintln(os.Stderr, "Error: --packet-size must be at least 16")
		os.Exit(1)
	}

	if *forceRelay {
		os.Setenv("NB_FORCE_RELAY", "true")
	}
	os.Setenv("NB_USE_NETSTACK_MODE", "true")

	fmt.Println("=== NetBird Performance Test ===")
	fmt.Printf("Management URL: %s\n", *managementURL)
	fmt.Printf("Peers:          %d\n", *numPeers)
	fmt.Printf("Force relay:    %v\n", *forceRelay)
	fmt.Printf("Duration:       %s\n", *duration)
	fmt.Printf("Packet size:    %d bytes\n", *packetSize)
	fmt.Println()

	// Phase 1: Create peers
	fmt.Println("--- Phase 1: Creating peers ---")
	peers := make([]peerInfo, *numPeers)
	for i := 0; i < *numPeers; i++ {
		name := fmt.Sprintf("perf-peer-%d", i)
		port := 0
		c, err := embed.New(embed.Options{
			DeviceName:    name,
			SetupKey:      *setupKey,
			ManagementURL: *managementURL,
			WireguardPort: &port,
			LogLevel:      *logLevel,
			LogOutput:     io.Discard,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error creating peer %s: %v\n", name, err)
			os.Exit(1)
		}
		peers[i] = peerInfo{client: c, name: name}
		fmt.Printf("  Created %s\n", name)
	}

	// Phase 2: Start peers in parallel
	fmt.Println("\n--- Phase 2: Starting peers ---")
	startTime := time.Now()
	var wg sync.WaitGroup
	startErrors := make([]error, *numPeers)

	for i := range peers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), startTimeout)
			defer cancel()
			t := time.Now()
			if err := peers[idx].client.Start(ctx); err != nil {
				startErrors[idx] = err
				return
			}
			fmt.Printf("  %s started in %s\n", peers[idx].name, time.Since(t).Round(time.Millisecond))
		}(i)
	}
	wg.Wait()

	// Check for start errors
	var failed bool
	for i, err := range startErrors {
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error starting %s: %v\n", peers[i].name, err)
			failed = true
		}
	}
	if failed {
		cleanup(peers)
		os.Exit(1)
	}
	fmt.Printf("  All peers started in %s\n", time.Since(startTime).Round(time.Millisecond))

	// Get tunnel IPs
	for i := range peers {
		status, err := peers[i].client.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error getting status for %s: %v\n", peers[i].name, err)
			cleanup(peers)
			os.Exit(1)
		}
		ip := status.LocalPeerState.IP
		// Strip CIDR suffix if present (e.g. "100.64.0.1/16" -> "100.64.0.1")
		if idx := strings.Index(ip, "/"); idx != -1 {
			ip = ip[:idx]
		}
		peers[i].tunnelIP = ip
		fmt.Printf("  %s -> %s\n", peers[i].name, peers[i].tunnelIP)
	}

	// Phase 3: Wait for connections
	fmt.Println("\n--- Phase 3: Waiting for peer connections ---")
	connStart := time.Now()
	expectedPeers := *numPeers - 1
	deadline := time.After(connectTimeout)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	allConnected := false
waitLoop:
	for {
		select {
		case <-deadline:
			fmt.Fprintf(os.Stderr, "  Timeout waiting for connections after %s\n", connectTimeout)
			printConnectionStatus(peers)
			cleanup(peers)
			os.Exit(1)
		case <-ticker.C:
			allConnected = true
			for i := range peers {
				connected := countConnectedPeers(peers[i].client)
				if connected < expectedPeers {
					allConnected = false
					break
				}
			}
			if allConnected {
				break waitLoop
			}
		}
	}

	fmt.Printf("  All peers connected in %s\n", time.Since(connStart).Round(time.Millisecond))
	printConnectionStatus(peers)

	// Phase 4: Traffic test
	fmt.Printf("\n--- Phase 4: Traffic test (%s) ---\n", *duration)

	// Start echo listeners on all peers
	listeners := make([]net.PacketConn, *numPeers)
	for i := range peers {
		conn, err := peers[i].client.ListenUDP(fmt.Sprintf(":%d", echoPort))
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error creating listener on %s: %v\n", peers[i].name, err)
			cleanup(peers)
			os.Exit(1)
		}
		listeners[i] = conn
		go echoServer(conn, *packetSize)
		fmt.Printf("  Echo listener started on %s:%d\n", peers[i].tunnelIP, echoPort)
	}

	// Run traffic between all pairs (i < j)
	var statsMu sync.Mutex
	var allStats []pairStats

	var trafficWg sync.WaitGroup
	for i := 0; i < *numPeers; i++ {
		for j := i + 1; j < *numPeers; j++ {
			trafficWg.Add(1)
			go func(from, to int) {
				defer trafficWg.Done()
				stats := runTraffic(peers[from].client, peers[from].name, peers[to].tunnelIP, peers[to].name, *duration, *packetSize)
				statsMu.Lock()
				allStats = append(allStats, stats)
				statsMu.Unlock()
			}(i, j)
		}
	}
	trafficWg.Wait()

	// Close listeners
	for _, l := range listeners {
		if l != nil {
			l.Close()
		}
	}

	// Phase 5: Report
	fmt.Println("\n--- Phase 5: Results ---")
	printReport(allStats)

	// Cleanup
	fmt.Println("\n--- Cleanup ---")
	cleanup(peers)
	fmt.Println("Done.")
}

func countConnectedPeers(c *embed.Client) int {
	status, err := c.Status()
	if err != nil {
		return 0
	}
	count := 0
	for _, p := range status.Peers {
		if p.ConnStatus == embed.PeerStatusConnected {
			count++
		}
	}
	return count
}

func printConnectionStatus(peers []peerInfo) {
	for i := range peers {
		status, err := peers[i].client.Status()
		if err != nil {
			fmt.Printf("  %s: error getting status: %v\n", peers[i].name, err)
			continue
		}
		connected := 0
		relayed := 0
		for _, p := range status.Peers {
			if p.ConnStatus == embed.PeerStatusConnected {
				connected++
				if p.Relayed {
					relayed++
				}
			}
		}
		connType := "direct"
		if relayed > 0 {
			connType = fmt.Sprintf("%d direct, %d relayed", connected-relayed, relayed)
		}
		fmt.Printf("  %s: %d/%d connected (%s)\n", peers[i].name, connected, len(status.Peers), connType)
	}
}

func echoServer(conn net.PacketConn, maxSize int) {
	buf := make([]byte, maxSize+100)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteTo(buf[:n], addr)
	}
}

func runTraffic(client *embed.Client, fromName, toIP, toName string, duration time.Duration, packetSize int) pairStats {
	stats := pairStats{
		from: fromName,
		to:   toName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration+10*time.Second)
	defer cancel()

	conn, err := client.Dial(ctx, "udp", fmt.Sprintf("%s:%d", toIP, echoPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "  Error dialing %s -> %s: %v\n", fromName, toName, err)
		return stats
	}
	defer conn.Close()

	deadline := time.Now().Add(duration)
	buf := make([]byte, packetSize)
	recvBuf := make([]byte, packetSize+100)
	var seq uint64

	for time.Now().Before(deadline) {
		seq++
		// Encode timestamp and sequence number
		binary.BigEndian.PutUint64(buf[0:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(buf[8:16], seq)

		stats.sent++
		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := conn.Write(buf)
		if err != nil {
			fmt.Fprintf(os.Stderr, "  Error sending packet to %s: %v\n", toName, err)
			stats.lost++
			continue
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		n, err := conn.Read(recvBuf)
		if err != nil {
			stats.lost++
			continue
		}

		if n >= 8 {
			sentNano := binary.BigEndian.Uint64(recvBuf[0:8])
			rtt := time.Since(time.Unix(0, int64(sentNano)))
			stats.received++
			stats.rtts = append(stats.rtts, rtt)
		} else {
			stats.received++
		}

		// Small sleep to avoid flooding
		time.Sleep(10 * time.Millisecond)
	}

	return stats
}

func printReport(allStats []pairStats) {
	if len(allStats) == 0 {
		fmt.Println("  No traffic data collected.")
		return
	}

	fmt.Printf("  %-30s %8s %8s %8s %8s %10s %10s %10s\n",
		"Pair", "Sent", "Recv", "Lost", "Loss%", "Avg RTT", "Min RTT", "Max RTT")
	fmt.Println("  " + strings.Repeat("-", 108))

	var totalSent, totalRecv, totalLost int64
	var totalRTTs []time.Duration

	for _, s := range allStats {
		avg, min, max, loss := s.summary()
		pair := fmt.Sprintf("%s -> %s", s.from, s.to)
		fmt.Printf("  %-30s %8d %8d %8d %7.1f%% %10s %10s %10s\n",
			pair, s.sent, s.received, s.lost, loss,
			avg.Round(time.Microsecond), min.Round(time.Microsecond), max.Round(time.Microsecond))
		totalSent += s.sent
		totalRecv += s.received
		totalLost += s.lost
		totalRTTs = append(totalRTTs, s.rtts...)
	}

	fmt.Println("  " + strings.Repeat("-", 108))

	// Overall summary
	var overallLoss float64
	if totalSent > 0 {
		overallLoss = float64(totalLost) / float64(totalSent) * 100
	}

	var avgRTT, minRTT, maxRTT time.Duration
	if len(totalRTTs) > 0 {
		minRTT = totalRTTs[0]
		maxRTT = totalRTTs[0]
		var total time.Duration
		for _, rtt := range totalRTTs {
			total += rtt
			if rtt < minRTT {
				minRTT = rtt
			}
			if rtt > maxRTT {
				maxRTT = rtt
			}
		}
		avgRTT = total / time.Duration(len(totalRTTs))
	}

	fmt.Printf("  %-30s %8d %8d %8d %7.1f%% %10s %10s %10s\n",
		"TOTAL", totalSent, totalRecv, totalLost, overallLoss,
		avgRTT.Round(time.Microsecond), minRTT.Round(time.Microsecond), maxRTT.Round(time.Microsecond))

	// Extra stats
	if len(totalRTTs) > 0 {
		fmt.Println()
		var sumSq float64
		avgNs := float64(avgRTT.Nanoseconds())
		for _, rtt := range totalRTTs {
			diff := float64(rtt.Nanoseconds()) - avgNs
			sumSq += diff * diff
		}
		stddev := time.Duration(math.Sqrt(sumSq / float64(len(totalRTTs))))

		fmt.Printf("  RTT stddev:  %s\n", stddev.Round(time.Microsecond))
		fmt.Printf("  Pairs tested: %d\n", len(allStats))
	}
}

func cleanup(peers []peerInfo) {
	ctx, cancel := context.WithTimeout(context.Background(), stopTimeout)
	defer cancel()

	var wg sync.WaitGroup
	for i := range peers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if err := peers[idx].client.Stop(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "  Error stopping %s: %v\n", peers[idx].name, err)
			} else {
				fmt.Printf("  Stopped %s\n", peers[idx].name)
			}
		}(i)
	}
	wg.Wait()
}
