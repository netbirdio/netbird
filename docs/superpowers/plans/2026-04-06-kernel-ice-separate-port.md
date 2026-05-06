# Kernel WireGuard ICE Separate Port Fix

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix P2P ICE connectivity in kernel WireGuard mode by using a separate UDP port for ICE instead of sharing port 51820 with the kernel WireGuard module via raw sockets.

**Architecture:** Replace the `sharedsock` raw socket approach in `device_kernel_unix.go` with a standard UDP socket on a separate port (system-assigned). The UDPMux will use this dedicated socket for all ICE STUN traffic, while WireGuard keeps exclusive ownership of port 51820. This mirrors how the userspace mode works but without coupling ICE to the WireGuard bind.

**Tech Stack:** Go, Pion ICE, WireGuard kernel module, Linux UDP sockets

---

### Task 1: Replace sharedsock with standard UDP socket in TunKernelDevice.Up()

**Files:**
- Modify: `client/iface/device/device_kernel_unix.go:82-118`

- [ ] **Step 1: Replace raw socket with standard UDP socket**

Replace the `sharedsock.Listen()` call with a standard `net.ListenUDP()` on port 0 (system-assigned). Update the UDPMux creation to use this socket.

In `device_kernel_unix.go`, replace the `Up()` method:

```go
func (t *TunKernelDevice) Up() (*udpmux.UniversalUDPMuxDefault, error) {
	if t.udpMux != nil {
		return t.udpMux, nil
	}

	if t.link == nil {
		return nil, fmt.Errorf("device is not ready yet")
	}

	log.Debugf("bringing up interface: %s", t.name)

	if err := t.link.up(); err != nil {
		log.Errorf("error bringing up interface: %s", t.name)
		return nil, err
	}

	// Use a dedicated UDP socket for ICE instead of sharing the WireGuard port
	// via raw sockets. The kernel WireGuard module owns port 51820 exclusively;
	// attempting to share it via sharedsock causes ICE packets to never be sent.
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: 0})
	if err != nil {
		return nil, fmt.Errorf("listen udp for ICE: %w", err)
	}
	log.Infof("ICE using dedicated UDP port: %d (WireGuard kernel owns port %d)", udpConn.LocalAddr().(*net.UDPAddr).Port, t.wgPort)

	bindParams := udpmux.UniversalUDPMuxParams{
		UDPConn:   nbnet.WrapPacketConn(udpConn),
		Net:       t.transportNet,
		FilterFn:  t.filterFn,
		WGAddress: t.address,
		MTU:       t.mtu,
	}
	mux := udpmux.NewUniversalUDPMuxDefault(bindParams)
	go mux.ReadFromConn(t.ctx)
	t.udpMuxConn = udpConn
	t.udpMux = mux

	log.Debugf("device is ready to use: %s", t.name)
	return t.udpMux, nil
}
```

- [ ] **Step 2: Remove unused sharedsock import**

Remove `"github.com/netbirdio/netbird/sharedsock"` from the imports in `device_kernel_unix.go` since it is no longer used.

- [ ] **Step 3: Build and verify compilation**

Run: `cd /home/ai-agent/projects/netbird && GOOS=linux GOARCH=arm64 go build ./client/`
Expected: Successful build, no errors.

- [ ] **Step 4: Cross-compile for arm64 (OpenWrt router)**

```bash
cd /home/ai-agent/projects/netbird
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o /tmp/netbird-kernel-fix-arm64 ./client/
```

- [ ] **Step 5: Deploy to test router and verify**

```bash
# Stop NetBird, install kmod-wireguard, deploy new binary
ssh root@<router-ip> 'killall -9 netbird; sleep 2'
cat /tmp/netbird-kernel-fix-arm64 | ssh root@<router-ip> 'cat > /usr/bin/netbird && chmod +x /usr/bin/netbird'
ssh root@<router-ip> 'apk add kmod-wireguard && modprobe wireguard'
ssh root@<router-ip> '/etc/init.d/netbird restart'
```

Wait 20s, then verify:
- `netbird status` shows `Interface type: Kernel`
- Connection to same-LAN peer shows `Connection type: P2P`
- ICE candidate endpoints show LAN IPs (e.g. `192.168.91.x:NNNNN`)

- [ ] **Step 6: Commit**

```bash
git add client/iface/device/device_kernel_unix.go
git commit -m "fix(client): use separate UDP port for ICE in kernel WireGuard mode

In kernel WireGuard mode, the WireGuard module exclusively owns UDP port
51820. The previous approach used a raw socket (sharedsock) to intercept
STUN packets on the same port, but this failed to send ICE connectivity
checks on some platforms (confirmed on OpenWrt/ARM64).

Replace the shared raw socket with a dedicated UDP socket on a
system-assigned port. ICE STUN traffic now flows through this separate
port while WireGuard retains exclusive use of port 51820.

This fixes P2P connections failing in kernel WireGuard mode, where all
peers would fall back to relay despite being on the same LAN."
```
