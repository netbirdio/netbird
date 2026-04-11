package internal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/netbirdio/netbird/client/firewall/uspfilter/forwarder"
	"github.com/netbirdio/netbird/client/inspect"
	"github.com/netbirdio/netbird/client/internal/acl/id"
	"github.com/netbirdio/netbird/shared/management/domain"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// updateTransparentProxy processes transparent proxy configuration from the network map.
func (e *Engine) updateTransparentProxy(cfg *mgmProto.TransparentProxyConfig) {
	if cfg == nil || !cfg.Enabled {
		if cfg == nil {
			log.Tracef("inspect: config is nil")
		} else {
			log.Tracef("inspect: config disabled")
		}
		// Only stop if explicitly disabled. Don't stop on nil config to avoid
		// a gap during policy edits where management briefly pushes empty config.
		if cfg != nil && !cfg.Enabled {
			e.stopTransparentProxy()
		}
		return
	}

	log.Debugf("inspect: config received: enabled=%v mode=%v default_action=%v rules=%d has_ca=%v",
		cfg.Enabled, cfg.Mode, cfg.DefaultAction, len(cfg.Rules), len(cfg.CaCertPem) > 0)

	// BlockInbound prevents adding TPROXY rules since kernel TPROXY bypasses ACLs.
	// The userspace forwarder path still works as it operates within the forwarder hook.
	if e.config.BlockInbound {
		log.Warnf("inspect: BlockInbound is set, skipping redirect rules (userspace path still active)")
	}

	proxyConfig, err := toProxyConfig(cfg)
	if err != nil {
		log.Errorf("inspect: parse config: %v", err)
		e.stopTransparentProxy()
		return
	}

	// CA priority: local config > management-pushed > auto-generated self-signed.
	// Local wins over mgmt to prevent compromised management from injecting a CA.
	e.resolveInspectionCA(&proxyConfig)

	if e.transparentProxy != nil {
		// Mode change requires full recreate (envoy lifecycle, listener changes).
		if proxyConfig.Mode != e.transparentProxy.Mode() {
			log.Infof("inspect: mode changed to %s, recreating engine", proxyConfig.Mode)
			e.stopTransparentProxy()
		} else {
			e.transparentProxy.UpdateConfig(proxyConfig)
			e.syncTProxyRules(proxyConfig)
			e.syncUDPInspectionHook()
			return
		}
	}

	if e.wgInterface != nil {
		proxyConfig.WGNetwork = e.wgInterface.Address().Network
		proxyConfig.ListenAddr = netip.AddrPortFrom(
			e.wgInterface.Address().IP.Unmap(),
			proxyConfig.ListenAddr.Port(),
		)
	}

	// Pass local IP checker for SSRF prevention
	if checker, ok := e.firewall.(inspect.LocalIPChecker); ok {
		proxyConfig.LocalIPChecker = checker
	}

	p, err := inspect.New(e.ctx, log.WithField("component", "inspect"), proxyConfig)
	if err != nil {
		log.Errorf("inspect: start engine: %v", err)
		return
	}
	e.transparentProxy = p

	e.attachProxyToForwarder(p)
	e.syncTProxyRules(proxyConfig)
	e.syncUDPInspectionHook()

	log.Infof("inspect: engine started (mode=%s, rules=%d)", proxyConfig.Mode, len(proxyConfig.Rules))
}

// stopTransparentProxy shuts down the transparent proxy and removes interception.
func (e *Engine) stopTransparentProxy() {
	if e.transparentProxy == nil {
		return
	}

	e.attachProxyToForwarder(nil)
	e.removeTProxyRule()
	e.removeUDPInspectionHook()

	if err := e.transparentProxy.Close(); err != nil {
		log.Debugf("inspect: close engine: %v", err)
	}
	e.transparentProxy = nil

	log.Info("inspect: engine stopped")
}

const tproxyRuleID = "tproxy-redirect"

// syncTProxyRules adds a TPROXY rule via the firewall manager to intercept
// matching traffic on the WG interface and redirect it to the proxy socket.
func (e *Engine) syncTProxyRules(config inspect.Config) {
	if e.config.BlockInbound {
		e.removeTProxyRule()
		return
	}

	var listenPort uint16
	if e.transparentProxy != nil {
		listenPort = e.transparentProxy.ListenPort()
	}
	if listenPort == 0 {
		e.removeTProxyRule()
		return
	}

	if e.firewall == nil {
		return
	}

	dstPorts := make([]uint16, len(config.RedirectPorts))
	copy(dstPorts, config.RedirectPorts)

	log.Debugf("inspect: syncing redirect rules: listen port %d, redirect ports %v, sources %v",
		listenPort, dstPorts, config.RedirectSources)

	if err := e.firewall.AddTProxyRule(tproxyRuleID, config.RedirectSources, dstPorts, listenPort); err != nil {
		log.Errorf("inspect: add redirect rule: %v", err)
		return
	}
}

// removeTProxyRule removes the TPROXY redirect rule.
func (e *Engine) removeTProxyRule() {
	if e.firewall == nil {
		return
	}
	if err := e.firewall.RemoveTProxyRule(tproxyRuleID); err != nil {
		log.Debugf("inspect: remove redirect rule: %v", err)
	}
}

// syncUDPInspectionHook registers a UDP packet hook on port 443 for QUIC SNI blocking.
// The hook is called by the USP filter for each UDP packet matching the port,
// allowing the inspection engine to extract QUIC SNI and block by domain.
func (e *Engine) syncUDPInspectionHook() {
	e.removeUDPInspectionHook()

	if e.firewall == nil || e.transparentProxy == nil {
		return
	}

	p := e.transparentProxy
	hookID := e.firewall.AddUDPInspectionHook(443, func(packet []byte) bool {
		srcIP, dstIP, dstPort, udpPayload, ok := parseUDPPacket(packet)
		if !ok {
			return false
		}

		src := inspect.SourceInfo{IP: srcIP}
		dst := netip.AddrPortFrom(dstIP, dstPort)
		action := p.HandleUDPPacket(udpPayload, dst, src)
		return action == inspect.ActionBlock
	})

	e.udpInspectionHookID = hookID
	log.Debugf("inspect: registered UDP inspection hook on port 443 (id=%s)", hookID)
}

// removeUDPInspectionHook removes the QUIC inspection hook.
func (e *Engine) removeUDPInspectionHook() {
	if e.udpInspectionHookID == "" || e.firewall == nil {
		return
	}
	e.firewall.RemoveUDPInspectionHook(e.udpInspectionHookID)
	e.udpInspectionHookID = ""
}

// parseUDPPacket extracts source/destination IP, destination port, and UDP
// payload from a raw IP packet. Supports both IPv4 and IPv6.
func parseUDPPacket(packet []byte) (srcIP, dstIP netip.Addr, dstPort uint16, payload []byte, ok bool) {
	if len(packet) < 1 {
		return srcIP, dstIP, 0, nil, false
	}

	version := packet[0] >> 4

	var udpOffset int
	switch version {
	case 4:
		if len(packet) < 20 {
			return srcIP, dstIP, 0, nil, false
		}
		ihl := int(packet[0]&0x0f) * 4
		if len(packet) < ihl+8 {
			return srcIP, dstIP, 0, nil, false
		}
		var srcOK, dstOK bool
		srcIP, srcOK = netip.AddrFromSlice(packet[12:16])
		dstIP, dstOK = netip.AddrFromSlice(packet[16:20])
		if !srcOK || !dstOK {
			return srcIP, dstIP, 0, nil, false
		}
		udpOffset = ihl

	case 6:
		// IPv6 fixed header is 40 bytes. Next header must be UDP (17).
		if len(packet) < 48 { // 40 header + 8 UDP
			return srcIP, dstIP, 0, nil, false
		}
		nextHeader := packet[6]
		if nextHeader != 17 { // not UDP (may have extension headers)
			return srcIP, dstIP, 0, nil, false
		}
		var srcOK, dstOK bool
		srcIP, srcOK = netip.AddrFromSlice(packet[8:24])
		dstIP, dstOK = netip.AddrFromSlice(packet[24:40])
		if !srcOK || !dstOK {
			return srcIP, dstIP, 0, nil, false
		}
		udpOffset = 40

	default:
		return srcIP, dstIP, 0, nil, false
	}

	srcIP = srcIP.Unmap()
	dstIP = dstIP.Unmap()
	dstPort = uint16(packet[udpOffset+2])<<8 | uint16(packet[udpOffset+3])
	payload = packet[udpOffset+8:]

	return srcIP, dstIP, dstPort, payload, true
}

// attachProxyToForwarder sets or clears the proxy on the userspace forwarder.
func (e *Engine) attachProxyToForwarder(p *inspect.Proxy) {
	type forwarderGetter interface {
		GetForwarder() *forwarder.Forwarder
	}

	if fg, ok := e.firewall.(forwarderGetter); ok {
		if fwd := fg.GetForwarder(); fwd != nil {
			fwd.SetProxy(p)
		}
	}
}

// toProxyConfig converts a proto TransparentProxyConfig to the inspect.Config type.
func toProxyConfig(cfg *mgmProto.TransparentProxyConfig) (inspect.Config, error) {
	config := inspect.Config{
		Enabled:       cfg.Enabled,
		DefaultAction: toProxyAction(cfg.DefaultAction),
	}

	switch cfg.Mode {
	case mgmProto.TransparentProxyMode_TP_MODE_ENVOY:
		config.Mode = inspect.ModeEnvoy
	case mgmProto.TransparentProxyMode_TP_MODE_EXTERNAL:
		config.Mode = inspect.ModeExternal
	default:
		config.Mode = inspect.ModeBuiltin
	}

	if cfg.ExternalProxyUrl != "" {
		u, err := url.Parse(cfg.ExternalProxyUrl)
		if err != nil {
			return inspect.Config{}, fmt.Errorf("parse external proxy URL: %w", err)
		}
		config.ExternalURL = u
	}

	for _, s := range cfg.RedirectSources {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return inspect.Config{}, fmt.Errorf("parse redirect source %q: %w", s, err)
		}
		config.RedirectSources = append(config.RedirectSources, prefix)
	}

	for _, p := range cfg.RedirectPorts {
		config.RedirectPorts = append(config.RedirectPorts, uint16(p))
	}

	// TPROXY listen port: fixed default, overridable via env var.
	if config.Mode == inspect.ModeBuiltin {
		port := uint16(inspect.DefaultTProxyPort)
		if v := os.Getenv("NB_TPROXY_PORT"); v != "" {
			if p, err := strconv.ParseUint(v, 10, 16); err == nil {
				port = uint16(p)
			} else {
				log.Warnf("invalid NB_TPROXY_PORT %q, using default %d", v, inspect.DefaultTProxyPort)
			}
		}
		config.ListenAddr = netip.AddrPortFrom(netip.IPv4Unspecified(), port)
	}

	for _, r := range cfg.Rules {
		rule, err := toProxyRule(r)
		if err != nil {
			return inspect.Config{}, fmt.Errorf("parse rule %q: %w", r.Id, err)
		}
		config.Rules = append(config.Rules, rule)
	}

	if cfg.Icap != nil {
		icapCfg, err := toICAPConfig(cfg.Icap)
		if err != nil {
			return inspect.Config{}, fmt.Errorf("parse ICAP config: %w", err)
		}
		config.ICAP = icapCfg
	}

	if len(cfg.CaCertPem) > 0 && len(cfg.CaKeyPem) > 0 {
		tlsCfg, err := parseTLSConfig(cfg.CaCertPem, cfg.CaKeyPem)
		if err != nil {
			return inspect.Config{}, fmt.Errorf("parse TLS config: %w", err)
		}
		config.TLS = tlsCfg
	}

	if config.Mode == inspect.ModeEnvoy {
		envCfg := &inspect.EnvoyConfig{
			BinaryPath: cfg.EnvoyBinaryPath,
			AdminPort:  uint16(cfg.EnvoyAdminPort),
		}
		if cfg.EnvoySnippets != nil {
			envCfg.Snippets = &inspect.EnvoySnippets{
				HTTPFilters:    cfg.EnvoySnippets.HttpFilters,
				NetworkFilters: cfg.EnvoySnippets.NetworkFilters,
				Clusters:       cfg.EnvoySnippets.Clusters,
			}
		}
		config.Envoy = envCfg
	}

	return config, nil
}

func toProxyRule(r *mgmProto.TransparentProxyRule) (inspect.Rule, error) {
	rule := inspect.Rule{
		ID:       id.RuleID(r.Id),
		Action:   toProxyAction(r.Action),
		Priority: int(r.Priority),
	}

	for _, d := range r.Domains {
		dom, err := domain.FromString(d)
		if err != nil {
			return inspect.Rule{}, fmt.Errorf("parse domain %q: %w", d, err)
		}
		rule.Domains = append(rule.Domains, dom)
	}

	for _, n := range r.Networks {
		prefix, err := netip.ParsePrefix(n)
		if err != nil {
			return inspect.Rule{}, fmt.Errorf("parse network %q: %w", n, err)
		}
		rule.Networks = append(rule.Networks, prefix)
	}

	for _, p := range r.Ports {
		rule.Ports = append(rule.Ports, uint16(p))
	}

	for _, proto := range r.Protocols {
		rule.Protocols = append(rule.Protocols, toProxyProtoType(proto))
	}

	rule.Paths = r.Paths

	return rule, nil
}

func toProxyProtoType(p mgmProto.TransparentProxyProtocol) inspect.ProtoType {
	switch p {
	case mgmProto.TransparentProxyProtocol_TP_PROTO_HTTP:
		return inspect.ProtoHTTP
	case mgmProto.TransparentProxyProtocol_TP_PROTO_HTTPS:
		return inspect.ProtoHTTPS
	case mgmProto.TransparentProxyProtocol_TP_PROTO_H2:
		return inspect.ProtoH2
	case mgmProto.TransparentProxyProtocol_TP_PROTO_H3:
		return inspect.ProtoH3
	case mgmProto.TransparentProxyProtocol_TP_PROTO_WEBSOCKET:
		return inspect.ProtoWebSocket
	case mgmProto.TransparentProxyProtocol_TP_PROTO_OTHER:
		return inspect.ProtoOther
	default:
		return ""
	}
}

func toProxyAction(a mgmProto.TransparentProxyAction) inspect.Action {
	switch a {
	case mgmProto.TransparentProxyAction_TP_ACTION_BLOCK:
		return inspect.ActionBlock
	case mgmProto.TransparentProxyAction_TP_ACTION_INSPECT:
		return inspect.ActionInspect
	default:
		return inspect.ActionAllow
	}
}

func toICAPConfig(cfg *mgmProto.TransparentProxyICAPConfig) (*inspect.ICAPConfig, error) {
	icap := &inspect.ICAPConfig{
		MaxConnections: int(cfg.MaxConnections),
	}

	if cfg.ReqmodUrl != "" {
		u, err := url.Parse(cfg.ReqmodUrl)
		if err != nil {
			return nil, fmt.Errorf("parse ICAP reqmod URL: %w", err)
		}
		icap.ReqModURL = u
	}

	if cfg.RespmodUrl != "" {
		u, err := url.Parse(cfg.RespmodUrl)
		if err != nil {
			return nil, fmt.Errorf("parse ICAP respmod URL: %w", err)
		}
		icap.RespModURL = u
	}

	return icap, nil
}

func parseTLSConfig(certPEM, keyPEM []byte) (*inspect.TLSConfig, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, fmt.Errorf("decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode CA key PEM")
	}

	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS8 as fallback
		pkcs8Key, pkcs8Err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if pkcs8Err != nil {
			return nil, fmt.Errorf("parse CA private key (tried EC and PKCS8): %w", err)
		}
		return &inspect.TLSConfig{CA: cert, CAKey: pkcs8Key}, nil
	}

	return &inspect.TLSConfig{CA: cert, CAKey: key}, nil
}

// resolveInspectionCA sets the TLS config on the proxy config using priority:
// 1. Local config file CA (InspectionCACertPath/InspectionCAKeyPath)
// 2. Management-pushed CA (already parsed in toProxyConfig)
// 3. Auto-generated self-signed CA (ephemeral, for testing)
// Local always wins to prevent a compromised management server from injecting a CA.
func (e *Engine) resolveInspectionCA(config *inspect.Config) {
	// 1. Local CA from config file or env vars
	certPath := e.config.InspectionCACertPath
	keyPath := e.config.InspectionCAKeyPath
	if certPath == "" {
		certPath = os.Getenv("NB_INSPECTION_CA_CERT")
	}
	if keyPath == "" {
		keyPath = os.Getenv("NB_INSPECTION_CA_KEY")
	}
	if certPath != "" && keyPath != "" {
		certPEM, err := os.ReadFile(certPath)
		if err != nil {
			log.Errorf("read local inspection CA cert %s: %v", certPath, err)
			return
		}
		keyPEM, err := os.ReadFile(keyPath)
		if err != nil {
			log.Errorf("read local inspection CA key %s: %v", keyPath, err)
			return
		}
		tlsCfg, err := parseTLSConfig(certPEM, keyPEM)
		if err != nil {
			log.Errorf("parse local inspection CA: %v", err)
			return
		}
		log.Infof("inspect: using local CA from %s", certPath)
		config.TLS = tlsCfg
		return
	}

	// 2. Management-pushed CA (already set by toProxyConfig)
	if config.TLS != nil {
		log.Infof("inspect: using management-pushed CA")
		return
	}

	// 3. Auto-generate self-signed CA for testing / accept-cert UX
	tlsCfg, err := generateSelfSignedCA()
	if err != nil {
		log.Errorf("generate self-signed inspection CA: %v", err)
		return
	}
	log.Infof("inspect: using auto-generated self-signed CA (clients will see certificate warnings)")
	config.TLS = tlsCfg
}

// generateSelfSignedCA creates an ephemeral ECDSA P-256 CA certificate.
// Clients will see certificate warnings but can choose to accept.
func generateSelfSignedCA() (*inspect.TLSConfig, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"NetBird Transparent Proxy"},
			CommonName:   "NetBird Inspection CA (auto-generated)",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("create CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated CA certificate: %w", err)
	}

	return &inspect.TLSConfig{CA: cert, CAKey: key}, nil
}
