module github.com/netbirdio/netbird

go 1.23.0

require (
	cunicu.li/go-rosenpass v0.4.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/golang/protobuf v1.5.4
	github.com/google/uuid v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/kardianos/service v1.2.3-0.20240613133416-becf2eb62b83
	github.com/onsi/ginkgo v1.16.5
	github.com/onsi/gomega v1.27.6
	github.com/pion/ice/v3 v3.0.2
	github.com/rs/cors v1.8.0
	github.com/sirupsen/logrus v1.9.3
	github.com/spf13/cobra v1.7.0
	github.com/spf13/pflag v1.0.5
	github.com/vishvananda/netlink v1.2.1-beta.2
	golang.org/x/crypto v0.32.0
	golang.org/x/sys v0.29.0
	golang.zx2c4.com/wireguard v0.0.0-20230704135630-469159ecf7d1
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20230429144221-925a1e7659e6
	golang.zx2c4.com/wireguard/windows v0.5.3
	google.golang.org/grpc v1.64.1
	google.golang.org/protobuf v1.34.2
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

require (
	fyne.io/fyne/v2 v2.5.3
	fyne.io/systray v1.11.0
	github.com/TheJumpCloud/jcapi-go v3.0.0+incompatible
	github.com/c-robinson/iplib v1.0.3
	github.com/caddyserver/certmagic v0.21.3
	github.com/cilium/ebpf v0.15.0
	github.com/coreos/go-iptables v0.7.0
	github.com/creack/pty v1.1.18
	github.com/davecgh/go-spew v1.1.1
	github.com/eko/gocache/v3 v3.1.1
	github.com/fsnotify/fsnotify v1.7.0
	github.com/gliderlabs/ssh v0.3.8
	github.com/godbus/dbus/v5 v5.1.0
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.6.0
	github.com/google/gopacket v1.1.19
	github.com/google/nftables v0.2.0
	github.com/gopacket/gopacket v1.1.1
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.0.2-0.20240212192251-757544f21357
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-version v1.6.0
	github.com/libdns/route53 v1.5.0
	github.com/libp2p/go-netroute v0.2.1
	github.com/magiconair/properties v1.8.7
	github.com/mattn/go-sqlite3 v1.14.19
	github.com/mdlayher/socket v0.5.1
	github.com/miekg/dns v1.1.59
	github.com/mitchellh/hashstructure/v2 v2.0.2
	github.com/nadoo/ipset v0.5.0
	github.com/netbirdio/management-integrations/integrations v0.0.0-20241211172827-ba0a446be480
	github.com/netbirdio/signal-dispatcher/dispatcher v0.0.0-20241010133937-e0df50df217d
	github.com/okta/okta-sdk-golang/v2 v2.18.0
	github.com/oschwald/maxminddb-golang v1.12.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pion/logging v0.2.2
	github.com/pion/randutil v0.1.0
	github.com/pion/stun/v2 v2.0.0
	github.com/pion/transport/v3 v3.0.1
	github.com/pion/turn/v3 v3.0.1
	github.com/prometheus/client_golang v1.19.1
	github.com/rs/xid v1.3.0
	github.com/shirou/gopsutil/v3 v3.24.4
	github.com/skratchdot/open-golang v0.0.0-20200116055534-eef842397966
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/stretchr/testify v1.9.0
	github.com/testcontainers/testcontainers-go v0.31.0
	github.com/testcontainers/testcontainers-go/modules/mysql v0.31.0
	github.com/testcontainers/testcontainers-go/modules/postgres v0.31.0
	github.com/things-go/go-socks5 v0.0.4
	github.com/yusufpapurcu/wmi v1.2.4
	github.com/zcalusic/sysinfo v1.1.3
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.49.0
	go.opentelemetry.io/otel v1.26.0
	go.opentelemetry.io/otel/exporters/prometheus v0.48.0
	go.opentelemetry.io/otel/metric v1.26.0
	go.opentelemetry.io/otel/sdk/metric v1.26.0
	go.uber.org/zap v1.27.0
	goauthentik.io/api/v3 v3.2023051.3
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	golang.org/x/mobile v0.0.0-20231127183840-76ac6878050a
	golang.org/x/net v0.30.0
	golang.org/x/oauth2 v0.19.0
	golang.org/x/sync v0.10.0
	golang.org/x/term v0.28.0
	google.golang.org/api v0.177.0
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/driver/mysql v1.5.7
	gorm.io/driver/postgres v1.5.7
	gorm.io/driver/sqlite v1.5.3
	gorm.io/gorm v1.25.7
	nhooyr.io/websocket v1.8.11
)

require (
	cloud.google.com/go/auth v0.3.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.2 // indirect
	cloud.google.com/go/compute/metadata v0.3.0 // indirect
	dario.cat/mergo v1.0.0 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/BurntSushi/toml v1.4.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/Microsoft/hcsshim v0.12.3 // indirect
	github.com/XiaoMi/pegasus-go-client v0.0.0-20210427083443-f3b6b08bc4c2 // indirect
	github.com/anmitsu/go-shlex v0.0.0-20200514113438-38f4b401e2be // indirect
	github.com/aws/aws-sdk-go-v2 v1.30.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.27 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.27 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.11 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.15 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.17 // indirect
	github.com/aws/aws-sdk-go-v2/service/route53 v1.42.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.3 // indirect
	github.com/aws/smithy-go v1.20.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bradfitz/gomemcache v0.0.0-20220106215444-fb4bf637b56d // indirect
	github.com/caddyserver/zerossl v0.1.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/containerd/containerd v1.7.16 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/cpuguy83/dockercfg v0.3.1 // indirect
	github.com/dgraph-io/ristretto v0.1.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/distribution/reference v0.6.0 // indirect
	github.com/docker/docker v26.1.5+incompatible // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fredbi/uri v1.1.0 // indirect
	github.com/fyne-io/gl-js v0.0.0-20220119005834-d2da28d9ccfe // indirect
	github.com/fyne-io/glfw-js v0.0.0-20241126112943-313d8a0fe1d0 // indirect
	github.com/fyne-io/image v0.0.0-20220602074514-4956b0afb3d2 // indirect
	github.com/go-gl/gl v0.0.0-20211210172815-726fda9656d6 // indirect
	github.com/go-gl/glfw/v3.3/glfw v0.0.0-20240506104042-037f3cc74f2a // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/go-sql-driver/mysql v1.8.1 // indirect
	github.com/go-text/render v0.2.0 // indirect
	github.com/go-text/typesetting v0.2.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/s2a-go v0.1.7 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.2 // indirect
	github.com/googleapis/gax-go/v2 v2.12.3 // indirect
	github.com/gopherjs/gopherjs v1.17.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20221227161230-091c0ba34f0a // indirect
	github.com/jackc/pgx/v5 v5.5.5 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/jeandeaual/go-locale v0.0.0-20240223122105-ce5225dcaa49 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jsummers/gobmp v0.0.0-20151104160322-e2ba15ffa76e // indirect
	github.com/kelseyhightower/envconfig v1.4.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/libdns/libdns v0.2.2 // indirect
	github.com/lufia/plan9stats v0.0.0-20240513124658-fba389f38bae // indirect
	github.com/mdlayher/genetlink v1.3.2 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mholt/acmez/v2 v2.0.1 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/patternmatcher v0.6.0 // indirect
	github.com/moby/sys/sequential v0.5.0 // indirect
	github.com/moby/sys/user v0.1.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/morikuni/aec v1.0.0 // indirect
	github.com/nicksnyder/go-i18n/v2 v2.4.0 // indirect
	github.com/nxadm/tail v1.4.8 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/pegasus-kv/thrift v0.13.0 // indirect
	github.com/pion/dtls/v2 v2.2.10 // indirect
	github.com/pion/mdns v0.0.12 // indirect
	github.com/pion/transport/v2 v2.2.4 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.53.0 // indirect
	github.com/prometheus/procfs v0.15.0 // indirect
	github.com/rymdport/portal v0.3.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/spf13/cast v1.5.0 // indirect
	github.com/srwiley/oksvg v0.0.0-20221011165216-be6e8873101c // indirect
	github.com/srwiley/rasterx v0.0.0-20220730225603-2ab79fcdd4ef // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.14 // indirect
	github.com/tklauser/numcpus v0.8.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	github.com/yuin/goldmark v1.7.1 // indirect
	github.com/zeebo/blake3 v0.2.3 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.51.0 // indirect
	go.opentelemetry.io/otel/sdk v1.26.0 // indirect
	go.opentelemetry.io/otel/trace v1.26.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/image v0.18.0 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/text v0.21.0 // indirect
	golang.org/x/time v0.5.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20240509183442-62759503f434 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240903143218-8af14fe29dc1 // indirect
	gopkg.in/square/go-jose.v2 v2.6.0 // indirect
	gopkg.in/tomb.v1 v1.0.0-20141024135613-dd632973f1e7 // indirect
	gopkg.in/tomb.v2 v2.0.0-20161208151619-d5d1b5820637 // indirect
	gvisor.dev/gvisor v0.0.0-20231020174304-db3d49b921f9 // indirect
	k8s.io/apimachinery v0.26.2 // indirect
)

replace github.com/kardianos/service => github.com/netbirdio/service v0.0.0-20240911161631-f62744f42502

replace github.com/getlantern/systray => github.com/netbirdio/systray v0.0.0-20231030152038-ef1ed2a27949

replace golang.zx2c4.com/wireguard => github.com/netbirdio/wireguard-go v0.0.0-20241125150134-f9cdce5e32e9

replace github.com/cloudflare/circl => github.com/cunicu/circl v0.0.0-20230801113412-fec58fc7b5f6

replace github.com/pion/ice/v3 => github.com/netbirdio/ice/v3 v3.0.0-20240315174635-e72a50fcb64e

replace github.com/libp2p/go-netroute => github.com/netbirdio/go-netroute v0.0.0-20240611143515-f59b0e1d3944
