// This is a generated file - do not edit.
//
// Generated from daemon.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports
// ignore_for_file: unused_import

import 'dart:convert' as $convert;
import 'dart:core' as $core;
import 'dart:typed_data' as $typed_data;

@$core.Deprecated('Use logLevelDescriptor instead')
const LogLevel$json = {
  '1': 'LogLevel',
  '2': [
    {'1': 'UNKNOWN', '2': 0},
    {'1': 'PANIC', '2': 1},
    {'1': 'FATAL', '2': 2},
    {'1': 'ERROR', '2': 3},
    {'1': 'WARN', '2': 4},
    {'1': 'INFO', '2': 5},
    {'1': 'DEBUG', '2': 6},
    {'1': 'TRACE', '2': 7},
  ],
};

/// Descriptor for `LogLevel`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List logLevelDescriptor = $convert.base64Decode(
    'CghMb2dMZXZlbBILCgdVTktOT1dOEAASCQoFUEFOSUMQARIJCgVGQVRBTBACEgkKBUVSUk9SEA'
    'MSCAoEV0FSThAEEggKBElORk8QBRIJCgVERUJVRxAGEgkKBVRSQUNFEAc=');

@$core.Deprecated('Use exposeProtocolDescriptor instead')
const ExposeProtocol$json = {
  '1': 'ExposeProtocol',
  '2': [
    {'1': 'EXPOSE_HTTP', '2': 0},
    {'1': 'EXPOSE_HTTPS', '2': 1},
    {'1': 'EXPOSE_TCP', '2': 2},
    {'1': 'EXPOSE_UDP', '2': 3},
    {'1': 'EXPOSE_TLS', '2': 4},
  ],
};

/// Descriptor for `ExposeProtocol`. Decode as a `google.protobuf.EnumDescriptorProto`.
final $typed_data.Uint8List exposeProtocolDescriptor = $convert.base64Decode(
    'Cg5FeHBvc2VQcm90b2NvbBIPCgtFWFBPU0VfSFRUUBAAEhAKDEVYUE9TRV9IVFRQUxABEg4KCk'
    'VYUE9TRV9UQ1AQAhIOCgpFWFBPU0VfVURQEAMSDgoKRVhQT1NFX1RMUxAE');

@$core.Deprecated('Use emptyRequestDescriptor instead')
const EmptyRequest$json = {
  '1': 'EmptyRequest',
};

/// Descriptor for `EmptyRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List emptyRequestDescriptor =
    $convert.base64Decode('CgxFbXB0eVJlcXVlc3Q=');

@$core.Deprecated('Use oSLifecycleRequestDescriptor instead')
const OSLifecycleRequest$json = {
  '1': 'OSLifecycleRequest',
  '2': [
    {
      '1': 'type',
      '3': 1,
      '4': 1,
      '5': 14,
      '6': '.daemon.OSLifecycleRequest.CycleType',
      '10': 'type'
    },
  ],
  '4': [OSLifecycleRequest_CycleType$json],
};

@$core.Deprecated('Use oSLifecycleRequestDescriptor instead')
const OSLifecycleRequest_CycleType$json = {
  '1': 'CycleType',
  '2': [
    {'1': 'UNKNOWN', '2': 0},
    {'1': 'SLEEP', '2': 1},
    {'1': 'WAKEUP', '2': 2},
  ],
};

/// Descriptor for `OSLifecycleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oSLifecycleRequestDescriptor = $convert.base64Decode(
    'ChJPU0xpZmVjeWNsZVJlcXVlc3QSOAoEdHlwZRgBIAEoDjIkLmRhZW1vbi5PU0xpZmVjeWNsZV'
    'JlcXVlc3QuQ3ljbGVUeXBlUgR0eXBlIi8KCUN5Y2xlVHlwZRILCgdVTktOT1dOEAASCQoFU0xF'
    'RVAQARIKCgZXQUtFVVAQAg==');

@$core.Deprecated('Use oSLifecycleResponseDescriptor instead')
const OSLifecycleResponse$json = {
  '1': 'OSLifecycleResponse',
};

/// Descriptor for `OSLifecycleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List oSLifecycleResponseDescriptor =
    $convert.base64Decode('ChNPU0xpZmVjeWNsZVJlc3BvbnNl');

@$core.Deprecated('Use loginRequestDescriptor instead')
const LoginRequest$json = {
  '1': 'LoginRequest',
  '2': [
    {'1': 'setupKey', '3': 1, '4': 1, '5': 9, '10': 'setupKey'},
    {
      '1': 'preSharedKey',
      '3': 2,
      '4': 1,
      '5': 9,
      '8': {'3': true},
      '10': 'preSharedKey',
    },
    {'1': 'managementUrl', '3': 3, '4': 1, '5': 9, '10': 'managementUrl'},
    {'1': 'adminURL', '3': 4, '4': 1, '5': 9, '10': 'adminURL'},
    {'1': 'natExternalIPs', '3': 5, '4': 3, '5': 9, '10': 'natExternalIPs'},
    {
      '1': 'cleanNATExternalIPs',
      '3': 6,
      '4': 1,
      '5': 8,
      '10': 'cleanNATExternalIPs'
    },
    {
      '1': 'customDNSAddress',
      '3': 7,
      '4': 1,
      '5': 12,
      '10': 'customDNSAddress'
    },
    {
      '1': 'isUnixDesktopClient',
      '3': 8,
      '4': 1,
      '5': 8,
      '10': 'isUnixDesktopClient'
    },
    {'1': 'hostname', '3': 9, '4': 1, '5': 9, '10': 'hostname'},
    {
      '1': 'rosenpassEnabled',
      '3': 10,
      '4': 1,
      '5': 8,
      '9': 0,
      '10': 'rosenpassEnabled',
      '17': true
    },
    {
      '1': 'interfaceName',
      '3': 11,
      '4': 1,
      '5': 9,
      '9': 1,
      '10': 'interfaceName',
      '17': true
    },
    {
      '1': 'wireguardPort',
      '3': 12,
      '4': 1,
      '5': 3,
      '9': 2,
      '10': 'wireguardPort',
      '17': true
    },
    {
      '1': 'optionalPreSharedKey',
      '3': 13,
      '4': 1,
      '5': 9,
      '9': 3,
      '10': 'optionalPreSharedKey',
      '17': true
    },
    {
      '1': 'disableAutoConnect',
      '3': 14,
      '4': 1,
      '5': 8,
      '9': 4,
      '10': 'disableAutoConnect',
      '17': true
    },
    {
      '1': 'serverSSHAllowed',
      '3': 15,
      '4': 1,
      '5': 8,
      '9': 5,
      '10': 'serverSSHAllowed',
      '17': true
    },
    {
      '1': 'rosenpassPermissive',
      '3': 16,
      '4': 1,
      '5': 8,
      '9': 6,
      '10': 'rosenpassPermissive',
      '17': true
    },
    {
      '1': 'extraIFaceBlacklist',
      '3': 17,
      '4': 3,
      '5': 9,
      '10': 'extraIFaceBlacklist'
    },
    {
      '1': 'networkMonitor',
      '3': 18,
      '4': 1,
      '5': 8,
      '9': 7,
      '10': 'networkMonitor',
      '17': true
    },
    {
      '1': 'dnsRouteInterval',
      '3': 19,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Duration',
      '9': 8,
      '10': 'dnsRouteInterval',
      '17': true
    },
    {
      '1': 'disable_client_routes',
      '3': 20,
      '4': 1,
      '5': 8,
      '9': 9,
      '10': 'disableClientRoutes',
      '17': true
    },
    {
      '1': 'disable_server_routes',
      '3': 21,
      '4': 1,
      '5': 8,
      '9': 10,
      '10': 'disableServerRoutes',
      '17': true
    },
    {
      '1': 'disable_dns',
      '3': 22,
      '4': 1,
      '5': 8,
      '9': 11,
      '10': 'disableDns',
      '17': true
    },
    {
      '1': 'disable_firewall',
      '3': 23,
      '4': 1,
      '5': 8,
      '9': 12,
      '10': 'disableFirewall',
      '17': true
    },
    {
      '1': 'block_lan_access',
      '3': 24,
      '4': 1,
      '5': 8,
      '9': 13,
      '10': 'blockLanAccess',
      '17': true
    },
    {
      '1': 'disable_notifications',
      '3': 25,
      '4': 1,
      '5': 8,
      '9': 14,
      '10': 'disableNotifications',
      '17': true
    },
    {'1': 'dns_labels', '3': 26, '4': 3, '5': 9, '10': 'dnsLabels'},
    {'1': 'cleanDNSLabels', '3': 27, '4': 1, '5': 8, '10': 'cleanDNSLabels'},
    {
      '1': 'lazyConnectionEnabled',
      '3': 28,
      '4': 1,
      '5': 8,
      '9': 15,
      '10': 'lazyConnectionEnabled',
      '17': true
    },
    {
      '1': 'block_inbound',
      '3': 29,
      '4': 1,
      '5': 8,
      '9': 16,
      '10': 'blockInbound',
      '17': true
    },
    {
      '1': 'profileName',
      '3': 30,
      '4': 1,
      '5': 9,
      '9': 17,
      '10': 'profileName',
      '17': true
    },
    {
      '1': 'username',
      '3': 31,
      '4': 1,
      '5': 9,
      '9': 18,
      '10': 'username',
      '17': true
    },
    {'1': 'mtu', '3': 32, '4': 1, '5': 3, '9': 19, '10': 'mtu', '17': true},
    {'1': 'hint', '3': 33, '4': 1, '5': 9, '9': 20, '10': 'hint', '17': true},
    {
      '1': 'enableSSHRoot',
      '3': 34,
      '4': 1,
      '5': 8,
      '9': 21,
      '10': 'enableSSHRoot',
      '17': true
    },
    {
      '1': 'enableSSHSFTP',
      '3': 35,
      '4': 1,
      '5': 8,
      '9': 22,
      '10': 'enableSSHSFTP',
      '17': true
    },
    {
      '1': 'enableSSHLocalPortForwarding',
      '3': 36,
      '4': 1,
      '5': 8,
      '9': 23,
      '10': 'enableSSHLocalPortForwarding',
      '17': true
    },
    {
      '1': 'enableSSHRemotePortForwarding',
      '3': 37,
      '4': 1,
      '5': 8,
      '9': 24,
      '10': 'enableSSHRemotePortForwarding',
      '17': true
    },
    {
      '1': 'disableSSHAuth',
      '3': 38,
      '4': 1,
      '5': 8,
      '9': 25,
      '10': 'disableSSHAuth',
      '17': true
    },
    {
      '1': 'sshJWTCacheTTL',
      '3': 39,
      '4': 1,
      '5': 5,
      '9': 26,
      '10': 'sshJWTCacheTTL',
      '17': true
    },
  ],
  '8': [
    {'1': '_rosenpassEnabled'},
    {'1': '_interfaceName'},
    {'1': '_wireguardPort'},
    {'1': '_optionalPreSharedKey'},
    {'1': '_disableAutoConnect'},
    {'1': '_serverSSHAllowed'},
    {'1': '_rosenpassPermissive'},
    {'1': '_networkMonitor'},
    {'1': '_dnsRouteInterval'},
    {'1': '_disable_client_routes'},
    {'1': '_disable_server_routes'},
    {'1': '_disable_dns'},
    {'1': '_disable_firewall'},
    {'1': '_block_lan_access'},
    {'1': '_disable_notifications'},
    {'1': '_lazyConnectionEnabled'},
    {'1': '_block_inbound'},
    {'1': '_profileName'},
    {'1': '_username'},
    {'1': '_mtu'},
    {'1': '_hint'},
    {'1': '_enableSSHRoot'},
    {'1': '_enableSSHSFTP'},
    {'1': '_enableSSHLocalPortForwarding'},
    {'1': '_enableSSHRemotePortForwarding'},
    {'1': '_disableSSHAuth'},
    {'1': '_sshJWTCacheTTL'},
  ],
};

/// Descriptor for `LoginRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List loginRequestDescriptor = $convert.base64Decode(
    'CgxMb2dpblJlcXVlc3QSGgoIc2V0dXBLZXkYASABKAlSCHNldHVwS2V5EiYKDHByZVNoYXJlZE'
    'tleRgCIAEoCUICGAFSDHByZVNoYXJlZEtleRIkCg1tYW5hZ2VtZW50VXJsGAMgASgJUg1tYW5h'
    'Z2VtZW50VXJsEhoKCGFkbWluVVJMGAQgASgJUghhZG1pblVSTBImCg5uYXRFeHRlcm5hbElQcx'
    'gFIAMoCVIObmF0RXh0ZXJuYWxJUHMSMAoTY2xlYW5OQVRFeHRlcm5hbElQcxgGIAEoCFITY2xl'
    'YW5OQVRFeHRlcm5hbElQcxIqChBjdXN0b21ETlNBZGRyZXNzGAcgASgMUhBjdXN0b21ETlNBZG'
    'RyZXNzEjAKE2lzVW5peERlc2t0b3BDbGllbnQYCCABKAhSE2lzVW5peERlc2t0b3BDbGllbnQS'
    'GgoIaG9zdG5hbWUYCSABKAlSCGhvc3RuYW1lEi8KEHJvc2VucGFzc0VuYWJsZWQYCiABKAhIAF'
    'IQcm9zZW5wYXNzRW5hYmxlZIgBARIpCg1pbnRlcmZhY2VOYW1lGAsgASgJSAFSDWludGVyZmFj'
    'ZU5hbWWIAQESKQoNd2lyZWd1YXJkUG9ydBgMIAEoA0gCUg13aXJlZ3VhcmRQb3J0iAEBEjcKFG'
    '9wdGlvbmFsUHJlU2hhcmVkS2V5GA0gASgJSANSFG9wdGlvbmFsUHJlU2hhcmVkS2V5iAEBEjMK'
    'EmRpc2FibGVBdXRvQ29ubmVjdBgOIAEoCEgEUhJkaXNhYmxlQXV0b0Nvbm5lY3SIAQESLwoQc2'
    'VydmVyU1NIQWxsb3dlZBgPIAEoCEgFUhBzZXJ2ZXJTU0hBbGxvd2VkiAEBEjUKE3Jvc2VucGFz'
    'c1Blcm1pc3NpdmUYECABKAhIBlITcm9zZW5wYXNzUGVybWlzc2l2ZYgBARIwChNleHRyYUlGYW'
    'NlQmxhY2tsaXN0GBEgAygJUhNleHRyYUlGYWNlQmxhY2tsaXN0EisKDm5ldHdvcmtNb25pdG9y'
    'GBIgASgISAdSDm5ldHdvcmtNb25pdG9yiAEBEkoKEGRuc1JvdXRlSW50ZXJ2YWwYEyABKAsyGS'
    '5nb29nbGUucHJvdG9idWYuRHVyYXRpb25ICFIQZG5zUm91dGVJbnRlcnZhbIgBARI3ChVkaXNh'
    'YmxlX2NsaWVudF9yb3V0ZXMYFCABKAhICVITZGlzYWJsZUNsaWVudFJvdXRlc4gBARI3ChVkaX'
    'NhYmxlX3NlcnZlcl9yb3V0ZXMYFSABKAhIClITZGlzYWJsZVNlcnZlclJvdXRlc4gBARIkCgtk'
    'aXNhYmxlX2RucxgWIAEoCEgLUgpkaXNhYmxlRG5ziAEBEi4KEGRpc2FibGVfZmlyZXdhbGwYFy'
    'ABKAhIDFIPZGlzYWJsZUZpcmV3YWxsiAEBEi0KEGJsb2NrX2xhbl9hY2Nlc3MYGCABKAhIDVIO'
    'YmxvY2tMYW5BY2Nlc3OIAQESOAoVZGlzYWJsZV9ub3RpZmljYXRpb25zGBkgASgISA5SFGRpc2'
    'FibGVOb3RpZmljYXRpb25ziAEBEh0KCmRuc19sYWJlbHMYGiADKAlSCWRuc0xhYmVscxImCg5j'
    'bGVhbkROU0xhYmVscxgbIAEoCFIOY2xlYW5ETlNMYWJlbHMSOQoVbGF6eUNvbm5lY3Rpb25Fbm'
    'FibGVkGBwgASgISA9SFWxhenlDb25uZWN0aW9uRW5hYmxlZIgBARIoCg1ibG9ja19pbmJvdW5k'
    'GB0gASgISBBSDGJsb2NrSW5ib3VuZIgBARIlCgtwcm9maWxlTmFtZRgeIAEoCUgRUgtwcm9maW'
    'xlTmFtZYgBARIfCgh1c2VybmFtZRgfIAEoCUgSUgh1c2VybmFtZYgBARIVCgNtdHUYICABKANI'
    'E1IDbXR1iAEBEhcKBGhpbnQYISABKAlIFFIEaGludIgBARIpCg1lbmFibGVTU0hSb290GCIgAS'
    'gISBVSDWVuYWJsZVNTSFJvb3SIAQESKQoNZW5hYmxlU1NIU0ZUUBgjIAEoCEgWUg1lbmFibGVT'
    'U0hTRlRQiAEBEkcKHGVuYWJsZVNTSExvY2FsUG9ydEZvcndhcmRpbmcYJCABKAhIF1IcZW5hYm'
    'xlU1NITG9jYWxQb3J0Rm9yd2FyZGluZ4gBARJJCh1lbmFibGVTU0hSZW1vdGVQb3J0Rm9yd2Fy'
    'ZGluZxglIAEoCEgYUh1lbmFibGVTU0hSZW1vdGVQb3J0Rm9yd2FyZGluZ4gBARIrCg5kaXNhYm'
    'xlU1NIQXV0aBgmIAEoCEgZUg5kaXNhYmxlU1NIQXV0aIgBARIrCg5zc2hKV1RDYWNoZVRUTBgn'
    'IAEoBUgaUg5zc2hKV1RDYWNoZVRUTIgBAUITChFfcm9zZW5wYXNzRW5hYmxlZEIQCg5faW50ZX'
    'JmYWNlTmFtZUIQCg5fd2lyZWd1YXJkUG9ydEIXChVfb3B0aW9uYWxQcmVTaGFyZWRLZXlCFQoT'
    'X2Rpc2FibGVBdXRvQ29ubmVjdEITChFfc2VydmVyU1NIQWxsb3dlZEIWChRfcm9zZW5wYXNzUG'
    'VybWlzc2l2ZUIRCg9fbmV0d29ya01vbml0b3JCEwoRX2Ruc1JvdXRlSW50ZXJ2YWxCGAoWX2Rp'
    'c2FibGVfY2xpZW50X3JvdXRlc0IYChZfZGlzYWJsZV9zZXJ2ZXJfcm91dGVzQg4KDF9kaXNhYm'
    'xlX2Ruc0ITChFfZGlzYWJsZV9maXJld2FsbEITChFfYmxvY2tfbGFuX2FjY2Vzc0IYChZfZGlz'
    'YWJsZV9ub3RpZmljYXRpb25zQhgKFl9sYXp5Q29ubmVjdGlvbkVuYWJsZWRCEAoOX2Jsb2NrX2'
    'luYm91bmRCDgoMX3Byb2ZpbGVOYW1lQgsKCV91c2VybmFtZUIGCgRfbXR1QgcKBV9oaW50QhAK'
    'Dl9lbmFibGVTU0hSb290QhAKDl9lbmFibGVTU0hTRlRQQh8KHV9lbmFibGVTU0hMb2NhbFBvcn'
    'RGb3J3YXJkaW5nQiAKHl9lbmFibGVTU0hSZW1vdGVQb3J0Rm9yd2FyZGluZ0IRCg9fZGlzYWJs'
    'ZVNTSEF1dGhCEQoPX3NzaEpXVENhY2hlVFRM');

@$core.Deprecated('Use loginResponseDescriptor instead')
const LoginResponse$json = {
  '1': 'LoginResponse',
  '2': [
    {'1': 'needsSSOLogin', '3': 1, '4': 1, '5': 8, '10': 'needsSSOLogin'},
    {'1': 'userCode', '3': 2, '4': 1, '5': 9, '10': 'userCode'},
    {'1': 'verificationURI', '3': 3, '4': 1, '5': 9, '10': 'verificationURI'},
    {
      '1': 'verificationURIComplete',
      '3': 4,
      '4': 1,
      '5': 9,
      '10': 'verificationURIComplete'
    },
  ],
};

/// Descriptor for `LoginResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List loginResponseDescriptor = $convert.base64Decode(
    'Cg1Mb2dpblJlc3BvbnNlEiQKDW5lZWRzU1NPTG9naW4YASABKAhSDW5lZWRzU1NPTG9naW4SGg'
    'oIdXNlckNvZGUYAiABKAlSCHVzZXJDb2RlEigKD3ZlcmlmaWNhdGlvblVSSRgDIAEoCVIPdmVy'
    'aWZpY2F0aW9uVVJJEjgKF3ZlcmlmaWNhdGlvblVSSUNvbXBsZXRlGAQgASgJUhd2ZXJpZmljYX'
    'Rpb25VUklDb21wbGV0ZQ==');

@$core.Deprecated('Use waitSSOLoginRequestDescriptor instead')
const WaitSSOLoginRequest$json = {
  '1': 'WaitSSOLoginRequest',
  '2': [
    {'1': 'userCode', '3': 1, '4': 1, '5': 9, '10': 'userCode'},
    {'1': 'hostname', '3': 2, '4': 1, '5': 9, '10': 'hostname'},
  ],
};

/// Descriptor for `WaitSSOLoginRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List waitSSOLoginRequestDescriptor = $convert.base64Decode(
    'ChNXYWl0U1NPTG9naW5SZXF1ZXN0EhoKCHVzZXJDb2RlGAEgASgJUgh1c2VyQ29kZRIaCghob3'
    'N0bmFtZRgCIAEoCVIIaG9zdG5hbWU=');

@$core.Deprecated('Use waitSSOLoginResponseDescriptor instead')
const WaitSSOLoginResponse$json = {
  '1': 'WaitSSOLoginResponse',
  '2': [
    {'1': 'email', '3': 1, '4': 1, '5': 9, '10': 'email'},
  ],
};

/// Descriptor for `WaitSSOLoginResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List waitSSOLoginResponseDescriptor =
    $convert.base64Decode(
        'ChRXYWl0U1NPTG9naW5SZXNwb25zZRIUCgVlbWFpbBgBIAEoCVIFZW1haWw=');

@$core.Deprecated('Use upRequestDescriptor instead')
const UpRequest$json = {
  '1': 'UpRequest',
  '2': [
    {
      '1': 'profileName',
      '3': 1,
      '4': 1,
      '5': 9,
      '9': 0,
      '10': 'profileName',
      '17': true
    },
    {
      '1': 'username',
      '3': 2,
      '4': 1,
      '5': 9,
      '9': 1,
      '10': 'username',
      '17': true
    },
  ],
  '8': [
    {'1': '_profileName'},
    {'1': '_username'},
  ],
  '9': [
    {'1': 3, '2': 4},
  ],
};

/// Descriptor for `UpRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List upRequestDescriptor = $convert.base64Decode(
    'CglVcFJlcXVlc3QSJQoLcHJvZmlsZU5hbWUYASABKAlIAFILcHJvZmlsZU5hbWWIAQESHwoIdX'
    'Nlcm5hbWUYAiABKAlIAVIIdXNlcm5hbWWIAQFCDgoMX3Byb2ZpbGVOYW1lQgsKCV91c2VybmFt'
    'ZUoECAMQBA==');

@$core.Deprecated('Use upResponseDescriptor instead')
const UpResponse$json = {
  '1': 'UpResponse',
};

/// Descriptor for `UpResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List upResponseDescriptor =
    $convert.base64Decode('CgpVcFJlc3BvbnNl');

@$core.Deprecated('Use statusRequestDescriptor instead')
const StatusRequest$json = {
  '1': 'StatusRequest',
  '2': [
    {
      '1': 'getFullPeerStatus',
      '3': 1,
      '4': 1,
      '5': 8,
      '10': 'getFullPeerStatus'
    },
    {'1': 'shouldRunProbes', '3': 2, '4': 1, '5': 8, '10': 'shouldRunProbes'},
    {
      '1': 'waitForReady',
      '3': 3,
      '4': 1,
      '5': 8,
      '9': 0,
      '10': 'waitForReady',
      '17': true
    },
  ],
  '8': [
    {'1': '_waitForReady'},
  ],
};

/// Descriptor for `StatusRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List statusRequestDescriptor = $convert.base64Decode(
    'Cg1TdGF0dXNSZXF1ZXN0EiwKEWdldEZ1bGxQZWVyU3RhdHVzGAEgASgIUhFnZXRGdWxsUGVlcl'
    'N0YXR1cxIoCg9zaG91bGRSdW5Qcm9iZXMYAiABKAhSD3Nob3VsZFJ1blByb2JlcxInCgx3YWl0'
    'Rm9yUmVhZHkYAyABKAhIAFIMd2FpdEZvclJlYWR5iAEBQg8KDV93YWl0Rm9yUmVhZHk=');

@$core.Deprecated('Use statusResponseDescriptor instead')
const StatusResponse$json = {
  '1': 'StatusResponse',
  '2': [
    {'1': 'status', '3': 1, '4': 1, '5': 9, '10': 'status'},
    {
      '1': 'fullStatus',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.daemon.FullStatus',
      '10': 'fullStatus'
    },
    {'1': 'daemonVersion', '3': 3, '4': 1, '5': 9, '10': 'daemonVersion'},
  ],
};

/// Descriptor for `StatusResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List statusResponseDescriptor = $convert.base64Decode(
    'Cg5TdGF0dXNSZXNwb25zZRIWCgZzdGF0dXMYASABKAlSBnN0YXR1cxIyCgpmdWxsU3RhdHVzGA'
    'IgASgLMhIuZGFlbW9uLkZ1bGxTdGF0dXNSCmZ1bGxTdGF0dXMSJAoNZGFlbW9uVmVyc2lvbhgD'
    'IAEoCVINZGFlbW9uVmVyc2lvbg==');

@$core.Deprecated('Use downRequestDescriptor instead')
const DownRequest$json = {
  '1': 'DownRequest',
};

/// Descriptor for `DownRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List downRequestDescriptor =
    $convert.base64Decode('CgtEb3duUmVxdWVzdA==');

@$core.Deprecated('Use downResponseDescriptor instead')
const DownResponse$json = {
  '1': 'DownResponse',
};

/// Descriptor for `DownResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List downResponseDescriptor =
    $convert.base64Decode('CgxEb3duUmVzcG9uc2U=');

@$core.Deprecated('Use getConfigRequestDescriptor instead')
const GetConfigRequest$json = {
  '1': 'GetConfigRequest',
  '2': [
    {'1': 'profileName', '3': 1, '4': 1, '5': 9, '10': 'profileName'},
    {'1': 'username', '3': 2, '4': 1, '5': 9, '10': 'username'},
  ],
};

/// Descriptor for `GetConfigRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getConfigRequestDescriptor = $convert.base64Decode(
    'ChBHZXRDb25maWdSZXF1ZXN0EiAKC3Byb2ZpbGVOYW1lGAEgASgJUgtwcm9maWxlTmFtZRIaCg'
    'h1c2VybmFtZRgCIAEoCVIIdXNlcm5hbWU=');

@$core.Deprecated('Use getConfigResponseDescriptor instead')
const GetConfigResponse$json = {
  '1': 'GetConfigResponse',
  '2': [
    {'1': 'managementUrl', '3': 1, '4': 1, '5': 9, '10': 'managementUrl'},
    {'1': 'configFile', '3': 2, '4': 1, '5': 9, '10': 'configFile'},
    {'1': 'logFile', '3': 3, '4': 1, '5': 9, '10': 'logFile'},
    {'1': 'preSharedKey', '3': 4, '4': 1, '5': 9, '10': 'preSharedKey'},
    {'1': 'adminURL', '3': 5, '4': 1, '5': 9, '10': 'adminURL'},
    {'1': 'interfaceName', '3': 6, '4': 1, '5': 9, '10': 'interfaceName'},
    {'1': 'wireguardPort', '3': 7, '4': 1, '5': 3, '10': 'wireguardPort'},
    {'1': 'mtu', '3': 8, '4': 1, '5': 3, '10': 'mtu'},
    {
      '1': 'disableAutoConnect',
      '3': 9,
      '4': 1,
      '5': 8,
      '10': 'disableAutoConnect'
    },
    {
      '1': 'serverSSHAllowed',
      '3': 10,
      '4': 1,
      '5': 8,
      '10': 'serverSSHAllowed'
    },
    {
      '1': 'rosenpassEnabled',
      '3': 11,
      '4': 1,
      '5': 8,
      '10': 'rosenpassEnabled'
    },
    {
      '1': 'rosenpassPermissive',
      '3': 12,
      '4': 1,
      '5': 8,
      '10': 'rosenpassPermissive'
    },
    {
      '1': 'disable_notifications',
      '3': 13,
      '4': 1,
      '5': 8,
      '10': 'disableNotifications'
    },
    {
      '1': 'lazyConnectionEnabled',
      '3': 14,
      '4': 1,
      '5': 8,
      '10': 'lazyConnectionEnabled'
    },
    {'1': 'blockInbound', '3': 15, '4': 1, '5': 8, '10': 'blockInbound'},
    {'1': 'networkMonitor', '3': 16, '4': 1, '5': 8, '10': 'networkMonitor'},
    {'1': 'disable_dns', '3': 17, '4': 1, '5': 8, '10': 'disableDns'},
    {
      '1': 'disable_client_routes',
      '3': 18,
      '4': 1,
      '5': 8,
      '10': 'disableClientRoutes'
    },
    {
      '1': 'disable_server_routes',
      '3': 19,
      '4': 1,
      '5': 8,
      '10': 'disableServerRoutes'
    },
    {'1': 'block_lan_access', '3': 20, '4': 1, '5': 8, '10': 'blockLanAccess'},
    {'1': 'enableSSHRoot', '3': 21, '4': 1, '5': 8, '10': 'enableSSHRoot'},
    {'1': 'enableSSHSFTP', '3': 24, '4': 1, '5': 8, '10': 'enableSSHSFTP'},
    {
      '1': 'enableSSHLocalPortForwarding',
      '3': 22,
      '4': 1,
      '5': 8,
      '10': 'enableSSHLocalPortForwarding'
    },
    {
      '1': 'enableSSHRemotePortForwarding',
      '3': 23,
      '4': 1,
      '5': 8,
      '10': 'enableSSHRemotePortForwarding'
    },
    {'1': 'disableSSHAuth', '3': 25, '4': 1, '5': 8, '10': 'disableSSHAuth'},
    {'1': 'sshJWTCacheTTL', '3': 26, '4': 1, '5': 5, '10': 'sshJWTCacheTTL'},
  ],
};

/// Descriptor for `GetConfigResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getConfigResponseDescriptor = $convert.base64Decode(
    'ChFHZXRDb25maWdSZXNwb25zZRIkCg1tYW5hZ2VtZW50VXJsGAEgASgJUg1tYW5hZ2VtZW50VX'
    'JsEh4KCmNvbmZpZ0ZpbGUYAiABKAlSCmNvbmZpZ0ZpbGUSGAoHbG9nRmlsZRgDIAEoCVIHbG9n'
    'RmlsZRIiCgxwcmVTaGFyZWRLZXkYBCABKAlSDHByZVNoYXJlZEtleRIaCghhZG1pblVSTBgFIA'
    'EoCVIIYWRtaW5VUkwSJAoNaW50ZXJmYWNlTmFtZRgGIAEoCVINaW50ZXJmYWNlTmFtZRIkCg13'
    'aXJlZ3VhcmRQb3J0GAcgASgDUg13aXJlZ3VhcmRQb3J0EhAKA210dRgIIAEoA1IDbXR1Ei4KEm'
    'Rpc2FibGVBdXRvQ29ubmVjdBgJIAEoCFISZGlzYWJsZUF1dG9Db25uZWN0EioKEHNlcnZlclNT'
    'SEFsbG93ZWQYCiABKAhSEHNlcnZlclNTSEFsbG93ZWQSKgoQcm9zZW5wYXNzRW5hYmxlZBgLIA'
    'EoCFIQcm9zZW5wYXNzRW5hYmxlZBIwChNyb3NlbnBhc3NQZXJtaXNzaXZlGAwgASgIUhNyb3Nl'
    'bnBhc3NQZXJtaXNzaXZlEjMKFWRpc2FibGVfbm90aWZpY2F0aW9ucxgNIAEoCFIUZGlzYWJsZU'
    '5vdGlmaWNhdGlvbnMSNAoVbGF6eUNvbm5lY3Rpb25FbmFibGVkGA4gASgIUhVsYXp5Q29ubmVj'
    'dGlvbkVuYWJsZWQSIgoMYmxvY2tJbmJvdW5kGA8gASgIUgxibG9ja0luYm91bmQSJgoObmV0d2'
    '9ya01vbml0b3IYECABKAhSDm5ldHdvcmtNb25pdG9yEh8KC2Rpc2FibGVfZG5zGBEgASgIUgpk'
    'aXNhYmxlRG5zEjIKFWRpc2FibGVfY2xpZW50X3JvdXRlcxgSIAEoCFITZGlzYWJsZUNsaWVudF'
    'JvdXRlcxIyChVkaXNhYmxlX3NlcnZlcl9yb3V0ZXMYEyABKAhSE2Rpc2FibGVTZXJ2ZXJSb3V0'
    'ZXMSKAoQYmxvY2tfbGFuX2FjY2VzcxgUIAEoCFIOYmxvY2tMYW5BY2Nlc3MSJAoNZW5hYmxlU1'
    'NIUm9vdBgVIAEoCFINZW5hYmxlU1NIUm9vdBIkCg1lbmFibGVTU0hTRlRQGBggASgIUg1lbmFi'
    'bGVTU0hTRlRQEkIKHGVuYWJsZVNTSExvY2FsUG9ydEZvcndhcmRpbmcYFiABKAhSHGVuYWJsZV'
    'NTSExvY2FsUG9ydEZvcndhcmRpbmcSRAodZW5hYmxlU1NIUmVtb3RlUG9ydEZvcndhcmRpbmcY'
    'FyABKAhSHWVuYWJsZVNTSFJlbW90ZVBvcnRGb3J3YXJkaW5nEiYKDmRpc2FibGVTU0hBdXRoGB'
    'kgASgIUg5kaXNhYmxlU1NIQXV0aBImCg5zc2hKV1RDYWNoZVRUTBgaIAEoBVIOc3NoSldUQ2Fj'
    'aGVUVEw=');

@$core.Deprecated('Use peerStateDescriptor instead')
const PeerState$json = {
  '1': 'PeerState',
  '2': [
    {'1': 'IP', '3': 1, '4': 1, '5': 9, '10': 'IP'},
    {'1': 'pubKey', '3': 2, '4': 1, '5': 9, '10': 'pubKey'},
    {'1': 'connStatus', '3': 3, '4': 1, '5': 9, '10': 'connStatus'},
    {
      '1': 'connStatusUpdate',
      '3': 4,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'connStatusUpdate'
    },
    {'1': 'relayed', '3': 5, '4': 1, '5': 8, '10': 'relayed'},
    {
      '1': 'localIceCandidateType',
      '3': 7,
      '4': 1,
      '5': 9,
      '10': 'localIceCandidateType'
    },
    {
      '1': 'remoteIceCandidateType',
      '3': 8,
      '4': 1,
      '5': 9,
      '10': 'remoteIceCandidateType'
    },
    {'1': 'fqdn', '3': 9, '4': 1, '5': 9, '10': 'fqdn'},
    {
      '1': 'localIceCandidateEndpoint',
      '3': 10,
      '4': 1,
      '5': 9,
      '10': 'localIceCandidateEndpoint'
    },
    {
      '1': 'remoteIceCandidateEndpoint',
      '3': 11,
      '4': 1,
      '5': 9,
      '10': 'remoteIceCandidateEndpoint'
    },
    {
      '1': 'lastWireguardHandshake',
      '3': 12,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'lastWireguardHandshake'
    },
    {'1': 'bytesRx', '3': 13, '4': 1, '5': 3, '10': 'bytesRx'},
    {'1': 'bytesTx', '3': 14, '4': 1, '5': 3, '10': 'bytesTx'},
    {
      '1': 'rosenpassEnabled',
      '3': 15,
      '4': 1,
      '5': 8,
      '10': 'rosenpassEnabled'
    },
    {'1': 'networks', '3': 16, '4': 3, '5': 9, '10': 'networks'},
    {
      '1': 'latency',
      '3': 17,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Duration',
      '10': 'latency'
    },
    {'1': 'relayAddress', '3': 18, '4': 1, '5': 9, '10': 'relayAddress'},
    {'1': 'sshHostKey', '3': 19, '4': 1, '5': 12, '10': 'sshHostKey'},
  ],
};

/// Descriptor for `PeerState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List peerStateDescriptor = $convert.base64Decode(
    'CglQZWVyU3RhdGUSDgoCSVAYASABKAlSAklQEhYKBnB1YktleRgCIAEoCVIGcHViS2V5Eh4KCm'
    'Nvbm5TdGF0dXMYAyABKAlSCmNvbm5TdGF0dXMSRgoQY29ublN0YXR1c1VwZGF0ZRgEIAEoCzIa'
    'Lmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSEGNvbm5TdGF0dXNVcGRhdGUSGAoHcmVsYXllZB'
    'gFIAEoCFIHcmVsYXllZBI0ChVsb2NhbEljZUNhbmRpZGF0ZVR5cGUYByABKAlSFWxvY2FsSWNl'
    'Q2FuZGlkYXRlVHlwZRI2ChZyZW1vdGVJY2VDYW5kaWRhdGVUeXBlGAggASgJUhZyZW1vdGVJY2'
    'VDYW5kaWRhdGVUeXBlEhIKBGZxZG4YCSABKAlSBGZxZG4SPAoZbG9jYWxJY2VDYW5kaWRhdGVF'
    'bmRwb2ludBgKIAEoCVIZbG9jYWxJY2VDYW5kaWRhdGVFbmRwb2ludBI+ChpyZW1vdGVJY2VDYW'
    '5kaWRhdGVFbmRwb2ludBgLIAEoCVIacmVtb3RlSWNlQ2FuZGlkYXRlRW5kcG9pbnQSUgoWbGFz'
    'dFdpcmVndWFyZEhhbmRzaGFrZRgMIAEoCzIaLmdvb2dsZS5wcm90b2J1Zi5UaW1lc3RhbXBSFm'
    'xhc3RXaXJlZ3VhcmRIYW5kc2hha2USGAoHYnl0ZXNSeBgNIAEoA1IHYnl0ZXNSeBIYCgdieXRl'
    'c1R4GA4gASgDUgdieXRlc1R4EioKEHJvc2VucGFzc0VuYWJsZWQYDyABKAhSEHJvc2VucGFzc0'
    'VuYWJsZWQSGgoIbmV0d29ya3MYECADKAlSCG5ldHdvcmtzEjMKB2xhdGVuY3kYESABKAsyGS5n'
    'b29nbGUucHJvdG9idWYuRHVyYXRpb25SB2xhdGVuY3kSIgoMcmVsYXlBZGRyZXNzGBIgASgJUg'
    'xyZWxheUFkZHJlc3MSHgoKc3NoSG9zdEtleRgTIAEoDFIKc3NoSG9zdEtleQ==');

@$core.Deprecated('Use localPeerStateDescriptor instead')
const LocalPeerState$json = {
  '1': 'LocalPeerState',
  '2': [
    {'1': 'IP', '3': 1, '4': 1, '5': 9, '10': 'IP'},
    {'1': 'pubKey', '3': 2, '4': 1, '5': 9, '10': 'pubKey'},
    {'1': 'kernelInterface', '3': 3, '4': 1, '5': 8, '10': 'kernelInterface'},
    {'1': 'fqdn', '3': 4, '4': 1, '5': 9, '10': 'fqdn'},
    {'1': 'rosenpassEnabled', '3': 5, '4': 1, '5': 8, '10': 'rosenpassEnabled'},
    {
      '1': 'rosenpassPermissive',
      '3': 6,
      '4': 1,
      '5': 8,
      '10': 'rosenpassPermissive'
    },
    {'1': 'networks', '3': 7, '4': 3, '5': 9, '10': 'networks'},
  ],
};

/// Descriptor for `LocalPeerState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List localPeerStateDescriptor = $convert.base64Decode(
    'Cg5Mb2NhbFBlZXJTdGF0ZRIOCgJJUBgBIAEoCVICSVASFgoGcHViS2V5GAIgASgJUgZwdWJLZX'
    'kSKAoPa2VybmVsSW50ZXJmYWNlGAMgASgIUg9rZXJuZWxJbnRlcmZhY2USEgoEZnFkbhgEIAEo'
    'CVIEZnFkbhIqChByb3NlbnBhc3NFbmFibGVkGAUgASgIUhByb3NlbnBhc3NFbmFibGVkEjAKE3'
    'Jvc2VucGFzc1Blcm1pc3NpdmUYBiABKAhSE3Jvc2VucGFzc1Blcm1pc3NpdmUSGgoIbmV0d29y'
    'a3MYByADKAlSCG5ldHdvcmtz');

@$core.Deprecated('Use signalStateDescriptor instead')
const SignalState$json = {
  '1': 'SignalState',
  '2': [
    {'1': 'URL', '3': 1, '4': 1, '5': 9, '10': 'URL'},
    {'1': 'connected', '3': 2, '4': 1, '5': 8, '10': 'connected'},
    {'1': 'error', '3': 3, '4': 1, '5': 9, '10': 'error'},
  ],
};

/// Descriptor for `SignalState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List signalStateDescriptor = $convert.base64Decode(
    'CgtTaWduYWxTdGF0ZRIQCgNVUkwYASABKAlSA1VSTBIcCgljb25uZWN0ZWQYAiABKAhSCWNvbm'
    '5lY3RlZBIUCgVlcnJvchgDIAEoCVIFZXJyb3I=');

@$core.Deprecated('Use managementStateDescriptor instead')
const ManagementState$json = {
  '1': 'ManagementState',
  '2': [
    {'1': 'URL', '3': 1, '4': 1, '5': 9, '10': 'URL'},
    {'1': 'connected', '3': 2, '4': 1, '5': 8, '10': 'connected'},
    {'1': 'error', '3': 3, '4': 1, '5': 9, '10': 'error'},
  ],
};

/// Descriptor for `ManagementState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List managementStateDescriptor = $convert.base64Decode(
    'Cg9NYW5hZ2VtZW50U3RhdGUSEAoDVVJMGAEgASgJUgNVUkwSHAoJY29ubmVjdGVkGAIgASgIUg'
    'ljb25uZWN0ZWQSFAoFZXJyb3IYAyABKAlSBWVycm9y');

@$core.Deprecated('Use relayStateDescriptor instead')
const RelayState$json = {
  '1': 'RelayState',
  '2': [
    {'1': 'URI', '3': 1, '4': 1, '5': 9, '10': 'URI'},
    {'1': 'available', '3': 2, '4': 1, '5': 8, '10': 'available'},
    {'1': 'error', '3': 3, '4': 1, '5': 9, '10': 'error'},
  ],
};

/// Descriptor for `RelayState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List relayStateDescriptor = $convert.base64Decode(
    'CgpSZWxheVN0YXRlEhAKA1VSSRgBIAEoCVIDVVJJEhwKCWF2YWlsYWJsZRgCIAEoCFIJYXZhaW'
    'xhYmxlEhQKBWVycm9yGAMgASgJUgVlcnJvcg==');

@$core.Deprecated('Use nSGroupStateDescriptor instead')
const NSGroupState$json = {
  '1': 'NSGroupState',
  '2': [
    {'1': 'servers', '3': 1, '4': 3, '5': 9, '10': 'servers'},
    {'1': 'domains', '3': 2, '4': 3, '5': 9, '10': 'domains'},
    {'1': 'enabled', '3': 3, '4': 1, '5': 8, '10': 'enabled'},
    {'1': 'error', '3': 4, '4': 1, '5': 9, '10': 'error'},
  ],
};

/// Descriptor for `NSGroupState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List nSGroupStateDescriptor = $convert.base64Decode(
    'CgxOU0dyb3VwU3RhdGUSGAoHc2VydmVycxgBIAMoCVIHc2VydmVycxIYCgdkb21haW5zGAIgAy'
    'gJUgdkb21haW5zEhgKB2VuYWJsZWQYAyABKAhSB2VuYWJsZWQSFAoFZXJyb3IYBCABKAlSBWVy'
    'cm9y');

@$core.Deprecated('Use sSHSessionInfoDescriptor instead')
const SSHSessionInfo$json = {
  '1': 'SSHSessionInfo',
  '2': [
    {'1': 'username', '3': 1, '4': 1, '5': 9, '10': 'username'},
    {'1': 'remoteAddress', '3': 2, '4': 1, '5': 9, '10': 'remoteAddress'},
    {'1': 'command', '3': 3, '4': 1, '5': 9, '10': 'command'},
    {'1': 'jwtUsername', '3': 4, '4': 1, '5': 9, '10': 'jwtUsername'},
    {'1': 'portForwards', '3': 5, '4': 3, '5': 9, '10': 'portForwards'},
  ],
};

/// Descriptor for `SSHSessionInfo`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List sSHSessionInfoDescriptor = $convert.base64Decode(
    'Cg5TU0hTZXNzaW9uSW5mbxIaCgh1c2VybmFtZRgBIAEoCVIIdXNlcm5hbWUSJAoNcmVtb3RlQW'
    'RkcmVzcxgCIAEoCVINcmVtb3RlQWRkcmVzcxIYCgdjb21tYW5kGAMgASgJUgdjb21tYW5kEiAK'
    'C2p3dFVzZXJuYW1lGAQgASgJUgtqd3RVc2VybmFtZRIiCgxwb3J0Rm9yd2FyZHMYBSADKAlSDH'
    'BvcnRGb3J3YXJkcw==');

@$core.Deprecated('Use sSHServerStateDescriptor instead')
const SSHServerState$json = {
  '1': 'SSHServerState',
  '2': [
    {'1': 'enabled', '3': 1, '4': 1, '5': 8, '10': 'enabled'},
    {
      '1': 'sessions',
      '3': 2,
      '4': 3,
      '5': 11,
      '6': '.daemon.SSHSessionInfo',
      '10': 'sessions'
    },
  ],
};

/// Descriptor for `SSHServerState`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List sSHServerStateDescriptor = $convert.base64Decode(
    'Cg5TU0hTZXJ2ZXJTdGF0ZRIYCgdlbmFibGVkGAEgASgIUgdlbmFibGVkEjIKCHNlc3Npb25zGA'
    'IgAygLMhYuZGFlbW9uLlNTSFNlc3Npb25JbmZvUghzZXNzaW9ucw==');

@$core.Deprecated('Use fullStatusDescriptor instead')
const FullStatus$json = {
  '1': 'FullStatus',
  '2': [
    {
      '1': 'managementState',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.daemon.ManagementState',
      '10': 'managementState'
    },
    {
      '1': 'signalState',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.daemon.SignalState',
      '10': 'signalState'
    },
    {
      '1': 'localPeerState',
      '3': 3,
      '4': 1,
      '5': 11,
      '6': '.daemon.LocalPeerState',
      '10': 'localPeerState'
    },
    {
      '1': 'peers',
      '3': 4,
      '4': 3,
      '5': 11,
      '6': '.daemon.PeerState',
      '10': 'peers'
    },
    {
      '1': 'relays',
      '3': 5,
      '4': 3,
      '5': 11,
      '6': '.daemon.RelayState',
      '10': 'relays'
    },
    {
      '1': 'dns_servers',
      '3': 6,
      '4': 3,
      '5': 11,
      '6': '.daemon.NSGroupState',
      '10': 'dnsServers'
    },
    {
      '1': 'NumberOfForwardingRules',
      '3': 8,
      '4': 1,
      '5': 5,
      '10': 'NumberOfForwardingRules'
    },
    {
      '1': 'events',
      '3': 7,
      '4': 3,
      '5': 11,
      '6': '.daemon.SystemEvent',
      '10': 'events'
    },
    {
      '1': 'lazyConnectionEnabled',
      '3': 9,
      '4': 1,
      '5': 8,
      '10': 'lazyConnectionEnabled'
    },
    {
      '1': 'sshServerState',
      '3': 10,
      '4': 1,
      '5': 11,
      '6': '.daemon.SSHServerState',
      '10': 'sshServerState'
    },
  ],
};

/// Descriptor for `FullStatus`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List fullStatusDescriptor = $convert.base64Decode(
    'CgpGdWxsU3RhdHVzEkEKD21hbmFnZW1lbnRTdGF0ZRgBIAEoCzIXLmRhZW1vbi5NYW5hZ2VtZW'
    '50U3RhdGVSD21hbmFnZW1lbnRTdGF0ZRI1CgtzaWduYWxTdGF0ZRgCIAEoCzITLmRhZW1vbi5T'
    'aWduYWxTdGF0ZVILc2lnbmFsU3RhdGUSPgoObG9jYWxQZWVyU3RhdGUYAyABKAsyFi5kYWVtb2'
    '4uTG9jYWxQZWVyU3RhdGVSDmxvY2FsUGVlclN0YXRlEicKBXBlZXJzGAQgAygLMhEuZGFlbW9u'
    'LlBlZXJTdGF0ZVIFcGVlcnMSKgoGcmVsYXlzGAUgAygLMhIuZGFlbW9uLlJlbGF5U3RhdGVSBn'
    'JlbGF5cxI1CgtkbnNfc2VydmVycxgGIAMoCzIULmRhZW1vbi5OU0dyb3VwU3RhdGVSCmRuc1Nl'
    'cnZlcnMSOAoXTnVtYmVyT2ZGb3J3YXJkaW5nUnVsZXMYCCABKAVSF051bWJlck9mRm9yd2FyZG'
    'luZ1J1bGVzEisKBmV2ZW50cxgHIAMoCzITLmRhZW1vbi5TeXN0ZW1FdmVudFIGZXZlbnRzEjQK'
    'FWxhenlDb25uZWN0aW9uRW5hYmxlZBgJIAEoCFIVbGF6eUNvbm5lY3Rpb25FbmFibGVkEj4KDn'
    'NzaFNlcnZlclN0YXRlGAogASgLMhYuZGFlbW9uLlNTSFNlcnZlclN0YXRlUg5zc2hTZXJ2ZXJT'
    'dGF0ZQ==');

@$core.Deprecated('Use listNetworksRequestDescriptor instead')
const ListNetworksRequest$json = {
  '1': 'ListNetworksRequest',
};

/// Descriptor for `ListNetworksRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listNetworksRequestDescriptor =
    $convert.base64Decode('ChNMaXN0TmV0d29ya3NSZXF1ZXN0');

@$core.Deprecated('Use listNetworksResponseDescriptor instead')
const ListNetworksResponse$json = {
  '1': 'ListNetworksResponse',
  '2': [
    {
      '1': 'routes',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.daemon.Network',
      '10': 'routes'
    },
  ],
};

/// Descriptor for `ListNetworksResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listNetworksResponseDescriptor = $convert.base64Decode(
    'ChRMaXN0TmV0d29ya3NSZXNwb25zZRInCgZyb3V0ZXMYASADKAsyDy5kYWVtb24uTmV0d29ya1'
    'IGcm91dGVz');

@$core.Deprecated('Use selectNetworksRequestDescriptor instead')
const SelectNetworksRequest$json = {
  '1': 'SelectNetworksRequest',
  '2': [
    {'1': 'networkIDs', '3': 1, '4': 3, '5': 9, '10': 'networkIDs'},
    {'1': 'append', '3': 2, '4': 1, '5': 8, '10': 'append'},
    {'1': 'all', '3': 3, '4': 1, '5': 8, '10': 'all'},
  ],
};

/// Descriptor for `SelectNetworksRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List selectNetworksRequestDescriptor = $convert.base64Decode(
    'ChVTZWxlY3ROZXR3b3Jrc1JlcXVlc3QSHgoKbmV0d29ya0lEcxgBIAMoCVIKbmV0d29ya0lEcx'
    'IWCgZhcHBlbmQYAiABKAhSBmFwcGVuZBIQCgNhbGwYAyABKAhSA2FsbA==');

@$core.Deprecated('Use selectNetworksResponseDescriptor instead')
const SelectNetworksResponse$json = {
  '1': 'SelectNetworksResponse',
};

/// Descriptor for `SelectNetworksResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List selectNetworksResponseDescriptor =
    $convert.base64Decode('ChZTZWxlY3ROZXR3b3Jrc1Jlc3BvbnNl');

@$core.Deprecated('Use iPListDescriptor instead')
const IPList$json = {
  '1': 'IPList',
  '2': [
    {'1': 'ips', '3': 1, '4': 3, '5': 9, '10': 'ips'},
  ],
};

/// Descriptor for `IPList`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List iPListDescriptor =
    $convert.base64Decode('CgZJUExpc3QSEAoDaXBzGAEgAygJUgNpcHM=');

@$core.Deprecated('Use networkDescriptor instead')
const Network$json = {
  '1': 'Network',
  '2': [
    {'1': 'ID', '3': 1, '4': 1, '5': 9, '10': 'ID'},
    {'1': 'range', '3': 2, '4': 1, '5': 9, '10': 'range'},
    {'1': 'selected', '3': 3, '4': 1, '5': 8, '10': 'selected'},
    {'1': 'domains', '3': 4, '4': 3, '5': 9, '10': 'domains'},
    {
      '1': 'resolvedIPs',
      '3': 5,
      '4': 3,
      '5': 11,
      '6': '.daemon.Network.ResolvedIPsEntry',
      '10': 'resolvedIPs'
    },
  ],
  '3': [Network_ResolvedIPsEntry$json],
};

@$core.Deprecated('Use networkDescriptor instead')
const Network_ResolvedIPsEntry$json = {
  '1': 'ResolvedIPsEntry',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
    {
      '1': 'value',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.daemon.IPList',
      '10': 'value'
    },
  ],
  '7': {'7': true},
};

/// Descriptor for `Network`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List networkDescriptor = $convert.base64Decode(
    'CgdOZXR3b3JrEg4KAklEGAEgASgJUgJJRBIUCgVyYW5nZRgCIAEoCVIFcmFuZ2USGgoIc2VsZW'
    'N0ZWQYAyABKAhSCHNlbGVjdGVkEhgKB2RvbWFpbnMYBCADKAlSB2RvbWFpbnMSQgoLcmVzb2x2'
    'ZWRJUHMYBSADKAsyIC5kYWVtb24uTmV0d29yay5SZXNvbHZlZElQc0VudHJ5UgtyZXNvbHZlZE'
    'lQcxpOChBSZXNvbHZlZElQc0VudHJ5EhAKA2tleRgBIAEoCVIDa2V5EiQKBXZhbHVlGAIgASgL'
    'Mg4uZGFlbW9uLklQTGlzdFIFdmFsdWU6AjgB');

@$core.Deprecated('Use portInfoDescriptor instead')
const PortInfo$json = {
  '1': 'PortInfo',
  '2': [
    {'1': 'port', '3': 1, '4': 1, '5': 13, '9': 0, '10': 'port'},
    {
      '1': 'range',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.daemon.PortInfo.Range',
      '9': 0,
      '10': 'range'
    },
  ],
  '3': [PortInfo_Range$json],
  '8': [
    {'1': 'portSelection'},
  ],
};

@$core.Deprecated('Use portInfoDescriptor instead')
const PortInfo_Range$json = {
  '1': 'Range',
  '2': [
    {'1': 'start', '3': 1, '4': 1, '5': 13, '10': 'start'},
    {'1': 'end', '3': 2, '4': 1, '5': 13, '10': 'end'},
  ],
};

/// Descriptor for `PortInfo`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List portInfoDescriptor = $convert.base64Decode(
    'CghQb3J0SW5mbxIUCgRwb3J0GAEgASgNSABSBHBvcnQSLgoFcmFuZ2UYAiABKAsyFi5kYWVtb2'
    '4uUG9ydEluZm8uUmFuZ2VIAFIFcmFuZ2UaLwoFUmFuZ2USFAoFc3RhcnQYASABKA1SBXN0YXJ0'
    'EhAKA2VuZBgCIAEoDVIDZW5kQg8KDXBvcnRTZWxlY3Rpb24=');

@$core.Deprecated('Use forwardingRuleDescriptor instead')
const ForwardingRule$json = {
  '1': 'ForwardingRule',
  '2': [
    {'1': 'protocol', '3': 1, '4': 1, '5': 9, '10': 'protocol'},
    {
      '1': 'destinationPort',
      '3': 2,
      '4': 1,
      '5': 11,
      '6': '.daemon.PortInfo',
      '10': 'destinationPort'
    },
    {
      '1': 'translatedAddress',
      '3': 3,
      '4': 1,
      '5': 9,
      '10': 'translatedAddress'
    },
    {
      '1': 'translatedHostname',
      '3': 4,
      '4': 1,
      '5': 9,
      '10': 'translatedHostname'
    },
    {
      '1': 'translatedPort',
      '3': 5,
      '4': 1,
      '5': 11,
      '6': '.daemon.PortInfo',
      '10': 'translatedPort'
    },
  ],
};

/// Descriptor for `ForwardingRule`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List forwardingRuleDescriptor = $convert.base64Decode(
    'Cg5Gb3J3YXJkaW5nUnVsZRIaCghwcm90b2NvbBgBIAEoCVIIcHJvdG9jb2wSOgoPZGVzdGluYX'
    'Rpb25Qb3J0GAIgASgLMhAuZGFlbW9uLlBvcnRJbmZvUg9kZXN0aW5hdGlvblBvcnQSLAoRdHJh'
    'bnNsYXRlZEFkZHJlc3MYAyABKAlSEXRyYW5zbGF0ZWRBZGRyZXNzEi4KEnRyYW5zbGF0ZWRIb3'
    'N0bmFtZRgEIAEoCVISdHJhbnNsYXRlZEhvc3RuYW1lEjgKDnRyYW5zbGF0ZWRQb3J0GAUgASgL'
    'MhAuZGFlbW9uLlBvcnRJbmZvUg50cmFuc2xhdGVkUG9ydA==');

@$core.Deprecated('Use forwardingRulesResponseDescriptor instead')
const ForwardingRulesResponse$json = {
  '1': 'ForwardingRulesResponse',
  '2': [
    {
      '1': 'rules',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.daemon.ForwardingRule',
      '10': 'rules'
    },
  ],
};

/// Descriptor for `ForwardingRulesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List forwardingRulesResponseDescriptor =
    $convert.base64Decode(
        'ChdGb3J3YXJkaW5nUnVsZXNSZXNwb25zZRIsCgVydWxlcxgBIAMoCzIWLmRhZW1vbi5Gb3J3YX'
        'JkaW5nUnVsZVIFcnVsZXM=');

@$core.Deprecated('Use debugBundleRequestDescriptor instead')
const DebugBundleRequest$json = {
  '1': 'DebugBundleRequest',
  '2': [
    {'1': 'anonymize', '3': 1, '4': 1, '5': 8, '10': 'anonymize'},
    {'1': 'systemInfo', '3': 3, '4': 1, '5': 8, '10': 'systemInfo'},
    {'1': 'uploadURL', '3': 4, '4': 1, '5': 9, '10': 'uploadURL'},
    {'1': 'logFileCount', '3': 5, '4': 1, '5': 13, '10': 'logFileCount'},
  ],
};

/// Descriptor for `DebugBundleRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List debugBundleRequestDescriptor = $convert.base64Decode(
    'ChJEZWJ1Z0J1bmRsZVJlcXVlc3QSHAoJYW5vbnltaXplGAEgASgIUglhbm9ueW1pemUSHgoKc3'
    'lzdGVtSW5mbxgDIAEoCFIKc3lzdGVtSW5mbxIcCgl1cGxvYWRVUkwYBCABKAlSCXVwbG9hZFVS'
    'TBIiCgxsb2dGaWxlQ291bnQYBSABKA1SDGxvZ0ZpbGVDb3VudA==');

@$core.Deprecated('Use debugBundleResponseDescriptor instead')
const DebugBundleResponse$json = {
  '1': 'DebugBundleResponse',
  '2': [
    {'1': 'path', '3': 1, '4': 1, '5': 9, '10': 'path'},
    {'1': 'uploadedKey', '3': 2, '4': 1, '5': 9, '10': 'uploadedKey'},
    {
      '1': 'uploadFailureReason',
      '3': 3,
      '4': 1,
      '5': 9,
      '10': 'uploadFailureReason'
    },
  ],
};

/// Descriptor for `DebugBundleResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List debugBundleResponseDescriptor = $convert.base64Decode(
    'ChNEZWJ1Z0J1bmRsZVJlc3BvbnNlEhIKBHBhdGgYASABKAlSBHBhdGgSIAoLdXBsb2FkZWRLZX'
    'kYAiABKAlSC3VwbG9hZGVkS2V5EjAKE3VwbG9hZEZhaWx1cmVSZWFzb24YAyABKAlSE3VwbG9h'
    'ZEZhaWx1cmVSZWFzb24=');

@$core.Deprecated('Use getLogLevelRequestDescriptor instead')
const GetLogLevelRequest$json = {
  '1': 'GetLogLevelRequest',
};

/// Descriptor for `GetLogLevelRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getLogLevelRequestDescriptor =
    $convert.base64Decode('ChJHZXRMb2dMZXZlbFJlcXVlc3Q=');

@$core.Deprecated('Use getLogLevelResponseDescriptor instead')
const GetLogLevelResponse$json = {
  '1': 'GetLogLevelResponse',
  '2': [
    {
      '1': 'level',
      '3': 1,
      '4': 1,
      '5': 14,
      '6': '.daemon.LogLevel',
      '10': 'level'
    },
  ],
};

/// Descriptor for `GetLogLevelResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getLogLevelResponseDescriptor = $convert.base64Decode(
    'ChNHZXRMb2dMZXZlbFJlc3BvbnNlEiYKBWxldmVsGAEgASgOMhAuZGFlbW9uLkxvZ0xldmVsUg'
    'VsZXZlbA==');

@$core.Deprecated('Use setLogLevelRequestDescriptor instead')
const SetLogLevelRequest$json = {
  '1': 'SetLogLevelRequest',
  '2': [
    {
      '1': 'level',
      '3': 1,
      '4': 1,
      '5': 14,
      '6': '.daemon.LogLevel',
      '10': 'level'
    },
  ],
};

/// Descriptor for `SetLogLevelRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List setLogLevelRequestDescriptor = $convert.base64Decode(
    'ChJTZXRMb2dMZXZlbFJlcXVlc3QSJgoFbGV2ZWwYASABKA4yEC5kYWVtb24uTG9nTGV2ZWxSBW'
    'xldmVs');

@$core.Deprecated('Use setLogLevelResponseDescriptor instead')
const SetLogLevelResponse$json = {
  '1': 'SetLogLevelResponse',
};

/// Descriptor for `SetLogLevelResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List setLogLevelResponseDescriptor =
    $convert.base64Decode('ChNTZXRMb2dMZXZlbFJlc3BvbnNl');

@$core.Deprecated('Use stateDescriptor instead')
const State$json = {
  '1': 'State',
  '2': [
    {'1': 'name', '3': 1, '4': 1, '5': 9, '10': 'name'},
  ],
};

/// Descriptor for `State`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List stateDescriptor =
    $convert.base64Decode('CgVTdGF0ZRISCgRuYW1lGAEgASgJUgRuYW1l');

@$core.Deprecated('Use listStatesRequestDescriptor instead')
const ListStatesRequest$json = {
  '1': 'ListStatesRequest',
};

/// Descriptor for `ListStatesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listStatesRequestDescriptor =
    $convert.base64Decode('ChFMaXN0U3RhdGVzUmVxdWVzdA==');

@$core.Deprecated('Use listStatesResponseDescriptor instead')
const ListStatesResponse$json = {
  '1': 'ListStatesResponse',
  '2': [
    {
      '1': 'states',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.daemon.State',
      '10': 'states'
    },
  ],
};

/// Descriptor for `ListStatesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listStatesResponseDescriptor = $convert.base64Decode(
    'ChJMaXN0U3RhdGVzUmVzcG9uc2USJQoGc3RhdGVzGAEgAygLMg0uZGFlbW9uLlN0YXRlUgZzdG'
    'F0ZXM=');

@$core.Deprecated('Use cleanStateRequestDescriptor instead')
const CleanStateRequest$json = {
  '1': 'CleanStateRequest',
  '2': [
    {'1': 'state_name', '3': 1, '4': 1, '5': 9, '10': 'stateName'},
    {'1': 'all', '3': 2, '4': 1, '5': 8, '10': 'all'},
  ],
};

/// Descriptor for `CleanStateRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List cleanStateRequestDescriptor = $convert.base64Decode(
    'ChFDbGVhblN0YXRlUmVxdWVzdBIdCgpzdGF0ZV9uYW1lGAEgASgJUglzdGF0ZU5hbWUSEAoDYW'
    'xsGAIgASgIUgNhbGw=');

@$core.Deprecated('Use cleanStateResponseDescriptor instead')
const CleanStateResponse$json = {
  '1': 'CleanStateResponse',
  '2': [
    {'1': 'cleaned_states', '3': 1, '4': 1, '5': 5, '10': 'cleanedStates'},
  ],
};

/// Descriptor for `CleanStateResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List cleanStateResponseDescriptor = $convert.base64Decode(
    'ChJDbGVhblN0YXRlUmVzcG9uc2USJQoOY2xlYW5lZF9zdGF0ZXMYASABKAVSDWNsZWFuZWRTdG'
    'F0ZXM=');

@$core.Deprecated('Use deleteStateRequestDescriptor instead')
const DeleteStateRequest$json = {
  '1': 'DeleteStateRequest',
  '2': [
    {'1': 'state_name', '3': 1, '4': 1, '5': 9, '10': 'stateName'},
    {'1': 'all', '3': 2, '4': 1, '5': 8, '10': 'all'},
  ],
};

/// Descriptor for `DeleteStateRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List deleteStateRequestDescriptor = $convert.base64Decode(
    'ChJEZWxldGVTdGF0ZVJlcXVlc3QSHQoKc3RhdGVfbmFtZRgBIAEoCVIJc3RhdGVOYW1lEhAKA2'
    'FsbBgCIAEoCFIDYWxs');

@$core.Deprecated('Use deleteStateResponseDescriptor instead')
const DeleteStateResponse$json = {
  '1': 'DeleteStateResponse',
  '2': [
    {'1': 'deleted_states', '3': 1, '4': 1, '5': 5, '10': 'deletedStates'},
  ],
};

/// Descriptor for `DeleteStateResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List deleteStateResponseDescriptor = $convert.base64Decode(
    'ChNEZWxldGVTdGF0ZVJlc3BvbnNlEiUKDmRlbGV0ZWRfc3RhdGVzGAEgASgFUg1kZWxldGVkU3'
    'RhdGVz');

@$core.Deprecated('Use setSyncResponsePersistenceRequestDescriptor instead')
const SetSyncResponsePersistenceRequest$json = {
  '1': 'SetSyncResponsePersistenceRequest',
  '2': [
    {'1': 'enabled', '3': 1, '4': 1, '5': 8, '10': 'enabled'},
  ],
};

/// Descriptor for `SetSyncResponsePersistenceRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List setSyncResponsePersistenceRequestDescriptor =
    $convert.base64Decode(
        'CiFTZXRTeW5jUmVzcG9uc2VQZXJzaXN0ZW5jZVJlcXVlc3QSGAoHZW5hYmxlZBgBIAEoCFIHZW'
        '5hYmxlZA==');

@$core.Deprecated('Use setSyncResponsePersistenceResponseDescriptor instead')
const SetSyncResponsePersistenceResponse$json = {
  '1': 'SetSyncResponsePersistenceResponse',
};

/// Descriptor for `SetSyncResponsePersistenceResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List setSyncResponsePersistenceResponseDescriptor =
    $convert.base64Decode('CiJTZXRTeW5jUmVzcG9uc2VQZXJzaXN0ZW5jZVJlc3BvbnNl');

@$core.Deprecated('Use tCPFlagsDescriptor instead')
const TCPFlags$json = {
  '1': 'TCPFlags',
  '2': [
    {'1': 'syn', '3': 1, '4': 1, '5': 8, '10': 'syn'},
    {'1': 'ack', '3': 2, '4': 1, '5': 8, '10': 'ack'},
    {'1': 'fin', '3': 3, '4': 1, '5': 8, '10': 'fin'},
    {'1': 'rst', '3': 4, '4': 1, '5': 8, '10': 'rst'},
    {'1': 'psh', '3': 5, '4': 1, '5': 8, '10': 'psh'},
    {'1': 'urg', '3': 6, '4': 1, '5': 8, '10': 'urg'},
  ],
};

/// Descriptor for `TCPFlags`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List tCPFlagsDescriptor = $convert.base64Decode(
    'CghUQ1BGbGFncxIQCgNzeW4YASABKAhSA3N5bhIQCgNhY2sYAiABKAhSA2FjaxIQCgNmaW4YAy'
    'ABKAhSA2ZpbhIQCgNyc3QYBCABKAhSA3JzdBIQCgNwc2gYBSABKAhSA3BzaBIQCgN1cmcYBiAB'
    'KAhSA3VyZw==');

@$core.Deprecated('Use tracePacketRequestDescriptor instead')
const TracePacketRequest$json = {
  '1': 'TracePacketRequest',
  '2': [
    {'1': 'source_ip', '3': 1, '4': 1, '5': 9, '10': 'sourceIp'},
    {'1': 'destination_ip', '3': 2, '4': 1, '5': 9, '10': 'destinationIp'},
    {'1': 'protocol', '3': 3, '4': 1, '5': 9, '10': 'protocol'},
    {'1': 'source_port', '3': 4, '4': 1, '5': 13, '10': 'sourcePort'},
    {'1': 'destination_port', '3': 5, '4': 1, '5': 13, '10': 'destinationPort'},
    {'1': 'direction', '3': 6, '4': 1, '5': 9, '10': 'direction'},
    {
      '1': 'tcp_flags',
      '3': 7,
      '4': 1,
      '5': 11,
      '6': '.daemon.TCPFlags',
      '9': 0,
      '10': 'tcpFlags',
      '17': true
    },
    {
      '1': 'icmp_type',
      '3': 8,
      '4': 1,
      '5': 13,
      '9': 1,
      '10': 'icmpType',
      '17': true
    },
    {
      '1': 'icmp_code',
      '3': 9,
      '4': 1,
      '5': 13,
      '9': 2,
      '10': 'icmpCode',
      '17': true
    },
  ],
  '8': [
    {'1': '_tcp_flags'},
    {'1': '_icmp_type'},
    {'1': '_icmp_code'},
  ],
};

/// Descriptor for `TracePacketRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List tracePacketRequestDescriptor = $convert.base64Decode(
    'ChJUcmFjZVBhY2tldFJlcXVlc3QSGwoJc291cmNlX2lwGAEgASgJUghzb3VyY2VJcBIlCg5kZX'
    'N0aW5hdGlvbl9pcBgCIAEoCVINZGVzdGluYXRpb25JcBIaCghwcm90b2NvbBgDIAEoCVIIcHJv'
    'dG9jb2wSHwoLc291cmNlX3BvcnQYBCABKA1SCnNvdXJjZVBvcnQSKQoQZGVzdGluYXRpb25fcG'
    '9ydBgFIAEoDVIPZGVzdGluYXRpb25Qb3J0EhwKCWRpcmVjdGlvbhgGIAEoCVIJZGlyZWN0aW9u'
    'EjIKCXRjcF9mbGFncxgHIAEoCzIQLmRhZW1vbi5UQ1BGbGFnc0gAUgh0Y3BGbGFnc4gBARIgCg'
    'lpY21wX3R5cGUYCCABKA1IAVIIaWNtcFR5cGWIAQESIAoJaWNtcF9jb2RlGAkgASgNSAJSCGlj'
    'bXBDb2RliAEBQgwKCl90Y3BfZmxhZ3NCDAoKX2ljbXBfdHlwZUIMCgpfaWNtcF9jb2Rl');

@$core.Deprecated('Use traceStageDescriptor instead')
const TraceStage$json = {
  '1': 'TraceStage',
  '2': [
    {'1': 'name', '3': 1, '4': 1, '5': 9, '10': 'name'},
    {'1': 'message', '3': 2, '4': 1, '5': 9, '10': 'message'},
    {'1': 'allowed', '3': 3, '4': 1, '5': 8, '10': 'allowed'},
    {
      '1': 'forwarding_details',
      '3': 4,
      '4': 1,
      '5': 9,
      '9': 0,
      '10': 'forwardingDetails',
      '17': true
    },
  ],
  '8': [
    {'1': '_forwarding_details'},
  ],
};

/// Descriptor for `TraceStage`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List traceStageDescriptor = $convert.base64Decode(
    'CgpUcmFjZVN0YWdlEhIKBG5hbWUYASABKAlSBG5hbWUSGAoHbWVzc2FnZRgCIAEoCVIHbWVzc2'
    'FnZRIYCgdhbGxvd2VkGAMgASgIUgdhbGxvd2VkEjIKEmZvcndhcmRpbmdfZGV0YWlscxgEIAEo'
    'CUgAUhFmb3J3YXJkaW5nRGV0YWlsc4gBAUIVChNfZm9yd2FyZGluZ19kZXRhaWxz');

@$core.Deprecated('Use tracePacketResponseDescriptor instead')
const TracePacketResponse$json = {
  '1': 'TracePacketResponse',
  '2': [
    {
      '1': 'stages',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.daemon.TraceStage',
      '10': 'stages'
    },
    {
      '1': 'final_disposition',
      '3': 2,
      '4': 1,
      '5': 8,
      '10': 'finalDisposition'
    },
  ],
};

/// Descriptor for `TracePacketResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List tracePacketResponseDescriptor = $convert.base64Decode(
    'ChNUcmFjZVBhY2tldFJlc3BvbnNlEioKBnN0YWdlcxgBIAMoCzISLmRhZW1vbi5UcmFjZVN0YW'
    'dlUgZzdGFnZXMSKwoRZmluYWxfZGlzcG9zaXRpb24YAiABKAhSEGZpbmFsRGlzcG9zaXRpb24=');

@$core.Deprecated('Use subscribeRequestDescriptor instead')
const SubscribeRequest$json = {
  '1': 'SubscribeRequest',
};

/// Descriptor for `SubscribeRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List subscribeRequestDescriptor =
    $convert.base64Decode('ChBTdWJzY3JpYmVSZXF1ZXN0');

@$core.Deprecated('Use systemEventDescriptor instead')
const SystemEvent$json = {
  '1': 'SystemEvent',
  '2': [
    {'1': 'id', '3': 1, '4': 1, '5': 9, '10': 'id'},
    {
      '1': 'severity',
      '3': 2,
      '4': 1,
      '5': 14,
      '6': '.daemon.SystemEvent.Severity',
      '10': 'severity'
    },
    {
      '1': 'category',
      '3': 3,
      '4': 1,
      '5': 14,
      '6': '.daemon.SystemEvent.Category',
      '10': 'category'
    },
    {'1': 'message', '3': 4, '4': 1, '5': 9, '10': 'message'},
    {'1': 'userMessage', '3': 5, '4': 1, '5': 9, '10': 'userMessage'},
    {
      '1': 'timestamp',
      '3': 6,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Timestamp',
      '10': 'timestamp'
    },
    {
      '1': 'metadata',
      '3': 7,
      '4': 3,
      '5': 11,
      '6': '.daemon.SystemEvent.MetadataEntry',
      '10': 'metadata'
    },
  ],
  '3': [SystemEvent_MetadataEntry$json],
  '4': [SystemEvent_Severity$json, SystemEvent_Category$json],
};

@$core.Deprecated('Use systemEventDescriptor instead')
const SystemEvent_MetadataEntry$json = {
  '1': 'MetadataEntry',
  '2': [
    {'1': 'key', '3': 1, '4': 1, '5': 9, '10': 'key'},
    {'1': 'value', '3': 2, '4': 1, '5': 9, '10': 'value'},
  ],
  '7': {'7': true},
};

@$core.Deprecated('Use systemEventDescriptor instead')
const SystemEvent_Severity$json = {
  '1': 'Severity',
  '2': [
    {'1': 'INFO', '2': 0},
    {'1': 'WARNING', '2': 1},
    {'1': 'ERROR', '2': 2},
    {'1': 'CRITICAL', '2': 3},
  ],
};

@$core.Deprecated('Use systemEventDescriptor instead')
const SystemEvent_Category$json = {
  '1': 'Category',
  '2': [
    {'1': 'NETWORK', '2': 0},
    {'1': 'DNS', '2': 1},
    {'1': 'AUTHENTICATION', '2': 2},
    {'1': 'CONNECTIVITY', '2': 3},
    {'1': 'SYSTEM', '2': 4},
  ],
};

/// Descriptor for `SystemEvent`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List systemEventDescriptor = $convert.base64Decode(
    'CgtTeXN0ZW1FdmVudBIOCgJpZBgBIAEoCVICaWQSOAoIc2V2ZXJpdHkYAiABKA4yHC5kYWVtb2'
    '4uU3lzdGVtRXZlbnQuU2V2ZXJpdHlSCHNldmVyaXR5EjgKCGNhdGVnb3J5GAMgASgOMhwuZGFl'
    'bW9uLlN5c3RlbUV2ZW50LkNhdGVnb3J5UghjYXRlZ29yeRIYCgdtZXNzYWdlGAQgASgJUgdtZX'
    'NzYWdlEiAKC3VzZXJNZXNzYWdlGAUgASgJUgt1c2VyTWVzc2FnZRI4Cgl0aW1lc3RhbXAYBiAB'
    'KAsyGi5nb29nbGUucHJvdG9idWYuVGltZXN0YW1wUgl0aW1lc3RhbXASPQoIbWV0YWRhdGEYBy'
    'ADKAsyIS5kYWVtb24uU3lzdGVtRXZlbnQuTWV0YWRhdGFFbnRyeVIIbWV0YWRhdGEaOwoNTWV0'
    'YWRhdGFFbnRyeRIQCgNrZXkYASABKAlSA2tleRIUCgV2YWx1ZRgCIAEoCVIFdmFsdWU6AjgBIj'
    'oKCFNldmVyaXR5EggKBElORk8QABILCgdXQVJOSU5HEAESCQoFRVJST1IQAhIMCghDUklUSUNB'
    'TBADIlIKCENhdGVnb3J5EgsKB05FVFdPUksQABIHCgNETlMQARISCg5BVVRIRU5USUNBVElPTh'
    'ACEhAKDENPTk5FQ1RJVklUWRADEgoKBlNZU1RFTRAE');

@$core.Deprecated('Use getEventsRequestDescriptor instead')
const GetEventsRequest$json = {
  '1': 'GetEventsRequest',
};

/// Descriptor for `GetEventsRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getEventsRequestDescriptor =
    $convert.base64Decode('ChBHZXRFdmVudHNSZXF1ZXN0');

@$core.Deprecated('Use getEventsResponseDescriptor instead')
const GetEventsResponse$json = {
  '1': 'GetEventsResponse',
  '2': [
    {
      '1': 'events',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.daemon.SystemEvent',
      '10': 'events'
    },
  ],
};

/// Descriptor for `GetEventsResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getEventsResponseDescriptor = $convert.base64Decode(
    'ChFHZXRFdmVudHNSZXNwb25zZRIrCgZldmVudHMYASADKAsyEy5kYWVtb24uU3lzdGVtRXZlbn'
    'RSBmV2ZW50cw==');

@$core.Deprecated('Use switchProfileRequestDescriptor instead')
const SwitchProfileRequest$json = {
  '1': 'SwitchProfileRequest',
  '2': [
    {
      '1': 'profileName',
      '3': 1,
      '4': 1,
      '5': 9,
      '9': 0,
      '10': 'profileName',
      '17': true
    },
    {
      '1': 'username',
      '3': 2,
      '4': 1,
      '5': 9,
      '9': 1,
      '10': 'username',
      '17': true
    },
  ],
  '8': [
    {'1': '_profileName'},
    {'1': '_username'},
  ],
};

/// Descriptor for `SwitchProfileRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List switchProfileRequestDescriptor = $convert.base64Decode(
    'ChRTd2l0Y2hQcm9maWxlUmVxdWVzdBIlCgtwcm9maWxlTmFtZRgBIAEoCUgAUgtwcm9maWxlTm'
    'FtZYgBARIfCgh1c2VybmFtZRgCIAEoCUgBUgh1c2VybmFtZYgBAUIOCgxfcHJvZmlsZU5hbWVC'
    'CwoJX3VzZXJuYW1l');

@$core.Deprecated('Use switchProfileResponseDescriptor instead')
const SwitchProfileResponse$json = {
  '1': 'SwitchProfileResponse',
};

/// Descriptor for `SwitchProfileResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List switchProfileResponseDescriptor =
    $convert.base64Decode('ChVTd2l0Y2hQcm9maWxlUmVzcG9uc2U=');

@$core.Deprecated('Use setConfigRequestDescriptor instead')
const SetConfigRequest$json = {
  '1': 'SetConfigRequest',
  '2': [
    {'1': 'username', '3': 1, '4': 1, '5': 9, '10': 'username'},
    {'1': 'profileName', '3': 2, '4': 1, '5': 9, '10': 'profileName'},
    {'1': 'managementUrl', '3': 3, '4': 1, '5': 9, '10': 'managementUrl'},
    {'1': 'adminURL', '3': 4, '4': 1, '5': 9, '10': 'adminURL'},
    {
      '1': 'rosenpassEnabled',
      '3': 5,
      '4': 1,
      '5': 8,
      '9': 0,
      '10': 'rosenpassEnabled',
      '17': true
    },
    {
      '1': 'interfaceName',
      '3': 6,
      '4': 1,
      '5': 9,
      '9': 1,
      '10': 'interfaceName',
      '17': true
    },
    {
      '1': 'wireguardPort',
      '3': 7,
      '4': 1,
      '5': 3,
      '9': 2,
      '10': 'wireguardPort',
      '17': true
    },
    {
      '1': 'optionalPreSharedKey',
      '3': 8,
      '4': 1,
      '5': 9,
      '9': 3,
      '10': 'optionalPreSharedKey',
      '17': true
    },
    {
      '1': 'disableAutoConnect',
      '3': 9,
      '4': 1,
      '5': 8,
      '9': 4,
      '10': 'disableAutoConnect',
      '17': true
    },
    {
      '1': 'serverSSHAllowed',
      '3': 10,
      '4': 1,
      '5': 8,
      '9': 5,
      '10': 'serverSSHAllowed',
      '17': true
    },
    {
      '1': 'rosenpassPermissive',
      '3': 11,
      '4': 1,
      '5': 8,
      '9': 6,
      '10': 'rosenpassPermissive',
      '17': true
    },
    {
      '1': 'networkMonitor',
      '3': 12,
      '4': 1,
      '5': 8,
      '9': 7,
      '10': 'networkMonitor',
      '17': true
    },
    {
      '1': 'disable_client_routes',
      '3': 13,
      '4': 1,
      '5': 8,
      '9': 8,
      '10': 'disableClientRoutes',
      '17': true
    },
    {
      '1': 'disable_server_routes',
      '3': 14,
      '4': 1,
      '5': 8,
      '9': 9,
      '10': 'disableServerRoutes',
      '17': true
    },
    {
      '1': 'disable_dns',
      '3': 15,
      '4': 1,
      '5': 8,
      '9': 10,
      '10': 'disableDns',
      '17': true
    },
    {
      '1': 'disable_firewall',
      '3': 16,
      '4': 1,
      '5': 8,
      '9': 11,
      '10': 'disableFirewall',
      '17': true
    },
    {
      '1': 'block_lan_access',
      '3': 17,
      '4': 1,
      '5': 8,
      '9': 12,
      '10': 'blockLanAccess',
      '17': true
    },
    {
      '1': 'disable_notifications',
      '3': 18,
      '4': 1,
      '5': 8,
      '9': 13,
      '10': 'disableNotifications',
      '17': true
    },
    {
      '1': 'lazyConnectionEnabled',
      '3': 19,
      '4': 1,
      '5': 8,
      '9': 14,
      '10': 'lazyConnectionEnabled',
      '17': true
    },
    {
      '1': 'block_inbound',
      '3': 20,
      '4': 1,
      '5': 8,
      '9': 15,
      '10': 'blockInbound',
      '17': true
    },
    {'1': 'natExternalIPs', '3': 21, '4': 3, '5': 9, '10': 'natExternalIPs'},
    {
      '1': 'cleanNATExternalIPs',
      '3': 22,
      '4': 1,
      '5': 8,
      '10': 'cleanNATExternalIPs'
    },
    {
      '1': 'customDNSAddress',
      '3': 23,
      '4': 1,
      '5': 12,
      '10': 'customDNSAddress'
    },
    {
      '1': 'extraIFaceBlacklist',
      '3': 24,
      '4': 3,
      '5': 9,
      '10': 'extraIFaceBlacklist'
    },
    {'1': 'dns_labels', '3': 25, '4': 3, '5': 9, '10': 'dnsLabels'},
    {'1': 'cleanDNSLabels', '3': 26, '4': 1, '5': 8, '10': 'cleanDNSLabels'},
    {
      '1': 'dnsRouteInterval',
      '3': 27,
      '4': 1,
      '5': 11,
      '6': '.google.protobuf.Duration',
      '9': 16,
      '10': 'dnsRouteInterval',
      '17': true
    },
    {'1': 'mtu', '3': 28, '4': 1, '5': 3, '9': 17, '10': 'mtu', '17': true},
    {
      '1': 'enableSSHRoot',
      '3': 29,
      '4': 1,
      '5': 8,
      '9': 18,
      '10': 'enableSSHRoot',
      '17': true
    },
    {
      '1': 'enableSSHSFTP',
      '3': 30,
      '4': 1,
      '5': 8,
      '9': 19,
      '10': 'enableSSHSFTP',
      '17': true
    },
    {
      '1': 'enableSSHLocalPortForwarding',
      '3': 31,
      '4': 1,
      '5': 8,
      '9': 20,
      '10': 'enableSSHLocalPortForwarding',
      '17': true
    },
    {
      '1': 'enableSSHRemotePortForwarding',
      '3': 32,
      '4': 1,
      '5': 8,
      '9': 21,
      '10': 'enableSSHRemotePortForwarding',
      '17': true
    },
    {
      '1': 'disableSSHAuth',
      '3': 33,
      '4': 1,
      '5': 8,
      '9': 22,
      '10': 'disableSSHAuth',
      '17': true
    },
    {
      '1': 'sshJWTCacheTTL',
      '3': 34,
      '4': 1,
      '5': 5,
      '9': 23,
      '10': 'sshJWTCacheTTL',
      '17': true
    },
  ],
  '8': [
    {'1': '_rosenpassEnabled'},
    {'1': '_interfaceName'},
    {'1': '_wireguardPort'},
    {'1': '_optionalPreSharedKey'},
    {'1': '_disableAutoConnect'},
    {'1': '_serverSSHAllowed'},
    {'1': '_rosenpassPermissive'},
    {'1': '_networkMonitor'},
    {'1': '_disable_client_routes'},
    {'1': '_disable_server_routes'},
    {'1': '_disable_dns'},
    {'1': '_disable_firewall'},
    {'1': '_block_lan_access'},
    {'1': '_disable_notifications'},
    {'1': '_lazyConnectionEnabled'},
    {'1': '_block_inbound'},
    {'1': '_dnsRouteInterval'},
    {'1': '_mtu'},
    {'1': '_enableSSHRoot'},
    {'1': '_enableSSHSFTP'},
    {'1': '_enableSSHLocalPortForwarding'},
    {'1': '_enableSSHRemotePortForwarding'},
    {'1': '_disableSSHAuth'},
    {'1': '_sshJWTCacheTTL'},
  ],
};

/// Descriptor for `SetConfigRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List setConfigRequestDescriptor = $convert.base64Decode(
    'ChBTZXRDb25maWdSZXF1ZXN0EhoKCHVzZXJuYW1lGAEgASgJUgh1c2VybmFtZRIgCgtwcm9maW'
    'xlTmFtZRgCIAEoCVILcHJvZmlsZU5hbWUSJAoNbWFuYWdlbWVudFVybBgDIAEoCVINbWFuYWdl'
    'bWVudFVybBIaCghhZG1pblVSTBgEIAEoCVIIYWRtaW5VUkwSLwoQcm9zZW5wYXNzRW5hYmxlZB'
    'gFIAEoCEgAUhByb3NlbnBhc3NFbmFibGVkiAEBEikKDWludGVyZmFjZU5hbWUYBiABKAlIAVIN'
    'aW50ZXJmYWNlTmFtZYgBARIpCg13aXJlZ3VhcmRQb3J0GAcgASgDSAJSDXdpcmVndWFyZFBvcn'
    'SIAQESNwoUb3B0aW9uYWxQcmVTaGFyZWRLZXkYCCABKAlIA1IUb3B0aW9uYWxQcmVTaGFyZWRL'
    'ZXmIAQESMwoSZGlzYWJsZUF1dG9Db25uZWN0GAkgASgISARSEmRpc2FibGVBdXRvQ29ubmVjdI'
    'gBARIvChBzZXJ2ZXJTU0hBbGxvd2VkGAogASgISAVSEHNlcnZlclNTSEFsbG93ZWSIAQESNQoT'
    'cm9zZW5wYXNzUGVybWlzc2l2ZRgLIAEoCEgGUhNyb3NlbnBhc3NQZXJtaXNzaXZliAEBEisKDm'
    '5ldHdvcmtNb25pdG9yGAwgASgISAdSDm5ldHdvcmtNb25pdG9yiAEBEjcKFWRpc2FibGVfY2xp'
    'ZW50X3JvdXRlcxgNIAEoCEgIUhNkaXNhYmxlQ2xpZW50Um91dGVziAEBEjcKFWRpc2FibGVfc2'
    'VydmVyX3JvdXRlcxgOIAEoCEgJUhNkaXNhYmxlU2VydmVyUm91dGVziAEBEiQKC2Rpc2FibGVf'
    'ZG5zGA8gASgISApSCmRpc2FibGVEbnOIAQESLgoQZGlzYWJsZV9maXJld2FsbBgQIAEoCEgLUg'
    '9kaXNhYmxlRmlyZXdhbGyIAQESLQoQYmxvY2tfbGFuX2FjY2VzcxgRIAEoCEgMUg5ibG9ja0xh'
    'bkFjY2Vzc4gBARI4ChVkaXNhYmxlX25vdGlmaWNhdGlvbnMYEiABKAhIDVIUZGlzYWJsZU5vdG'
    'lmaWNhdGlvbnOIAQESOQoVbGF6eUNvbm5lY3Rpb25FbmFibGVkGBMgASgISA5SFWxhenlDb25u'
    'ZWN0aW9uRW5hYmxlZIgBARIoCg1ibG9ja19pbmJvdW5kGBQgASgISA9SDGJsb2NrSW5ib3VuZI'
    'gBARImCg5uYXRFeHRlcm5hbElQcxgVIAMoCVIObmF0RXh0ZXJuYWxJUHMSMAoTY2xlYW5OQVRF'
    'eHRlcm5hbElQcxgWIAEoCFITY2xlYW5OQVRFeHRlcm5hbElQcxIqChBjdXN0b21ETlNBZGRyZX'
    'NzGBcgASgMUhBjdXN0b21ETlNBZGRyZXNzEjAKE2V4dHJhSUZhY2VCbGFja2xpc3QYGCADKAlS'
    'E2V4dHJhSUZhY2VCbGFja2xpc3QSHQoKZG5zX2xhYmVscxgZIAMoCVIJZG5zTGFiZWxzEiYKDm'
    'NsZWFuRE5TTGFiZWxzGBogASgIUg5jbGVhbkROU0xhYmVscxJKChBkbnNSb3V0ZUludGVydmFs'
    'GBsgASgLMhkuZ29vZ2xlLnByb3RvYnVmLkR1cmF0aW9uSBBSEGRuc1JvdXRlSW50ZXJ2YWyIAQ'
    'ESFQoDbXR1GBwgASgDSBFSA210dYgBARIpCg1lbmFibGVTU0hSb290GB0gASgISBJSDWVuYWJs'
    'ZVNTSFJvb3SIAQESKQoNZW5hYmxlU1NIU0ZUUBgeIAEoCEgTUg1lbmFibGVTU0hTRlRQiAEBEk'
    'cKHGVuYWJsZVNTSExvY2FsUG9ydEZvcndhcmRpbmcYHyABKAhIFFIcZW5hYmxlU1NITG9jYWxQ'
    'b3J0Rm9yd2FyZGluZ4gBARJJCh1lbmFibGVTU0hSZW1vdGVQb3J0Rm9yd2FyZGluZxggIAEoCE'
    'gVUh1lbmFibGVTU0hSZW1vdGVQb3J0Rm9yd2FyZGluZ4gBARIrCg5kaXNhYmxlU1NIQXV0aBgh'
    'IAEoCEgWUg5kaXNhYmxlU1NIQXV0aIgBARIrCg5zc2hKV1RDYWNoZVRUTBgiIAEoBUgXUg5zc2'
    'hKV1RDYWNoZVRUTIgBAUITChFfcm9zZW5wYXNzRW5hYmxlZEIQCg5faW50ZXJmYWNlTmFtZUIQ'
    'Cg5fd2lyZWd1YXJkUG9ydEIXChVfb3B0aW9uYWxQcmVTaGFyZWRLZXlCFQoTX2Rpc2FibGVBdX'
    'RvQ29ubmVjdEITChFfc2VydmVyU1NIQWxsb3dlZEIWChRfcm9zZW5wYXNzUGVybWlzc2l2ZUIR'
    'Cg9fbmV0d29ya01vbml0b3JCGAoWX2Rpc2FibGVfY2xpZW50X3JvdXRlc0IYChZfZGlzYWJsZV'
    '9zZXJ2ZXJfcm91dGVzQg4KDF9kaXNhYmxlX2Ruc0ITChFfZGlzYWJsZV9maXJld2FsbEITChFf'
    'YmxvY2tfbGFuX2FjY2Vzc0IYChZfZGlzYWJsZV9ub3RpZmljYXRpb25zQhgKFl9sYXp5Q29ubm'
    'VjdGlvbkVuYWJsZWRCEAoOX2Jsb2NrX2luYm91bmRCEwoRX2Ruc1JvdXRlSW50ZXJ2YWxCBgoE'
    'X210dUIQCg5fZW5hYmxlU1NIUm9vdEIQCg5fZW5hYmxlU1NIU0ZUUEIfCh1fZW5hYmxlU1NITG'
    '9jYWxQb3J0Rm9yd2FyZGluZ0IgCh5fZW5hYmxlU1NIUmVtb3RlUG9ydEZvcndhcmRpbmdCEQoP'
    'X2Rpc2FibGVTU0hBdXRoQhEKD19zc2hKV1RDYWNoZVRUTA==');

@$core.Deprecated('Use setConfigResponseDescriptor instead')
const SetConfigResponse$json = {
  '1': 'SetConfigResponse',
};

/// Descriptor for `SetConfigResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List setConfigResponseDescriptor =
    $convert.base64Decode('ChFTZXRDb25maWdSZXNwb25zZQ==');

@$core.Deprecated('Use addProfileRequestDescriptor instead')
const AddProfileRequest$json = {
  '1': 'AddProfileRequest',
  '2': [
    {'1': 'username', '3': 1, '4': 1, '5': 9, '10': 'username'},
    {'1': 'profileName', '3': 2, '4': 1, '5': 9, '10': 'profileName'},
  ],
};

/// Descriptor for `AddProfileRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List addProfileRequestDescriptor = $convert.base64Decode(
    'ChFBZGRQcm9maWxlUmVxdWVzdBIaCgh1c2VybmFtZRgBIAEoCVIIdXNlcm5hbWUSIAoLcHJvZm'
    'lsZU5hbWUYAiABKAlSC3Byb2ZpbGVOYW1l');

@$core.Deprecated('Use addProfileResponseDescriptor instead')
const AddProfileResponse$json = {
  '1': 'AddProfileResponse',
};

/// Descriptor for `AddProfileResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List addProfileResponseDescriptor =
    $convert.base64Decode('ChJBZGRQcm9maWxlUmVzcG9uc2U=');

@$core.Deprecated('Use removeProfileRequestDescriptor instead')
const RemoveProfileRequest$json = {
  '1': 'RemoveProfileRequest',
  '2': [
    {'1': 'username', '3': 1, '4': 1, '5': 9, '10': 'username'},
    {'1': 'profileName', '3': 2, '4': 1, '5': 9, '10': 'profileName'},
  ],
};

/// Descriptor for `RemoveProfileRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeProfileRequestDescriptor = $convert.base64Decode(
    'ChRSZW1vdmVQcm9maWxlUmVxdWVzdBIaCgh1c2VybmFtZRgBIAEoCVIIdXNlcm5hbWUSIAoLcH'
    'JvZmlsZU5hbWUYAiABKAlSC3Byb2ZpbGVOYW1l');

@$core.Deprecated('Use removeProfileResponseDescriptor instead')
const RemoveProfileResponse$json = {
  '1': 'RemoveProfileResponse',
};

/// Descriptor for `RemoveProfileResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List removeProfileResponseDescriptor =
    $convert.base64Decode('ChVSZW1vdmVQcm9maWxlUmVzcG9uc2U=');

@$core.Deprecated('Use listProfilesRequestDescriptor instead')
const ListProfilesRequest$json = {
  '1': 'ListProfilesRequest',
  '2': [
    {'1': 'username', '3': 1, '4': 1, '5': 9, '10': 'username'},
  ],
};

/// Descriptor for `ListProfilesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listProfilesRequestDescriptor =
    $convert.base64Decode(
        'ChNMaXN0UHJvZmlsZXNSZXF1ZXN0EhoKCHVzZXJuYW1lGAEgASgJUgh1c2VybmFtZQ==');

@$core.Deprecated('Use listProfilesResponseDescriptor instead')
const ListProfilesResponse$json = {
  '1': 'ListProfilesResponse',
  '2': [
    {
      '1': 'profiles',
      '3': 1,
      '4': 3,
      '5': 11,
      '6': '.daemon.Profile',
      '10': 'profiles'
    },
  ],
};

/// Descriptor for `ListProfilesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List listProfilesResponseDescriptor = $convert.base64Decode(
    'ChRMaXN0UHJvZmlsZXNSZXNwb25zZRIrCghwcm9maWxlcxgBIAMoCzIPLmRhZW1vbi5Qcm9maW'
    'xlUghwcm9maWxlcw==');

@$core.Deprecated('Use profileDescriptor instead')
const Profile$json = {
  '1': 'Profile',
  '2': [
    {'1': 'name', '3': 1, '4': 1, '5': 9, '10': 'name'},
    {'1': 'is_active', '3': 2, '4': 1, '5': 8, '10': 'isActive'},
  ],
};

/// Descriptor for `Profile`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List profileDescriptor = $convert.base64Decode(
    'CgdQcm9maWxlEhIKBG5hbWUYASABKAlSBG5hbWUSGwoJaXNfYWN0aXZlGAIgASgIUghpc0FjdG'
    'l2ZQ==');

@$core.Deprecated('Use getActiveProfileRequestDescriptor instead')
const GetActiveProfileRequest$json = {
  '1': 'GetActiveProfileRequest',
};

/// Descriptor for `GetActiveProfileRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getActiveProfileRequestDescriptor =
    $convert.base64Decode('ChdHZXRBY3RpdmVQcm9maWxlUmVxdWVzdA==');

@$core.Deprecated('Use getActiveProfileResponseDescriptor instead')
const GetActiveProfileResponse$json = {
  '1': 'GetActiveProfileResponse',
  '2': [
    {'1': 'profileName', '3': 1, '4': 1, '5': 9, '10': 'profileName'},
    {'1': 'username', '3': 2, '4': 1, '5': 9, '10': 'username'},
  ],
};

/// Descriptor for `GetActiveProfileResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getActiveProfileResponseDescriptor =
    $convert.base64Decode(
        'ChhHZXRBY3RpdmVQcm9maWxlUmVzcG9uc2USIAoLcHJvZmlsZU5hbWUYASABKAlSC3Byb2ZpbG'
        'VOYW1lEhoKCHVzZXJuYW1lGAIgASgJUgh1c2VybmFtZQ==');

@$core.Deprecated('Use logoutRequestDescriptor instead')
const LogoutRequest$json = {
  '1': 'LogoutRequest',
  '2': [
    {
      '1': 'profileName',
      '3': 1,
      '4': 1,
      '5': 9,
      '9': 0,
      '10': 'profileName',
      '17': true
    },
    {
      '1': 'username',
      '3': 2,
      '4': 1,
      '5': 9,
      '9': 1,
      '10': 'username',
      '17': true
    },
  ],
  '8': [
    {'1': '_profileName'},
    {'1': '_username'},
  ],
};

/// Descriptor for `LogoutRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List logoutRequestDescriptor = $convert.base64Decode(
    'Cg1Mb2dvdXRSZXF1ZXN0EiUKC3Byb2ZpbGVOYW1lGAEgASgJSABSC3Byb2ZpbGVOYW1liAEBEh'
    '8KCHVzZXJuYW1lGAIgASgJSAFSCHVzZXJuYW1liAEBQg4KDF9wcm9maWxlTmFtZUILCglfdXNl'
    'cm5hbWU=');

@$core.Deprecated('Use logoutResponseDescriptor instead')
const LogoutResponse$json = {
  '1': 'LogoutResponse',
};

/// Descriptor for `LogoutResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List logoutResponseDescriptor =
    $convert.base64Decode('Cg5Mb2dvdXRSZXNwb25zZQ==');

@$core.Deprecated('Use getFeaturesRequestDescriptor instead')
const GetFeaturesRequest$json = {
  '1': 'GetFeaturesRequest',
};

/// Descriptor for `GetFeaturesRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getFeaturesRequestDescriptor =
    $convert.base64Decode('ChJHZXRGZWF0dXJlc1JlcXVlc3Q=');

@$core.Deprecated('Use getFeaturesResponseDescriptor instead')
const GetFeaturesResponse$json = {
  '1': 'GetFeaturesResponse',
  '2': [
    {'1': 'disable_profiles', '3': 1, '4': 1, '5': 8, '10': 'disableProfiles'},
    {
      '1': 'disable_update_settings',
      '3': 2,
      '4': 1,
      '5': 8,
      '10': 'disableUpdateSettings'
    },
    {'1': 'disable_networks', '3': 3, '4': 1, '5': 8, '10': 'disableNetworks'},
  ],
};

/// Descriptor for `GetFeaturesResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getFeaturesResponseDescriptor = $convert.base64Decode(
    'ChNHZXRGZWF0dXJlc1Jlc3BvbnNlEikKEGRpc2FibGVfcHJvZmlsZXMYASABKAhSD2Rpc2FibG'
    'VQcm9maWxlcxI2ChdkaXNhYmxlX3VwZGF0ZV9zZXR0aW5ncxgCIAEoCFIVZGlzYWJsZVVwZGF0'
    'ZVNldHRpbmdzEikKEGRpc2FibGVfbmV0d29ya3MYAyABKAhSD2Rpc2FibGVOZXR3b3Jrcw==');

@$core.Deprecated('Use triggerUpdateRequestDescriptor instead')
const TriggerUpdateRequest$json = {
  '1': 'TriggerUpdateRequest',
};

/// Descriptor for `TriggerUpdateRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List triggerUpdateRequestDescriptor =
    $convert.base64Decode('ChRUcmlnZ2VyVXBkYXRlUmVxdWVzdA==');

@$core.Deprecated('Use triggerUpdateResponseDescriptor instead')
const TriggerUpdateResponse$json = {
  '1': 'TriggerUpdateResponse',
  '2': [
    {'1': 'success', '3': 1, '4': 1, '5': 8, '10': 'success'},
    {'1': 'errorMsg', '3': 2, '4': 1, '5': 9, '10': 'errorMsg'},
  ],
};

/// Descriptor for `TriggerUpdateResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List triggerUpdateResponseDescriptor = $convert.base64Decode(
    'ChVUcmlnZ2VyVXBkYXRlUmVzcG9uc2USGAoHc3VjY2VzcxgBIAEoCFIHc3VjY2VzcxIaCghlcn'
    'Jvck1zZxgCIAEoCVIIZXJyb3JNc2c=');

@$core.Deprecated('Use getPeerSSHHostKeyRequestDescriptor instead')
const GetPeerSSHHostKeyRequest$json = {
  '1': 'GetPeerSSHHostKeyRequest',
  '2': [
    {'1': 'peerAddress', '3': 1, '4': 1, '5': 9, '10': 'peerAddress'},
  ],
};

/// Descriptor for `GetPeerSSHHostKeyRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPeerSSHHostKeyRequestDescriptor =
    $convert.base64Decode(
        'ChhHZXRQZWVyU1NISG9zdEtleVJlcXVlc3QSIAoLcGVlckFkZHJlc3MYASABKAlSC3BlZXJBZG'
        'RyZXNz');

@$core.Deprecated('Use getPeerSSHHostKeyResponseDescriptor instead')
const GetPeerSSHHostKeyResponse$json = {
  '1': 'GetPeerSSHHostKeyResponse',
  '2': [
    {'1': 'sshHostKey', '3': 1, '4': 1, '5': 12, '10': 'sshHostKey'},
    {'1': 'peerIP', '3': 2, '4': 1, '5': 9, '10': 'peerIP'},
    {'1': 'peerFQDN', '3': 3, '4': 1, '5': 9, '10': 'peerFQDN'},
    {'1': 'found', '3': 4, '4': 1, '5': 8, '10': 'found'},
  ],
};

/// Descriptor for `GetPeerSSHHostKeyResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List getPeerSSHHostKeyResponseDescriptor = $convert.base64Decode(
    'ChlHZXRQZWVyU1NISG9zdEtleVJlc3BvbnNlEh4KCnNzaEhvc3RLZXkYASABKAxSCnNzaEhvc3'
    'RLZXkSFgoGcGVlcklQGAIgASgJUgZwZWVySVASGgoIcGVlckZRRE4YAyABKAlSCHBlZXJGUURO'
    'EhQKBWZvdW5kGAQgASgIUgVmb3VuZA==');

@$core.Deprecated('Use requestJWTAuthRequestDescriptor instead')
const RequestJWTAuthRequest$json = {
  '1': 'RequestJWTAuthRequest',
  '2': [
    {'1': 'hint', '3': 1, '4': 1, '5': 9, '9': 0, '10': 'hint', '17': true},
  ],
  '8': [
    {'1': '_hint'},
  ],
};

/// Descriptor for `RequestJWTAuthRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List requestJWTAuthRequestDescriptor = $convert.base64Decode(
    'ChVSZXF1ZXN0SldUQXV0aFJlcXVlc3QSFwoEaGludBgBIAEoCUgAUgRoaW50iAEBQgcKBV9oaW'
    '50');

@$core.Deprecated('Use requestJWTAuthResponseDescriptor instead')
const RequestJWTAuthResponse$json = {
  '1': 'RequestJWTAuthResponse',
  '2': [
    {'1': 'verificationURI', '3': 1, '4': 1, '5': 9, '10': 'verificationURI'},
    {
      '1': 'verificationURIComplete',
      '3': 2,
      '4': 1,
      '5': 9,
      '10': 'verificationURIComplete'
    },
    {'1': 'userCode', '3': 3, '4': 1, '5': 9, '10': 'userCode'},
    {'1': 'deviceCode', '3': 4, '4': 1, '5': 9, '10': 'deviceCode'},
    {'1': 'expiresIn', '3': 5, '4': 1, '5': 3, '10': 'expiresIn'},
    {'1': 'cachedToken', '3': 6, '4': 1, '5': 9, '10': 'cachedToken'},
    {'1': 'maxTokenAge', '3': 7, '4': 1, '5': 3, '10': 'maxTokenAge'},
  ],
};

/// Descriptor for `RequestJWTAuthResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List requestJWTAuthResponseDescriptor = $convert.base64Decode(
    'ChZSZXF1ZXN0SldUQXV0aFJlc3BvbnNlEigKD3ZlcmlmaWNhdGlvblVSSRgBIAEoCVIPdmVyaW'
    'ZpY2F0aW9uVVJJEjgKF3ZlcmlmaWNhdGlvblVSSUNvbXBsZXRlGAIgASgJUhd2ZXJpZmljYXRp'
    'b25VUklDb21wbGV0ZRIaCgh1c2VyQ29kZRgDIAEoCVIIdXNlckNvZGUSHgoKZGV2aWNlQ29kZR'
    'gEIAEoCVIKZGV2aWNlQ29kZRIcCglleHBpcmVzSW4YBSABKANSCWV4cGlyZXNJbhIgCgtjYWNo'
    'ZWRUb2tlbhgGIAEoCVILY2FjaGVkVG9rZW4SIAoLbWF4VG9rZW5BZ2UYByABKANSC21heFRva2'
    'VuQWdl');

@$core.Deprecated('Use waitJWTTokenRequestDescriptor instead')
const WaitJWTTokenRequest$json = {
  '1': 'WaitJWTTokenRequest',
  '2': [
    {'1': 'deviceCode', '3': 1, '4': 1, '5': 9, '10': 'deviceCode'},
    {'1': 'userCode', '3': 2, '4': 1, '5': 9, '10': 'userCode'},
  ],
};

/// Descriptor for `WaitJWTTokenRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List waitJWTTokenRequestDescriptor = $convert.base64Decode(
    'ChNXYWl0SldUVG9rZW5SZXF1ZXN0Eh4KCmRldmljZUNvZGUYASABKAlSCmRldmljZUNvZGUSGg'
    'oIdXNlckNvZGUYAiABKAlSCHVzZXJDb2Rl');

@$core.Deprecated('Use waitJWTTokenResponseDescriptor instead')
const WaitJWTTokenResponse$json = {
  '1': 'WaitJWTTokenResponse',
  '2': [
    {'1': 'token', '3': 1, '4': 1, '5': 9, '10': 'token'},
    {'1': 'tokenType', '3': 2, '4': 1, '5': 9, '10': 'tokenType'},
    {'1': 'expiresIn', '3': 3, '4': 1, '5': 3, '10': 'expiresIn'},
  ],
};

/// Descriptor for `WaitJWTTokenResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List waitJWTTokenResponseDescriptor = $convert.base64Decode(
    'ChRXYWl0SldUVG9rZW5SZXNwb25zZRIUCgV0b2tlbhgBIAEoCVIFdG9rZW4SHAoJdG9rZW5UeX'
    'BlGAIgASgJUgl0b2tlblR5cGUSHAoJZXhwaXJlc0luGAMgASgDUglleHBpcmVzSW4=');

@$core.Deprecated('Use startCPUProfileRequestDescriptor instead')
const StartCPUProfileRequest$json = {
  '1': 'StartCPUProfileRequest',
};

/// Descriptor for `StartCPUProfileRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List startCPUProfileRequestDescriptor =
    $convert.base64Decode('ChZTdGFydENQVVByb2ZpbGVSZXF1ZXN0');

@$core.Deprecated('Use startCPUProfileResponseDescriptor instead')
const StartCPUProfileResponse$json = {
  '1': 'StartCPUProfileResponse',
};

/// Descriptor for `StartCPUProfileResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List startCPUProfileResponseDescriptor =
    $convert.base64Decode('ChdTdGFydENQVVByb2ZpbGVSZXNwb25zZQ==');

@$core.Deprecated('Use stopCPUProfileRequestDescriptor instead')
const StopCPUProfileRequest$json = {
  '1': 'StopCPUProfileRequest',
};

/// Descriptor for `StopCPUProfileRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List stopCPUProfileRequestDescriptor =
    $convert.base64Decode('ChVTdG9wQ1BVUHJvZmlsZVJlcXVlc3Q=');

@$core.Deprecated('Use stopCPUProfileResponseDescriptor instead')
const StopCPUProfileResponse$json = {
  '1': 'StopCPUProfileResponse',
};

/// Descriptor for `StopCPUProfileResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List stopCPUProfileResponseDescriptor =
    $convert.base64Decode('ChZTdG9wQ1BVUHJvZmlsZVJlc3BvbnNl');

@$core.Deprecated('Use installerResultRequestDescriptor instead')
const InstallerResultRequest$json = {
  '1': 'InstallerResultRequest',
};

/// Descriptor for `InstallerResultRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List installerResultRequestDescriptor =
    $convert.base64Decode('ChZJbnN0YWxsZXJSZXN1bHRSZXF1ZXN0');

@$core.Deprecated('Use installerResultResponseDescriptor instead')
const InstallerResultResponse$json = {
  '1': 'InstallerResultResponse',
  '2': [
    {'1': 'success', '3': 1, '4': 1, '5': 8, '10': 'success'},
    {'1': 'errorMsg', '3': 2, '4': 1, '5': 9, '10': 'errorMsg'},
  ],
};

/// Descriptor for `InstallerResultResponse`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List installerResultResponseDescriptor =
    $convert.base64Decode(
        'ChdJbnN0YWxsZXJSZXN1bHRSZXNwb25zZRIYCgdzdWNjZXNzGAEgASgIUgdzdWNjZXNzEhoKCG'
        'Vycm9yTXNnGAIgASgJUghlcnJvck1zZw==');

@$core.Deprecated('Use exposeServiceRequestDescriptor instead')
const ExposeServiceRequest$json = {
  '1': 'ExposeServiceRequest',
  '2': [
    {'1': 'port', '3': 1, '4': 1, '5': 13, '10': 'port'},
    {
      '1': 'protocol',
      '3': 2,
      '4': 1,
      '5': 14,
      '6': '.daemon.ExposeProtocol',
      '10': 'protocol'
    },
    {'1': 'pin', '3': 3, '4': 1, '5': 9, '10': 'pin'},
    {'1': 'password', '3': 4, '4': 1, '5': 9, '10': 'password'},
    {'1': 'user_groups', '3': 5, '4': 3, '5': 9, '10': 'userGroups'},
    {'1': 'domain', '3': 6, '4': 1, '5': 9, '10': 'domain'},
    {'1': 'name_prefix', '3': 7, '4': 1, '5': 9, '10': 'namePrefix'},
    {'1': 'listen_port', '3': 8, '4': 1, '5': 13, '10': 'listenPort'},
  ],
};

/// Descriptor for `ExposeServiceRequest`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List exposeServiceRequestDescriptor = $convert.base64Decode(
    'ChRFeHBvc2VTZXJ2aWNlUmVxdWVzdBISCgRwb3J0GAEgASgNUgRwb3J0EjIKCHByb3RvY29sGA'
    'IgASgOMhYuZGFlbW9uLkV4cG9zZVByb3RvY29sUghwcm90b2NvbBIQCgNwaW4YAyABKAlSA3Bp'
    'bhIaCghwYXNzd29yZBgEIAEoCVIIcGFzc3dvcmQSHwoLdXNlcl9ncm91cHMYBSADKAlSCnVzZX'
    'JHcm91cHMSFgoGZG9tYWluGAYgASgJUgZkb21haW4SHwoLbmFtZV9wcmVmaXgYByABKAlSCm5h'
    'bWVQcmVmaXgSHwoLbGlzdGVuX3BvcnQYCCABKA1SCmxpc3RlblBvcnQ=');

@$core.Deprecated('Use exposeServiceEventDescriptor instead')
const ExposeServiceEvent$json = {
  '1': 'ExposeServiceEvent',
  '2': [
    {
      '1': 'ready',
      '3': 1,
      '4': 1,
      '5': 11,
      '6': '.daemon.ExposeServiceReady',
      '9': 0,
      '10': 'ready'
    },
  ],
  '8': [
    {'1': 'event'},
  ],
};

/// Descriptor for `ExposeServiceEvent`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List exposeServiceEventDescriptor = $convert.base64Decode(
    'ChJFeHBvc2VTZXJ2aWNlRXZlbnQSMgoFcmVhZHkYASABKAsyGi5kYWVtb24uRXhwb3NlU2Vydm'
    'ljZVJlYWR5SABSBXJlYWR5QgcKBWV2ZW50');

@$core.Deprecated('Use exposeServiceReadyDescriptor instead')
const ExposeServiceReady$json = {
  '1': 'ExposeServiceReady',
  '2': [
    {'1': 'service_name', '3': 1, '4': 1, '5': 9, '10': 'serviceName'},
    {'1': 'service_url', '3': 2, '4': 1, '5': 9, '10': 'serviceUrl'},
    {'1': 'domain', '3': 3, '4': 1, '5': 9, '10': 'domain'},
    {
      '1': 'port_auto_assigned',
      '3': 4,
      '4': 1,
      '5': 8,
      '10': 'portAutoAssigned'
    },
  ],
};

/// Descriptor for `ExposeServiceReady`. Decode as a `google.protobuf.DescriptorProto`.
final $typed_data.Uint8List exposeServiceReadyDescriptor = $convert.base64Decode(
    'ChJFeHBvc2VTZXJ2aWNlUmVhZHkSIQoMc2VydmljZV9uYW1lGAEgASgJUgtzZXJ2aWNlTmFtZR'
    'IfCgtzZXJ2aWNlX3VybBgCIAEoCVIKc2VydmljZVVybBIWCgZkb21haW4YAyABKAlSBmRvbWFp'
    'bhIsChJwb3J0X2F1dG9fYXNzaWduZWQYBCABKAhSEHBvcnRBdXRvQXNzaWduZWQ=');
