// This is a generated file - do not edit.
//
// Generated from daemon.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:core' as $core;

import 'package:fixnum/fixnum.dart' as $fixnum;
import 'package:protobuf/protobuf.dart' as $pb;
import 'package:protobuf/well_known_types/google/protobuf/duration.pb.dart'
    as $1;
import 'package:protobuf/well_known_types/google/protobuf/timestamp.pb.dart'
    as $2;

import 'daemon.pbenum.dart';

export 'package:protobuf/protobuf.dart' show GeneratedMessageGenericExtensions;

export 'daemon.pbenum.dart';

class EmptyRequest extends $pb.GeneratedMessage {
  factory EmptyRequest() => create();

  EmptyRequest._();

  factory EmptyRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory EmptyRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'EmptyRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  EmptyRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  EmptyRequest copyWith(void Function(EmptyRequest) updates) =>
      super.copyWith((message) => updates(message as EmptyRequest))
          as EmptyRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static EmptyRequest create() => EmptyRequest._();
  @$core.override
  EmptyRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static EmptyRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<EmptyRequest>(create);
  static EmptyRequest? _defaultInstance;
}

class OSLifecycleRequest extends $pb.GeneratedMessage {
  factory OSLifecycleRequest({
    OSLifecycleRequest_CycleType? type,
  }) {
    final result = create();
    if (type != null) result.type = type;
    return result;
  }

  OSLifecycleRequest._();

  factory OSLifecycleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory OSLifecycleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'OSLifecycleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aE<OSLifecycleRequest_CycleType>(1, _omitFieldNames ? '' : 'type',
        enumValues: OSLifecycleRequest_CycleType.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OSLifecycleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OSLifecycleRequest copyWith(void Function(OSLifecycleRequest) updates) =>
      super.copyWith((message) => updates(message as OSLifecycleRequest))
          as OSLifecycleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static OSLifecycleRequest create() => OSLifecycleRequest._();
  @$core.override
  OSLifecycleRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static OSLifecycleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<OSLifecycleRequest>(create);
  static OSLifecycleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  OSLifecycleRequest_CycleType get type => $_getN(0);
  @$pb.TagNumber(1)
  set type(OSLifecycleRequest_CycleType value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasType() => $_has(0);
  @$pb.TagNumber(1)
  void clearType() => $_clearField(1);
}

class OSLifecycleResponse extends $pb.GeneratedMessage {
  factory OSLifecycleResponse() => create();

  OSLifecycleResponse._();

  factory OSLifecycleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory OSLifecycleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'OSLifecycleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OSLifecycleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  OSLifecycleResponse copyWith(void Function(OSLifecycleResponse) updates) =>
      super.copyWith((message) => updates(message as OSLifecycleResponse))
          as OSLifecycleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static OSLifecycleResponse create() => OSLifecycleResponse._();
  @$core.override
  OSLifecycleResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static OSLifecycleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<OSLifecycleResponse>(create);
  static OSLifecycleResponse? _defaultInstance;
}

class LoginRequest extends $pb.GeneratedMessage {
  factory LoginRequest({
    $core.String? setupKey,
    @$core.Deprecated('This field is deprecated.') $core.String? preSharedKey,
    $core.String? managementUrl,
    $core.String? adminURL,
    $core.Iterable<$core.String>? natExternalIPs,
    $core.bool? cleanNATExternalIPs,
    $core.List<$core.int>? customDNSAddress,
    $core.bool? isUnixDesktopClient,
    $core.String? hostname,
    $core.bool? rosenpassEnabled,
    $core.String? interfaceName,
    $fixnum.Int64? wireguardPort,
    $core.String? optionalPreSharedKey,
    $core.bool? disableAutoConnect,
    $core.bool? serverSSHAllowed,
    $core.bool? rosenpassPermissive,
    $core.Iterable<$core.String>? extraIFaceBlacklist,
    $core.bool? networkMonitor,
    $1.Duration? dnsRouteInterval,
    $core.bool? disableClientRoutes,
    $core.bool? disableServerRoutes,
    $core.bool? disableDns,
    $core.bool? disableFirewall,
    $core.bool? blockLanAccess,
    $core.bool? disableNotifications,
    $core.Iterable<$core.String>? dnsLabels,
    $core.bool? cleanDNSLabels,
    $core.bool? lazyConnectionEnabled,
    $core.bool? blockInbound,
    $core.String? profileName,
    $core.String? username,
    $fixnum.Int64? mtu,
    $core.String? hint,
    $core.bool? enableSSHRoot,
    $core.bool? enableSSHSFTP,
    $core.bool? enableSSHLocalPortForwarding,
    $core.bool? enableSSHRemotePortForwarding,
    $core.bool? disableSSHAuth,
    $core.int? sshJWTCacheTTL,
  }) {
    final result = create();
    if (setupKey != null) result.setupKey = setupKey;
    if (preSharedKey != null) result.preSharedKey = preSharedKey;
    if (managementUrl != null) result.managementUrl = managementUrl;
    if (adminURL != null) result.adminURL = adminURL;
    if (natExternalIPs != null) result.natExternalIPs.addAll(natExternalIPs);
    if (cleanNATExternalIPs != null)
      result.cleanNATExternalIPs = cleanNATExternalIPs;
    if (customDNSAddress != null) result.customDNSAddress = customDNSAddress;
    if (isUnixDesktopClient != null)
      result.isUnixDesktopClient = isUnixDesktopClient;
    if (hostname != null) result.hostname = hostname;
    if (rosenpassEnabled != null) result.rosenpassEnabled = rosenpassEnabled;
    if (interfaceName != null) result.interfaceName = interfaceName;
    if (wireguardPort != null) result.wireguardPort = wireguardPort;
    if (optionalPreSharedKey != null)
      result.optionalPreSharedKey = optionalPreSharedKey;
    if (disableAutoConnect != null)
      result.disableAutoConnect = disableAutoConnect;
    if (serverSSHAllowed != null) result.serverSSHAllowed = serverSSHAllowed;
    if (rosenpassPermissive != null)
      result.rosenpassPermissive = rosenpassPermissive;
    if (extraIFaceBlacklist != null)
      result.extraIFaceBlacklist.addAll(extraIFaceBlacklist);
    if (networkMonitor != null) result.networkMonitor = networkMonitor;
    if (dnsRouteInterval != null) result.dnsRouteInterval = dnsRouteInterval;
    if (disableClientRoutes != null)
      result.disableClientRoutes = disableClientRoutes;
    if (disableServerRoutes != null)
      result.disableServerRoutes = disableServerRoutes;
    if (disableDns != null) result.disableDns = disableDns;
    if (disableFirewall != null) result.disableFirewall = disableFirewall;
    if (blockLanAccess != null) result.blockLanAccess = blockLanAccess;
    if (disableNotifications != null)
      result.disableNotifications = disableNotifications;
    if (dnsLabels != null) result.dnsLabels.addAll(dnsLabels);
    if (cleanDNSLabels != null) result.cleanDNSLabels = cleanDNSLabels;
    if (lazyConnectionEnabled != null)
      result.lazyConnectionEnabled = lazyConnectionEnabled;
    if (blockInbound != null) result.blockInbound = blockInbound;
    if (profileName != null) result.profileName = profileName;
    if (username != null) result.username = username;
    if (mtu != null) result.mtu = mtu;
    if (hint != null) result.hint = hint;
    if (enableSSHRoot != null) result.enableSSHRoot = enableSSHRoot;
    if (enableSSHSFTP != null) result.enableSSHSFTP = enableSSHSFTP;
    if (enableSSHLocalPortForwarding != null)
      result.enableSSHLocalPortForwarding = enableSSHLocalPortForwarding;
    if (enableSSHRemotePortForwarding != null)
      result.enableSSHRemotePortForwarding = enableSSHRemotePortForwarding;
    if (disableSSHAuth != null) result.disableSSHAuth = disableSSHAuth;
    if (sshJWTCacheTTL != null) result.sshJWTCacheTTL = sshJWTCacheTTL;
    return result;
  }

  LoginRequest._();

  factory LoginRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory LoginRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'LoginRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'setupKey', protoName: 'setupKey')
    ..aOS(2, _omitFieldNames ? '' : 'preSharedKey', protoName: 'preSharedKey')
    ..aOS(3, _omitFieldNames ? '' : 'managementUrl', protoName: 'managementUrl')
    ..aOS(4, _omitFieldNames ? '' : 'adminURL', protoName: 'adminURL')
    ..pPS(5, _omitFieldNames ? '' : 'natExternalIPs',
        protoName: 'natExternalIPs')
    ..aOB(6, _omitFieldNames ? '' : 'cleanNATExternalIPs',
        protoName: 'cleanNATExternalIPs')
    ..a<$core.List<$core.int>>(
        7, _omitFieldNames ? '' : 'customDNSAddress', $pb.PbFieldType.OY,
        protoName: 'customDNSAddress')
    ..aOB(8, _omitFieldNames ? '' : 'isUnixDesktopClient',
        protoName: 'isUnixDesktopClient')
    ..aOS(9, _omitFieldNames ? '' : 'hostname')
    ..aOB(10, _omitFieldNames ? '' : 'rosenpassEnabled',
        protoName: 'rosenpassEnabled')
    ..aOS(11, _omitFieldNames ? '' : 'interfaceName',
        protoName: 'interfaceName')
    ..aInt64(12, _omitFieldNames ? '' : 'wireguardPort',
        protoName: 'wireguardPort')
    ..aOS(13, _omitFieldNames ? '' : 'optionalPreSharedKey',
        protoName: 'optionalPreSharedKey')
    ..aOB(14, _omitFieldNames ? '' : 'disableAutoConnect',
        protoName: 'disableAutoConnect')
    ..aOB(15, _omitFieldNames ? '' : 'serverSSHAllowed',
        protoName: 'serverSSHAllowed')
    ..aOB(16, _omitFieldNames ? '' : 'rosenpassPermissive',
        protoName: 'rosenpassPermissive')
    ..pPS(17, _omitFieldNames ? '' : 'extraIFaceBlacklist',
        protoName: 'extraIFaceBlacklist')
    ..aOB(18, _omitFieldNames ? '' : 'networkMonitor',
        protoName: 'networkMonitor')
    ..aOM<$1.Duration>(19, _omitFieldNames ? '' : 'dnsRouteInterval',
        protoName: 'dnsRouteInterval', subBuilder: $1.Duration.create)
    ..aOB(20, _omitFieldNames ? '' : 'disableClientRoutes')
    ..aOB(21, _omitFieldNames ? '' : 'disableServerRoutes')
    ..aOB(22, _omitFieldNames ? '' : 'disableDns')
    ..aOB(23, _omitFieldNames ? '' : 'disableFirewall')
    ..aOB(24, _omitFieldNames ? '' : 'blockLanAccess')
    ..aOB(25, _omitFieldNames ? '' : 'disableNotifications')
    ..pPS(26, _omitFieldNames ? '' : 'dnsLabels')
    ..aOB(27, _omitFieldNames ? '' : 'cleanDNSLabels',
        protoName: 'cleanDNSLabels')
    ..aOB(28, _omitFieldNames ? '' : 'lazyConnectionEnabled',
        protoName: 'lazyConnectionEnabled')
    ..aOB(29, _omitFieldNames ? '' : 'blockInbound')
    ..aOS(30, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(31, _omitFieldNames ? '' : 'username')
    ..aInt64(32, _omitFieldNames ? '' : 'mtu')
    ..aOS(33, _omitFieldNames ? '' : 'hint')
    ..aOB(34, _omitFieldNames ? '' : 'enableSSHRoot',
        protoName: 'enableSSHRoot')
    ..aOB(35, _omitFieldNames ? '' : 'enableSSHSFTP',
        protoName: 'enableSSHSFTP')
    ..aOB(36, _omitFieldNames ? '' : 'enableSSHLocalPortForwarding',
        protoName: 'enableSSHLocalPortForwarding')
    ..aOB(37, _omitFieldNames ? '' : 'enableSSHRemotePortForwarding',
        protoName: 'enableSSHRemotePortForwarding')
    ..aOB(38, _omitFieldNames ? '' : 'disableSSHAuth',
        protoName: 'disableSSHAuth')
    ..aI(39, _omitFieldNames ? '' : 'sshJWTCacheTTL',
        protoName: 'sshJWTCacheTTL')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LoginRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LoginRequest copyWith(void Function(LoginRequest) updates) =>
      super.copyWith((message) => updates(message as LoginRequest))
          as LoginRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static LoginRequest create() => LoginRequest._();
  @$core.override
  LoginRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static LoginRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<LoginRequest>(create);
  static LoginRequest? _defaultInstance;

  /// setupKey netbird setup key.
  @$pb.TagNumber(1)
  $core.String get setupKey => $_getSZ(0);
  @$pb.TagNumber(1)
  set setupKey($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSetupKey() => $_has(0);
  @$pb.TagNumber(1)
  void clearSetupKey() => $_clearField(1);

  /// This is the old PreSharedKey field which will be deprecated in favor of optionalPreSharedKey field that is defined as optional
  /// to allow clearing of preshared key while being able to persist in the config file.
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(2)
  $core.String get preSharedKey => $_getSZ(1);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(2)
  set preSharedKey($core.String value) => $_setString(1, value);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(2)
  $core.bool hasPreSharedKey() => $_has(1);
  @$core.Deprecated('This field is deprecated.')
  @$pb.TagNumber(2)
  void clearPreSharedKey() => $_clearField(2);

  /// managementUrl to authenticate.
  @$pb.TagNumber(3)
  $core.String get managementUrl => $_getSZ(2);
  @$pb.TagNumber(3)
  set managementUrl($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasManagementUrl() => $_has(2);
  @$pb.TagNumber(3)
  void clearManagementUrl() => $_clearField(3);

  /// adminUrl to manage keys.
  @$pb.TagNumber(4)
  $core.String get adminURL => $_getSZ(3);
  @$pb.TagNumber(4)
  set adminURL($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasAdminURL() => $_has(3);
  @$pb.TagNumber(4)
  void clearAdminURL() => $_clearField(4);

  /// natExternalIPs map list of external IPs
  @$pb.TagNumber(5)
  $pb.PbList<$core.String> get natExternalIPs => $_getList(4);

  /// cleanNATExternalIPs clean map list of external IPs.
  /// This is needed because the generated code
  /// omits initialized empty slices due to omitempty tags
  @$pb.TagNumber(6)
  $core.bool get cleanNATExternalIPs => $_getBF(5);
  @$pb.TagNumber(6)
  set cleanNATExternalIPs($core.bool value) => $_setBool(5, value);
  @$pb.TagNumber(6)
  $core.bool hasCleanNATExternalIPs() => $_has(5);
  @$pb.TagNumber(6)
  void clearCleanNATExternalIPs() => $_clearField(6);

  @$pb.TagNumber(7)
  $core.List<$core.int> get customDNSAddress => $_getN(6);
  @$pb.TagNumber(7)
  set customDNSAddress($core.List<$core.int> value) => $_setBytes(6, value);
  @$pb.TagNumber(7)
  $core.bool hasCustomDNSAddress() => $_has(6);
  @$pb.TagNumber(7)
  void clearCustomDNSAddress() => $_clearField(7);

  @$pb.TagNumber(8)
  $core.bool get isUnixDesktopClient => $_getBF(7);
  @$pb.TagNumber(8)
  set isUnixDesktopClient($core.bool value) => $_setBool(7, value);
  @$pb.TagNumber(8)
  $core.bool hasIsUnixDesktopClient() => $_has(7);
  @$pb.TagNumber(8)
  void clearIsUnixDesktopClient() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.String get hostname => $_getSZ(8);
  @$pb.TagNumber(9)
  set hostname($core.String value) => $_setString(8, value);
  @$pb.TagNumber(9)
  $core.bool hasHostname() => $_has(8);
  @$pb.TagNumber(9)
  void clearHostname() => $_clearField(9);

  @$pb.TagNumber(10)
  $core.bool get rosenpassEnabled => $_getBF(9);
  @$pb.TagNumber(10)
  set rosenpassEnabled($core.bool value) => $_setBool(9, value);
  @$pb.TagNumber(10)
  $core.bool hasRosenpassEnabled() => $_has(9);
  @$pb.TagNumber(10)
  void clearRosenpassEnabled() => $_clearField(10);

  @$pb.TagNumber(11)
  $core.String get interfaceName => $_getSZ(10);
  @$pb.TagNumber(11)
  set interfaceName($core.String value) => $_setString(10, value);
  @$pb.TagNumber(11)
  $core.bool hasInterfaceName() => $_has(10);
  @$pb.TagNumber(11)
  void clearInterfaceName() => $_clearField(11);

  @$pb.TagNumber(12)
  $fixnum.Int64 get wireguardPort => $_getI64(11);
  @$pb.TagNumber(12)
  set wireguardPort($fixnum.Int64 value) => $_setInt64(11, value);
  @$pb.TagNumber(12)
  $core.bool hasWireguardPort() => $_has(11);
  @$pb.TagNumber(12)
  void clearWireguardPort() => $_clearField(12);

  @$pb.TagNumber(13)
  $core.String get optionalPreSharedKey => $_getSZ(12);
  @$pb.TagNumber(13)
  set optionalPreSharedKey($core.String value) => $_setString(12, value);
  @$pb.TagNumber(13)
  $core.bool hasOptionalPreSharedKey() => $_has(12);
  @$pb.TagNumber(13)
  void clearOptionalPreSharedKey() => $_clearField(13);

  @$pb.TagNumber(14)
  $core.bool get disableAutoConnect => $_getBF(13);
  @$pb.TagNumber(14)
  set disableAutoConnect($core.bool value) => $_setBool(13, value);
  @$pb.TagNumber(14)
  $core.bool hasDisableAutoConnect() => $_has(13);
  @$pb.TagNumber(14)
  void clearDisableAutoConnect() => $_clearField(14);

  @$pb.TagNumber(15)
  $core.bool get serverSSHAllowed => $_getBF(14);
  @$pb.TagNumber(15)
  set serverSSHAllowed($core.bool value) => $_setBool(14, value);
  @$pb.TagNumber(15)
  $core.bool hasServerSSHAllowed() => $_has(14);
  @$pb.TagNumber(15)
  void clearServerSSHAllowed() => $_clearField(15);

  @$pb.TagNumber(16)
  $core.bool get rosenpassPermissive => $_getBF(15);
  @$pb.TagNumber(16)
  set rosenpassPermissive($core.bool value) => $_setBool(15, value);
  @$pb.TagNumber(16)
  $core.bool hasRosenpassPermissive() => $_has(15);
  @$pb.TagNumber(16)
  void clearRosenpassPermissive() => $_clearField(16);

  @$pb.TagNumber(17)
  $pb.PbList<$core.String> get extraIFaceBlacklist => $_getList(16);

  @$pb.TagNumber(18)
  $core.bool get networkMonitor => $_getBF(17);
  @$pb.TagNumber(18)
  set networkMonitor($core.bool value) => $_setBool(17, value);
  @$pb.TagNumber(18)
  $core.bool hasNetworkMonitor() => $_has(17);
  @$pb.TagNumber(18)
  void clearNetworkMonitor() => $_clearField(18);

  @$pb.TagNumber(19)
  $1.Duration get dnsRouteInterval => $_getN(18);
  @$pb.TagNumber(19)
  set dnsRouteInterval($1.Duration value) => $_setField(19, value);
  @$pb.TagNumber(19)
  $core.bool hasDnsRouteInterval() => $_has(18);
  @$pb.TagNumber(19)
  void clearDnsRouteInterval() => $_clearField(19);
  @$pb.TagNumber(19)
  $1.Duration ensureDnsRouteInterval() => $_ensure(18);

  @$pb.TagNumber(20)
  $core.bool get disableClientRoutes => $_getBF(19);
  @$pb.TagNumber(20)
  set disableClientRoutes($core.bool value) => $_setBool(19, value);
  @$pb.TagNumber(20)
  $core.bool hasDisableClientRoutes() => $_has(19);
  @$pb.TagNumber(20)
  void clearDisableClientRoutes() => $_clearField(20);

  @$pb.TagNumber(21)
  $core.bool get disableServerRoutes => $_getBF(20);
  @$pb.TagNumber(21)
  set disableServerRoutes($core.bool value) => $_setBool(20, value);
  @$pb.TagNumber(21)
  $core.bool hasDisableServerRoutes() => $_has(20);
  @$pb.TagNumber(21)
  void clearDisableServerRoutes() => $_clearField(21);

  @$pb.TagNumber(22)
  $core.bool get disableDns => $_getBF(21);
  @$pb.TagNumber(22)
  set disableDns($core.bool value) => $_setBool(21, value);
  @$pb.TagNumber(22)
  $core.bool hasDisableDns() => $_has(21);
  @$pb.TagNumber(22)
  void clearDisableDns() => $_clearField(22);

  @$pb.TagNumber(23)
  $core.bool get disableFirewall => $_getBF(22);
  @$pb.TagNumber(23)
  set disableFirewall($core.bool value) => $_setBool(22, value);
  @$pb.TagNumber(23)
  $core.bool hasDisableFirewall() => $_has(22);
  @$pb.TagNumber(23)
  void clearDisableFirewall() => $_clearField(23);

  @$pb.TagNumber(24)
  $core.bool get blockLanAccess => $_getBF(23);
  @$pb.TagNumber(24)
  set blockLanAccess($core.bool value) => $_setBool(23, value);
  @$pb.TagNumber(24)
  $core.bool hasBlockLanAccess() => $_has(23);
  @$pb.TagNumber(24)
  void clearBlockLanAccess() => $_clearField(24);

  @$pb.TagNumber(25)
  $core.bool get disableNotifications => $_getBF(24);
  @$pb.TagNumber(25)
  set disableNotifications($core.bool value) => $_setBool(24, value);
  @$pb.TagNumber(25)
  $core.bool hasDisableNotifications() => $_has(24);
  @$pb.TagNumber(25)
  void clearDisableNotifications() => $_clearField(25);

  @$pb.TagNumber(26)
  $pb.PbList<$core.String> get dnsLabels => $_getList(25);

  /// cleanDNSLabels clean map list of DNS labels.
  /// This is needed because the generated code
  /// omits initialized empty slices due to omitempty tags
  @$pb.TagNumber(27)
  $core.bool get cleanDNSLabels => $_getBF(26);
  @$pb.TagNumber(27)
  set cleanDNSLabels($core.bool value) => $_setBool(26, value);
  @$pb.TagNumber(27)
  $core.bool hasCleanDNSLabels() => $_has(26);
  @$pb.TagNumber(27)
  void clearCleanDNSLabels() => $_clearField(27);

  @$pb.TagNumber(28)
  $core.bool get lazyConnectionEnabled => $_getBF(27);
  @$pb.TagNumber(28)
  set lazyConnectionEnabled($core.bool value) => $_setBool(27, value);
  @$pb.TagNumber(28)
  $core.bool hasLazyConnectionEnabled() => $_has(27);
  @$pb.TagNumber(28)
  void clearLazyConnectionEnabled() => $_clearField(28);

  @$pb.TagNumber(29)
  $core.bool get blockInbound => $_getBF(28);
  @$pb.TagNumber(29)
  set blockInbound($core.bool value) => $_setBool(28, value);
  @$pb.TagNumber(29)
  $core.bool hasBlockInbound() => $_has(28);
  @$pb.TagNumber(29)
  void clearBlockInbound() => $_clearField(29);

  @$pb.TagNumber(30)
  $core.String get profileName => $_getSZ(29);
  @$pb.TagNumber(30)
  set profileName($core.String value) => $_setString(29, value);
  @$pb.TagNumber(30)
  $core.bool hasProfileName() => $_has(29);
  @$pb.TagNumber(30)
  void clearProfileName() => $_clearField(30);

  @$pb.TagNumber(31)
  $core.String get username => $_getSZ(30);
  @$pb.TagNumber(31)
  set username($core.String value) => $_setString(30, value);
  @$pb.TagNumber(31)
  $core.bool hasUsername() => $_has(30);
  @$pb.TagNumber(31)
  void clearUsername() => $_clearField(31);

  @$pb.TagNumber(32)
  $fixnum.Int64 get mtu => $_getI64(31);
  @$pb.TagNumber(32)
  set mtu($fixnum.Int64 value) => $_setInt64(31, value);
  @$pb.TagNumber(32)
  $core.bool hasMtu() => $_has(31);
  @$pb.TagNumber(32)
  void clearMtu() => $_clearField(32);

  /// hint is used to pre-fill the email/username field during SSO authentication
  @$pb.TagNumber(33)
  $core.String get hint => $_getSZ(32);
  @$pb.TagNumber(33)
  set hint($core.String value) => $_setString(32, value);
  @$pb.TagNumber(33)
  $core.bool hasHint() => $_has(32);
  @$pb.TagNumber(33)
  void clearHint() => $_clearField(33);

  @$pb.TagNumber(34)
  $core.bool get enableSSHRoot => $_getBF(33);
  @$pb.TagNumber(34)
  set enableSSHRoot($core.bool value) => $_setBool(33, value);
  @$pb.TagNumber(34)
  $core.bool hasEnableSSHRoot() => $_has(33);
  @$pb.TagNumber(34)
  void clearEnableSSHRoot() => $_clearField(34);

  @$pb.TagNumber(35)
  $core.bool get enableSSHSFTP => $_getBF(34);
  @$pb.TagNumber(35)
  set enableSSHSFTP($core.bool value) => $_setBool(34, value);
  @$pb.TagNumber(35)
  $core.bool hasEnableSSHSFTP() => $_has(34);
  @$pb.TagNumber(35)
  void clearEnableSSHSFTP() => $_clearField(35);

  @$pb.TagNumber(36)
  $core.bool get enableSSHLocalPortForwarding => $_getBF(35);
  @$pb.TagNumber(36)
  set enableSSHLocalPortForwarding($core.bool value) => $_setBool(35, value);
  @$pb.TagNumber(36)
  $core.bool hasEnableSSHLocalPortForwarding() => $_has(35);
  @$pb.TagNumber(36)
  void clearEnableSSHLocalPortForwarding() => $_clearField(36);

  @$pb.TagNumber(37)
  $core.bool get enableSSHRemotePortForwarding => $_getBF(36);
  @$pb.TagNumber(37)
  set enableSSHRemotePortForwarding($core.bool value) => $_setBool(36, value);
  @$pb.TagNumber(37)
  $core.bool hasEnableSSHRemotePortForwarding() => $_has(36);
  @$pb.TagNumber(37)
  void clearEnableSSHRemotePortForwarding() => $_clearField(37);

  @$pb.TagNumber(38)
  $core.bool get disableSSHAuth => $_getBF(37);
  @$pb.TagNumber(38)
  set disableSSHAuth($core.bool value) => $_setBool(37, value);
  @$pb.TagNumber(38)
  $core.bool hasDisableSSHAuth() => $_has(37);
  @$pb.TagNumber(38)
  void clearDisableSSHAuth() => $_clearField(38);

  @$pb.TagNumber(39)
  $core.int get sshJWTCacheTTL => $_getIZ(38);
  @$pb.TagNumber(39)
  set sshJWTCacheTTL($core.int value) => $_setSignedInt32(38, value);
  @$pb.TagNumber(39)
  $core.bool hasSshJWTCacheTTL() => $_has(38);
  @$pb.TagNumber(39)
  void clearSshJWTCacheTTL() => $_clearField(39);
}

class LoginResponse extends $pb.GeneratedMessage {
  factory LoginResponse({
    $core.bool? needsSSOLogin,
    $core.String? userCode,
    $core.String? verificationURI,
    $core.String? verificationURIComplete,
  }) {
    final result = create();
    if (needsSSOLogin != null) result.needsSSOLogin = needsSSOLogin;
    if (userCode != null) result.userCode = userCode;
    if (verificationURI != null) result.verificationURI = verificationURI;
    if (verificationURIComplete != null)
      result.verificationURIComplete = verificationURIComplete;
    return result;
  }

  LoginResponse._();

  factory LoginResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory LoginResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'LoginResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'needsSSOLogin', protoName: 'needsSSOLogin')
    ..aOS(2, _omitFieldNames ? '' : 'userCode', protoName: 'userCode')
    ..aOS(3, _omitFieldNames ? '' : 'verificationURI',
        protoName: 'verificationURI')
    ..aOS(4, _omitFieldNames ? '' : 'verificationURIComplete',
        protoName: 'verificationURIComplete')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LoginResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LoginResponse copyWith(void Function(LoginResponse) updates) =>
      super.copyWith((message) => updates(message as LoginResponse))
          as LoginResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static LoginResponse create() => LoginResponse._();
  @$core.override
  LoginResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static LoginResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<LoginResponse>(create);
  static LoginResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get needsSSOLogin => $_getBF(0);
  @$pb.TagNumber(1)
  set needsSSOLogin($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasNeedsSSOLogin() => $_has(0);
  @$pb.TagNumber(1)
  void clearNeedsSSOLogin() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get userCode => $_getSZ(1);
  @$pb.TagNumber(2)
  set userCode($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUserCode() => $_has(1);
  @$pb.TagNumber(2)
  void clearUserCode() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get verificationURI => $_getSZ(2);
  @$pb.TagNumber(3)
  set verificationURI($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasVerificationURI() => $_has(2);
  @$pb.TagNumber(3)
  void clearVerificationURI() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get verificationURIComplete => $_getSZ(3);
  @$pb.TagNumber(4)
  set verificationURIComplete($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasVerificationURIComplete() => $_has(3);
  @$pb.TagNumber(4)
  void clearVerificationURIComplete() => $_clearField(4);
}

class WaitSSOLoginRequest extends $pb.GeneratedMessage {
  factory WaitSSOLoginRequest({
    $core.String? userCode,
    $core.String? hostname,
  }) {
    final result = create();
    if (userCode != null) result.userCode = userCode;
    if (hostname != null) result.hostname = hostname;
    return result;
  }

  WaitSSOLoginRequest._();

  factory WaitSSOLoginRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory WaitSSOLoginRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'WaitSSOLoginRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'userCode', protoName: 'userCode')
    ..aOS(2, _omitFieldNames ? '' : 'hostname')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitSSOLoginRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitSSOLoginRequest copyWith(void Function(WaitSSOLoginRequest) updates) =>
      super.copyWith((message) => updates(message as WaitSSOLoginRequest))
          as WaitSSOLoginRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static WaitSSOLoginRequest create() => WaitSSOLoginRequest._();
  @$core.override
  WaitSSOLoginRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static WaitSSOLoginRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<WaitSSOLoginRequest>(create);
  static WaitSSOLoginRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get userCode => $_getSZ(0);
  @$pb.TagNumber(1)
  set userCode($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUserCode() => $_has(0);
  @$pb.TagNumber(1)
  void clearUserCode() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get hostname => $_getSZ(1);
  @$pb.TagNumber(2)
  set hostname($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasHostname() => $_has(1);
  @$pb.TagNumber(2)
  void clearHostname() => $_clearField(2);
}

class WaitSSOLoginResponse extends $pb.GeneratedMessage {
  factory WaitSSOLoginResponse({
    $core.String? email,
  }) {
    final result = create();
    if (email != null) result.email = email;
    return result;
  }

  WaitSSOLoginResponse._();

  factory WaitSSOLoginResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory WaitSSOLoginResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'WaitSSOLoginResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'email')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitSSOLoginResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitSSOLoginResponse copyWith(void Function(WaitSSOLoginResponse) updates) =>
      super.copyWith((message) => updates(message as WaitSSOLoginResponse))
          as WaitSSOLoginResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static WaitSSOLoginResponse create() => WaitSSOLoginResponse._();
  @$core.override
  WaitSSOLoginResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static WaitSSOLoginResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<WaitSSOLoginResponse>(create);
  static WaitSSOLoginResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get email => $_getSZ(0);
  @$pb.TagNumber(1)
  set email($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasEmail() => $_has(0);
  @$pb.TagNumber(1)
  void clearEmail() => $_clearField(1);
}

class UpRequest extends $pb.GeneratedMessage {
  factory UpRequest({
    $core.String? profileName,
    $core.String? username,
  }) {
    final result = create();
    if (profileName != null) result.profileName = profileName;
    if (username != null) result.username = username;
    return result;
  }

  UpRequest._();

  factory UpRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory UpRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(2, _omitFieldNames ? '' : 'username')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpRequest copyWith(void Function(UpRequest) updates) =>
      super.copyWith((message) => updates(message as UpRequest)) as UpRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static UpRequest create() => UpRequest._();
  @$core.override
  UpRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static UpRequest getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<UpRequest>(create);
  static UpRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get profileName => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileName() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get username => $_getSZ(1);
  @$pb.TagNumber(2)
  set username($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUsername() => $_has(1);
  @$pb.TagNumber(2)
  void clearUsername() => $_clearField(2);
}

class UpResponse extends $pb.GeneratedMessage {
  factory UpResponse() => create();

  UpResponse._();

  factory UpResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory UpResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'UpResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  UpResponse copyWith(void Function(UpResponse) updates) =>
      super.copyWith((message) => updates(message as UpResponse)) as UpResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static UpResponse create() => UpResponse._();
  @$core.override
  UpResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static UpResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<UpResponse>(create);
  static UpResponse? _defaultInstance;
}

class StatusRequest extends $pb.GeneratedMessage {
  factory StatusRequest({
    $core.bool? getFullPeerStatus,
    $core.bool? shouldRunProbes,
    $core.bool? waitForReady,
  }) {
    final result = create();
    if (getFullPeerStatus != null) result.getFullPeerStatus = getFullPeerStatus;
    if (shouldRunProbes != null) result.shouldRunProbes = shouldRunProbes;
    if (waitForReady != null) result.waitForReady = waitForReady;
    return result;
  }

  StatusRequest._();

  factory StatusRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory StatusRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'StatusRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'getFullPeerStatus',
        protoName: 'getFullPeerStatus')
    ..aOB(2, _omitFieldNames ? '' : 'shouldRunProbes',
        protoName: 'shouldRunProbes')
    ..aOB(3, _omitFieldNames ? '' : 'waitForReady', protoName: 'waitForReady')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StatusRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StatusRequest copyWith(void Function(StatusRequest) updates) =>
      super.copyWith((message) => updates(message as StatusRequest))
          as StatusRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static StatusRequest create() => StatusRequest._();
  @$core.override
  StatusRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static StatusRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<StatusRequest>(create);
  static StatusRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get getFullPeerStatus => $_getBF(0);
  @$pb.TagNumber(1)
  set getFullPeerStatus($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasGetFullPeerStatus() => $_has(0);
  @$pb.TagNumber(1)
  void clearGetFullPeerStatus() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get shouldRunProbes => $_getBF(1);
  @$pb.TagNumber(2)
  set shouldRunProbes($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasShouldRunProbes() => $_has(1);
  @$pb.TagNumber(2)
  void clearShouldRunProbes() => $_clearField(2);

  /// the UI do not using this yet, but CLIs could use it to wait until the status is ready
  @$pb.TagNumber(3)
  $core.bool get waitForReady => $_getBF(2);
  @$pb.TagNumber(3)
  set waitForReady($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasWaitForReady() => $_has(2);
  @$pb.TagNumber(3)
  void clearWaitForReady() => $_clearField(3);
}

class StatusResponse extends $pb.GeneratedMessage {
  factory StatusResponse({
    $core.String? status,
    FullStatus? fullStatus,
    $core.String? daemonVersion,
  }) {
    final result = create();
    if (status != null) result.status = status;
    if (fullStatus != null) result.fullStatus = fullStatus;
    if (daemonVersion != null) result.daemonVersion = daemonVersion;
    return result;
  }

  StatusResponse._();

  factory StatusResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory StatusResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'StatusResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'status')
    ..aOM<FullStatus>(2, _omitFieldNames ? '' : 'fullStatus',
        protoName: 'fullStatus', subBuilder: FullStatus.create)
    ..aOS(3, _omitFieldNames ? '' : 'daemonVersion', protoName: 'daemonVersion')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StatusResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StatusResponse copyWith(void Function(StatusResponse) updates) =>
      super.copyWith((message) => updates(message as StatusResponse))
          as StatusResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static StatusResponse create() => StatusResponse._();
  @$core.override
  StatusResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static StatusResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<StatusResponse>(create);
  static StatusResponse? _defaultInstance;

  /// status of the server.
  @$pb.TagNumber(1)
  $core.String get status => $_getSZ(0);
  @$pb.TagNumber(1)
  set status($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasStatus() => $_has(0);
  @$pb.TagNumber(1)
  void clearStatus() => $_clearField(1);

  @$pb.TagNumber(2)
  FullStatus get fullStatus => $_getN(1);
  @$pb.TagNumber(2)
  set fullStatus(FullStatus value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasFullStatus() => $_has(1);
  @$pb.TagNumber(2)
  void clearFullStatus() => $_clearField(2);
  @$pb.TagNumber(2)
  FullStatus ensureFullStatus() => $_ensure(1);

  /// NetBird daemon version
  @$pb.TagNumber(3)
  $core.String get daemonVersion => $_getSZ(2);
  @$pb.TagNumber(3)
  set daemonVersion($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDaemonVersion() => $_has(2);
  @$pb.TagNumber(3)
  void clearDaemonVersion() => $_clearField(3);
}

class DownRequest extends $pb.GeneratedMessage {
  factory DownRequest() => create();

  DownRequest._();

  factory DownRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory DownRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'DownRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DownRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DownRequest copyWith(void Function(DownRequest) updates) =>
      super.copyWith((message) => updates(message as DownRequest))
          as DownRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DownRequest create() => DownRequest._();
  @$core.override
  DownRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static DownRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<DownRequest>(create);
  static DownRequest? _defaultInstance;
}

class DownResponse extends $pb.GeneratedMessage {
  factory DownResponse() => create();

  DownResponse._();

  factory DownResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory DownResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'DownResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DownResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DownResponse copyWith(void Function(DownResponse) updates) =>
      super.copyWith((message) => updates(message as DownResponse))
          as DownResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DownResponse create() => DownResponse._();
  @$core.override
  DownResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static DownResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<DownResponse>(create);
  static DownResponse? _defaultInstance;
}

class GetConfigRequest extends $pb.GeneratedMessage {
  factory GetConfigRequest({
    $core.String? profileName,
    $core.String? username,
  }) {
    final result = create();
    if (profileName != null) result.profileName = profileName;
    if (username != null) result.username = username;
    return result;
  }

  GetConfigRequest._();

  factory GetConfigRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetConfigRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetConfigRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(2, _omitFieldNames ? '' : 'username')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetConfigRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetConfigRequest copyWith(void Function(GetConfigRequest) updates) =>
      super.copyWith((message) => updates(message as GetConfigRequest))
          as GetConfigRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetConfigRequest create() => GetConfigRequest._();
  @$core.override
  GetConfigRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetConfigRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetConfigRequest>(create);
  static GetConfigRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get profileName => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileName() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get username => $_getSZ(1);
  @$pb.TagNumber(2)
  set username($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUsername() => $_has(1);
  @$pb.TagNumber(2)
  void clearUsername() => $_clearField(2);
}

class GetConfigResponse extends $pb.GeneratedMessage {
  factory GetConfigResponse({
    $core.String? managementUrl,
    $core.String? configFile,
    $core.String? logFile,
    $core.String? preSharedKey,
    $core.String? adminURL,
    $core.String? interfaceName,
    $fixnum.Int64? wireguardPort,
    $fixnum.Int64? mtu,
    $core.bool? disableAutoConnect,
    $core.bool? serverSSHAllowed,
    $core.bool? rosenpassEnabled,
    $core.bool? rosenpassPermissive,
    $core.bool? disableNotifications,
    $core.bool? lazyConnectionEnabled,
    $core.bool? blockInbound,
    $core.bool? networkMonitor,
    $core.bool? disableDns,
    $core.bool? disableClientRoutes,
    $core.bool? disableServerRoutes,
    $core.bool? blockLanAccess,
    $core.bool? enableSSHRoot,
    $core.bool? enableSSHLocalPortForwarding,
    $core.bool? enableSSHRemotePortForwarding,
    $core.bool? enableSSHSFTP,
    $core.bool? disableSSHAuth,
    $core.int? sshJWTCacheTTL,
  }) {
    final result = create();
    if (managementUrl != null) result.managementUrl = managementUrl;
    if (configFile != null) result.configFile = configFile;
    if (logFile != null) result.logFile = logFile;
    if (preSharedKey != null) result.preSharedKey = preSharedKey;
    if (adminURL != null) result.adminURL = adminURL;
    if (interfaceName != null) result.interfaceName = interfaceName;
    if (wireguardPort != null) result.wireguardPort = wireguardPort;
    if (mtu != null) result.mtu = mtu;
    if (disableAutoConnect != null)
      result.disableAutoConnect = disableAutoConnect;
    if (serverSSHAllowed != null) result.serverSSHAllowed = serverSSHAllowed;
    if (rosenpassEnabled != null) result.rosenpassEnabled = rosenpassEnabled;
    if (rosenpassPermissive != null)
      result.rosenpassPermissive = rosenpassPermissive;
    if (disableNotifications != null)
      result.disableNotifications = disableNotifications;
    if (lazyConnectionEnabled != null)
      result.lazyConnectionEnabled = lazyConnectionEnabled;
    if (blockInbound != null) result.blockInbound = blockInbound;
    if (networkMonitor != null) result.networkMonitor = networkMonitor;
    if (disableDns != null) result.disableDns = disableDns;
    if (disableClientRoutes != null)
      result.disableClientRoutes = disableClientRoutes;
    if (disableServerRoutes != null)
      result.disableServerRoutes = disableServerRoutes;
    if (blockLanAccess != null) result.blockLanAccess = blockLanAccess;
    if (enableSSHRoot != null) result.enableSSHRoot = enableSSHRoot;
    if (enableSSHLocalPortForwarding != null)
      result.enableSSHLocalPortForwarding = enableSSHLocalPortForwarding;
    if (enableSSHRemotePortForwarding != null)
      result.enableSSHRemotePortForwarding = enableSSHRemotePortForwarding;
    if (enableSSHSFTP != null) result.enableSSHSFTP = enableSSHSFTP;
    if (disableSSHAuth != null) result.disableSSHAuth = disableSSHAuth;
    if (sshJWTCacheTTL != null) result.sshJWTCacheTTL = sshJWTCacheTTL;
    return result;
  }

  GetConfigResponse._();

  factory GetConfigResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetConfigResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetConfigResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'managementUrl', protoName: 'managementUrl')
    ..aOS(2, _omitFieldNames ? '' : 'configFile', protoName: 'configFile')
    ..aOS(3, _omitFieldNames ? '' : 'logFile', protoName: 'logFile')
    ..aOS(4, _omitFieldNames ? '' : 'preSharedKey', protoName: 'preSharedKey')
    ..aOS(5, _omitFieldNames ? '' : 'adminURL', protoName: 'adminURL')
    ..aOS(6, _omitFieldNames ? '' : 'interfaceName', protoName: 'interfaceName')
    ..aInt64(7, _omitFieldNames ? '' : 'wireguardPort',
        protoName: 'wireguardPort')
    ..aInt64(8, _omitFieldNames ? '' : 'mtu')
    ..aOB(9, _omitFieldNames ? '' : 'disableAutoConnect',
        protoName: 'disableAutoConnect')
    ..aOB(10, _omitFieldNames ? '' : 'serverSSHAllowed',
        protoName: 'serverSSHAllowed')
    ..aOB(11, _omitFieldNames ? '' : 'rosenpassEnabled',
        protoName: 'rosenpassEnabled')
    ..aOB(12, _omitFieldNames ? '' : 'rosenpassPermissive',
        protoName: 'rosenpassPermissive')
    ..aOB(13, _omitFieldNames ? '' : 'disableNotifications')
    ..aOB(14, _omitFieldNames ? '' : 'lazyConnectionEnabled',
        protoName: 'lazyConnectionEnabled')
    ..aOB(15, _omitFieldNames ? '' : 'blockInbound', protoName: 'blockInbound')
    ..aOB(16, _omitFieldNames ? '' : 'networkMonitor',
        protoName: 'networkMonitor')
    ..aOB(17, _omitFieldNames ? '' : 'disableDns')
    ..aOB(18, _omitFieldNames ? '' : 'disableClientRoutes')
    ..aOB(19, _omitFieldNames ? '' : 'disableServerRoutes')
    ..aOB(20, _omitFieldNames ? '' : 'blockLanAccess')
    ..aOB(21, _omitFieldNames ? '' : 'enableSSHRoot',
        protoName: 'enableSSHRoot')
    ..aOB(22, _omitFieldNames ? '' : 'enableSSHLocalPortForwarding',
        protoName: 'enableSSHLocalPortForwarding')
    ..aOB(23, _omitFieldNames ? '' : 'enableSSHRemotePortForwarding',
        protoName: 'enableSSHRemotePortForwarding')
    ..aOB(24, _omitFieldNames ? '' : 'enableSSHSFTP',
        protoName: 'enableSSHSFTP')
    ..aOB(25, _omitFieldNames ? '' : 'disableSSHAuth',
        protoName: 'disableSSHAuth')
    ..aI(26, _omitFieldNames ? '' : 'sshJWTCacheTTL',
        protoName: 'sshJWTCacheTTL')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetConfigResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetConfigResponse copyWith(void Function(GetConfigResponse) updates) =>
      super.copyWith((message) => updates(message as GetConfigResponse))
          as GetConfigResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetConfigResponse create() => GetConfigResponse._();
  @$core.override
  GetConfigResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetConfigResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetConfigResponse>(create);
  static GetConfigResponse? _defaultInstance;

  /// managementUrl settings value.
  @$pb.TagNumber(1)
  $core.String get managementUrl => $_getSZ(0);
  @$pb.TagNumber(1)
  set managementUrl($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasManagementUrl() => $_has(0);
  @$pb.TagNumber(1)
  void clearManagementUrl() => $_clearField(1);

  /// configFile settings value.
  @$pb.TagNumber(2)
  $core.String get configFile => $_getSZ(1);
  @$pb.TagNumber(2)
  set configFile($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasConfigFile() => $_has(1);
  @$pb.TagNumber(2)
  void clearConfigFile() => $_clearField(2);

  /// logFile settings value.
  @$pb.TagNumber(3)
  $core.String get logFile => $_getSZ(2);
  @$pb.TagNumber(3)
  set logFile($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasLogFile() => $_has(2);
  @$pb.TagNumber(3)
  void clearLogFile() => $_clearField(3);

  /// preSharedKey settings value.
  @$pb.TagNumber(4)
  $core.String get preSharedKey => $_getSZ(3);
  @$pb.TagNumber(4)
  set preSharedKey($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasPreSharedKey() => $_has(3);
  @$pb.TagNumber(4)
  void clearPreSharedKey() => $_clearField(4);

  /// adminURL settings value.
  @$pb.TagNumber(5)
  $core.String get adminURL => $_getSZ(4);
  @$pb.TagNumber(5)
  set adminURL($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasAdminURL() => $_has(4);
  @$pb.TagNumber(5)
  void clearAdminURL() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.String get interfaceName => $_getSZ(5);
  @$pb.TagNumber(6)
  set interfaceName($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasInterfaceName() => $_has(5);
  @$pb.TagNumber(6)
  void clearInterfaceName() => $_clearField(6);

  @$pb.TagNumber(7)
  $fixnum.Int64 get wireguardPort => $_getI64(6);
  @$pb.TagNumber(7)
  set wireguardPort($fixnum.Int64 value) => $_setInt64(6, value);
  @$pb.TagNumber(7)
  $core.bool hasWireguardPort() => $_has(6);
  @$pb.TagNumber(7)
  void clearWireguardPort() => $_clearField(7);

  @$pb.TagNumber(8)
  $fixnum.Int64 get mtu => $_getI64(7);
  @$pb.TagNumber(8)
  set mtu($fixnum.Int64 value) => $_setInt64(7, value);
  @$pb.TagNumber(8)
  $core.bool hasMtu() => $_has(7);
  @$pb.TagNumber(8)
  void clearMtu() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.bool get disableAutoConnect => $_getBF(8);
  @$pb.TagNumber(9)
  set disableAutoConnect($core.bool value) => $_setBool(8, value);
  @$pb.TagNumber(9)
  $core.bool hasDisableAutoConnect() => $_has(8);
  @$pb.TagNumber(9)
  void clearDisableAutoConnect() => $_clearField(9);

  @$pb.TagNumber(10)
  $core.bool get serverSSHAllowed => $_getBF(9);
  @$pb.TagNumber(10)
  set serverSSHAllowed($core.bool value) => $_setBool(9, value);
  @$pb.TagNumber(10)
  $core.bool hasServerSSHAllowed() => $_has(9);
  @$pb.TagNumber(10)
  void clearServerSSHAllowed() => $_clearField(10);

  @$pb.TagNumber(11)
  $core.bool get rosenpassEnabled => $_getBF(10);
  @$pb.TagNumber(11)
  set rosenpassEnabled($core.bool value) => $_setBool(10, value);
  @$pb.TagNumber(11)
  $core.bool hasRosenpassEnabled() => $_has(10);
  @$pb.TagNumber(11)
  void clearRosenpassEnabled() => $_clearField(11);

  @$pb.TagNumber(12)
  $core.bool get rosenpassPermissive => $_getBF(11);
  @$pb.TagNumber(12)
  set rosenpassPermissive($core.bool value) => $_setBool(11, value);
  @$pb.TagNumber(12)
  $core.bool hasRosenpassPermissive() => $_has(11);
  @$pb.TagNumber(12)
  void clearRosenpassPermissive() => $_clearField(12);

  @$pb.TagNumber(13)
  $core.bool get disableNotifications => $_getBF(12);
  @$pb.TagNumber(13)
  set disableNotifications($core.bool value) => $_setBool(12, value);
  @$pb.TagNumber(13)
  $core.bool hasDisableNotifications() => $_has(12);
  @$pb.TagNumber(13)
  void clearDisableNotifications() => $_clearField(13);

  @$pb.TagNumber(14)
  $core.bool get lazyConnectionEnabled => $_getBF(13);
  @$pb.TagNumber(14)
  set lazyConnectionEnabled($core.bool value) => $_setBool(13, value);
  @$pb.TagNumber(14)
  $core.bool hasLazyConnectionEnabled() => $_has(13);
  @$pb.TagNumber(14)
  void clearLazyConnectionEnabled() => $_clearField(14);

  @$pb.TagNumber(15)
  $core.bool get blockInbound => $_getBF(14);
  @$pb.TagNumber(15)
  set blockInbound($core.bool value) => $_setBool(14, value);
  @$pb.TagNumber(15)
  $core.bool hasBlockInbound() => $_has(14);
  @$pb.TagNumber(15)
  void clearBlockInbound() => $_clearField(15);

  @$pb.TagNumber(16)
  $core.bool get networkMonitor => $_getBF(15);
  @$pb.TagNumber(16)
  set networkMonitor($core.bool value) => $_setBool(15, value);
  @$pb.TagNumber(16)
  $core.bool hasNetworkMonitor() => $_has(15);
  @$pb.TagNumber(16)
  void clearNetworkMonitor() => $_clearField(16);

  @$pb.TagNumber(17)
  $core.bool get disableDns => $_getBF(16);
  @$pb.TagNumber(17)
  set disableDns($core.bool value) => $_setBool(16, value);
  @$pb.TagNumber(17)
  $core.bool hasDisableDns() => $_has(16);
  @$pb.TagNumber(17)
  void clearDisableDns() => $_clearField(17);

  @$pb.TagNumber(18)
  $core.bool get disableClientRoutes => $_getBF(17);
  @$pb.TagNumber(18)
  set disableClientRoutes($core.bool value) => $_setBool(17, value);
  @$pb.TagNumber(18)
  $core.bool hasDisableClientRoutes() => $_has(17);
  @$pb.TagNumber(18)
  void clearDisableClientRoutes() => $_clearField(18);

  @$pb.TagNumber(19)
  $core.bool get disableServerRoutes => $_getBF(18);
  @$pb.TagNumber(19)
  set disableServerRoutes($core.bool value) => $_setBool(18, value);
  @$pb.TagNumber(19)
  $core.bool hasDisableServerRoutes() => $_has(18);
  @$pb.TagNumber(19)
  void clearDisableServerRoutes() => $_clearField(19);

  @$pb.TagNumber(20)
  $core.bool get blockLanAccess => $_getBF(19);
  @$pb.TagNumber(20)
  set blockLanAccess($core.bool value) => $_setBool(19, value);
  @$pb.TagNumber(20)
  $core.bool hasBlockLanAccess() => $_has(19);
  @$pb.TagNumber(20)
  void clearBlockLanAccess() => $_clearField(20);

  @$pb.TagNumber(21)
  $core.bool get enableSSHRoot => $_getBF(20);
  @$pb.TagNumber(21)
  set enableSSHRoot($core.bool value) => $_setBool(20, value);
  @$pb.TagNumber(21)
  $core.bool hasEnableSSHRoot() => $_has(20);
  @$pb.TagNumber(21)
  void clearEnableSSHRoot() => $_clearField(21);

  @$pb.TagNumber(22)
  $core.bool get enableSSHLocalPortForwarding => $_getBF(21);
  @$pb.TagNumber(22)
  set enableSSHLocalPortForwarding($core.bool value) => $_setBool(21, value);
  @$pb.TagNumber(22)
  $core.bool hasEnableSSHLocalPortForwarding() => $_has(21);
  @$pb.TagNumber(22)
  void clearEnableSSHLocalPortForwarding() => $_clearField(22);

  @$pb.TagNumber(23)
  $core.bool get enableSSHRemotePortForwarding => $_getBF(22);
  @$pb.TagNumber(23)
  set enableSSHRemotePortForwarding($core.bool value) => $_setBool(22, value);
  @$pb.TagNumber(23)
  $core.bool hasEnableSSHRemotePortForwarding() => $_has(22);
  @$pb.TagNumber(23)
  void clearEnableSSHRemotePortForwarding() => $_clearField(23);

  @$pb.TagNumber(24)
  $core.bool get enableSSHSFTP => $_getBF(23);
  @$pb.TagNumber(24)
  set enableSSHSFTP($core.bool value) => $_setBool(23, value);
  @$pb.TagNumber(24)
  $core.bool hasEnableSSHSFTP() => $_has(23);
  @$pb.TagNumber(24)
  void clearEnableSSHSFTP() => $_clearField(24);

  @$pb.TagNumber(25)
  $core.bool get disableSSHAuth => $_getBF(24);
  @$pb.TagNumber(25)
  set disableSSHAuth($core.bool value) => $_setBool(24, value);
  @$pb.TagNumber(25)
  $core.bool hasDisableSSHAuth() => $_has(24);
  @$pb.TagNumber(25)
  void clearDisableSSHAuth() => $_clearField(25);

  @$pb.TagNumber(26)
  $core.int get sshJWTCacheTTL => $_getIZ(25);
  @$pb.TagNumber(26)
  set sshJWTCacheTTL($core.int value) => $_setSignedInt32(25, value);
  @$pb.TagNumber(26)
  $core.bool hasSshJWTCacheTTL() => $_has(25);
  @$pb.TagNumber(26)
  void clearSshJWTCacheTTL() => $_clearField(26);
}

/// PeerState contains the latest state of a peer
class PeerState extends $pb.GeneratedMessage {
  factory PeerState({
    $core.String? iP,
    $core.String? pubKey,
    $core.String? connStatus,
    $2.Timestamp? connStatusUpdate,
    $core.bool? relayed,
    $core.String? localIceCandidateType,
    $core.String? remoteIceCandidateType,
    $core.String? fqdn,
    $core.String? localIceCandidateEndpoint,
    $core.String? remoteIceCandidateEndpoint,
    $2.Timestamp? lastWireguardHandshake,
    $fixnum.Int64? bytesRx,
    $fixnum.Int64? bytesTx,
    $core.bool? rosenpassEnabled,
    $core.Iterable<$core.String>? networks,
    $1.Duration? latency,
    $core.String? relayAddress,
    $core.List<$core.int>? sshHostKey,
  }) {
    final result = create();
    if (iP != null) result.iP = iP;
    if (pubKey != null) result.pubKey = pubKey;
    if (connStatus != null) result.connStatus = connStatus;
    if (connStatusUpdate != null) result.connStatusUpdate = connStatusUpdate;
    if (relayed != null) result.relayed = relayed;
    if (localIceCandidateType != null)
      result.localIceCandidateType = localIceCandidateType;
    if (remoteIceCandidateType != null)
      result.remoteIceCandidateType = remoteIceCandidateType;
    if (fqdn != null) result.fqdn = fqdn;
    if (localIceCandidateEndpoint != null)
      result.localIceCandidateEndpoint = localIceCandidateEndpoint;
    if (remoteIceCandidateEndpoint != null)
      result.remoteIceCandidateEndpoint = remoteIceCandidateEndpoint;
    if (lastWireguardHandshake != null)
      result.lastWireguardHandshake = lastWireguardHandshake;
    if (bytesRx != null) result.bytesRx = bytesRx;
    if (bytesTx != null) result.bytesTx = bytesTx;
    if (rosenpassEnabled != null) result.rosenpassEnabled = rosenpassEnabled;
    if (networks != null) result.networks.addAll(networks);
    if (latency != null) result.latency = latency;
    if (relayAddress != null) result.relayAddress = relayAddress;
    if (sshHostKey != null) result.sshHostKey = sshHostKey;
    return result;
  }

  PeerState._();

  factory PeerState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory PeerState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PeerState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'IP', protoName: 'IP')
    ..aOS(2, _omitFieldNames ? '' : 'pubKey', protoName: 'pubKey')
    ..aOS(3, _omitFieldNames ? '' : 'connStatus', protoName: 'connStatus')
    ..aOM<$2.Timestamp>(4, _omitFieldNames ? '' : 'connStatusUpdate',
        protoName: 'connStatusUpdate', subBuilder: $2.Timestamp.create)
    ..aOB(5, _omitFieldNames ? '' : 'relayed')
    ..aOS(7, _omitFieldNames ? '' : 'localIceCandidateType',
        protoName: 'localIceCandidateType')
    ..aOS(8, _omitFieldNames ? '' : 'remoteIceCandidateType',
        protoName: 'remoteIceCandidateType')
    ..aOS(9, _omitFieldNames ? '' : 'fqdn')
    ..aOS(10, _omitFieldNames ? '' : 'localIceCandidateEndpoint',
        protoName: 'localIceCandidateEndpoint')
    ..aOS(11, _omitFieldNames ? '' : 'remoteIceCandidateEndpoint',
        protoName: 'remoteIceCandidateEndpoint')
    ..aOM<$2.Timestamp>(12, _omitFieldNames ? '' : 'lastWireguardHandshake',
        protoName: 'lastWireguardHandshake', subBuilder: $2.Timestamp.create)
    ..aInt64(13, _omitFieldNames ? '' : 'bytesRx', protoName: 'bytesRx')
    ..aInt64(14, _omitFieldNames ? '' : 'bytesTx', protoName: 'bytesTx')
    ..aOB(15, _omitFieldNames ? '' : 'rosenpassEnabled',
        protoName: 'rosenpassEnabled')
    ..pPS(16, _omitFieldNames ? '' : 'networks')
    ..aOM<$1.Duration>(17, _omitFieldNames ? '' : 'latency',
        subBuilder: $1.Duration.create)
    ..aOS(18, _omitFieldNames ? '' : 'relayAddress', protoName: 'relayAddress')
    ..a<$core.List<$core.int>>(
        19, _omitFieldNames ? '' : 'sshHostKey', $pb.PbFieldType.OY,
        protoName: 'sshHostKey')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PeerState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PeerState copyWith(void Function(PeerState) updates) =>
      super.copyWith((message) => updates(message as PeerState)) as PeerState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PeerState create() => PeerState._();
  @$core.override
  PeerState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static PeerState getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PeerState>(create);
  static PeerState? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get iP => $_getSZ(0);
  @$pb.TagNumber(1)
  set iP($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasIP() => $_has(0);
  @$pb.TagNumber(1)
  void clearIP() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get pubKey => $_getSZ(1);
  @$pb.TagNumber(2)
  set pubKey($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPubKey() => $_has(1);
  @$pb.TagNumber(2)
  void clearPubKey() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get connStatus => $_getSZ(2);
  @$pb.TagNumber(3)
  set connStatus($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasConnStatus() => $_has(2);
  @$pb.TagNumber(3)
  void clearConnStatus() => $_clearField(3);

  @$pb.TagNumber(4)
  $2.Timestamp get connStatusUpdate => $_getN(3);
  @$pb.TagNumber(4)
  set connStatusUpdate($2.Timestamp value) => $_setField(4, value);
  @$pb.TagNumber(4)
  $core.bool hasConnStatusUpdate() => $_has(3);
  @$pb.TagNumber(4)
  void clearConnStatusUpdate() => $_clearField(4);
  @$pb.TagNumber(4)
  $2.Timestamp ensureConnStatusUpdate() => $_ensure(3);

  @$pb.TagNumber(5)
  $core.bool get relayed => $_getBF(4);
  @$pb.TagNumber(5)
  set relayed($core.bool value) => $_setBool(4, value);
  @$pb.TagNumber(5)
  $core.bool hasRelayed() => $_has(4);
  @$pb.TagNumber(5)
  void clearRelayed() => $_clearField(5);

  @$pb.TagNumber(7)
  $core.String get localIceCandidateType => $_getSZ(5);
  @$pb.TagNumber(7)
  set localIceCandidateType($core.String value) => $_setString(5, value);
  @$pb.TagNumber(7)
  $core.bool hasLocalIceCandidateType() => $_has(5);
  @$pb.TagNumber(7)
  void clearLocalIceCandidateType() => $_clearField(7);

  @$pb.TagNumber(8)
  $core.String get remoteIceCandidateType => $_getSZ(6);
  @$pb.TagNumber(8)
  set remoteIceCandidateType($core.String value) => $_setString(6, value);
  @$pb.TagNumber(8)
  $core.bool hasRemoteIceCandidateType() => $_has(6);
  @$pb.TagNumber(8)
  void clearRemoteIceCandidateType() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.String get fqdn => $_getSZ(7);
  @$pb.TagNumber(9)
  set fqdn($core.String value) => $_setString(7, value);
  @$pb.TagNumber(9)
  $core.bool hasFqdn() => $_has(7);
  @$pb.TagNumber(9)
  void clearFqdn() => $_clearField(9);

  @$pb.TagNumber(10)
  $core.String get localIceCandidateEndpoint => $_getSZ(8);
  @$pb.TagNumber(10)
  set localIceCandidateEndpoint($core.String value) => $_setString(8, value);
  @$pb.TagNumber(10)
  $core.bool hasLocalIceCandidateEndpoint() => $_has(8);
  @$pb.TagNumber(10)
  void clearLocalIceCandidateEndpoint() => $_clearField(10);

  @$pb.TagNumber(11)
  $core.String get remoteIceCandidateEndpoint => $_getSZ(9);
  @$pb.TagNumber(11)
  set remoteIceCandidateEndpoint($core.String value) => $_setString(9, value);
  @$pb.TagNumber(11)
  $core.bool hasRemoteIceCandidateEndpoint() => $_has(9);
  @$pb.TagNumber(11)
  void clearRemoteIceCandidateEndpoint() => $_clearField(11);

  @$pb.TagNumber(12)
  $2.Timestamp get lastWireguardHandshake => $_getN(10);
  @$pb.TagNumber(12)
  set lastWireguardHandshake($2.Timestamp value) => $_setField(12, value);
  @$pb.TagNumber(12)
  $core.bool hasLastWireguardHandshake() => $_has(10);
  @$pb.TagNumber(12)
  void clearLastWireguardHandshake() => $_clearField(12);
  @$pb.TagNumber(12)
  $2.Timestamp ensureLastWireguardHandshake() => $_ensure(10);

  @$pb.TagNumber(13)
  $fixnum.Int64 get bytesRx => $_getI64(11);
  @$pb.TagNumber(13)
  set bytesRx($fixnum.Int64 value) => $_setInt64(11, value);
  @$pb.TagNumber(13)
  $core.bool hasBytesRx() => $_has(11);
  @$pb.TagNumber(13)
  void clearBytesRx() => $_clearField(13);

  @$pb.TagNumber(14)
  $fixnum.Int64 get bytesTx => $_getI64(12);
  @$pb.TagNumber(14)
  set bytesTx($fixnum.Int64 value) => $_setInt64(12, value);
  @$pb.TagNumber(14)
  $core.bool hasBytesTx() => $_has(12);
  @$pb.TagNumber(14)
  void clearBytesTx() => $_clearField(14);

  @$pb.TagNumber(15)
  $core.bool get rosenpassEnabled => $_getBF(13);
  @$pb.TagNumber(15)
  set rosenpassEnabled($core.bool value) => $_setBool(13, value);
  @$pb.TagNumber(15)
  $core.bool hasRosenpassEnabled() => $_has(13);
  @$pb.TagNumber(15)
  void clearRosenpassEnabled() => $_clearField(15);

  @$pb.TagNumber(16)
  $pb.PbList<$core.String> get networks => $_getList(14);

  @$pb.TagNumber(17)
  $1.Duration get latency => $_getN(15);
  @$pb.TagNumber(17)
  set latency($1.Duration value) => $_setField(17, value);
  @$pb.TagNumber(17)
  $core.bool hasLatency() => $_has(15);
  @$pb.TagNumber(17)
  void clearLatency() => $_clearField(17);
  @$pb.TagNumber(17)
  $1.Duration ensureLatency() => $_ensure(15);

  @$pb.TagNumber(18)
  $core.String get relayAddress => $_getSZ(16);
  @$pb.TagNumber(18)
  set relayAddress($core.String value) => $_setString(16, value);
  @$pb.TagNumber(18)
  $core.bool hasRelayAddress() => $_has(16);
  @$pb.TagNumber(18)
  void clearRelayAddress() => $_clearField(18);

  @$pb.TagNumber(19)
  $core.List<$core.int> get sshHostKey => $_getN(17);
  @$pb.TagNumber(19)
  set sshHostKey($core.List<$core.int> value) => $_setBytes(17, value);
  @$pb.TagNumber(19)
  $core.bool hasSshHostKey() => $_has(17);
  @$pb.TagNumber(19)
  void clearSshHostKey() => $_clearField(19);
}

/// LocalPeerState contains the latest state of the local peer
class LocalPeerState extends $pb.GeneratedMessage {
  factory LocalPeerState({
    $core.String? iP,
    $core.String? pubKey,
    $core.bool? kernelInterface,
    $core.String? fqdn,
    $core.bool? rosenpassEnabled,
    $core.bool? rosenpassPermissive,
    $core.Iterable<$core.String>? networks,
  }) {
    final result = create();
    if (iP != null) result.iP = iP;
    if (pubKey != null) result.pubKey = pubKey;
    if (kernelInterface != null) result.kernelInterface = kernelInterface;
    if (fqdn != null) result.fqdn = fqdn;
    if (rosenpassEnabled != null) result.rosenpassEnabled = rosenpassEnabled;
    if (rosenpassPermissive != null)
      result.rosenpassPermissive = rosenpassPermissive;
    if (networks != null) result.networks.addAll(networks);
    return result;
  }

  LocalPeerState._();

  factory LocalPeerState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory LocalPeerState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'LocalPeerState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'IP', protoName: 'IP')
    ..aOS(2, _omitFieldNames ? '' : 'pubKey', protoName: 'pubKey')
    ..aOB(3, _omitFieldNames ? '' : 'kernelInterface',
        protoName: 'kernelInterface')
    ..aOS(4, _omitFieldNames ? '' : 'fqdn')
    ..aOB(5, _omitFieldNames ? '' : 'rosenpassEnabled',
        protoName: 'rosenpassEnabled')
    ..aOB(6, _omitFieldNames ? '' : 'rosenpassPermissive',
        protoName: 'rosenpassPermissive')
    ..pPS(7, _omitFieldNames ? '' : 'networks')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LocalPeerState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LocalPeerState copyWith(void Function(LocalPeerState) updates) =>
      super.copyWith((message) => updates(message as LocalPeerState))
          as LocalPeerState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static LocalPeerState create() => LocalPeerState._();
  @$core.override
  LocalPeerState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static LocalPeerState getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<LocalPeerState>(create);
  static LocalPeerState? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get iP => $_getSZ(0);
  @$pb.TagNumber(1)
  set iP($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasIP() => $_has(0);
  @$pb.TagNumber(1)
  void clearIP() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get pubKey => $_getSZ(1);
  @$pb.TagNumber(2)
  set pubKey($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPubKey() => $_has(1);
  @$pb.TagNumber(2)
  void clearPubKey() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get kernelInterface => $_getBF(2);
  @$pb.TagNumber(3)
  set kernelInterface($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasKernelInterface() => $_has(2);
  @$pb.TagNumber(3)
  void clearKernelInterface() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get fqdn => $_getSZ(3);
  @$pb.TagNumber(4)
  set fqdn($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasFqdn() => $_has(3);
  @$pb.TagNumber(4)
  void clearFqdn() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.bool get rosenpassEnabled => $_getBF(4);
  @$pb.TagNumber(5)
  set rosenpassEnabled($core.bool value) => $_setBool(4, value);
  @$pb.TagNumber(5)
  $core.bool hasRosenpassEnabled() => $_has(4);
  @$pb.TagNumber(5)
  void clearRosenpassEnabled() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.bool get rosenpassPermissive => $_getBF(5);
  @$pb.TagNumber(6)
  set rosenpassPermissive($core.bool value) => $_setBool(5, value);
  @$pb.TagNumber(6)
  $core.bool hasRosenpassPermissive() => $_has(5);
  @$pb.TagNumber(6)
  void clearRosenpassPermissive() => $_clearField(6);

  @$pb.TagNumber(7)
  $pb.PbList<$core.String> get networks => $_getList(6);
}

/// SignalState contains the latest state of a signal connection
class SignalState extends $pb.GeneratedMessage {
  factory SignalState({
    $core.String? uRL,
    $core.bool? connected,
    $core.String? error,
  }) {
    final result = create();
    if (uRL != null) result.uRL = uRL;
    if (connected != null) result.connected = connected;
    if (error != null) result.error = error;
    return result;
  }

  SignalState._();

  factory SignalState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SignalState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SignalState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'URL', protoName: 'URL')
    ..aOB(2, _omitFieldNames ? '' : 'connected')
    ..aOS(3, _omitFieldNames ? '' : 'error')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SignalState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SignalState copyWith(void Function(SignalState) updates) =>
      super.copyWith((message) => updates(message as SignalState))
          as SignalState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SignalState create() => SignalState._();
  @$core.override
  SignalState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SignalState getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SignalState>(create);
  static SignalState? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get uRL => $_getSZ(0);
  @$pb.TagNumber(1)
  set uRL($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasURL() => $_has(0);
  @$pb.TagNumber(1)
  void clearURL() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get connected => $_getBF(1);
  @$pb.TagNumber(2)
  set connected($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasConnected() => $_has(1);
  @$pb.TagNumber(2)
  void clearConnected() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get error => $_getSZ(2);
  @$pb.TagNumber(3)
  set error($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasError() => $_has(2);
  @$pb.TagNumber(3)
  void clearError() => $_clearField(3);
}

/// ManagementState contains the latest state of a management connection
class ManagementState extends $pb.GeneratedMessage {
  factory ManagementState({
    $core.String? uRL,
    $core.bool? connected,
    $core.String? error,
  }) {
    final result = create();
    if (uRL != null) result.uRL = uRL;
    if (connected != null) result.connected = connected;
    if (error != null) result.error = error;
    return result;
  }

  ManagementState._();

  factory ManagementState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ManagementState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ManagementState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'URL', protoName: 'URL')
    ..aOB(2, _omitFieldNames ? '' : 'connected')
    ..aOS(3, _omitFieldNames ? '' : 'error')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ManagementState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ManagementState copyWith(void Function(ManagementState) updates) =>
      super.copyWith((message) => updates(message as ManagementState))
          as ManagementState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ManagementState create() => ManagementState._();
  @$core.override
  ManagementState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ManagementState getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ManagementState>(create);
  static ManagementState? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get uRL => $_getSZ(0);
  @$pb.TagNumber(1)
  set uRL($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasURL() => $_has(0);
  @$pb.TagNumber(1)
  void clearURL() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get connected => $_getBF(1);
  @$pb.TagNumber(2)
  set connected($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasConnected() => $_has(1);
  @$pb.TagNumber(2)
  void clearConnected() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get error => $_getSZ(2);
  @$pb.TagNumber(3)
  set error($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasError() => $_has(2);
  @$pb.TagNumber(3)
  void clearError() => $_clearField(3);
}

/// RelayState contains the latest state of the relay
class RelayState extends $pb.GeneratedMessage {
  factory RelayState({
    $core.String? uRI,
    $core.bool? available,
    $core.String? error,
  }) {
    final result = create();
    if (uRI != null) result.uRI = uRI;
    if (available != null) result.available = available;
    if (error != null) result.error = error;
    return result;
  }

  RelayState._();

  factory RelayState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory RelayState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RelayState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'URI', protoName: 'URI')
    ..aOB(2, _omitFieldNames ? '' : 'available')
    ..aOS(3, _omitFieldNames ? '' : 'error')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RelayState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RelayState copyWith(void Function(RelayState) updates) =>
      super.copyWith((message) => updates(message as RelayState)) as RelayState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RelayState create() => RelayState._();
  @$core.override
  RelayState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static RelayState getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RelayState>(create);
  static RelayState? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get uRI => $_getSZ(0);
  @$pb.TagNumber(1)
  set uRI($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasURI() => $_has(0);
  @$pb.TagNumber(1)
  void clearURI() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get available => $_getBF(1);
  @$pb.TagNumber(2)
  set available($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAvailable() => $_has(1);
  @$pb.TagNumber(2)
  void clearAvailable() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get error => $_getSZ(2);
  @$pb.TagNumber(3)
  set error($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasError() => $_has(2);
  @$pb.TagNumber(3)
  void clearError() => $_clearField(3);
}

class NSGroupState extends $pb.GeneratedMessage {
  factory NSGroupState({
    $core.Iterable<$core.String>? servers,
    $core.Iterable<$core.String>? domains,
    $core.bool? enabled,
    $core.String? error,
  }) {
    final result = create();
    if (servers != null) result.servers.addAll(servers);
    if (domains != null) result.domains.addAll(domains);
    if (enabled != null) result.enabled = enabled;
    if (error != null) result.error = error;
    return result;
  }

  NSGroupState._();

  factory NSGroupState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory NSGroupState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'NSGroupState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPS(1, _omitFieldNames ? '' : 'servers')
    ..pPS(2, _omitFieldNames ? '' : 'domains')
    ..aOB(3, _omitFieldNames ? '' : 'enabled')
    ..aOS(4, _omitFieldNames ? '' : 'error')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  NSGroupState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  NSGroupState copyWith(void Function(NSGroupState) updates) =>
      super.copyWith((message) => updates(message as NSGroupState))
          as NSGroupState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static NSGroupState create() => NSGroupState._();
  @$core.override
  NSGroupState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static NSGroupState getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<NSGroupState>(create);
  static NSGroupState? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<$core.String> get servers => $_getList(0);

  @$pb.TagNumber(2)
  $pb.PbList<$core.String> get domains => $_getList(1);

  @$pb.TagNumber(3)
  $core.bool get enabled => $_getBF(2);
  @$pb.TagNumber(3)
  set enabled($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasEnabled() => $_has(2);
  @$pb.TagNumber(3)
  void clearEnabled() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get error => $_getSZ(3);
  @$pb.TagNumber(4)
  set error($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasError() => $_has(3);
  @$pb.TagNumber(4)
  void clearError() => $_clearField(4);
}

/// SSHSessionInfo contains information about an active SSH session
class SSHSessionInfo extends $pb.GeneratedMessage {
  factory SSHSessionInfo({
    $core.String? username,
    $core.String? remoteAddress,
    $core.String? command,
    $core.String? jwtUsername,
    $core.Iterable<$core.String>? portForwards,
  }) {
    final result = create();
    if (username != null) result.username = username;
    if (remoteAddress != null) result.remoteAddress = remoteAddress;
    if (command != null) result.command = command;
    if (jwtUsername != null) result.jwtUsername = jwtUsername;
    if (portForwards != null) result.portForwards.addAll(portForwards);
    return result;
  }

  SSHSessionInfo._();

  factory SSHSessionInfo.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SSHSessionInfo.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SSHSessionInfo',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'username')
    ..aOS(2, _omitFieldNames ? '' : 'remoteAddress', protoName: 'remoteAddress')
    ..aOS(3, _omitFieldNames ? '' : 'command')
    ..aOS(4, _omitFieldNames ? '' : 'jwtUsername', protoName: 'jwtUsername')
    ..pPS(5, _omitFieldNames ? '' : 'portForwards', protoName: 'portForwards')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SSHSessionInfo clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SSHSessionInfo copyWith(void Function(SSHSessionInfo) updates) =>
      super.copyWith((message) => updates(message as SSHSessionInfo))
          as SSHSessionInfo;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SSHSessionInfo create() => SSHSessionInfo._();
  @$core.override
  SSHSessionInfo createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SSHSessionInfo getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SSHSessionInfo>(create);
  static SSHSessionInfo? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get username => $_getSZ(0);
  @$pb.TagNumber(1)
  set username($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUsername() => $_has(0);
  @$pb.TagNumber(1)
  void clearUsername() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get remoteAddress => $_getSZ(1);
  @$pb.TagNumber(2)
  set remoteAddress($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasRemoteAddress() => $_has(1);
  @$pb.TagNumber(2)
  void clearRemoteAddress() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get command => $_getSZ(2);
  @$pb.TagNumber(3)
  set command($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasCommand() => $_has(2);
  @$pb.TagNumber(3)
  void clearCommand() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get jwtUsername => $_getSZ(3);
  @$pb.TagNumber(4)
  set jwtUsername($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasJwtUsername() => $_has(3);
  @$pb.TagNumber(4)
  void clearJwtUsername() => $_clearField(4);

  @$pb.TagNumber(5)
  $pb.PbList<$core.String> get portForwards => $_getList(4);
}

/// SSHServerState contains the latest state of the SSH server
class SSHServerState extends $pb.GeneratedMessage {
  factory SSHServerState({
    $core.bool? enabled,
    $core.Iterable<SSHSessionInfo>? sessions,
  }) {
    final result = create();
    if (enabled != null) result.enabled = enabled;
    if (sessions != null) result.sessions.addAll(sessions);
    return result;
  }

  SSHServerState._();

  factory SSHServerState.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SSHServerState.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SSHServerState',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'enabled')
    ..pPM<SSHSessionInfo>(2, _omitFieldNames ? '' : 'sessions',
        subBuilder: SSHSessionInfo.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SSHServerState clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SSHServerState copyWith(void Function(SSHServerState) updates) =>
      super.copyWith((message) => updates(message as SSHServerState))
          as SSHServerState;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SSHServerState create() => SSHServerState._();
  @$core.override
  SSHServerState createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SSHServerState getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SSHServerState>(create);
  static SSHServerState? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get enabled => $_getBF(0);
  @$pb.TagNumber(1)
  set enabled($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasEnabled() => $_has(0);
  @$pb.TagNumber(1)
  void clearEnabled() => $_clearField(1);

  @$pb.TagNumber(2)
  $pb.PbList<SSHSessionInfo> get sessions => $_getList(1);
}

/// FullStatus contains the full state held by the Status instance
class FullStatus extends $pb.GeneratedMessage {
  factory FullStatus({
    ManagementState? managementState,
    SignalState? signalState,
    LocalPeerState? localPeerState,
    $core.Iterable<PeerState>? peers,
    $core.Iterable<RelayState>? relays,
    $core.Iterable<NSGroupState>? dnsServers,
    $core.Iterable<SystemEvent>? events,
    $core.int? numberOfForwardingRules,
    $core.bool? lazyConnectionEnabled,
    SSHServerState? sshServerState,
  }) {
    final result = create();
    if (managementState != null) result.managementState = managementState;
    if (signalState != null) result.signalState = signalState;
    if (localPeerState != null) result.localPeerState = localPeerState;
    if (peers != null) result.peers.addAll(peers);
    if (relays != null) result.relays.addAll(relays);
    if (dnsServers != null) result.dnsServers.addAll(dnsServers);
    if (events != null) result.events.addAll(events);
    if (numberOfForwardingRules != null)
      result.numberOfForwardingRules = numberOfForwardingRules;
    if (lazyConnectionEnabled != null)
      result.lazyConnectionEnabled = lazyConnectionEnabled;
    if (sshServerState != null) result.sshServerState = sshServerState;
    return result;
  }

  FullStatus._();

  factory FullStatus.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory FullStatus.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'FullStatus',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOM<ManagementState>(1, _omitFieldNames ? '' : 'managementState',
        protoName: 'managementState', subBuilder: ManagementState.create)
    ..aOM<SignalState>(2, _omitFieldNames ? '' : 'signalState',
        protoName: 'signalState', subBuilder: SignalState.create)
    ..aOM<LocalPeerState>(3, _omitFieldNames ? '' : 'localPeerState',
        protoName: 'localPeerState', subBuilder: LocalPeerState.create)
    ..pPM<PeerState>(4, _omitFieldNames ? '' : 'peers',
        subBuilder: PeerState.create)
    ..pPM<RelayState>(5, _omitFieldNames ? '' : 'relays',
        subBuilder: RelayState.create)
    ..pPM<NSGroupState>(6, _omitFieldNames ? '' : 'dnsServers',
        subBuilder: NSGroupState.create)
    ..pPM<SystemEvent>(7, _omitFieldNames ? '' : 'events',
        subBuilder: SystemEvent.create)
    ..aI(8, _omitFieldNames ? '' : 'NumberOfForwardingRules',
        protoName: 'NumberOfForwardingRules')
    ..aOB(9, _omitFieldNames ? '' : 'lazyConnectionEnabled',
        protoName: 'lazyConnectionEnabled')
    ..aOM<SSHServerState>(10, _omitFieldNames ? '' : 'sshServerState',
        protoName: 'sshServerState', subBuilder: SSHServerState.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  FullStatus clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  FullStatus copyWith(void Function(FullStatus) updates) =>
      super.copyWith((message) => updates(message as FullStatus)) as FullStatus;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static FullStatus create() => FullStatus._();
  @$core.override
  FullStatus createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static FullStatus getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<FullStatus>(create);
  static FullStatus? _defaultInstance;

  @$pb.TagNumber(1)
  ManagementState get managementState => $_getN(0);
  @$pb.TagNumber(1)
  set managementState(ManagementState value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasManagementState() => $_has(0);
  @$pb.TagNumber(1)
  void clearManagementState() => $_clearField(1);
  @$pb.TagNumber(1)
  ManagementState ensureManagementState() => $_ensure(0);

  @$pb.TagNumber(2)
  SignalState get signalState => $_getN(1);
  @$pb.TagNumber(2)
  set signalState(SignalState value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasSignalState() => $_has(1);
  @$pb.TagNumber(2)
  void clearSignalState() => $_clearField(2);
  @$pb.TagNumber(2)
  SignalState ensureSignalState() => $_ensure(1);

  @$pb.TagNumber(3)
  LocalPeerState get localPeerState => $_getN(2);
  @$pb.TagNumber(3)
  set localPeerState(LocalPeerState value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasLocalPeerState() => $_has(2);
  @$pb.TagNumber(3)
  void clearLocalPeerState() => $_clearField(3);
  @$pb.TagNumber(3)
  LocalPeerState ensureLocalPeerState() => $_ensure(2);

  @$pb.TagNumber(4)
  $pb.PbList<PeerState> get peers => $_getList(3);

  @$pb.TagNumber(5)
  $pb.PbList<RelayState> get relays => $_getList(4);

  @$pb.TagNumber(6)
  $pb.PbList<NSGroupState> get dnsServers => $_getList(5);

  @$pb.TagNumber(7)
  $pb.PbList<SystemEvent> get events => $_getList(6);

  @$pb.TagNumber(8)
  $core.int get numberOfForwardingRules => $_getIZ(7);
  @$pb.TagNumber(8)
  set numberOfForwardingRules($core.int value) => $_setSignedInt32(7, value);
  @$pb.TagNumber(8)
  $core.bool hasNumberOfForwardingRules() => $_has(7);
  @$pb.TagNumber(8)
  void clearNumberOfForwardingRules() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.bool get lazyConnectionEnabled => $_getBF(8);
  @$pb.TagNumber(9)
  set lazyConnectionEnabled($core.bool value) => $_setBool(8, value);
  @$pb.TagNumber(9)
  $core.bool hasLazyConnectionEnabled() => $_has(8);
  @$pb.TagNumber(9)
  void clearLazyConnectionEnabled() => $_clearField(9);

  @$pb.TagNumber(10)
  SSHServerState get sshServerState => $_getN(9);
  @$pb.TagNumber(10)
  set sshServerState(SSHServerState value) => $_setField(10, value);
  @$pb.TagNumber(10)
  $core.bool hasSshServerState() => $_has(9);
  @$pb.TagNumber(10)
  void clearSshServerState() => $_clearField(10);
  @$pb.TagNumber(10)
  SSHServerState ensureSshServerState() => $_ensure(9);
}

/// Networks
class ListNetworksRequest extends $pb.GeneratedMessage {
  factory ListNetworksRequest() => create();

  ListNetworksRequest._();

  factory ListNetworksRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ListNetworksRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListNetworksRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListNetworksRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListNetworksRequest copyWith(void Function(ListNetworksRequest) updates) =>
      super.copyWith((message) => updates(message as ListNetworksRequest))
          as ListNetworksRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListNetworksRequest create() => ListNetworksRequest._();
  @$core.override
  ListNetworksRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ListNetworksRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListNetworksRequest>(create);
  static ListNetworksRequest? _defaultInstance;
}

class ListNetworksResponse extends $pb.GeneratedMessage {
  factory ListNetworksResponse({
    $core.Iterable<Network>? routes,
  }) {
    final result = create();
    if (routes != null) result.routes.addAll(routes);
    return result;
  }

  ListNetworksResponse._();

  factory ListNetworksResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ListNetworksResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListNetworksResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPM<Network>(1, _omitFieldNames ? '' : 'routes',
        subBuilder: Network.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListNetworksResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListNetworksResponse copyWith(void Function(ListNetworksResponse) updates) =>
      super.copyWith((message) => updates(message as ListNetworksResponse))
          as ListNetworksResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListNetworksResponse create() => ListNetworksResponse._();
  @$core.override
  ListNetworksResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ListNetworksResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListNetworksResponse>(create);
  static ListNetworksResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<Network> get routes => $_getList(0);
}

class SelectNetworksRequest extends $pb.GeneratedMessage {
  factory SelectNetworksRequest({
    $core.Iterable<$core.String>? networkIDs,
    $core.bool? append,
    $core.bool? all,
  }) {
    final result = create();
    if (networkIDs != null) result.networkIDs.addAll(networkIDs);
    if (append != null) result.append = append;
    if (all != null) result.all = all;
    return result;
  }

  SelectNetworksRequest._();

  factory SelectNetworksRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SelectNetworksRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SelectNetworksRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPS(1, _omitFieldNames ? '' : 'networkIDs', protoName: 'networkIDs')
    ..aOB(2, _omitFieldNames ? '' : 'append')
    ..aOB(3, _omitFieldNames ? '' : 'all')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SelectNetworksRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SelectNetworksRequest copyWith(
          void Function(SelectNetworksRequest) updates) =>
      super.copyWith((message) => updates(message as SelectNetworksRequest))
          as SelectNetworksRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SelectNetworksRequest create() => SelectNetworksRequest._();
  @$core.override
  SelectNetworksRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SelectNetworksRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SelectNetworksRequest>(create);
  static SelectNetworksRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<$core.String> get networkIDs => $_getList(0);

  @$pb.TagNumber(2)
  $core.bool get append => $_getBF(1);
  @$pb.TagNumber(2)
  set append($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAppend() => $_has(1);
  @$pb.TagNumber(2)
  void clearAppend() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get all => $_getBF(2);
  @$pb.TagNumber(3)
  set all($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasAll() => $_has(2);
  @$pb.TagNumber(3)
  void clearAll() => $_clearField(3);
}

class SelectNetworksResponse extends $pb.GeneratedMessage {
  factory SelectNetworksResponse() => create();

  SelectNetworksResponse._();

  factory SelectNetworksResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SelectNetworksResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SelectNetworksResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SelectNetworksResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SelectNetworksResponse copyWith(
          void Function(SelectNetworksResponse) updates) =>
      super.copyWith((message) => updates(message as SelectNetworksResponse))
          as SelectNetworksResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SelectNetworksResponse create() => SelectNetworksResponse._();
  @$core.override
  SelectNetworksResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SelectNetworksResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SelectNetworksResponse>(create);
  static SelectNetworksResponse? _defaultInstance;
}

class IPList extends $pb.GeneratedMessage {
  factory IPList({
    $core.Iterable<$core.String>? ips,
  }) {
    final result = create();
    if (ips != null) result.ips.addAll(ips);
    return result;
  }

  IPList._();

  factory IPList.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory IPList.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'IPList',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPS(1, _omitFieldNames ? '' : 'ips')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  IPList clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  IPList copyWith(void Function(IPList) updates) =>
      super.copyWith((message) => updates(message as IPList)) as IPList;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static IPList create() => IPList._();
  @$core.override
  IPList createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static IPList getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<IPList>(create);
  static IPList? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<$core.String> get ips => $_getList(0);
}

class Network extends $pb.GeneratedMessage {
  factory Network({
    $core.String? iD,
    $core.String? range,
    $core.bool? selected,
    $core.Iterable<$core.String>? domains,
    $core.Iterable<$core.MapEntry<$core.String, IPList>>? resolvedIPs,
  }) {
    final result = create();
    if (iD != null) result.iD = iD;
    if (range != null) result.range = range;
    if (selected != null) result.selected = selected;
    if (domains != null) result.domains.addAll(domains);
    if (resolvedIPs != null) result.resolvedIPs.addEntries(resolvedIPs);
    return result;
  }

  Network._();

  factory Network.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory Network.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'Network',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'ID', protoName: 'ID')
    ..aOS(2, _omitFieldNames ? '' : 'range')
    ..aOB(3, _omitFieldNames ? '' : 'selected')
    ..pPS(4, _omitFieldNames ? '' : 'domains')
    ..m<$core.String, IPList>(5, _omitFieldNames ? '' : 'resolvedIPs',
        protoName: 'resolvedIPs',
        entryClassName: 'Network.ResolvedIPsEntry',
        keyFieldType: $pb.PbFieldType.OS,
        valueFieldType: $pb.PbFieldType.OM,
        valueCreator: IPList.create,
        valueDefaultOrMaker: IPList.getDefault,
        packageName: const $pb.PackageName('daemon'))
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Network clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Network copyWith(void Function(Network) updates) =>
      super.copyWith((message) => updates(message as Network)) as Network;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static Network create() => Network._();
  @$core.override
  Network createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static Network getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<Network>(create);
  static Network? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get iD => $_getSZ(0);
  @$pb.TagNumber(1)
  set iD($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasID() => $_has(0);
  @$pb.TagNumber(1)
  void clearID() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get range => $_getSZ(1);
  @$pb.TagNumber(2)
  set range($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasRange() => $_has(1);
  @$pb.TagNumber(2)
  void clearRange() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get selected => $_getBF(2);
  @$pb.TagNumber(3)
  set selected($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasSelected() => $_has(2);
  @$pb.TagNumber(3)
  void clearSelected() => $_clearField(3);

  @$pb.TagNumber(4)
  $pb.PbList<$core.String> get domains => $_getList(3);

  @$pb.TagNumber(5)
  $pb.PbMap<$core.String, IPList> get resolvedIPs => $_getMap(4);
}

class PortInfo_Range extends $pb.GeneratedMessage {
  factory PortInfo_Range({
    $core.int? start,
    $core.int? end,
  }) {
    final result = create();
    if (start != null) result.start = start;
    if (end != null) result.end = end;
    return result;
  }

  PortInfo_Range._();

  factory PortInfo_Range.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory PortInfo_Range.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PortInfo.Range',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aI(1, _omitFieldNames ? '' : 'start', fieldType: $pb.PbFieldType.OU3)
    ..aI(2, _omitFieldNames ? '' : 'end', fieldType: $pb.PbFieldType.OU3)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PortInfo_Range clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PortInfo_Range copyWith(void Function(PortInfo_Range) updates) =>
      super.copyWith((message) => updates(message as PortInfo_Range))
          as PortInfo_Range;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PortInfo_Range create() => PortInfo_Range._();
  @$core.override
  PortInfo_Range createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static PortInfo_Range getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<PortInfo_Range>(create);
  static PortInfo_Range? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get start => $_getIZ(0);
  @$pb.TagNumber(1)
  set start($core.int value) => $_setUnsignedInt32(0, value);
  @$pb.TagNumber(1)
  $core.bool hasStart() => $_has(0);
  @$pb.TagNumber(1)
  void clearStart() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.int get end => $_getIZ(1);
  @$pb.TagNumber(2)
  set end($core.int value) => $_setUnsignedInt32(1, value);
  @$pb.TagNumber(2)
  $core.bool hasEnd() => $_has(1);
  @$pb.TagNumber(2)
  void clearEnd() => $_clearField(2);
}

enum PortInfo_PortSelection { port, range, notSet }

/// ForwardingRules
class PortInfo extends $pb.GeneratedMessage {
  factory PortInfo({
    $core.int? port,
    PortInfo_Range? range,
  }) {
    final result = create();
    if (port != null) result.port = port;
    if (range != null) result.range = range;
    return result;
  }

  PortInfo._();

  factory PortInfo.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory PortInfo.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, PortInfo_PortSelection>
      _PortInfo_PortSelectionByTag = {
    1: PortInfo_PortSelection.port,
    2: PortInfo_PortSelection.range,
    0: PortInfo_PortSelection.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'PortInfo',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..oo(0, [1, 2])
    ..aI(1, _omitFieldNames ? '' : 'port', fieldType: $pb.PbFieldType.OU3)
    ..aOM<PortInfo_Range>(2, _omitFieldNames ? '' : 'range',
        subBuilder: PortInfo_Range.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PortInfo clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  PortInfo copyWith(void Function(PortInfo) updates) =>
      super.copyWith((message) => updates(message as PortInfo)) as PortInfo;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static PortInfo create() => PortInfo._();
  @$core.override
  PortInfo createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static PortInfo getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<PortInfo>(create);
  static PortInfo? _defaultInstance;

  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  PortInfo_PortSelection whichPortSelection() =>
      _PortInfo_PortSelectionByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  @$pb.TagNumber(2)
  void clearPortSelection() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  $core.int get port => $_getIZ(0);
  @$pb.TagNumber(1)
  set port($core.int value) => $_setUnsignedInt32(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPort() => $_has(0);
  @$pb.TagNumber(1)
  void clearPort() => $_clearField(1);

  @$pb.TagNumber(2)
  PortInfo_Range get range => $_getN(1);
  @$pb.TagNumber(2)
  set range(PortInfo_Range value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasRange() => $_has(1);
  @$pb.TagNumber(2)
  void clearRange() => $_clearField(2);
  @$pb.TagNumber(2)
  PortInfo_Range ensureRange() => $_ensure(1);
}

class ForwardingRule extends $pb.GeneratedMessage {
  factory ForwardingRule({
    $core.String? protocol,
    PortInfo? destinationPort,
    $core.String? translatedAddress,
    $core.String? translatedHostname,
    PortInfo? translatedPort,
  }) {
    final result = create();
    if (protocol != null) result.protocol = protocol;
    if (destinationPort != null) result.destinationPort = destinationPort;
    if (translatedAddress != null) result.translatedAddress = translatedAddress;
    if (translatedHostname != null)
      result.translatedHostname = translatedHostname;
    if (translatedPort != null) result.translatedPort = translatedPort;
    return result;
  }

  ForwardingRule._();

  factory ForwardingRule.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ForwardingRule.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ForwardingRule',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'protocol')
    ..aOM<PortInfo>(2, _omitFieldNames ? '' : 'destinationPort',
        protoName: 'destinationPort', subBuilder: PortInfo.create)
    ..aOS(3, _omitFieldNames ? '' : 'translatedAddress',
        protoName: 'translatedAddress')
    ..aOS(4, _omitFieldNames ? '' : 'translatedHostname',
        protoName: 'translatedHostname')
    ..aOM<PortInfo>(5, _omitFieldNames ? '' : 'translatedPort',
        protoName: 'translatedPort', subBuilder: PortInfo.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ForwardingRule clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ForwardingRule copyWith(void Function(ForwardingRule) updates) =>
      super.copyWith((message) => updates(message as ForwardingRule))
          as ForwardingRule;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ForwardingRule create() => ForwardingRule._();
  @$core.override
  ForwardingRule createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ForwardingRule getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ForwardingRule>(create);
  static ForwardingRule? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get protocol => $_getSZ(0);
  @$pb.TagNumber(1)
  set protocol($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProtocol() => $_has(0);
  @$pb.TagNumber(1)
  void clearProtocol() => $_clearField(1);

  @$pb.TagNumber(2)
  PortInfo get destinationPort => $_getN(1);
  @$pb.TagNumber(2)
  set destinationPort(PortInfo value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasDestinationPort() => $_has(1);
  @$pb.TagNumber(2)
  void clearDestinationPort() => $_clearField(2);
  @$pb.TagNumber(2)
  PortInfo ensureDestinationPort() => $_ensure(1);

  @$pb.TagNumber(3)
  $core.String get translatedAddress => $_getSZ(2);
  @$pb.TagNumber(3)
  set translatedAddress($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasTranslatedAddress() => $_has(2);
  @$pb.TagNumber(3)
  void clearTranslatedAddress() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get translatedHostname => $_getSZ(3);
  @$pb.TagNumber(4)
  set translatedHostname($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasTranslatedHostname() => $_has(3);
  @$pb.TagNumber(4)
  void clearTranslatedHostname() => $_clearField(4);

  @$pb.TagNumber(5)
  PortInfo get translatedPort => $_getN(4);
  @$pb.TagNumber(5)
  set translatedPort(PortInfo value) => $_setField(5, value);
  @$pb.TagNumber(5)
  $core.bool hasTranslatedPort() => $_has(4);
  @$pb.TagNumber(5)
  void clearTranslatedPort() => $_clearField(5);
  @$pb.TagNumber(5)
  PortInfo ensureTranslatedPort() => $_ensure(4);
}

class ForwardingRulesResponse extends $pb.GeneratedMessage {
  factory ForwardingRulesResponse({
    $core.Iterable<ForwardingRule>? rules,
  }) {
    final result = create();
    if (rules != null) result.rules.addAll(rules);
    return result;
  }

  ForwardingRulesResponse._();

  factory ForwardingRulesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ForwardingRulesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ForwardingRulesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPM<ForwardingRule>(1, _omitFieldNames ? '' : 'rules',
        subBuilder: ForwardingRule.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ForwardingRulesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ForwardingRulesResponse copyWith(
          void Function(ForwardingRulesResponse) updates) =>
      super.copyWith((message) => updates(message as ForwardingRulesResponse))
          as ForwardingRulesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ForwardingRulesResponse create() => ForwardingRulesResponse._();
  @$core.override
  ForwardingRulesResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ForwardingRulesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ForwardingRulesResponse>(create);
  static ForwardingRulesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<ForwardingRule> get rules => $_getList(0);
}

/// DebugBundler
class DebugBundleRequest extends $pb.GeneratedMessage {
  factory DebugBundleRequest({
    $core.bool? anonymize,
    $core.bool? systemInfo,
    $core.String? uploadURL,
    $core.int? logFileCount,
  }) {
    final result = create();
    if (anonymize != null) result.anonymize = anonymize;
    if (systemInfo != null) result.systemInfo = systemInfo;
    if (uploadURL != null) result.uploadURL = uploadURL;
    if (logFileCount != null) result.logFileCount = logFileCount;
    return result;
  }

  DebugBundleRequest._();

  factory DebugBundleRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory DebugBundleRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'DebugBundleRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'anonymize')
    ..aOB(3, _omitFieldNames ? '' : 'systemInfo', protoName: 'systemInfo')
    ..aOS(4, _omitFieldNames ? '' : 'uploadURL', protoName: 'uploadURL')
    ..aI(5, _omitFieldNames ? '' : 'logFileCount',
        protoName: 'logFileCount', fieldType: $pb.PbFieldType.OU3)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DebugBundleRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DebugBundleRequest copyWith(void Function(DebugBundleRequest) updates) =>
      super.copyWith((message) => updates(message as DebugBundleRequest))
          as DebugBundleRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DebugBundleRequest create() => DebugBundleRequest._();
  @$core.override
  DebugBundleRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static DebugBundleRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<DebugBundleRequest>(create);
  static DebugBundleRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get anonymize => $_getBF(0);
  @$pb.TagNumber(1)
  set anonymize($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasAnonymize() => $_has(0);
  @$pb.TagNumber(1)
  void clearAnonymize() => $_clearField(1);

  @$pb.TagNumber(3)
  $core.bool get systemInfo => $_getBF(1);
  @$pb.TagNumber(3)
  set systemInfo($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(3)
  $core.bool hasSystemInfo() => $_has(1);
  @$pb.TagNumber(3)
  void clearSystemInfo() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get uploadURL => $_getSZ(2);
  @$pb.TagNumber(4)
  set uploadURL($core.String value) => $_setString(2, value);
  @$pb.TagNumber(4)
  $core.bool hasUploadURL() => $_has(2);
  @$pb.TagNumber(4)
  void clearUploadURL() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.int get logFileCount => $_getIZ(3);
  @$pb.TagNumber(5)
  set logFileCount($core.int value) => $_setUnsignedInt32(3, value);
  @$pb.TagNumber(5)
  $core.bool hasLogFileCount() => $_has(3);
  @$pb.TagNumber(5)
  void clearLogFileCount() => $_clearField(5);
}

class DebugBundleResponse extends $pb.GeneratedMessage {
  factory DebugBundleResponse({
    $core.String? path,
    $core.String? uploadedKey,
    $core.String? uploadFailureReason,
  }) {
    final result = create();
    if (path != null) result.path = path;
    if (uploadedKey != null) result.uploadedKey = uploadedKey;
    if (uploadFailureReason != null)
      result.uploadFailureReason = uploadFailureReason;
    return result;
  }

  DebugBundleResponse._();

  factory DebugBundleResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory DebugBundleResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'DebugBundleResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'path')
    ..aOS(2, _omitFieldNames ? '' : 'uploadedKey', protoName: 'uploadedKey')
    ..aOS(3, _omitFieldNames ? '' : 'uploadFailureReason',
        protoName: 'uploadFailureReason')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DebugBundleResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DebugBundleResponse copyWith(void Function(DebugBundleResponse) updates) =>
      super.copyWith((message) => updates(message as DebugBundleResponse))
          as DebugBundleResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DebugBundleResponse create() => DebugBundleResponse._();
  @$core.override
  DebugBundleResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static DebugBundleResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<DebugBundleResponse>(create);
  static DebugBundleResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get path => $_getSZ(0);
  @$pb.TagNumber(1)
  set path($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPath() => $_has(0);
  @$pb.TagNumber(1)
  void clearPath() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get uploadedKey => $_getSZ(1);
  @$pb.TagNumber(2)
  set uploadedKey($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUploadedKey() => $_has(1);
  @$pb.TagNumber(2)
  void clearUploadedKey() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get uploadFailureReason => $_getSZ(2);
  @$pb.TagNumber(3)
  set uploadFailureReason($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasUploadFailureReason() => $_has(2);
  @$pb.TagNumber(3)
  void clearUploadFailureReason() => $_clearField(3);
}

class GetLogLevelRequest extends $pb.GeneratedMessage {
  factory GetLogLevelRequest() => create();

  GetLogLevelRequest._();

  factory GetLogLevelRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetLogLevelRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetLogLevelRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLogLevelRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLogLevelRequest copyWith(void Function(GetLogLevelRequest) updates) =>
      super.copyWith((message) => updates(message as GetLogLevelRequest))
          as GetLogLevelRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetLogLevelRequest create() => GetLogLevelRequest._();
  @$core.override
  GetLogLevelRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetLogLevelRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetLogLevelRequest>(create);
  static GetLogLevelRequest? _defaultInstance;
}

class GetLogLevelResponse extends $pb.GeneratedMessage {
  factory GetLogLevelResponse({
    LogLevel? level,
  }) {
    final result = create();
    if (level != null) result.level = level;
    return result;
  }

  GetLogLevelResponse._();

  factory GetLogLevelResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetLogLevelResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetLogLevelResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aE<LogLevel>(1, _omitFieldNames ? '' : 'level',
        enumValues: LogLevel.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLogLevelResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetLogLevelResponse copyWith(void Function(GetLogLevelResponse) updates) =>
      super.copyWith((message) => updates(message as GetLogLevelResponse))
          as GetLogLevelResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetLogLevelResponse create() => GetLogLevelResponse._();
  @$core.override
  GetLogLevelResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetLogLevelResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetLogLevelResponse>(create);
  static GetLogLevelResponse? _defaultInstance;

  @$pb.TagNumber(1)
  LogLevel get level => $_getN(0);
  @$pb.TagNumber(1)
  set level(LogLevel value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasLevel() => $_has(0);
  @$pb.TagNumber(1)
  void clearLevel() => $_clearField(1);
}

class SetLogLevelRequest extends $pb.GeneratedMessage {
  factory SetLogLevelRequest({
    LogLevel? level,
  }) {
    final result = create();
    if (level != null) result.level = level;
    return result;
  }

  SetLogLevelRequest._();

  factory SetLogLevelRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SetLogLevelRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SetLogLevelRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aE<LogLevel>(1, _omitFieldNames ? '' : 'level',
        enumValues: LogLevel.values)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetLogLevelRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetLogLevelRequest copyWith(void Function(SetLogLevelRequest) updates) =>
      super.copyWith((message) => updates(message as SetLogLevelRequest))
          as SetLogLevelRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SetLogLevelRequest create() => SetLogLevelRequest._();
  @$core.override
  SetLogLevelRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SetLogLevelRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SetLogLevelRequest>(create);
  static SetLogLevelRequest? _defaultInstance;

  @$pb.TagNumber(1)
  LogLevel get level => $_getN(0);
  @$pb.TagNumber(1)
  set level(LogLevel value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasLevel() => $_has(0);
  @$pb.TagNumber(1)
  void clearLevel() => $_clearField(1);
}

class SetLogLevelResponse extends $pb.GeneratedMessage {
  factory SetLogLevelResponse() => create();

  SetLogLevelResponse._();

  factory SetLogLevelResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SetLogLevelResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SetLogLevelResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetLogLevelResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetLogLevelResponse copyWith(void Function(SetLogLevelResponse) updates) =>
      super.copyWith((message) => updates(message as SetLogLevelResponse))
          as SetLogLevelResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SetLogLevelResponse create() => SetLogLevelResponse._();
  @$core.override
  SetLogLevelResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SetLogLevelResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SetLogLevelResponse>(create);
  static SetLogLevelResponse? _defaultInstance;
}

/// State represents a daemon state entry
class State extends $pb.GeneratedMessage {
  factory State({
    $core.String? name,
  }) {
    final result = create();
    if (name != null) result.name = name;
    return result;
  }

  State._();

  factory State.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory State.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'State',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'name')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  State clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  State copyWith(void Function(State) updates) =>
      super.copyWith((message) => updates(message as State)) as State;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static State create() => State._();
  @$core.override
  State createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static State getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<State>(create);
  static State? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get name => $_getSZ(0);
  @$pb.TagNumber(1)
  set name($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasName() => $_has(0);
  @$pb.TagNumber(1)
  void clearName() => $_clearField(1);
}

/// ListStatesRequest is empty as it requires no parameters
class ListStatesRequest extends $pb.GeneratedMessage {
  factory ListStatesRequest() => create();

  ListStatesRequest._();

  factory ListStatesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ListStatesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListStatesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListStatesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListStatesRequest copyWith(void Function(ListStatesRequest) updates) =>
      super.copyWith((message) => updates(message as ListStatesRequest))
          as ListStatesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListStatesRequest create() => ListStatesRequest._();
  @$core.override
  ListStatesRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ListStatesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListStatesRequest>(create);
  static ListStatesRequest? _defaultInstance;
}

/// ListStatesResponse contains a list of states
class ListStatesResponse extends $pb.GeneratedMessage {
  factory ListStatesResponse({
    $core.Iterable<State>? states,
  }) {
    final result = create();
    if (states != null) result.states.addAll(states);
    return result;
  }

  ListStatesResponse._();

  factory ListStatesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ListStatesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListStatesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPM<State>(1, _omitFieldNames ? '' : 'states', subBuilder: State.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListStatesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListStatesResponse copyWith(void Function(ListStatesResponse) updates) =>
      super.copyWith((message) => updates(message as ListStatesResponse))
          as ListStatesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListStatesResponse create() => ListStatesResponse._();
  @$core.override
  ListStatesResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ListStatesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListStatesResponse>(create);
  static ListStatesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<State> get states => $_getList(0);
}

/// CleanStateRequest for cleaning states
class CleanStateRequest extends $pb.GeneratedMessage {
  factory CleanStateRequest({
    $core.String? stateName,
    $core.bool? all,
  }) {
    final result = create();
    if (stateName != null) result.stateName = stateName;
    if (all != null) result.all = all;
    return result;
  }

  CleanStateRequest._();

  factory CleanStateRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory CleanStateRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CleanStateRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'stateName')
    ..aOB(2, _omitFieldNames ? '' : 'all')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CleanStateRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CleanStateRequest copyWith(void Function(CleanStateRequest) updates) =>
      super.copyWith((message) => updates(message as CleanStateRequest))
          as CleanStateRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CleanStateRequest create() => CleanStateRequest._();
  @$core.override
  CleanStateRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static CleanStateRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CleanStateRequest>(create);
  static CleanStateRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get stateName => $_getSZ(0);
  @$pb.TagNumber(1)
  set stateName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasStateName() => $_has(0);
  @$pb.TagNumber(1)
  void clearStateName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get all => $_getBF(1);
  @$pb.TagNumber(2)
  set all($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAll() => $_has(1);
  @$pb.TagNumber(2)
  void clearAll() => $_clearField(2);
}

/// CleanStateResponse contains the result of the clean operation
class CleanStateResponse extends $pb.GeneratedMessage {
  factory CleanStateResponse({
    $core.int? cleanedStates,
  }) {
    final result = create();
    if (cleanedStates != null) result.cleanedStates = cleanedStates;
    return result;
  }

  CleanStateResponse._();

  factory CleanStateResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory CleanStateResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'CleanStateResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aI(1, _omitFieldNames ? '' : 'cleanedStates')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CleanStateResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  CleanStateResponse copyWith(void Function(CleanStateResponse) updates) =>
      super.copyWith((message) => updates(message as CleanStateResponse))
          as CleanStateResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static CleanStateResponse create() => CleanStateResponse._();
  @$core.override
  CleanStateResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static CleanStateResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<CleanStateResponse>(create);
  static CleanStateResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get cleanedStates => $_getIZ(0);
  @$pb.TagNumber(1)
  set cleanedStates($core.int value) => $_setSignedInt32(0, value);
  @$pb.TagNumber(1)
  $core.bool hasCleanedStates() => $_has(0);
  @$pb.TagNumber(1)
  void clearCleanedStates() => $_clearField(1);
}

/// DeleteStateRequest for deleting states
class DeleteStateRequest extends $pb.GeneratedMessage {
  factory DeleteStateRequest({
    $core.String? stateName,
    $core.bool? all,
  }) {
    final result = create();
    if (stateName != null) result.stateName = stateName;
    if (all != null) result.all = all;
    return result;
  }

  DeleteStateRequest._();

  factory DeleteStateRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory DeleteStateRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'DeleteStateRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'stateName')
    ..aOB(2, _omitFieldNames ? '' : 'all')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DeleteStateRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DeleteStateRequest copyWith(void Function(DeleteStateRequest) updates) =>
      super.copyWith((message) => updates(message as DeleteStateRequest))
          as DeleteStateRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DeleteStateRequest create() => DeleteStateRequest._();
  @$core.override
  DeleteStateRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static DeleteStateRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<DeleteStateRequest>(create);
  static DeleteStateRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get stateName => $_getSZ(0);
  @$pb.TagNumber(1)
  set stateName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasStateName() => $_has(0);
  @$pb.TagNumber(1)
  void clearStateName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get all => $_getBF(1);
  @$pb.TagNumber(2)
  set all($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAll() => $_has(1);
  @$pb.TagNumber(2)
  void clearAll() => $_clearField(2);
}

/// DeleteStateResponse contains the result of the delete operation
class DeleteStateResponse extends $pb.GeneratedMessage {
  factory DeleteStateResponse({
    $core.int? deletedStates,
  }) {
    final result = create();
    if (deletedStates != null) result.deletedStates = deletedStates;
    return result;
  }

  DeleteStateResponse._();

  factory DeleteStateResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory DeleteStateResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'DeleteStateResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aI(1, _omitFieldNames ? '' : 'deletedStates')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DeleteStateResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  DeleteStateResponse copyWith(void Function(DeleteStateResponse) updates) =>
      super.copyWith((message) => updates(message as DeleteStateResponse))
          as DeleteStateResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static DeleteStateResponse create() => DeleteStateResponse._();
  @$core.override
  DeleteStateResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static DeleteStateResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<DeleteStateResponse>(create);
  static DeleteStateResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get deletedStates => $_getIZ(0);
  @$pb.TagNumber(1)
  set deletedStates($core.int value) => $_setSignedInt32(0, value);
  @$pb.TagNumber(1)
  $core.bool hasDeletedStates() => $_has(0);
  @$pb.TagNumber(1)
  void clearDeletedStates() => $_clearField(1);
}

class SetSyncResponsePersistenceRequest extends $pb.GeneratedMessage {
  factory SetSyncResponsePersistenceRequest({
    $core.bool? enabled,
  }) {
    final result = create();
    if (enabled != null) result.enabled = enabled;
    return result;
  }

  SetSyncResponsePersistenceRequest._();

  factory SetSyncResponsePersistenceRequest.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SetSyncResponsePersistenceRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SetSyncResponsePersistenceRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'enabled')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetSyncResponsePersistenceRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetSyncResponsePersistenceRequest copyWith(
          void Function(SetSyncResponsePersistenceRequest) updates) =>
      super.copyWith((message) =>
              updates(message as SetSyncResponsePersistenceRequest))
          as SetSyncResponsePersistenceRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SetSyncResponsePersistenceRequest create() =>
      SetSyncResponsePersistenceRequest._();
  @$core.override
  SetSyncResponsePersistenceRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SetSyncResponsePersistenceRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SetSyncResponsePersistenceRequest>(
          create);
  static SetSyncResponsePersistenceRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get enabled => $_getBF(0);
  @$pb.TagNumber(1)
  set enabled($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasEnabled() => $_has(0);
  @$pb.TagNumber(1)
  void clearEnabled() => $_clearField(1);
}

class SetSyncResponsePersistenceResponse extends $pb.GeneratedMessage {
  factory SetSyncResponsePersistenceResponse() => create();

  SetSyncResponsePersistenceResponse._();

  factory SetSyncResponsePersistenceResponse.fromBuffer(
          $core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SetSyncResponsePersistenceResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SetSyncResponsePersistenceResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetSyncResponsePersistenceResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetSyncResponsePersistenceResponse copyWith(
          void Function(SetSyncResponsePersistenceResponse) updates) =>
      super.copyWith((message) =>
              updates(message as SetSyncResponsePersistenceResponse))
          as SetSyncResponsePersistenceResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SetSyncResponsePersistenceResponse create() =>
      SetSyncResponsePersistenceResponse._();
  @$core.override
  SetSyncResponsePersistenceResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SetSyncResponsePersistenceResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SetSyncResponsePersistenceResponse>(
          create);
  static SetSyncResponsePersistenceResponse? _defaultInstance;
}

class TCPFlags extends $pb.GeneratedMessage {
  factory TCPFlags({
    $core.bool? syn,
    $core.bool? ack,
    $core.bool? fin,
    $core.bool? rst,
    $core.bool? psh,
    $core.bool? urg,
  }) {
    final result = create();
    if (syn != null) result.syn = syn;
    if (ack != null) result.ack = ack;
    if (fin != null) result.fin = fin;
    if (rst != null) result.rst = rst;
    if (psh != null) result.psh = psh;
    if (urg != null) result.urg = urg;
    return result;
  }

  TCPFlags._();

  factory TCPFlags.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory TCPFlags.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TCPFlags',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'syn')
    ..aOB(2, _omitFieldNames ? '' : 'ack')
    ..aOB(3, _omitFieldNames ? '' : 'fin')
    ..aOB(4, _omitFieldNames ? '' : 'rst')
    ..aOB(5, _omitFieldNames ? '' : 'psh')
    ..aOB(6, _omitFieldNames ? '' : 'urg')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TCPFlags clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TCPFlags copyWith(void Function(TCPFlags) updates) =>
      super.copyWith((message) => updates(message as TCPFlags)) as TCPFlags;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static TCPFlags create() => TCPFlags._();
  @$core.override
  TCPFlags createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static TCPFlags getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<TCPFlags>(create);
  static TCPFlags? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get syn => $_getBF(0);
  @$pb.TagNumber(1)
  set syn($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSyn() => $_has(0);
  @$pb.TagNumber(1)
  void clearSyn() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get ack => $_getBF(1);
  @$pb.TagNumber(2)
  set ack($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasAck() => $_has(1);
  @$pb.TagNumber(2)
  void clearAck() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get fin => $_getBF(2);
  @$pb.TagNumber(3)
  set fin($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasFin() => $_has(2);
  @$pb.TagNumber(3)
  void clearFin() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.bool get rst => $_getBF(3);
  @$pb.TagNumber(4)
  set rst($core.bool value) => $_setBool(3, value);
  @$pb.TagNumber(4)
  $core.bool hasRst() => $_has(3);
  @$pb.TagNumber(4)
  void clearRst() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.bool get psh => $_getBF(4);
  @$pb.TagNumber(5)
  set psh($core.bool value) => $_setBool(4, value);
  @$pb.TagNumber(5)
  $core.bool hasPsh() => $_has(4);
  @$pb.TagNumber(5)
  void clearPsh() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.bool get urg => $_getBF(5);
  @$pb.TagNumber(6)
  set urg($core.bool value) => $_setBool(5, value);
  @$pb.TagNumber(6)
  $core.bool hasUrg() => $_has(5);
  @$pb.TagNumber(6)
  void clearUrg() => $_clearField(6);
}

class TracePacketRequest extends $pb.GeneratedMessage {
  factory TracePacketRequest({
    $core.String? sourceIp,
    $core.String? destinationIp,
    $core.String? protocol,
    $core.int? sourcePort,
    $core.int? destinationPort,
    $core.String? direction,
    TCPFlags? tcpFlags,
    $core.int? icmpType,
    $core.int? icmpCode,
  }) {
    final result = create();
    if (sourceIp != null) result.sourceIp = sourceIp;
    if (destinationIp != null) result.destinationIp = destinationIp;
    if (protocol != null) result.protocol = protocol;
    if (sourcePort != null) result.sourcePort = sourcePort;
    if (destinationPort != null) result.destinationPort = destinationPort;
    if (direction != null) result.direction = direction;
    if (tcpFlags != null) result.tcpFlags = tcpFlags;
    if (icmpType != null) result.icmpType = icmpType;
    if (icmpCode != null) result.icmpCode = icmpCode;
    return result;
  }

  TracePacketRequest._();

  factory TracePacketRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory TracePacketRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TracePacketRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'sourceIp')
    ..aOS(2, _omitFieldNames ? '' : 'destinationIp')
    ..aOS(3, _omitFieldNames ? '' : 'protocol')
    ..aI(4, _omitFieldNames ? '' : 'sourcePort', fieldType: $pb.PbFieldType.OU3)
    ..aI(5, _omitFieldNames ? '' : 'destinationPort',
        fieldType: $pb.PbFieldType.OU3)
    ..aOS(6, _omitFieldNames ? '' : 'direction')
    ..aOM<TCPFlags>(7, _omitFieldNames ? '' : 'tcpFlags',
        subBuilder: TCPFlags.create)
    ..aI(8, _omitFieldNames ? '' : 'icmpType', fieldType: $pb.PbFieldType.OU3)
    ..aI(9, _omitFieldNames ? '' : 'icmpCode', fieldType: $pb.PbFieldType.OU3)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TracePacketRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TracePacketRequest copyWith(void Function(TracePacketRequest) updates) =>
      super.copyWith((message) => updates(message as TracePacketRequest))
          as TracePacketRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static TracePacketRequest create() => TracePacketRequest._();
  @$core.override
  TracePacketRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static TracePacketRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<TracePacketRequest>(create);
  static TracePacketRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get sourceIp => $_getSZ(0);
  @$pb.TagNumber(1)
  set sourceIp($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSourceIp() => $_has(0);
  @$pb.TagNumber(1)
  void clearSourceIp() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get destinationIp => $_getSZ(1);
  @$pb.TagNumber(2)
  set destinationIp($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasDestinationIp() => $_has(1);
  @$pb.TagNumber(2)
  void clearDestinationIp() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get protocol => $_getSZ(2);
  @$pb.TagNumber(3)
  set protocol($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasProtocol() => $_has(2);
  @$pb.TagNumber(3)
  void clearProtocol() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.int get sourcePort => $_getIZ(3);
  @$pb.TagNumber(4)
  set sourcePort($core.int value) => $_setUnsignedInt32(3, value);
  @$pb.TagNumber(4)
  $core.bool hasSourcePort() => $_has(3);
  @$pb.TagNumber(4)
  void clearSourcePort() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.int get destinationPort => $_getIZ(4);
  @$pb.TagNumber(5)
  set destinationPort($core.int value) => $_setUnsignedInt32(4, value);
  @$pb.TagNumber(5)
  $core.bool hasDestinationPort() => $_has(4);
  @$pb.TagNumber(5)
  void clearDestinationPort() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.String get direction => $_getSZ(5);
  @$pb.TagNumber(6)
  set direction($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasDirection() => $_has(5);
  @$pb.TagNumber(6)
  void clearDirection() => $_clearField(6);

  @$pb.TagNumber(7)
  TCPFlags get tcpFlags => $_getN(6);
  @$pb.TagNumber(7)
  set tcpFlags(TCPFlags value) => $_setField(7, value);
  @$pb.TagNumber(7)
  $core.bool hasTcpFlags() => $_has(6);
  @$pb.TagNumber(7)
  void clearTcpFlags() => $_clearField(7);
  @$pb.TagNumber(7)
  TCPFlags ensureTcpFlags() => $_ensure(6);

  @$pb.TagNumber(8)
  $core.int get icmpType => $_getIZ(7);
  @$pb.TagNumber(8)
  set icmpType($core.int value) => $_setUnsignedInt32(7, value);
  @$pb.TagNumber(8)
  $core.bool hasIcmpType() => $_has(7);
  @$pb.TagNumber(8)
  void clearIcmpType() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.int get icmpCode => $_getIZ(8);
  @$pb.TagNumber(9)
  set icmpCode($core.int value) => $_setUnsignedInt32(8, value);
  @$pb.TagNumber(9)
  $core.bool hasIcmpCode() => $_has(8);
  @$pb.TagNumber(9)
  void clearIcmpCode() => $_clearField(9);
}

class TraceStage extends $pb.GeneratedMessage {
  factory TraceStage({
    $core.String? name,
    $core.String? message,
    $core.bool? allowed,
    $core.String? forwardingDetails,
  }) {
    final result = create();
    if (name != null) result.name = name;
    if (message != null) result.message = message;
    if (allowed != null) result.allowed = allowed;
    if (forwardingDetails != null) result.forwardingDetails = forwardingDetails;
    return result;
  }

  TraceStage._();

  factory TraceStage.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory TraceStage.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TraceStage',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'name')
    ..aOS(2, _omitFieldNames ? '' : 'message')
    ..aOB(3, _omitFieldNames ? '' : 'allowed')
    ..aOS(4, _omitFieldNames ? '' : 'forwardingDetails')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TraceStage clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TraceStage copyWith(void Function(TraceStage) updates) =>
      super.copyWith((message) => updates(message as TraceStage)) as TraceStage;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static TraceStage create() => TraceStage._();
  @$core.override
  TraceStage createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static TraceStage getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<TraceStage>(create);
  static TraceStage? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get name => $_getSZ(0);
  @$pb.TagNumber(1)
  set name($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasName() => $_has(0);
  @$pb.TagNumber(1)
  void clearName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get message => $_getSZ(1);
  @$pb.TagNumber(2)
  set message($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasMessage() => $_has(1);
  @$pb.TagNumber(2)
  void clearMessage() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get allowed => $_getBF(2);
  @$pb.TagNumber(3)
  set allowed($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasAllowed() => $_has(2);
  @$pb.TagNumber(3)
  void clearAllowed() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get forwardingDetails => $_getSZ(3);
  @$pb.TagNumber(4)
  set forwardingDetails($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasForwardingDetails() => $_has(3);
  @$pb.TagNumber(4)
  void clearForwardingDetails() => $_clearField(4);
}

class TracePacketResponse extends $pb.GeneratedMessage {
  factory TracePacketResponse({
    $core.Iterable<TraceStage>? stages,
    $core.bool? finalDisposition,
  }) {
    final result = create();
    if (stages != null) result.stages.addAll(stages);
    if (finalDisposition != null) result.finalDisposition = finalDisposition;
    return result;
  }

  TracePacketResponse._();

  factory TracePacketResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory TracePacketResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TracePacketResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPM<TraceStage>(1, _omitFieldNames ? '' : 'stages',
        subBuilder: TraceStage.create)
    ..aOB(2, _omitFieldNames ? '' : 'finalDisposition')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TracePacketResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TracePacketResponse copyWith(void Function(TracePacketResponse) updates) =>
      super.copyWith((message) => updates(message as TracePacketResponse))
          as TracePacketResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static TracePacketResponse create() => TracePacketResponse._();
  @$core.override
  TracePacketResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static TracePacketResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<TracePacketResponse>(create);
  static TracePacketResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<TraceStage> get stages => $_getList(0);

  @$pb.TagNumber(2)
  $core.bool get finalDisposition => $_getBF(1);
  @$pb.TagNumber(2)
  set finalDisposition($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasFinalDisposition() => $_has(1);
  @$pb.TagNumber(2)
  void clearFinalDisposition() => $_clearField(2);
}

class SubscribeRequest extends $pb.GeneratedMessage {
  factory SubscribeRequest() => create();

  SubscribeRequest._();

  factory SubscribeRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SubscribeRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SubscribeRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SubscribeRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SubscribeRequest copyWith(void Function(SubscribeRequest) updates) =>
      super.copyWith((message) => updates(message as SubscribeRequest))
          as SubscribeRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SubscribeRequest create() => SubscribeRequest._();
  @$core.override
  SubscribeRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SubscribeRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SubscribeRequest>(create);
  static SubscribeRequest? _defaultInstance;
}

class SystemEvent extends $pb.GeneratedMessage {
  factory SystemEvent({
    $core.String? id,
    SystemEvent_Severity? severity,
    SystemEvent_Category? category,
    $core.String? message,
    $core.String? userMessage,
    $2.Timestamp? timestamp,
    $core.Iterable<$core.MapEntry<$core.String, $core.String>>? metadata,
  }) {
    final result = create();
    if (id != null) result.id = id;
    if (severity != null) result.severity = severity;
    if (category != null) result.category = category;
    if (message != null) result.message = message;
    if (userMessage != null) result.userMessage = userMessage;
    if (timestamp != null) result.timestamp = timestamp;
    if (metadata != null) result.metadata.addEntries(metadata);
    return result;
  }

  SystemEvent._();

  factory SystemEvent.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SystemEvent.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SystemEvent',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'id')
    ..aE<SystemEvent_Severity>(2, _omitFieldNames ? '' : 'severity',
        enumValues: SystemEvent_Severity.values)
    ..aE<SystemEvent_Category>(3, _omitFieldNames ? '' : 'category',
        enumValues: SystemEvent_Category.values)
    ..aOS(4, _omitFieldNames ? '' : 'message')
    ..aOS(5, _omitFieldNames ? '' : 'userMessage', protoName: 'userMessage')
    ..aOM<$2.Timestamp>(6, _omitFieldNames ? '' : 'timestamp',
        subBuilder: $2.Timestamp.create)
    ..m<$core.String, $core.String>(7, _omitFieldNames ? '' : 'metadata',
        entryClassName: 'SystemEvent.MetadataEntry',
        keyFieldType: $pb.PbFieldType.OS,
        valueFieldType: $pb.PbFieldType.OS,
        packageName: const $pb.PackageName('daemon'))
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SystemEvent clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SystemEvent copyWith(void Function(SystemEvent) updates) =>
      super.copyWith((message) => updates(message as SystemEvent))
          as SystemEvent;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SystemEvent create() => SystemEvent._();
  @$core.override
  SystemEvent createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SystemEvent getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SystemEvent>(create);
  static SystemEvent? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get id => $_getSZ(0);
  @$pb.TagNumber(1)
  set id($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasId() => $_has(0);
  @$pb.TagNumber(1)
  void clearId() => $_clearField(1);

  @$pb.TagNumber(2)
  SystemEvent_Severity get severity => $_getN(1);
  @$pb.TagNumber(2)
  set severity(SystemEvent_Severity value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasSeverity() => $_has(1);
  @$pb.TagNumber(2)
  void clearSeverity() => $_clearField(2);

  @$pb.TagNumber(3)
  SystemEvent_Category get category => $_getN(2);
  @$pb.TagNumber(3)
  set category(SystemEvent_Category value) => $_setField(3, value);
  @$pb.TagNumber(3)
  $core.bool hasCategory() => $_has(2);
  @$pb.TagNumber(3)
  void clearCategory() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get message => $_getSZ(3);
  @$pb.TagNumber(4)
  set message($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasMessage() => $_has(3);
  @$pb.TagNumber(4)
  void clearMessage() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.String get userMessage => $_getSZ(4);
  @$pb.TagNumber(5)
  set userMessage($core.String value) => $_setString(4, value);
  @$pb.TagNumber(5)
  $core.bool hasUserMessage() => $_has(4);
  @$pb.TagNumber(5)
  void clearUserMessage() => $_clearField(5);

  @$pb.TagNumber(6)
  $2.Timestamp get timestamp => $_getN(5);
  @$pb.TagNumber(6)
  set timestamp($2.Timestamp value) => $_setField(6, value);
  @$pb.TagNumber(6)
  $core.bool hasTimestamp() => $_has(5);
  @$pb.TagNumber(6)
  void clearTimestamp() => $_clearField(6);
  @$pb.TagNumber(6)
  $2.Timestamp ensureTimestamp() => $_ensure(5);

  @$pb.TagNumber(7)
  $pb.PbMap<$core.String, $core.String> get metadata => $_getMap(6);
}

class GetEventsRequest extends $pb.GeneratedMessage {
  factory GetEventsRequest() => create();

  GetEventsRequest._();

  factory GetEventsRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetEventsRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetEventsRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetEventsRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetEventsRequest copyWith(void Function(GetEventsRequest) updates) =>
      super.copyWith((message) => updates(message as GetEventsRequest))
          as GetEventsRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetEventsRequest create() => GetEventsRequest._();
  @$core.override
  GetEventsRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetEventsRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetEventsRequest>(create);
  static GetEventsRequest? _defaultInstance;
}

class GetEventsResponse extends $pb.GeneratedMessage {
  factory GetEventsResponse({
    $core.Iterable<SystemEvent>? events,
  }) {
    final result = create();
    if (events != null) result.events.addAll(events);
    return result;
  }

  GetEventsResponse._();

  factory GetEventsResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetEventsResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetEventsResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPM<SystemEvent>(1, _omitFieldNames ? '' : 'events',
        subBuilder: SystemEvent.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetEventsResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetEventsResponse copyWith(void Function(GetEventsResponse) updates) =>
      super.copyWith((message) => updates(message as GetEventsResponse))
          as GetEventsResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetEventsResponse create() => GetEventsResponse._();
  @$core.override
  GetEventsResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetEventsResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetEventsResponse>(create);
  static GetEventsResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<SystemEvent> get events => $_getList(0);
}

class SwitchProfileRequest extends $pb.GeneratedMessage {
  factory SwitchProfileRequest({
    $core.String? profileName,
    $core.String? username,
  }) {
    final result = create();
    if (profileName != null) result.profileName = profileName;
    if (username != null) result.username = username;
    return result;
  }

  SwitchProfileRequest._();

  factory SwitchProfileRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SwitchProfileRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SwitchProfileRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(2, _omitFieldNames ? '' : 'username')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SwitchProfileRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SwitchProfileRequest copyWith(void Function(SwitchProfileRequest) updates) =>
      super.copyWith((message) => updates(message as SwitchProfileRequest))
          as SwitchProfileRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SwitchProfileRequest create() => SwitchProfileRequest._();
  @$core.override
  SwitchProfileRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SwitchProfileRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SwitchProfileRequest>(create);
  static SwitchProfileRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get profileName => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileName() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get username => $_getSZ(1);
  @$pb.TagNumber(2)
  set username($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUsername() => $_has(1);
  @$pb.TagNumber(2)
  void clearUsername() => $_clearField(2);
}

class SwitchProfileResponse extends $pb.GeneratedMessage {
  factory SwitchProfileResponse() => create();

  SwitchProfileResponse._();

  factory SwitchProfileResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SwitchProfileResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SwitchProfileResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SwitchProfileResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SwitchProfileResponse copyWith(
          void Function(SwitchProfileResponse) updates) =>
      super.copyWith((message) => updates(message as SwitchProfileResponse))
          as SwitchProfileResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SwitchProfileResponse create() => SwitchProfileResponse._();
  @$core.override
  SwitchProfileResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SwitchProfileResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SwitchProfileResponse>(create);
  static SwitchProfileResponse? _defaultInstance;
}

class SetConfigRequest extends $pb.GeneratedMessage {
  factory SetConfigRequest({
    $core.String? username,
    $core.String? profileName,
    $core.String? managementUrl,
    $core.String? adminURL,
    $core.bool? rosenpassEnabled,
    $core.String? interfaceName,
    $fixnum.Int64? wireguardPort,
    $core.String? optionalPreSharedKey,
    $core.bool? disableAutoConnect,
    $core.bool? serverSSHAllowed,
    $core.bool? rosenpassPermissive,
    $core.bool? networkMonitor,
    $core.bool? disableClientRoutes,
    $core.bool? disableServerRoutes,
    $core.bool? disableDns,
    $core.bool? disableFirewall,
    $core.bool? blockLanAccess,
    $core.bool? disableNotifications,
    $core.bool? lazyConnectionEnabled,
    $core.bool? blockInbound,
    $core.Iterable<$core.String>? natExternalIPs,
    $core.bool? cleanNATExternalIPs,
    $core.List<$core.int>? customDNSAddress,
    $core.Iterable<$core.String>? extraIFaceBlacklist,
    $core.Iterable<$core.String>? dnsLabels,
    $core.bool? cleanDNSLabels,
    $1.Duration? dnsRouteInterval,
    $fixnum.Int64? mtu,
    $core.bool? enableSSHRoot,
    $core.bool? enableSSHSFTP,
    $core.bool? enableSSHLocalPortForwarding,
    $core.bool? enableSSHRemotePortForwarding,
    $core.bool? disableSSHAuth,
    $core.int? sshJWTCacheTTL,
  }) {
    final result = create();
    if (username != null) result.username = username;
    if (profileName != null) result.profileName = profileName;
    if (managementUrl != null) result.managementUrl = managementUrl;
    if (adminURL != null) result.adminURL = adminURL;
    if (rosenpassEnabled != null) result.rosenpassEnabled = rosenpassEnabled;
    if (interfaceName != null) result.interfaceName = interfaceName;
    if (wireguardPort != null) result.wireguardPort = wireguardPort;
    if (optionalPreSharedKey != null)
      result.optionalPreSharedKey = optionalPreSharedKey;
    if (disableAutoConnect != null)
      result.disableAutoConnect = disableAutoConnect;
    if (serverSSHAllowed != null) result.serverSSHAllowed = serverSSHAllowed;
    if (rosenpassPermissive != null)
      result.rosenpassPermissive = rosenpassPermissive;
    if (networkMonitor != null) result.networkMonitor = networkMonitor;
    if (disableClientRoutes != null)
      result.disableClientRoutes = disableClientRoutes;
    if (disableServerRoutes != null)
      result.disableServerRoutes = disableServerRoutes;
    if (disableDns != null) result.disableDns = disableDns;
    if (disableFirewall != null) result.disableFirewall = disableFirewall;
    if (blockLanAccess != null) result.blockLanAccess = blockLanAccess;
    if (disableNotifications != null)
      result.disableNotifications = disableNotifications;
    if (lazyConnectionEnabled != null)
      result.lazyConnectionEnabled = lazyConnectionEnabled;
    if (blockInbound != null) result.blockInbound = blockInbound;
    if (natExternalIPs != null) result.natExternalIPs.addAll(natExternalIPs);
    if (cleanNATExternalIPs != null)
      result.cleanNATExternalIPs = cleanNATExternalIPs;
    if (customDNSAddress != null) result.customDNSAddress = customDNSAddress;
    if (extraIFaceBlacklist != null)
      result.extraIFaceBlacklist.addAll(extraIFaceBlacklist);
    if (dnsLabels != null) result.dnsLabels.addAll(dnsLabels);
    if (cleanDNSLabels != null) result.cleanDNSLabels = cleanDNSLabels;
    if (dnsRouteInterval != null) result.dnsRouteInterval = dnsRouteInterval;
    if (mtu != null) result.mtu = mtu;
    if (enableSSHRoot != null) result.enableSSHRoot = enableSSHRoot;
    if (enableSSHSFTP != null) result.enableSSHSFTP = enableSSHSFTP;
    if (enableSSHLocalPortForwarding != null)
      result.enableSSHLocalPortForwarding = enableSSHLocalPortForwarding;
    if (enableSSHRemotePortForwarding != null)
      result.enableSSHRemotePortForwarding = enableSSHRemotePortForwarding;
    if (disableSSHAuth != null) result.disableSSHAuth = disableSSHAuth;
    if (sshJWTCacheTTL != null) result.sshJWTCacheTTL = sshJWTCacheTTL;
    return result;
  }

  SetConfigRequest._();

  factory SetConfigRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SetConfigRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SetConfigRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'username')
    ..aOS(2, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(3, _omitFieldNames ? '' : 'managementUrl', protoName: 'managementUrl')
    ..aOS(4, _omitFieldNames ? '' : 'adminURL', protoName: 'adminURL')
    ..aOB(5, _omitFieldNames ? '' : 'rosenpassEnabled',
        protoName: 'rosenpassEnabled')
    ..aOS(6, _omitFieldNames ? '' : 'interfaceName', protoName: 'interfaceName')
    ..aInt64(7, _omitFieldNames ? '' : 'wireguardPort',
        protoName: 'wireguardPort')
    ..aOS(8, _omitFieldNames ? '' : 'optionalPreSharedKey',
        protoName: 'optionalPreSharedKey')
    ..aOB(9, _omitFieldNames ? '' : 'disableAutoConnect',
        protoName: 'disableAutoConnect')
    ..aOB(10, _omitFieldNames ? '' : 'serverSSHAllowed',
        protoName: 'serverSSHAllowed')
    ..aOB(11, _omitFieldNames ? '' : 'rosenpassPermissive',
        protoName: 'rosenpassPermissive')
    ..aOB(12, _omitFieldNames ? '' : 'networkMonitor',
        protoName: 'networkMonitor')
    ..aOB(13, _omitFieldNames ? '' : 'disableClientRoutes')
    ..aOB(14, _omitFieldNames ? '' : 'disableServerRoutes')
    ..aOB(15, _omitFieldNames ? '' : 'disableDns')
    ..aOB(16, _omitFieldNames ? '' : 'disableFirewall')
    ..aOB(17, _omitFieldNames ? '' : 'blockLanAccess')
    ..aOB(18, _omitFieldNames ? '' : 'disableNotifications')
    ..aOB(19, _omitFieldNames ? '' : 'lazyConnectionEnabled',
        protoName: 'lazyConnectionEnabled')
    ..aOB(20, _omitFieldNames ? '' : 'blockInbound')
    ..pPS(21, _omitFieldNames ? '' : 'natExternalIPs',
        protoName: 'natExternalIPs')
    ..aOB(22, _omitFieldNames ? '' : 'cleanNATExternalIPs',
        protoName: 'cleanNATExternalIPs')
    ..a<$core.List<$core.int>>(
        23, _omitFieldNames ? '' : 'customDNSAddress', $pb.PbFieldType.OY,
        protoName: 'customDNSAddress')
    ..pPS(24, _omitFieldNames ? '' : 'extraIFaceBlacklist',
        protoName: 'extraIFaceBlacklist')
    ..pPS(25, _omitFieldNames ? '' : 'dnsLabels')
    ..aOB(26, _omitFieldNames ? '' : 'cleanDNSLabels',
        protoName: 'cleanDNSLabels')
    ..aOM<$1.Duration>(27, _omitFieldNames ? '' : 'dnsRouteInterval',
        protoName: 'dnsRouteInterval', subBuilder: $1.Duration.create)
    ..aInt64(28, _omitFieldNames ? '' : 'mtu')
    ..aOB(29, _omitFieldNames ? '' : 'enableSSHRoot',
        protoName: 'enableSSHRoot')
    ..aOB(30, _omitFieldNames ? '' : 'enableSSHSFTP',
        protoName: 'enableSSHSFTP')
    ..aOB(31, _omitFieldNames ? '' : 'enableSSHLocalPortForwarding',
        protoName: 'enableSSHLocalPortForwarding')
    ..aOB(32, _omitFieldNames ? '' : 'enableSSHRemotePortForwarding',
        protoName: 'enableSSHRemotePortForwarding')
    ..aOB(33, _omitFieldNames ? '' : 'disableSSHAuth',
        protoName: 'disableSSHAuth')
    ..aI(34, _omitFieldNames ? '' : 'sshJWTCacheTTL',
        protoName: 'sshJWTCacheTTL')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetConfigRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetConfigRequest copyWith(void Function(SetConfigRequest) updates) =>
      super.copyWith((message) => updates(message as SetConfigRequest))
          as SetConfigRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SetConfigRequest create() => SetConfigRequest._();
  @$core.override
  SetConfigRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SetConfigRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SetConfigRequest>(create);
  static SetConfigRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get username => $_getSZ(0);
  @$pb.TagNumber(1)
  set username($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUsername() => $_has(0);
  @$pb.TagNumber(1)
  void clearUsername() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileName => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileName($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileName() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileName() => $_clearField(2);

  /// managementUrl to authenticate.
  @$pb.TagNumber(3)
  $core.String get managementUrl => $_getSZ(2);
  @$pb.TagNumber(3)
  set managementUrl($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasManagementUrl() => $_has(2);
  @$pb.TagNumber(3)
  void clearManagementUrl() => $_clearField(3);

  /// adminUrl to manage keys.
  @$pb.TagNumber(4)
  $core.String get adminURL => $_getSZ(3);
  @$pb.TagNumber(4)
  set adminURL($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasAdminURL() => $_has(3);
  @$pb.TagNumber(4)
  void clearAdminURL() => $_clearField(4);

  @$pb.TagNumber(5)
  $core.bool get rosenpassEnabled => $_getBF(4);
  @$pb.TagNumber(5)
  set rosenpassEnabled($core.bool value) => $_setBool(4, value);
  @$pb.TagNumber(5)
  $core.bool hasRosenpassEnabled() => $_has(4);
  @$pb.TagNumber(5)
  void clearRosenpassEnabled() => $_clearField(5);

  @$pb.TagNumber(6)
  $core.String get interfaceName => $_getSZ(5);
  @$pb.TagNumber(6)
  set interfaceName($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasInterfaceName() => $_has(5);
  @$pb.TagNumber(6)
  void clearInterfaceName() => $_clearField(6);

  @$pb.TagNumber(7)
  $fixnum.Int64 get wireguardPort => $_getI64(6);
  @$pb.TagNumber(7)
  set wireguardPort($fixnum.Int64 value) => $_setInt64(6, value);
  @$pb.TagNumber(7)
  $core.bool hasWireguardPort() => $_has(6);
  @$pb.TagNumber(7)
  void clearWireguardPort() => $_clearField(7);

  @$pb.TagNumber(8)
  $core.String get optionalPreSharedKey => $_getSZ(7);
  @$pb.TagNumber(8)
  set optionalPreSharedKey($core.String value) => $_setString(7, value);
  @$pb.TagNumber(8)
  $core.bool hasOptionalPreSharedKey() => $_has(7);
  @$pb.TagNumber(8)
  void clearOptionalPreSharedKey() => $_clearField(8);

  @$pb.TagNumber(9)
  $core.bool get disableAutoConnect => $_getBF(8);
  @$pb.TagNumber(9)
  set disableAutoConnect($core.bool value) => $_setBool(8, value);
  @$pb.TagNumber(9)
  $core.bool hasDisableAutoConnect() => $_has(8);
  @$pb.TagNumber(9)
  void clearDisableAutoConnect() => $_clearField(9);

  @$pb.TagNumber(10)
  $core.bool get serverSSHAllowed => $_getBF(9);
  @$pb.TagNumber(10)
  set serverSSHAllowed($core.bool value) => $_setBool(9, value);
  @$pb.TagNumber(10)
  $core.bool hasServerSSHAllowed() => $_has(9);
  @$pb.TagNumber(10)
  void clearServerSSHAllowed() => $_clearField(10);

  @$pb.TagNumber(11)
  $core.bool get rosenpassPermissive => $_getBF(10);
  @$pb.TagNumber(11)
  set rosenpassPermissive($core.bool value) => $_setBool(10, value);
  @$pb.TagNumber(11)
  $core.bool hasRosenpassPermissive() => $_has(10);
  @$pb.TagNumber(11)
  void clearRosenpassPermissive() => $_clearField(11);

  @$pb.TagNumber(12)
  $core.bool get networkMonitor => $_getBF(11);
  @$pb.TagNumber(12)
  set networkMonitor($core.bool value) => $_setBool(11, value);
  @$pb.TagNumber(12)
  $core.bool hasNetworkMonitor() => $_has(11);
  @$pb.TagNumber(12)
  void clearNetworkMonitor() => $_clearField(12);

  @$pb.TagNumber(13)
  $core.bool get disableClientRoutes => $_getBF(12);
  @$pb.TagNumber(13)
  set disableClientRoutes($core.bool value) => $_setBool(12, value);
  @$pb.TagNumber(13)
  $core.bool hasDisableClientRoutes() => $_has(12);
  @$pb.TagNumber(13)
  void clearDisableClientRoutes() => $_clearField(13);

  @$pb.TagNumber(14)
  $core.bool get disableServerRoutes => $_getBF(13);
  @$pb.TagNumber(14)
  set disableServerRoutes($core.bool value) => $_setBool(13, value);
  @$pb.TagNumber(14)
  $core.bool hasDisableServerRoutes() => $_has(13);
  @$pb.TagNumber(14)
  void clearDisableServerRoutes() => $_clearField(14);

  @$pb.TagNumber(15)
  $core.bool get disableDns => $_getBF(14);
  @$pb.TagNumber(15)
  set disableDns($core.bool value) => $_setBool(14, value);
  @$pb.TagNumber(15)
  $core.bool hasDisableDns() => $_has(14);
  @$pb.TagNumber(15)
  void clearDisableDns() => $_clearField(15);

  @$pb.TagNumber(16)
  $core.bool get disableFirewall => $_getBF(15);
  @$pb.TagNumber(16)
  set disableFirewall($core.bool value) => $_setBool(15, value);
  @$pb.TagNumber(16)
  $core.bool hasDisableFirewall() => $_has(15);
  @$pb.TagNumber(16)
  void clearDisableFirewall() => $_clearField(16);

  @$pb.TagNumber(17)
  $core.bool get blockLanAccess => $_getBF(16);
  @$pb.TagNumber(17)
  set blockLanAccess($core.bool value) => $_setBool(16, value);
  @$pb.TagNumber(17)
  $core.bool hasBlockLanAccess() => $_has(16);
  @$pb.TagNumber(17)
  void clearBlockLanAccess() => $_clearField(17);

  @$pb.TagNumber(18)
  $core.bool get disableNotifications => $_getBF(17);
  @$pb.TagNumber(18)
  set disableNotifications($core.bool value) => $_setBool(17, value);
  @$pb.TagNumber(18)
  $core.bool hasDisableNotifications() => $_has(17);
  @$pb.TagNumber(18)
  void clearDisableNotifications() => $_clearField(18);

  @$pb.TagNumber(19)
  $core.bool get lazyConnectionEnabled => $_getBF(18);
  @$pb.TagNumber(19)
  set lazyConnectionEnabled($core.bool value) => $_setBool(18, value);
  @$pb.TagNumber(19)
  $core.bool hasLazyConnectionEnabled() => $_has(18);
  @$pb.TagNumber(19)
  void clearLazyConnectionEnabled() => $_clearField(19);

  @$pb.TagNumber(20)
  $core.bool get blockInbound => $_getBF(19);
  @$pb.TagNumber(20)
  set blockInbound($core.bool value) => $_setBool(19, value);
  @$pb.TagNumber(20)
  $core.bool hasBlockInbound() => $_has(19);
  @$pb.TagNumber(20)
  void clearBlockInbound() => $_clearField(20);

  @$pb.TagNumber(21)
  $pb.PbList<$core.String> get natExternalIPs => $_getList(20);

  @$pb.TagNumber(22)
  $core.bool get cleanNATExternalIPs => $_getBF(21);
  @$pb.TagNumber(22)
  set cleanNATExternalIPs($core.bool value) => $_setBool(21, value);
  @$pb.TagNumber(22)
  $core.bool hasCleanNATExternalIPs() => $_has(21);
  @$pb.TagNumber(22)
  void clearCleanNATExternalIPs() => $_clearField(22);

  @$pb.TagNumber(23)
  $core.List<$core.int> get customDNSAddress => $_getN(22);
  @$pb.TagNumber(23)
  set customDNSAddress($core.List<$core.int> value) => $_setBytes(22, value);
  @$pb.TagNumber(23)
  $core.bool hasCustomDNSAddress() => $_has(22);
  @$pb.TagNumber(23)
  void clearCustomDNSAddress() => $_clearField(23);

  @$pb.TagNumber(24)
  $pb.PbList<$core.String> get extraIFaceBlacklist => $_getList(23);

  @$pb.TagNumber(25)
  $pb.PbList<$core.String> get dnsLabels => $_getList(24);

  /// cleanDNSLabels clean map list of DNS labels.
  @$pb.TagNumber(26)
  $core.bool get cleanDNSLabels => $_getBF(25);
  @$pb.TagNumber(26)
  set cleanDNSLabels($core.bool value) => $_setBool(25, value);
  @$pb.TagNumber(26)
  $core.bool hasCleanDNSLabels() => $_has(25);
  @$pb.TagNumber(26)
  void clearCleanDNSLabels() => $_clearField(26);

  @$pb.TagNumber(27)
  $1.Duration get dnsRouteInterval => $_getN(26);
  @$pb.TagNumber(27)
  set dnsRouteInterval($1.Duration value) => $_setField(27, value);
  @$pb.TagNumber(27)
  $core.bool hasDnsRouteInterval() => $_has(26);
  @$pb.TagNumber(27)
  void clearDnsRouteInterval() => $_clearField(27);
  @$pb.TagNumber(27)
  $1.Duration ensureDnsRouteInterval() => $_ensure(26);

  @$pb.TagNumber(28)
  $fixnum.Int64 get mtu => $_getI64(27);
  @$pb.TagNumber(28)
  set mtu($fixnum.Int64 value) => $_setInt64(27, value);
  @$pb.TagNumber(28)
  $core.bool hasMtu() => $_has(27);
  @$pb.TagNumber(28)
  void clearMtu() => $_clearField(28);

  @$pb.TagNumber(29)
  $core.bool get enableSSHRoot => $_getBF(28);
  @$pb.TagNumber(29)
  set enableSSHRoot($core.bool value) => $_setBool(28, value);
  @$pb.TagNumber(29)
  $core.bool hasEnableSSHRoot() => $_has(28);
  @$pb.TagNumber(29)
  void clearEnableSSHRoot() => $_clearField(29);

  @$pb.TagNumber(30)
  $core.bool get enableSSHSFTP => $_getBF(29);
  @$pb.TagNumber(30)
  set enableSSHSFTP($core.bool value) => $_setBool(29, value);
  @$pb.TagNumber(30)
  $core.bool hasEnableSSHSFTP() => $_has(29);
  @$pb.TagNumber(30)
  void clearEnableSSHSFTP() => $_clearField(30);

  @$pb.TagNumber(31)
  $core.bool get enableSSHLocalPortForwarding => $_getBF(30);
  @$pb.TagNumber(31)
  set enableSSHLocalPortForwarding($core.bool value) => $_setBool(30, value);
  @$pb.TagNumber(31)
  $core.bool hasEnableSSHLocalPortForwarding() => $_has(30);
  @$pb.TagNumber(31)
  void clearEnableSSHLocalPortForwarding() => $_clearField(31);

  @$pb.TagNumber(32)
  $core.bool get enableSSHRemotePortForwarding => $_getBF(31);
  @$pb.TagNumber(32)
  set enableSSHRemotePortForwarding($core.bool value) => $_setBool(31, value);
  @$pb.TagNumber(32)
  $core.bool hasEnableSSHRemotePortForwarding() => $_has(31);
  @$pb.TagNumber(32)
  void clearEnableSSHRemotePortForwarding() => $_clearField(32);

  @$pb.TagNumber(33)
  $core.bool get disableSSHAuth => $_getBF(32);
  @$pb.TagNumber(33)
  set disableSSHAuth($core.bool value) => $_setBool(32, value);
  @$pb.TagNumber(33)
  $core.bool hasDisableSSHAuth() => $_has(32);
  @$pb.TagNumber(33)
  void clearDisableSSHAuth() => $_clearField(33);

  @$pb.TagNumber(34)
  $core.int get sshJWTCacheTTL => $_getIZ(33);
  @$pb.TagNumber(34)
  set sshJWTCacheTTL($core.int value) => $_setSignedInt32(33, value);
  @$pb.TagNumber(34)
  $core.bool hasSshJWTCacheTTL() => $_has(33);
  @$pb.TagNumber(34)
  void clearSshJWTCacheTTL() => $_clearField(34);
}

class SetConfigResponse extends $pb.GeneratedMessage {
  factory SetConfigResponse() => create();

  SetConfigResponse._();

  factory SetConfigResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory SetConfigResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'SetConfigResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetConfigResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  SetConfigResponse copyWith(void Function(SetConfigResponse) updates) =>
      super.copyWith((message) => updates(message as SetConfigResponse))
          as SetConfigResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static SetConfigResponse create() => SetConfigResponse._();
  @$core.override
  SetConfigResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static SetConfigResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<SetConfigResponse>(create);
  static SetConfigResponse? _defaultInstance;
}

class AddProfileRequest extends $pb.GeneratedMessage {
  factory AddProfileRequest({
    $core.String? username,
    $core.String? profileName,
  }) {
    final result = create();
    if (username != null) result.username = username;
    if (profileName != null) result.profileName = profileName;
    return result;
  }

  AddProfileRequest._();

  factory AddProfileRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory AddProfileRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AddProfileRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'username')
    ..aOS(2, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AddProfileRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AddProfileRequest copyWith(void Function(AddProfileRequest) updates) =>
      super.copyWith((message) => updates(message as AddProfileRequest))
          as AddProfileRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static AddProfileRequest create() => AddProfileRequest._();
  @$core.override
  AddProfileRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static AddProfileRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<AddProfileRequest>(create);
  static AddProfileRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get username => $_getSZ(0);
  @$pb.TagNumber(1)
  set username($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUsername() => $_has(0);
  @$pb.TagNumber(1)
  void clearUsername() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileName => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileName($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileName() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileName() => $_clearField(2);
}

class AddProfileResponse extends $pb.GeneratedMessage {
  factory AddProfileResponse() => create();

  AddProfileResponse._();

  factory AddProfileResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory AddProfileResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'AddProfileResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AddProfileResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  AddProfileResponse copyWith(void Function(AddProfileResponse) updates) =>
      super.copyWith((message) => updates(message as AddProfileResponse))
          as AddProfileResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static AddProfileResponse create() => AddProfileResponse._();
  @$core.override
  AddProfileResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static AddProfileResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<AddProfileResponse>(create);
  static AddProfileResponse? _defaultInstance;
}

class RemoveProfileRequest extends $pb.GeneratedMessage {
  factory RemoveProfileRequest({
    $core.String? username,
    $core.String? profileName,
  }) {
    final result = create();
    if (username != null) result.username = username;
    if (profileName != null) result.profileName = profileName;
    return result;
  }

  RemoveProfileRequest._();

  factory RemoveProfileRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory RemoveProfileRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveProfileRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'username')
    ..aOS(2, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveProfileRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveProfileRequest copyWith(void Function(RemoveProfileRequest) updates) =>
      super.copyWith((message) => updates(message as RemoveProfileRequest))
          as RemoveProfileRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RemoveProfileRequest create() => RemoveProfileRequest._();
  @$core.override
  RemoveProfileRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static RemoveProfileRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveProfileRequest>(create);
  static RemoveProfileRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get username => $_getSZ(0);
  @$pb.TagNumber(1)
  set username($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUsername() => $_has(0);
  @$pb.TagNumber(1)
  void clearUsername() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get profileName => $_getSZ(1);
  @$pb.TagNumber(2)
  set profileName($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasProfileName() => $_has(1);
  @$pb.TagNumber(2)
  void clearProfileName() => $_clearField(2);
}

class RemoveProfileResponse extends $pb.GeneratedMessage {
  factory RemoveProfileResponse() => create();

  RemoveProfileResponse._();

  factory RemoveProfileResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory RemoveProfileResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RemoveProfileResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveProfileResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RemoveProfileResponse copyWith(
          void Function(RemoveProfileResponse) updates) =>
      super.copyWith((message) => updates(message as RemoveProfileResponse))
          as RemoveProfileResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RemoveProfileResponse create() => RemoveProfileResponse._();
  @$core.override
  RemoveProfileResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static RemoveProfileResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RemoveProfileResponse>(create);
  static RemoveProfileResponse? _defaultInstance;
}

class ListProfilesRequest extends $pb.GeneratedMessage {
  factory ListProfilesRequest({
    $core.String? username,
  }) {
    final result = create();
    if (username != null) result.username = username;
    return result;
  }

  ListProfilesRequest._();

  factory ListProfilesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ListProfilesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListProfilesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'username')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListProfilesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListProfilesRequest copyWith(void Function(ListProfilesRequest) updates) =>
      super.copyWith((message) => updates(message as ListProfilesRequest))
          as ListProfilesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListProfilesRequest create() => ListProfilesRequest._();
  @$core.override
  ListProfilesRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ListProfilesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListProfilesRequest>(create);
  static ListProfilesRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get username => $_getSZ(0);
  @$pb.TagNumber(1)
  set username($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasUsername() => $_has(0);
  @$pb.TagNumber(1)
  void clearUsername() => $_clearField(1);
}

class ListProfilesResponse extends $pb.GeneratedMessage {
  factory ListProfilesResponse({
    $core.Iterable<Profile>? profiles,
  }) {
    final result = create();
    if (profiles != null) result.profiles.addAll(profiles);
    return result;
  }

  ListProfilesResponse._();

  factory ListProfilesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ListProfilesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ListProfilesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..pPM<Profile>(1, _omitFieldNames ? '' : 'profiles',
        subBuilder: Profile.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListProfilesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ListProfilesResponse copyWith(void Function(ListProfilesResponse) updates) =>
      super.copyWith((message) => updates(message as ListProfilesResponse))
          as ListProfilesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ListProfilesResponse create() => ListProfilesResponse._();
  @$core.override
  ListProfilesResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ListProfilesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ListProfilesResponse>(create);
  static ListProfilesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $pb.PbList<Profile> get profiles => $_getList(0);
}

class Profile extends $pb.GeneratedMessage {
  factory Profile({
    $core.String? name,
    $core.bool? isActive,
  }) {
    final result = create();
    if (name != null) result.name = name;
    if (isActive != null) result.isActive = isActive;
    return result;
  }

  Profile._();

  factory Profile.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory Profile.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'Profile',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'name')
    ..aOB(2, _omitFieldNames ? '' : 'isActive')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Profile clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  Profile copyWith(void Function(Profile) updates) =>
      super.copyWith((message) => updates(message as Profile)) as Profile;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static Profile create() => Profile._();
  @$core.override
  Profile createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static Profile getDefault() =>
      _defaultInstance ??= $pb.GeneratedMessage.$_defaultFor<Profile>(create);
  static Profile? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get name => $_getSZ(0);
  @$pb.TagNumber(1)
  set name($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasName() => $_has(0);
  @$pb.TagNumber(1)
  void clearName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get isActive => $_getBF(1);
  @$pb.TagNumber(2)
  set isActive($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasIsActive() => $_has(1);
  @$pb.TagNumber(2)
  void clearIsActive() => $_clearField(2);
}

class GetActiveProfileRequest extends $pb.GeneratedMessage {
  factory GetActiveProfileRequest() => create();

  GetActiveProfileRequest._();

  factory GetActiveProfileRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetActiveProfileRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetActiveProfileRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetActiveProfileRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetActiveProfileRequest copyWith(
          void Function(GetActiveProfileRequest) updates) =>
      super.copyWith((message) => updates(message as GetActiveProfileRequest))
          as GetActiveProfileRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetActiveProfileRequest create() => GetActiveProfileRequest._();
  @$core.override
  GetActiveProfileRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetActiveProfileRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetActiveProfileRequest>(create);
  static GetActiveProfileRequest? _defaultInstance;
}

class GetActiveProfileResponse extends $pb.GeneratedMessage {
  factory GetActiveProfileResponse({
    $core.String? profileName,
    $core.String? username,
  }) {
    final result = create();
    if (profileName != null) result.profileName = profileName;
    if (username != null) result.username = username;
    return result;
  }

  GetActiveProfileResponse._();

  factory GetActiveProfileResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetActiveProfileResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetActiveProfileResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(2, _omitFieldNames ? '' : 'username')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetActiveProfileResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetActiveProfileResponse copyWith(
          void Function(GetActiveProfileResponse) updates) =>
      super.copyWith((message) => updates(message as GetActiveProfileResponse))
          as GetActiveProfileResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetActiveProfileResponse create() => GetActiveProfileResponse._();
  @$core.override
  GetActiveProfileResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetActiveProfileResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetActiveProfileResponse>(create);
  static GetActiveProfileResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get profileName => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileName() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get username => $_getSZ(1);
  @$pb.TagNumber(2)
  set username($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUsername() => $_has(1);
  @$pb.TagNumber(2)
  void clearUsername() => $_clearField(2);
}

class LogoutRequest extends $pb.GeneratedMessage {
  factory LogoutRequest({
    $core.String? profileName,
    $core.String? username,
  }) {
    final result = create();
    if (profileName != null) result.profileName = profileName;
    if (username != null) result.username = username;
    return result;
  }

  LogoutRequest._();

  factory LogoutRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory LogoutRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'LogoutRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'profileName', protoName: 'profileName')
    ..aOS(2, _omitFieldNames ? '' : 'username')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LogoutRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LogoutRequest copyWith(void Function(LogoutRequest) updates) =>
      super.copyWith((message) => updates(message as LogoutRequest))
          as LogoutRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static LogoutRequest create() => LogoutRequest._();
  @$core.override
  LogoutRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static LogoutRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<LogoutRequest>(create);
  static LogoutRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get profileName => $_getSZ(0);
  @$pb.TagNumber(1)
  set profileName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasProfileName() => $_has(0);
  @$pb.TagNumber(1)
  void clearProfileName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get username => $_getSZ(1);
  @$pb.TagNumber(2)
  set username($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUsername() => $_has(1);
  @$pb.TagNumber(2)
  void clearUsername() => $_clearField(2);
}

class LogoutResponse extends $pb.GeneratedMessage {
  factory LogoutResponse() => create();

  LogoutResponse._();

  factory LogoutResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory LogoutResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'LogoutResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LogoutResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  LogoutResponse copyWith(void Function(LogoutResponse) updates) =>
      super.copyWith((message) => updates(message as LogoutResponse))
          as LogoutResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static LogoutResponse create() => LogoutResponse._();
  @$core.override
  LogoutResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static LogoutResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<LogoutResponse>(create);
  static LogoutResponse? _defaultInstance;
}

class GetFeaturesRequest extends $pb.GeneratedMessage {
  factory GetFeaturesRequest() => create();

  GetFeaturesRequest._();

  factory GetFeaturesRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetFeaturesRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetFeaturesRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetFeaturesRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetFeaturesRequest copyWith(void Function(GetFeaturesRequest) updates) =>
      super.copyWith((message) => updates(message as GetFeaturesRequest))
          as GetFeaturesRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetFeaturesRequest create() => GetFeaturesRequest._();
  @$core.override
  GetFeaturesRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetFeaturesRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetFeaturesRequest>(create);
  static GetFeaturesRequest? _defaultInstance;
}

class GetFeaturesResponse extends $pb.GeneratedMessage {
  factory GetFeaturesResponse({
    $core.bool? disableProfiles,
    $core.bool? disableUpdateSettings,
    $core.bool? disableNetworks,
  }) {
    final result = create();
    if (disableProfiles != null) result.disableProfiles = disableProfiles;
    if (disableUpdateSettings != null)
      result.disableUpdateSettings = disableUpdateSettings;
    if (disableNetworks != null) result.disableNetworks = disableNetworks;
    return result;
  }

  GetFeaturesResponse._();

  factory GetFeaturesResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetFeaturesResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetFeaturesResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'disableProfiles')
    ..aOB(2, _omitFieldNames ? '' : 'disableUpdateSettings')
    ..aOB(3, _omitFieldNames ? '' : 'disableNetworks')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetFeaturesResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetFeaturesResponse copyWith(void Function(GetFeaturesResponse) updates) =>
      super.copyWith((message) => updates(message as GetFeaturesResponse))
          as GetFeaturesResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetFeaturesResponse create() => GetFeaturesResponse._();
  @$core.override
  GetFeaturesResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetFeaturesResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetFeaturesResponse>(create);
  static GetFeaturesResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get disableProfiles => $_getBF(0);
  @$pb.TagNumber(1)
  set disableProfiles($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasDisableProfiles() => $_has(0);
  @$pb.TagNumber(1)
  void clearDisableProfiles() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.bool get disableUpdateSettings => $_getBF(1);
  @$pb.TagNumber(2)
  set disableUpdateSettings($core.bool value) => $_setBool(1, value);
  @$pb.TagNumber(2)
  $core.bool hasDisableUpdateSettings() => $_has(1);
  @$pb.TagNumber(2)
  void clearDisableUpdateSettings() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.bool get disableNetworks => $_getBF(2);
  @$pb.TagNumber(3)
  set disableNetworks($core.bool value) => $_setBool(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDisableNetworks() => $_has(2);
  @$pb.TagNumber(3)
  void clearDisableNetworks() => $_clearField(3);
}

class TriggerUpdateRequest extends $pb.GeneratedMessage {
  factory TriggerUpdateRequest() => create();

  TriggerUpdateRequest._();

  factory TriggerUpdateRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory TriggerUpdateRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TriggerUpdateRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TriggerUpdateRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TriggerUpdateRequest copyWith(void Function(TriggerUpdateRequest) updates) =>
      super.copyWith((message) => updates(message as TriggerUpdateRequest))
          as TriggerUpdateRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static TriggerUpdateRequest create() => TriggerUpdateRequest._();
  @$core.override
  TriggerUpdateRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static TriggerUpdateRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<TriggerUpdateRequest>(create);
  static TriggerUpdateRequest? _defaultInstance;
}

class TriggerUpdateResponse extends $pb.GeneratedMessage {
  factory TriggerUpdateResponse({
    $core.bool? success,
    $core.String? errorMsg,
  }) {
    final result = create();
    if (success != null) result.success = success;
    if (errorMsg != null) result.errorMsg = errorMsg;
    return result;
  }

  TriggerUpdateResponse._();

  factory TriggerUpdateResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory TriggerUpdateResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'TriggerUpdateResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'success')
    ..aOS(2, _omitFieldNames ? '' : 'errorMsg', protoName: 'errorMsg')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TriggerUpdateResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  TriggerUpdateResponse copyWith(
          void Function(TriggerUpdateResponse) updates) =>
      super.copyWith((message) => updates(message as TriggerUpdateResponse))
          as TriggerUpdateResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static TriggerUpdateResponse create() => TriggerUpdateResponse._();
  @$core.override
  TriggerUpdateResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static TriggerUpdateResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<TriggerUpdateResponse>(create);
  static TriggerUpdateResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get success => $_getBF(0);
  @$pb.TagNumber(1)
  set success($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSuccess() => $_has(0);
  @$pb.TagNumber(1)
  void clearSuccess() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get errorMsg => $_getSZ(1);
  @$pb.TagNumber(2)
  set errorMsg($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasErrorMsg() => $_has(1);
  @$pb.TagNumber(2)
  void clearErrorMsg() => $_clearField(2);
}

/// GetPeerSSHHostKeyRequest for retrieving SSH host key for a specific peer
class GetPeerSSHHostKeyRequest extends $pb.GeneratedMessage {
  factory GetPeerSSHHostKeyRequest({
    $core.String? peerAddress,
  }) {
    final result = create();
    if (peerAddress != null) result.peerAddress = peerAddress;
    return result;
  }

  GetPeerSSHHostKeyRequest._();

  factory GetPeerSSHHostKeyRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetPeerSSHHostKeyRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPeerSSHHostKeyRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'peerAddress', protoName: 'peerAddress')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPeerSSHHostKeyRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPeerSSHHostKeyRequest copyWith(
          void Function(GetPeerSSHHostKeyRequest) updates) =>
      super.copyWith((message) => updates(message as GetPeerSSHHostKeyRequest))
          as GetPeerSSHHostKeyRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetPeerSSHHostKeyRequest create() => GetPeerSSHHostKeyRequest._();
  @$core.override
  GetPeerSSHHostKeyRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetPeerSSHHostKeyRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetPeerSSHHostKeyRequest>(create);
  static GetPeerSSHHostKeyRequest? _defaultInstance;

  /// peer IP address or FQDN to get SSH host key for
  @$pb.TagNumber(1)
  $core.String get peerAddress => $_getSZ(0);
  @$pb.TagNumber(1)
  set peerAddress($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPeerAddress() => $_has(0);
  @$pb.TagNumber(1)
  void clearPeerAddress() => $_clearField(1);
}

/// GetPeerSSHHostKeyResponse contains the SSH host key for the requested peer
class GetPeerSSHHostKeyResponse extends $pb.GeneratedMessage {
  factory GetPeerSSHHostKeyResponse({
    $core.List<$core.int>? sshHostKey,
    $core.String? peerIP,
    $core.String? peerFQDN,
    $core.bool? found,
  }) {
    final result = create();
    if (sshHostKey != null) result.sshHostKey = sshHostKey;
    if (peerIP != null) result.peerIP = peerIP;
    if (peerFQDN != null) result.peerFQDN = peerFQDN;
    if (found != null) result.found = found;
    return result;
  }

  GetPeerSSHHostKeyResponse._();

  factory GetPeerSSHHostKeyResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory GetPeerSSHHostKeyResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'GetPeerSSHHostKeyResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..a<$core.List<$core.int>>(
        1, _omitFieldNames ? '' : 'sshHostKey', $pb.PbFieldType.OY,
        protoName: 'sshHostKey')
    ..aOS(2, _omitFieldNames ? '' : 'peerIP', protoName: 'peerIP')
    ..aOS(3, _omitFieldNames ? '' : 'peerFQDN', protoName: 'peerFQDN')
    ..aOB(4, _omitFieldNames ? '' : 'found')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPeerSSHHostKeyResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  GetPeerSSHHostKeyResponse copyWith(
          void Function(GetPeerSSHHostKeyResponse) updates) =>
      super.copyWith((message) => updates(message as GetPeerSSHHostKeyResponse))
          as GetPeerSSHHostKeyResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static GetPeerSSHHostKeyResponse create() => GetPeerSSHHostKeyResponse._();
  @$core.override
  GetPeerSSHHostKeyResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static GetPeerSSHHostKeyResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<GetPeerSSHHostKeyResponse>(create);
  static GetPeerSSHHostKeyResponse? _defaultInstance;

  /// SSH host key in SSH public key format (e.g., "ssh-ed25519 AAAAC3... hostname")
  @$pb.TagNumber(1)
  $core.List<$core.int> get sshHostKey => $_getN(0);
  @$pb.TagNumber(1)
  set sshHostKey($core.List<$core.int> value) => $_setBytes(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSshHostKey() => $_has(0);
  @$pb.TagNumber(1)
  void clearSshHostKey() => $_clearField(1);

  /// peer IP address
  @$pb.TagNumber(2)
  $core.String get peerIP => $_getSZ(1);
  @$pb.TagNumber(2)
  set peerIP($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasPeerIP() => $_has(1);
  @$pb.TagNumber(2)
  void clearPeerIP() => $_clearField(2);

  /// peer FQDN
  @$pb.TagNumber(3)
  $core.String get peerFQDN => $_getSZ(2);
  @$pb.TagNumber(3)
  set peerFQDN($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasPeerFQDN() => $_has(2);
  @$pb.TagNumber(3)
  void clearPeerFQDN() => $_clearField(3);

  /// indicates if the SSH host key was found
  @$pb.TagNumber(4)
  $core.bool get found => $_getBF(3);
  @$pb.TagNumber(4)
  set found($core.bool value) => $_setBool(3, value);
  @$pb.TagNumber(4)
  $core.bool hasFound() => $_has(3);
  @$pb.TagNumber(4)
  void clearFound() => $_clearField(4);
}

/// RequestJWTAuthRequest for initiating JWT authentication flow
class RequestJWTAuthRequest extends $pb.GeneratedMessage {
  factory RequestJWTAuthRequest({
    $core.String? hint,
  }) {
    final result = create();
    if (hint != null) result.hint = hint;
    return result;
  }

  RequestJWTAuthRequest._();

  factory RequestJWTAuthRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory RequestJWTAuthRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RequestJWTAuthRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'hint')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequestJWTAuthRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequestJWTAuthRequest copyWith(
          void Function(RequestJWTAuthRequest) updates) =>
      super.copyWith((message) => updates(message as RequestJWTAuthRequest))
          as RequestJWTAuthRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RequestJWTAuthRequest create() => RequestJWTAuthRequest._();
  @$core.override
  RequestJWTAuthRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static RequestJWTAuthRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RequestJWTAuthRequest>(create);
  static RequestJWTAuthRequest? _defaultInstance;

  /// hint for OIDC login_hint parameter (typically email address)
  @$pb.TagNumber(1)
  $core.String get hint => $_getSZ(0);
  @$pb.TagNumber(1)
  set hint($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasHint() => $_has(0);
  @$pb.TagNumber(1)
  void clearHint() => $_clearField(1);
}

/// RequestJWTAuthResponse contains authentication flow information
class RequestJWTAuthResponse extends $pb.GeneratedMessage {
  factory RequestJWTAuthResponse({
    $core.String? verificationURI,
    $core.String? verificationURIComplete,
    $core.String? userCode,
    $core.String? deviceCode,
    $fixnum.Int64? expiresIn,
    $core.String? cachedToken,
    $fixnum.Int64? maxTokenAge,
  }) {
    final result = create();
    if (verificationURI != null) result.verificationURI = verificationURI;
    if (verificationURIComplete != null)
      result.verificationURIComplete = verificationURIComplete;
    if (userCode != null) result.userCode = userCode;
    if (deviceCode != null) result.deviceCode = deviceCode;
    if (expiresIn != null) result.expiresIn = expiresIn;
    if (cachedToken != null) result.cachedToken = cachedToken;
    if (maxTokenAge != null) result.maxTokenAge = maxTokenAge;
    return result;
  }

  RequestJWTAuthResponse._();

  factory RequestJWTAuthResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory RequestJWTAuthResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'RequestJWTAuthResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'verificationURI',
        protoName: 'verificationURI')
    ..aOS(2, _omitFieldNames ? '' : 'verificationURIComplete',
        protoName: 'verificationURIComplete')
    ..aOS(3, _omitFieldNames ? '' : 'userCode', protoName: 'userCode')
    ..aOS(4, _omitFieldNames ? '' : 'deviceCode', protoName: 'deviceCode')
    ..aInt64(5, _omitFieldNames ? '' : 'expiresIn', protoName: 'expiresIn')
    ..aOS(6, _omitFieldNames ? '' : 'cachedToken', protoName: 'cachedToken')
    ..aInt64(7, _omitFieldNames ? '' : 'maxTokenAge', protoName: 'maxTokenAge')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequestJWTAuthResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  RequestJWTAuthResponse copyWith(
          void Function(RequestJWTAuthResponse) updates) =>
      super.copyWith((message) => updates(message as RequestJWTAuthResponse))
          as RequestJWTAuthResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static RequestJWTAuthResponse create() => RequestJWTAuthResponse._();
  @$core.override
  RequestJWTAuthResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static RequestJWTAuthResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<RequestJWTAuthResponse>(create);
  static RequestJWTAuthResponse? _defaultInstance;

  /// verification URI for user authentication
  @$pb.TagNumber(1)
  $core.String get verificationURI => $_getSZ(0);
  @$pb.TagNumber(1)
  set verificationURI($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasVerificationURI() => $_has(0);
  @$pb.TagNumber(1)
  void clearVerificationURI() => $_clearField(1);

  /// complete verification URI (with embedded user code)
  @$pb.TagNumber(2)
  $core.String get verificationURIComplete => $_getSZ(1);
  @$pb.TagNumber(2)
  set verificationURIComplete($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasVerificationURIComplete() => $_has(1);
  @$pb.TagNumber(2)
  void clearVerificationURIComplete() => $_clearField(2);

  /// user code to enter on verification URI
  @$pb.TagNumber(3)
  $core.String get userCode => $_getSZ(2);
  @$pb.TagNumber(3)
  set userCode($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasUserCode() => $_has(2);
  @$pb.TagNumber(3)
  void clearUserCode() => $_clearField(3);

  /// device code for polling
  @$pb.TagNumber(4)
  $core.String get deviceCode => $_getSZ(3);
  @$pb.TagNumber(4)
  set deviceCode($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasDeviceCode() => $_has(3);
  @$pb.TagNumber(4)
  void clearDeviceCode() => $_clearField(4);

  /// expiration time in seconds
  @$pb.TagNumber(5)
  $fixnum.Int64 get expiresIn => $_getI64(4);
  @$pb.TagNumber(5)
  set expiresIn($fixnum.Int64 value) => $_setInt64(4, value);
  @$pb.TagNumber(5)
  $core.bool hasExpiresIn() => $_has(4);
  @$pb.TagNumber(5)
  void clearExpiresIn() => $_clearField(5);

  /// if a cached token is available, it will be returned here
  @$pb.TagNumber(6)
  $core.String get cachedToken => $_getSZ(5);
  @$pb.TagNumber(6)
  set cachedToken($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasCachedToken() => $_has(5);
  @$pb.TagNumber(6)
  void clearCachedToken() => $_clearField(6);

  /// maximum age of JWT tokens in seconds (from management server)
  @$pb.TagNumber(7)
  $fixnum.Int64 get maxTokenAge => $_getI64(6);
  @$pb.TagNumber(7)
  set maxTokenAge($fixnum.Int64 value) => $_setInt64(6, value);
  @$pb.TagNumber(7)
  $core.bool hasMaxTokenAge() => $_has(6);
  @$pb.TagNumber(7)
  void clearMaxTokenAge() => $_clearField(7);
}

/// WaitJWTTokenRequest for waiting for authentication completion
class WaitJWTTokenRequest extends $pb.GeneratedMessage {
  factory WaitJWTTokenRequest({
    $core.String? deviceCode,
    $core.String? userCode,
  }) {
    final result = create();
    if (deviceCode != null) result.deviceCode = deviceCode;
    if (userCode != null) result.userCode = userCode;
    return result;
  }

  WaitJWTTokenRequest._();

  factory WaitJWTTokenRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory WaitJWTTokenRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'WaitJWTTokenRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'deviceCode', protoName: 'deviceCode')
    ..aOS(2, _omitFieldNames ? '' : 'userCode', protoName: 'userCode')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitJWTTokenRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitJWTTokenRequest copyWith(void Function(WaitJWTTokenRequest) updates) =>
      super.copyWith((message) => updates(message as WaitJWTTokenRequest))
          as WaitJWTTokenRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static WaitJWTTokenRequest create() => WaitJWTTokenRequest._();
  @$core.override
  WaitJWTTokenRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static WaitJWTTokenRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<WaitJWTTokenRequest>(create);
  static WaitJWTTokenRequest? _defaultInstance;

  /// device code from RequestJWTAuthResponse
  @$pb.TagNumber(1)
  $core.String get deviceCode => $_getSZ(0);
  @$pb.TagNumber(1)
  set deviceCode($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasDeviceCode() => $_has(0);
  @$pb.TagNumber(1)
  void clearDeviceCode() => $_clearField(1);

  /// user code for verification
  @$pb.TagNumber(2)
  $core.String get userCode => $_getSZ(1);
  @$pb.TagNumber(2)
  set userCode($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasUserCode() => $_has(1);
  @$pb.TagNumber(2)
  void clearUserCode() => $_clearField(2);
}

/// WaitJWTTokenResponse contains the JWT token after authentication
class WaitJWTTokenResponse extends $pb.GeneratedMessage {
  factory WaitJWTTokenResponse({
    $core.String? token,
    $core.String? tokenType,
    $fixnum.Int64? expiresIn,
  }) {
    final result = create();
    if (token != null) result.token = token;
    if (tokenType != null) result.tokenType = tokenType;
    if (expiresIn != null) result.expiresIn = expiresIn;
    return result;
  }

  WaitJWTTokenResponse._();

  factory WaitJWTTokenResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory WaitJWTTokenResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'WaitJWTTokenResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'token')
    ..aOS(2, _omitFieldNames ? '' : 'tokenType', protoName: 'tokenType')
    ..aInt64(3, _omitFieldNames ? '' : 'expiresIn', protoName: 'expiresIn')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitJWTTokenResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  WaitJWTTokenResponse copyWith(void Function(WaitJWTTokenResponse) updates) =>
      super.copyWith((message) => updates(message as WaitJWTTokenResponse))
          as WaitJWTTokenResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static WaitJWTTokenResponse create() => WaitJWTTokenResponse._();
  @$core.override
  WaitJWTTokenResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static WaitJWTTokenResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<WaitJWTTokenResponse>(create);
  static WaitJWTTokenResponse? _defaultInstance;

  /// JWT token (access token or ID token)
  @$pb.TagNumber(1)
  $core.String get token => $_getSZ(0);
  @$pb.TagNumber(1)
  set token($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasToken() => $_has(0);
  @$pb.TagNumber(1)
  void clearToken() => $_clearField(1);

  /// token type (e.g., "Bearer")
  @$pb.TagNumber(2)
  $core.String get tokenType => $_getSZ(1);
  @$pb.TagNumber(2)
  set tokenType($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasTokenType() => $_has(1);
  @$pb.TagNumber(2)
  void clearTokenType() => $_clearField(2);

  /// expiration time in seconds
  @$pb.TagNumber(3)
  $fixnum.Int64 get expiresIn => $_getI64(2);
  @$pb.TagNumber(3)
  set expiresIn($fixnum.Int64 value) => $_setInt64(2, value);
  @$pb.TagNumber(3)
  $core.bool hasExpiresIn() => $_has(2);
  @$pb.TagNumber(3)
  void clearExpiresIn() => $_clearField(3);
}

/// StartCPUProfileRequest for starting CPU profiling
class StartCPUProfileRequest extends $pb.GeneratedMessage {
  factory StartCPUProfileRequest() => create();

  StartCPUProfileRequest._();

  factory StartCPUProfileRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory StartCPUProfileRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'StartCPUProfileRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StartCPUProfileRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StartCPUProfileRequest copyWith(
          void Function(StartCPUProfileRequest) updates) =>
      super.copyWith((message) => updates(message as StartCPUProfileRequest))
          as StartCPUProfileRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static StartCPUProfileRequest create() => StartCPUProfileRequest._();
  @$core.override
  StartCPUProfileRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static StartCPUProfileRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<StartCPUProfileRequest>(create);
  static StartCPUProfileRequest? _defaultInstance;
}

/// StartCPUProfileResponse confirms CPU profiling has started
class StartCPUProfileResponse extends $pb.GeneratedMessage {
  factory StartCPUProfileResponse() => create();

  StartCPUProfileResponse._();

  factory StartCPUProfileResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory StartCPUProfileResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'StartCPUProfileResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StartCPUProfileResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StartCPUProfileResponse copyWith(
          void Function(StartCPUProfileResponse) updates) =>
      super.copyWith((message) => updates(message as StartCPUProfileResponse))
          as StartCPUProfileResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static StartCPUProfileResponse create() => StartCPUProfileResponse._();
  @$core.override
  StartCPUProfileResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static StartCPUProfileResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<StartCPUProfileResponse>(create);
  static StartCPUProfileResponse? _defaultInstance;
}

/// StopCPUProfileRequest for stopping CPU profiling
class StopCPUProfileRequest extends $pb.GeneratedMessage {
  factory StopCPUProfileRequest() => create();

  StopCPUProfileRequest._();

  factory StopCPUProfileRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory StopCPUProfileRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'StopCPUProfileRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StopCPUProfileRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StopCPUProfileRequest copyWith(
          void Function(StopCPUProfileRequest) updates) =>
      super.copyWith((message) => updates(message as StopCPUProfileRequest))
          as StopCPUProfileRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static StopCPUProfileRequest create() => StopCPUProfileRequest._();
  @$core.override
  StopCPUProfileRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static StopCPUProfileRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<StopCPUProfileRequest>(create);
  static StopCPUProfileRequest? _defaultInstance;
}

/// StopCPUProfileResponse confirms CPU profiling has stopped
class StopCPUProfileResponse extends $pb.GeneratedMessage {
  factory StopCPUProfileResponse() => create();

  StopCPUProfileResponse._();

  factory StopCPUProfileResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory StopCPUProfileResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'StopCPUProfileResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StopCPUProfileResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  StopCPUProfileResponse copyWith(
          void Function(StopCPUProfileResponse) updates) =>
      super.copyWith((message) => updates(message as StopCPUProfileResponse))
          as StopCPUProfileResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static StopCPUProfileResponse create() => StopCPUProfileResponse._();
  @$core.override
  StopCPUProfileResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static StopCPUProfileResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<StopCPUProfileResponse>(create);
  static StopCPUProfileResponse? _defaultInstance;
}

class InstallerResultRequest extends $pb.GeneratedMessage {
  factory InstallerResultRequest() => create();

  InstallerResultRequest._();

  factory InstallerResultRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory InstallerResultRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'InstallerResultRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  InstallerResultRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  InstallerResultRequest copyWith(
          void Function(InstallerResultRequest) updates) =>
      super.copyWith((message) => updates(message as InstallerResultRequest))
          as InstallerResultRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static InstallerResultRequest create() => InstallerResultRequest._();
  @$core.override
  InstallerResultRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static InstallerResultRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<InstallerResultRequest>(create);
  static InstallerResultRequest? _defaultInstance;
}

class InstallerResultResponse extends $pb.GeneratedMessage {
  factory InstallerResultResponse({
    $core.bool? success,
    $core.String? errorMsg,
  }) {
    final result = create();
    if (success != null) result.success = success;
    if (errorMsg != null) result.errorMsg = errorMsg;
    return result;
  }

  InstallerResultResponse._();

  factory InstallerResultResponse.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory InstallerResultResponse.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'InstallerResultResponse',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOB(1, _omitFieldNames ? '' : 'success')
    ..aOS(2, _omitFieldNames ? '' : 'errorMsg', protoName: 'errorMsg')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  InstallerResultResponse clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  InstallerResultResponse copyWith(
          void Function(InstallerResultResponse) updates) =>
      super.copyWith((message) => updates(message as InstallerResultResponse))
          as InstallerResultResponse;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static InstallerResultResponse create() => InstallerResultResponse._();
  @$core.override
  InstallerResultResponse createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static InstallerResultResponse getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<InstallerResultResponse>(create);
  static InstallerResultResponse? _defaultInstance;

  @$pb.TagNumber(1)
  $core.bool get success => $_getBF(0);
  @$pb.TagNumber(1)
  set success($core.bool value) => $_setBool(0, value);
  @$pb.TagNumber(1)
  $core.bool hasSuccess() => $_has(0);
  @$pb.TagNumber(1)
  void clearSuccess() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get errorMsg => $_getSZ(1);
  @$pb.TagNumber(2)
  set errorMsg($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasErrorMsg() => $_has(1);
  @$pb.TagNumber(2)
  void clearErrorMsg() => $_clearField(2);
}

class ExposeServiceRequest extends $pb.GeneratedMessage {
  factory ExposeServiceRequest({
    $core.int? port,
    ExposeProtocol? protocol,
    $core.String? pin,
    $core.String? password,
    $core.Iterable<$core.String>? userGroups,
    $core.String? domain,
    $core.String? namePrefix,
    $core.int? listenPort,
  }) {
    final result = create();
    if (port != null) result.port = port;
    if (protocol != null) result.protocol = protocol;
    if (pin != null) result.pin = pin;
    if (password != null) result.password = password;
    if (userGroups != null) result.userGroups.addAll(userGroups);
    if (domain != null) result.domain = domain;
    if (namePrefix != null) result.namePrefix = namePrefix;
    if (listenPort != null) result.listenPort = listenPort;
    return result;
  }

  ExposeServiceRequest._();

  factory ExposeServiceRequest.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ExposeServiceRequest.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ExposeServiceRequest',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aI(1, _omitFieldNames ? '' : 'port', fieldType: $pb.PbFieldType.OU3)
    ..aE<ExposeProtocol>(2, _omitFieldNames ? '' : 'protocol',
        enumValues: ExposeProtocol.values)
    ..aOS(3, _omitFieldNames ? '' : 'pin')
    ..aOS(4, _omitFieldNames ? '' : 'password')
    ..pPS(5, _omitFieldNames ? '' : 'userGroups')
    ..aOS(6, _omitFieldNames ? '' : 'domain')
    ..aOS(7, _omitFieldNames ? '' : 'namePrefix')
    ..aI(8, _omitFieldNames ? '' : 'listenPort', fieldType: $pb.PbFieldType.OU3)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExposeServiceRequest clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExposeServiceRequest copyWith(void Function(ExposeServiceRequest) updates) =>
      super.copyWith((message) => updates(message as ExposeServiceRequest))
          as ExposeServiceRequest;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ExposeServiceRequest create() => ExposeServiceRequest._();
  @$core.override
  ExposeServiceRequest createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ExposeServiceRequest getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ExposeServiceRequest>(create);
  static ExposeServiceRequest? _defaultInstance;

  @$pb.TagNumber(1)
  $core.int get port => $_getIZ(0);
  @$pb.TagNumber(1)
  set port($core.int value) => $_setUnsignedInt32(0, value);
  @$pb.TagNumber(1)
  $core.bool hasPort() => $_has(0);
  @$pb.TagNumber(1)
  void clearPort() => $_clearField(1);

  @$pb.TagNumber(2)
  ExposeProtocol get protocol => $_getN(1);
  @$pb.TagNumber(2)
  set protocol(ExposeProtocol value) => $_setField(2, value);
  @$pb.TagNumber(2)
  $core.bool hasProtocol() => $_has(1);
  @$pb.TagNumber(2)
  void clearProtocol() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get pin => $_getSZ(2);
  @$pb.TagNumber(3)
  set pin($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasPin() => $_has(2);
  @$pb.TagNumber(3)
  void clearPin() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.String get password => $_getSZ(3);
  @$pb.TagNumber(4)
  set password($core.String value) => $_setString(3, value);
  @$pb.TagNumber(4)
  $core.bool hasPassword() => $_has(3);
  @$pb.TagNumber(4)
  void clearPassword() => $_clearField(4);

  @$pb.TagNumber(5)
  $pb.PbList<$core.String> get userGroups => $_getList(4);

  @$pb.TagNumber(6)
  $core.String get domain => $_getSZ(5);
  @$pb.TagNumber(6)
  set domain($core.String value) => $_setString(5, value);
  @$pb.TagNumber(6)
  $core.bool hasDomain() => $_has(5);
  @$pb.TagNumber(6)
  void clearDomain() => $_clearField(6);

  @$pb.TagNumber(7)
  $core.String get namePrefix => $_getSZ(6);
  @$pb.TagNumber(7)
  set namePrefix($core.String value) => $_setString(6, value);
  @$pb.TagNumber(7)
  $core.bool hasNamePrefix() => $_has(6);
  @$pb.TagNumber(7)
  void clearNamePrefix() => $_clearField(7);

  @$pb.TagNumber(8)
  $core.int get listenPort => $_getIZ(7);
  @$pb.TagNumber(8)
  set listenPort($core.int value) => $_setUnsignedInt32(7, value);
  @$pb.TagNumber(8)
  $core.bool hasListenPort() => $_has(7);
  @$pb.TagNumber(8)
  void clearListenPort() => $_clearField(8);
}

enum ExposeServiceEvent_Event { ready, notSet }

class ExposeServiceEvent extends $pb.GeneratedMessage {
  factory ExposeServiceEvent({
    ExposeServiceReady? ready,
  }) {
    final result = create();
    if (ready != null) result.ready = ready;
    return result;
  }

  ExposeServiceEvent._();

  factory ExposeServiceEvent.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ExposeServiceEvent.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static const $core.Map<$core.int, ExposeServiceEvent_Event>
      _ExposeServiceEvent_EventByTag = {
    1: ExposeServiceEvent_Event.ready,
    0: ExposeServiceEvent_Event.notSet
  };
  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ExposeServiceEvent',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..oo(0, [1])
    ..aOM<ExposeServiceReady>(1, _omitFieldNames ? '' : 'ready',
        subBuilder: ExposeServiceReady.create)
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExposeServiceEvent clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExposeServiceEvent copyWith(void Function(ExposeServiceEvent) updates) =>
      super.copyWith((message) => updates(message as ExposeServiceEvent))
          as ExposeServiceEvent;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ExposeServiceEvent create() => ExposeServiceEvent._();
  @$core.override
  ExposeServiceEvent createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ExposeServiceEvent getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ExposeServiceEvent>(create);
  static ExposeServiceEvent? _defaultInstance;

  @$pb.TagNumber(1)
  ExposeServiceEvent_Event whichEvent() =>
      _ExposeServiceEvent_EventByTag[$_whichOneof(0)]!;
  @$pb.TagNumber(1)
  void clearEvent() => $_clearField($_whichOneof(0));

  @$pb.TagNumber(1)
  ExposeServiceReady get ready => $_getN(0);
  @$pb.TagNumber(1)
  set ready(ExposeServiceReady value) => $_setField(1, value);
  @$pb.TagNumber(1)
  $core.bool hasReady() => $_has(0);
  @$pb.TagNumber(1)
  void clearReady() => $_clearField(1);
  @$pb.TagNumber(1)
  ExposeServiceReady ensureReady() => $_ensure(0);
}

class ExposeServiceReady extends $pb.GeneratedMessage {
  factory ExposeServiceReady({
    $core.String? serviceName,
    $core.String? serviceUrl,
    $core.String? domain,
    $core.bool? portAutoAssigned,
  }) {
    final result = create();
    if (serviceName != null) result.serviceName = serviceName;
    if (serviceUrl != null) result.serviceUrl = serviceUrl;
    if (domain != null) result.domain = domain;
    if (portAutoAssigned != null) result.portAutoAssigned = portAutoAssigned;
    return result;
  }

  ExposeServiceReady._();

  factory ExposeServiceReady.fromBuffer($core.List<$core.int> data,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromBuffer(data, registry);
  factory ExposeServiceReady.fromJson($core.String json,
          [$pb.ExtensionRegistry registry = $pb.ExtensionRegistry.EMPTY]) =>
      create()..mergeFromJson(json, registry);

  static final $pb.BuilderInfo _i = $pb.BuilderInfo(
      _omitMessageNames ? '' : 'ExposeServiceReady',
      package: const $pb.PackageName(_omitMessageNames ? '' : 'daemon'),
      createEmptyInstance: create)
    ..aOS(1, _omitFieldNames ? '' : 'serviceName')
    ..aOS(2, _omitFieldNames ? '' : 'serviceUrl')
    ..aOS(3, _omitFieldNames ? '' : 'domain')
    ..aOB(4, _omitFieldNames ? '' : 'portAutoAssigned')
    ..hasRequiredFields = false;

  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExposeServiceReady clone() => deepCopy();
  @$core.Deprecated('See https://github.com/google/protobuf.dart/issues/998.')
  ExposeServiceReady copyWith(void Function(ExposeServiceReady) updates) =>
      super.copyWith((message) => updates(message as ExposeServiceReady))
          as ExposeServiceReady;

  @$core.override
  $pb.BuilderInfo get info_ => _i;

  @$core.pragma('dart2js:noInline')
  static ExposeServiceReady create() => ExposeServiceReady._();
  @$core.override
  ExposeServiceReady createEmptyInstance() => create();
  @$core.pragma('dart2js:noInline')
  static ExposeServiceReady getDefault() => _defaultInstance ??=
      $pb.GeneratedMessage.$_defaultFor<ExposeServiceReady>(create);
  static ExposeServiceReady? _defaultInstance;

  @$pb.TagNumber(1)
  $core.String get serviceName => $_getSZ(0);
  @$pb.TagNumber(1)
  set serviceName($core.String value) => $_setString(0, value);
  @$pb.TagNumber(1)
  $core.bool hasServiceName() => $_has(0);
  @$pb.TagNumber(1)
  void clearServiceName() => $_clearField(1);

  @$pb.TagNumber(2)
  $core.String get serviceUrl => $_getSZ(1);
  @$pb.TagNumber(2)
  set serviceUrl($core.String value) => $_setString(1, value);
  @$pb.TagNumber(2)
  $core.bool hasServiceUrl() => $_has(1);
  @$pb.TagNumber(2)
  void clearServiceUrl() => $_clearField(2);

  @$pb.TagNumber(3)
  $core.String get domain => $_getSZ(2);
  @$pb.TagNumber(3)
  set domain($core.String value) => $_setString(2, value);
  @$pb.TagNumber(3)
  $core.bool hasDomain() => $_has(2);
  @$pb.TagNumber(3)
  void clearDomain() => $_clearField(3);

  @$pb.TagNumber(4)
  $core.bool get portAutoAssigned => $_getBF(3);
  @$pb.TagNumber(4)
  set portAutoAssigned($core.bool value) => $_setBool(3, value);
  @$pb.TagNumber(4)
  $core.bool hasPortAutoAssigned() => $_has(3);
  @$pb.TagNumber(4)
  void clearPortAutoAssigned() => $_clearField(4);
}

const $core.bool _omitFieldNames =
    $core.bool.fromEnvironment('protobuf.omit_field_names');
const $core.bool _omitMessageNames =
    $core.bool.fromEnvironment('protobuf.omit_message_names');
