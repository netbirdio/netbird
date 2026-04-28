// This is a generated file - do not edit.
//
// Generated from daemon.proto.

// @dart = 3.3

// ignore_for_file: annotate_overrides, camel_case_types, comment_references
// ignore_for_file: constant_identifier_names
// ignore_for_file: curly_braces_in_flow_control_structures
// ignore_for_file: deprecated_member_use_from_same_package, library_prefixes
// ignore_for_file: non_constant_identifier_names, prefer_relative_imports

import 'dart:async' as $async;
import 'dart:core' as $core;

import 'package:grpc/service_api.dart' as $grpc;
import 'package:protobuf/protobuf.dart' as $pb;

import 'daemon.pb.dart' as $0;

export 'daemon.pb.dart';

@$pb.GrpcServiceName('daemon.DaemonService')
class DaemonServiceClient extends $grpc.Client {
  /// The hostname for this service.
  static const $core.String defaultHost = '';

  /// OAuth scopes needed for the client.
  static const $core.List<$core.String> oauthScopes = [
    '',
  ];

  DaemonServiceClient(super.channel, {super.options, super.interceptors});

  /// Login uses setup key to prepare configuration for the daemon.
  $grpc.ResponseFuture<$0.LoginResponse> login(
    $0.LoginRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$login, request, options: options);
  }

  /// WaitSSOLogin uses the userCode to validate the TokenInfo and
  /// waits for the user to continue with the login on a browser
  $grpc.ResponseFuture<$0.WaitSSOLoginResponse> waitSSOLogin(
    $0.WaitSSOLoginRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$waitSSOLogin, request, options: options);
  }

  /// Up starts engine work in the daemon.
  $grpc.ResponseFuture<$0.UpResponse> up(
    $0.UpRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$up, request, options: options);
  }

  /// Status of the service.
  $grpc.ResponseFuture<$0.StatusResponse> status(
    $0.StatusRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$status, request, options: options);
  }

  /// Down stops engine work in the daemon.
  $grpc.ResponseFuture<$0.DownResponse> down(
    $0.DownRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$down, request, options: options);
  }

  /// GetConfig of the daemon.
  $grpc.ResponseFuture<$0.GetConfigResponse> getConfig(
    $0.GetConfigRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getConfig, request, options: options);
  }

  /// List available networks
  $grpc.ResponseFuture<$0.ListNetworksResponse> listNetworks(
    $0.ListNetworksRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$listNetworks, request, options: options);
  }

  /// Select specific routes
  $grpc.ResponseFuture<$0.SelectNetworksResponse> selectNetworks(
    $0.SelectNetworksRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$selectNetworks, request, options: options);
  }

  /// Deselect specific routes
  $grpc.ResponseFuture<$0.SelectNetworksResponse> deselectNetworks(
    $0.SelectNetworksRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$deselectNetworks, request, options: options);
  }

  $grpc.ResponseFuture<$0.ForwardingRulesResponse> forwardingRules(
    $0.EmptyRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$forwardingRules, request, options: options);
  }

  /// DebugBundle creates a debug bundle
  $grpc.ResponseFuture<$0.DebugBundleResponse> debugBundle(
    $0.DebugBundleRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$debugBundle, request, options: options);
  }

  /// GetLogLevel gets the log level of the daemon
  $grpc.ResponseFuture<$0.GetLogLevelResponse> getLogLevel(
    $0.GetLogLevelRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getLogLevel, request, options: options);
  }

  /// SetLogLevel sets the log level of the daemon
  $grpc.ResponseFuture<$0.SetLogLevelResponse> setLogLevel(
    $0.SetLogLevelRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$setLogLevel, request, options: options);
  }

  /// List all states
  $grpc.ResponseFuture<$0.ListStatesResponse> listStates(
    $0.ListStatesRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$listStates, request, options: options);
  }

  /// Clean specific state or all states
  $grpc.ResponseFuture<$0.CleanStateResponse> cleanState(
    $0.CleanStateRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$cleanState, request, options: options);
  }

  /// Delete specific state or all states
  $grpc.ResponseFuture<$0.DeleteStateResponse> deleteState(
    $0.DeleteStateRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$deleteState, request, options: options);
  }

  /// SetSyncResponsePersistence enables or disables sync response persistence
  $grpc.ResponseFuture<$0.SetSyncResponsePersistenceResponse>
      setSyncResponsePersistence(
    $0.SetSyncResponsePersistenceRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$setSyncResponsePersistence, request,
        options: options);
  }

  $grpc.ResponseFuture<$0.TracePacketResponse> tracePacket(
    $0.TracePacketRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$tracePacket, request, options: options);
  }

  $grpc.ResponseStream<$0.SystemEvent> subscribeEvents(
    $0.SubscribeRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createStreamingCall(
        _$subscribeEvents, $async.Stream.fromIterable([request]),
        options: options);
  }

  $grpc.ResponseFuture<$0.GetEventsResponse> getEvents(
    $0.GetEventsRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getEvents, request, options: options);
  }

  $grpc.ResponseFuture<$0.SwitchProfileResponse> switchProfile(
    $0.SwitchProfileRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$switchProfile, request, options: options);
  }

  $grpc.ResponseFuture<$0.SetConfigResponse> setConfig(
    $0.SetConfigRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$setConfig, request, options: options);
  }

  $grpc.ResponseFuture<$0.AddProfileResponse> addProfile(
    $0.AddProfileRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$addProfile, request, options: options);
  }

  $grpc.ResponseFuture<$0.RemoveProfileResponse> removeProfile(
    $0.RemoveProfileRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$removeProfile, request, options: options);
  }

  $grpc.ResponseFuture<$0.ListProfilesResponse> listProfiles(
    $0.ListProfilesRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$listProfiles, request, options: options);
  }

  $grpc.ResponseFuture<$0.GetActiveProfileResponse> getActiveProfile(
    $0.GetActiveProfileRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getActiveProfile, request, options: options);
  }

  /// Logout disconnects from the network and deletes the peer from the management server
  $grpc.ResponseFuture<$0.LogoutResponse> logout(
    $0.LogoutRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$logout, request, options: options);
  }

  $grpc.ResponseFuture<$0.GetFeaturesResponse> getFeatures(
    $0.GetFeaturesRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getFeatures, request, options: options);
  }

  /// TriggerUpdate initiates installation of the pending enforced version.
  /// Called when the user clicks the install button in the UI (Mode 2 / enforced update).
  $grpc.ResponseFuture<$0.TriggerUpdateResponse> triggerUpdate(
    $0.TriggerUpdateRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$triggerUpdate, request, options: options);
  }

  /// GetPeerSSHHostKey retrieves SSH host key for a specific peer
  $grpc.ResponseFuture<$0.GetPeerSSHHostKeyResponse> getPeerSSHHostKey(
    $0.GetPeerSSHHostKeyRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getPeerSSHHostKey, request, options: options);
  }

  /// RequestJWTAuth initiates JWT authentication flow for SSH
  $grpc.ResponseFuture<$0.RequestJWTAuthResponse> requestJWTAuth(
    $0.RequestJWTAuthRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$requestJWTAuth, request, options: options);
  }

  /// WaitJWTToken waits for JWT authentication completion
  $grpc.ResponseFuture<$0.WaitJWTTokenResponse> waitJWTToken(
    $0.WaitJWTTokenRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$waitJWTToken, request, options: options);
  }

  /// StartCPUProfile starts CPU profiling in the daemon
  $grpc.ResponseFuture<$0.StartCPUProfileResponse> startCPUProfile(
    $0.StartCPUProfileRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$startCPUProfile, request, options: options);
  }

  /// StopCPUProfile stops CPU profiling in the daemon
  $grpc.ResponseFuture<$0.StopCPUProfileResponse> stopCPUProfile(
    $0.StopCPUProfileRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$stopCPUProfile, request, options: options);
  }

  $grpc.ResponseFuture<$0.OSLifecycleResponse> notifyOSLifecycle(
    $0.OSLifecycleRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$notifyOSLifecycle, request, options: options);
  }

  $grpc.ResponseFuture<$0.InstallerResultResponse> getInstallerResult(
    $0.InstallerResultRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createUnaryCall(_$getInstallerResult, request, options: options);
  }

  /// ExposeService exposes a local port via the NetBird reverse proxy
  $grpc.ResponseStream<$0.ExposeServiceEvent> exposeService(
    $0.ExposeServiceRequest request, {
    $grpc.CallOptions? options,
  }) {
    return $createStreamingCall(
        _$exposeService, $async.Stream.fromIterable([request]),
        options: options);
  }

  // method descriptors

  static final _$login = $grpc.ClientMethod<$0.LoginRequest, $0.LoginResponse>(
      '/daemon.DaemonService/Login',
      ($0.LoginRequest value) => value.writeToBuffer(),
      $0.LoginResponse.fromBuffer);
  static final _$waitSSOLogin =
      $grpc.ClientMethod<$0.WaitSSOLoginRequest, $0.WaitSSOLoginResponse>(
          '/daemon.DaemonService/WaitSSOLogin',
          ($0.WaitSSOLoginRequest value) => value.writeToBuffer(),
          $0.WaitSSOLoginResponse.fromBuffer);
  static final _$up = $grpc.ClientMethod<$0.UpRequest, $0.UpResponse>(
      '/daemon.DaemonService/Up',
      ($0.UpRequest value) => value.writeToBuffer(),
      $0.UpResponse.fromBuffer);
  static final _$status =
      $grpc.ClientMethod<$0.StatusRequest, $0.StatusResponse>(
          '/daemon.DaemonService/Status',
          ($0.StatusRequest value) => value.writeToBuffer(),
          $0.StatusResponse.fromBuffer);
  static final _$down = $grpc.ClientMethod<$0.DownRequest, $0.DownResponse>(
      '/daemon.DaemonService/Down',
      ($0.DownRequest value) => value.writeToBuffer(),
      $0.DownResponse.fromBuffer);
  static final _$getConfig =
      $grpc.ClientMethod<$0.GetConfigRequest, $0.GetConfigResponse>(
          '/daemon.DaemonService/GetConfig',
          ($0.GetConfigRequest value) => value.writeToBuffer(),
          $0.GetConfigResponse.fromBuffer);
  static final _$listNetworks =
      $grpc.ClientMethod<$0.ListNetworksRequest, $0.ListNetworksResponse>(
          '/daemon.DaemonService/ListNetworks',
          ($0.ListNetworksRequest value) => value.writeToBuffer(),
          $0.ListNetworksResponse.fromBuffer);
  static final _$selectNetworks =
      $grpc.ClientMethod<$0.SelectNetworksRequest, $0.SelectNetworksResponse>(
          '/daemon.DaemonService/SelectNetworks',
          ($0.SelectNetworksRequest value) => value.writeToBuffer(),
          $0.SelectNetworksResponse.fromBuffer);
  static final _$deselectNetworks =
      $grpc.ClientMethod<$0.SelectNetworksRequest, $0.SelectNetworksResponse>(
          '/daemon.DaemonService/DeselectNetworks',
          ($0.SelectNetworksRequest value) => value.writeToBuffer(),
          $0.SelectNetworksResponse.fromBuffer);
  static final _$forwardingRules =
      $grpc.ClientMethod<$0.EmptyRequest, $0.ForwardingRulesResponse>(
          '/daemon.DaemonService/ForwardingRules',
          ($0.EmptyRequest value) => value.writeToBuffer(),
          $0.ForwardingRulesResponse.fromBuffer);
  static final _$debugBundle =
      $grpc.ClientMethod<$0.DebugBundleRequest, $0.DebugBundleResponse>(
          '/daemon.DaemonService/DebugBundle',
          ($0.DebugBundleRequest value) => value.writeToBuffer(),
          $0.DebugBundleResponse.fromBuffer);
  static final _$getLogLevel =
      $grpc.ClientMethod<$0.GetLogLevelRequest, $0.GetLogLevelResponse>(
          '/daemon.DaemonService/GetLogLevel',
          ($0.GetLogLevelRequest value) => value.writeToBuffer(),
          $0.GetLogLevelResponse.fromBuffer);
  static final _$setLogLevel =
      $grpc.ClientMethod<$0.SetLogLevelRequest, $0.SetLogLevelResponse>(
          '/daemon.DaemonService/SetLogLevel',
          ($0.SetLogLevelRequest value) => value.writeToBuffer(),
          $0.SetLogLevelResponse.fromBuffer);
  static final _$listStates =
      $grpc.ClientMethod<$0.ListStatesRequest, $0.ListStatesResponse>(
          '/daemon.DaemonService/ListStates',
          ($0.ListStatesRequest value) => value.writeToBuffer(),
          $0.ListStatesResponse.fromBuffer);
  static final _$cleanState =
      $grpc.ClientMethod<$0.CleanStateRequest, $0.CleanStateResponse>(
          '/daemon.DaemonService/CleanState',
          ($0.CleanStateRequest value) => value.writeToBuffer(),
          $0.CleanStateResponse.fromBuffer);
  static final _$deleteState =
      $grpc.ClientMethod<$0.DeleteStateRequest, $0.DeleteStateResponse>(
          '/daemon.DaemonService/DeleteState',
          ($0.DeleteStateRequest value) => value.writeToBuffer(),
          $0.DeleteStateResponse.fromBuffer);
  static final _$setSyncResponsePersistence = $grpc.ClientMethod<
          $0.SetSyncResponsePersistenceRequest,
          $0.SetSyncResponsePersistenceResponse>(
      '/daemon.DaemonService/SetSyncResponsePersistence',
      ($0.SetSyncResponsePersistenceRequest value) => value.writeToBuffer(),
      $0.SetSyncResponsePersistenceResponse.fromBuffer);
  static final _$tracePacket =
      $grpc.ClientMethod<$0.TracePacketRequest, $0.TracePacketResponse>(
          '/daemon.DaemonService/TracePacket',
          ($0.TracePacketRequest value) => value.writeToBuffer(),
          $0.TracePacketResponse.fromBuffer);
  static final _$subscribeEvents =
      $grpc.ClientMethod<$0.SubscribeRequest, $0.SystemEvent>(
          '/daemon.DaemonService/SubscribeEvents',
          ($0.SubscribeRequest value) => value.writeToBuffer(),
          $0.SystemEvent.fromBuffer);
  static final _$getEvents =
      $grpc.ClientMethod<$0.GetEventsRequest, $0.GetEventsResponse>(
          '/daemon.DaemonService/GetEvents',
          ($0.GetEventsRequest value) => value.writeToBuffer(),
          $0.GetEventsResponse.fromBuffer);
  static final _$switchProfile =
      $grpc.ClientMethod<$0.SwitchProfileRequest, $0.SwitchProfileResponse>(
          '/daemon.DaemonService/SwitchProfile',
          ($0.SwitchProfileRequest value) => value.writeToBuffer(),
          $0.SwitchProfileResponse.fromBuffer);
  static final _$setConfig =
      $grpc.ClientMethod<$0.SetConfigRequest, $0.SetConfigResponse>(
          '/daemon.DaemonService/SetConfig',
          ($0.SetConfigRequest value) => value.writeToBuffer(),
          $0.SetConfigResponse.fromBuffer);
  static final _$addProfile =
      $grpc.ClientMethod<$0.AddProfileRequest, $0.AddProfileResponse>(
          '/daemon.DaemonService/AddProfile',
          ($0.AddProfileRequest value) => value.writeToBuffer(),
          $0.AddProfileResponse.fromBuffer);
  static final _$removeProfile =
      $grpc.ClientMethod<$0.RemoveProfileRequest, $0.RemoveProfileResponse>(
          '/daemon.DaemonService/RemoveProfile',
          ($0.RemoveProfileRequest value) => value.writeToBuffer(),
          $0.RemoveProfileResponse.fromBuffer);
  static final _$listProfiles =
      $grpc.ClientMethod<$0.ListProfilesRequest, $0.ListProfilesResponse>(
          '/daemon.DaemonService/ListProfiles',
          ($0.ListProfilesRequest value) => value.writeToBuffer(),
          $0.ListProfilesResponse.fromBuffer);
  static final _$getActiveProfile = $grpc.ClientMethod<
          $0.GetActiveProfileRequest, $0.GetActiveProfileResponse>(
      '/daemon.DaemonService/GetActiveProfile',
      ($0.GetActiveProfileRequest value) => value.writeToBuffer(),
      $0.GetActiveProfileResponse.fromBuffer);
  static final _$logout =
      $grpc.ClientMethod<$0.LogoutRequest, $0.LogoutResponse>(
          '/daemon.DaemonService/Logout',
          ($0.LogoutRequest value) => value.writeToBuffer(),
          $0.LogoutResponse.fromBuffer);
  static final _$getFeatures =
      $grpc.ClientMethod<$0.GetFeaturesRequest, $0.GetFeaturesResponse>(
          '/daemon.DaemonService/GetFeatures',
          ($0.GetFeaturesRequest value) => value.writeToBuffer(),
          $0.GetFeaturesResponse.fromBuffer);
  static final _$triggerUpdate =
      $grpc.ClientMethod<$0.TriggerUpdateRequest, $0.TriggerUpdateResponse>(
          '/daemon.DaemonService/TriggerUpdate',
          ($0.TriggerUpdateRequest value) => value.writeToBuffer(),
          $0.TriggerUpdateResponse.fromBuffer);
  static final _$getPeerSSHHostKey = $grpc.ClientMethod<
          $0.GetPeerSSHHostKeyRequest, $0.GetPeerSSHHostKeyResponse>(
      '/daemon.DaemonService/GetPeerSSHHostKey',
      ($0.GetPeerSSHHostKeyRequest value) => value.writeToBuffer(),
      $0.GetPeerSSHHostKeyResponse.fromBuffer);
  static final _$requestJWTAuth =
      $grpc.ClientMethod<$0.RequestJWTAuthRequest, $0.RequestJWTAuthResponse>(
          '/daemon.DaemonService/RequestJWTAuth',
          ($0.RequestJWTAuthRequest value) => value.writeToBuffer(),
          $0.RequestJWTAuthResponse.fromBuffer);
  static final _$waitJWTToken =
      $grpc.ClientMethod<$0.WaitJWTTokenRequest, $0.WaitJWTTokenResponse>(
          '/daemon.DaemonService/WaitJWTToken',
          ($0.WaitJWTTokenRequest value) => value.writeToBuffer(),
          $0.WaitJWTTokenResponse.fromBuffer);
  static final _$startCPUProfile =
      $grpc.ClientMethod<$0.StartCPUProfileRequest, $0.StartCPUProfileResponse>(
          '/daemon.DaemonService/StartCPUProfile',
          ($0.StartCPUProfileRequest value) => value.writeToBuffer(),
          $0.StartCPUProfileResponse.fromBuffer);
  static final _$stopCPUProfile =
      $grpc.ClientMethod<$0.StopCPUProfileRequest, $0.StopCPUProfileResponse>(
          '/daemon.DaemonService/StopCPUProfile',
          ($0.StopCPUProfileRequest value) => value.writeToBuffer(),
          $0.StopCPUProfileResponse.fromBuffer);
  static final _$notifyOSLifecycle =
      $grpc.ClientMethod<$0.OSLifecycleRequest, $0.OSLifecycleResponse>(
          '/daemon.DaemonService/NotifyOSLifecycle',
          ($0.OSLifecycleRequest value) => value.writeToBuffer(),
          $0.OSLifecycleResponse.fromBuffer);
  static final _$getInstallerResult =
      $grpc.ClientMethod<$0.InstallerResultRequest, $0.InstallerResultResponse>(
          '/daemon.DaemonService/GetInstallerResult',
          ($0.InstallerResultRequest value) => value.writeToBuffer(),
          $0.InstallerResultResponse.fromBuffer);
  static final _$exposeService =
      $grpc.ClientMethod<$0.ExposeServiceRequest, $0.ExposeServiceEvent>(
          '/daemon.DaemonService/ExposeService',
          ($0.ExposeServiceRequest value) => value.writeToBuffer(),
          $0.ExposeServiceEvent.fromBuffer);
}

@$pb.GrpcServiceName('daemon.DaemonService')
abstract class DaemonServiceBase extends $grpc.Service {
  $core.String get $name => 'daemon.DaemonService';

  DaemonServiceBase() {
    $addMethod($grpc.ServiceMethod<$0.LoginRequest, $0.LoginResponse>(
        'Login',
        login_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.LoginRequest.fromBuffer(value),
        ($0.LoginResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.WaitSSOLoginRequest, $0.WaitSSOLoginResponse>(
            'WaitSSOLogin',
            waitSSOLogin_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.WaitSSOLoginRequest.fromBuffer(value),
            ($0.WaitSSOLoginResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.UpRequest, $0.UpResponse>(
        'Up',
        up_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.UpRequest.fromBuffer(value),
        ($0.UpResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.StatusRequest, $0.StatusResponse>(
        'Status',
        status_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.StatusRequest.fromBuffer(value),
        ($0.StatusResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.DownRequest, $0.DownResponse>(
        'Down',
        down_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.DownRequest.fromBuffer(value),
        ($0.DownResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.GetConfigRequest, $0.GetConfigResponse>(
        'GetConfig',
        getConfig_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.GetConfigRequest.fromBuffer(value),
        ($0.GetConfigResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.ListNetworksRequest, $0.ListNetworksResponse>(
            'ListNetworks',
            listNetworks_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.ListNetworksRequest.fromBuffer(value),
            ($0.ListNetworksResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.SelectNetworksRequest,
            $0.SelectNetworksResponse>(
        'SelectNetworks',
        selectNetworks_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.SelectNetworksRequest.fromBuffer(value),
        ($0.SelectNetworksResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.SelectNetworksRequest,
            $0.SelectNetworksResponse>(
        'DeselectNetworks',
        deselectNetworks_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.SelectNetworksRequest.fromBuffer(value),
        ($0.SelectNetworksResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.EmptyRequest, $0.ForwardingRulesResponse>(
        'ForwardingRules',
        forwardingRules_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.EmptyRequest.fromBuffer(value),
        ($0.ForwardingRulesResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.DebugBundleRequest, $0.DebugBundleResponse>(
            'DebugBundle',
            debugBundle_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.DebugBundleRequest.fromBuffer(value),
            ($0.DebugBundleResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.GetLogLevelRequest, $0.GetLogLevelResponse>(
            'GetLogLevel',
            getLogLevel_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.GetLogLevelRequest.fromBuffer(value),
            ($0.GetLogLevelResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.SetLogLevelRequest, $0.SetLogLevelResponse>(
            'SetLogLevel',
            setLogLevel_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.SetLogLevelRequest.fromBuffer(value),
            ($0.SetLogLevelResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.ListStatesRequest, $0.ListStatesResponse>(
        'ListStates',
        listStates_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.ListStatesRequest.fromBuffer(value),
        ($0.ListStatesResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.CleanStateRequest, $0.CleanStateResponse>(
        'CleanState',
        cleanState_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.CleanStateRequest.fromBuffer(value),
        ($0.CleanStateResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.DeleteStateRequest, $0.DeleteStateResponse>(
            'DeleteState',
            deleteState_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.DeleteStateRequest.fromBuffer(value),
            ($0.DeleteStateResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.SetSyncResponsePersistenceRequest,
            $0.SetSyncResponsePersistenceResponse>(
        'SetSyncResponsePersistence',
        setSyncResponsePersistence_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.SetSyncResponsePersistenceRequest.fromBuffer(value),
        ($0.SetSyncResponsePersistenceResponse value) =>
            value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.TracePacketRequest, $0.TracePacketResponse>(
            'TracePacket',
            tracePacket_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.TracePacketRequest.fromBuffer(value),
            ($0.TracePacketResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.SubscribeRequest, $0.SystemEvent>(
        'SubscribeEvents',
        subscribeEvents_Pre,
        false,
        true,
        ($core.List<$core.int> value) => $0.SubscribeRequest.fromBuffer(value),
        ($0.SystemEvent value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.GetEventsRequest, $0.GetEventsResponse>(
        'GetEvents',
        getEvents_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.GetEventsRequest.fromBuffer(value),
        ($0.GetEventsResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.SwitchProfileRequest, $0.SwitchProfileResponse>(
            'SwitchProfile',
            switchProfile_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.SwitchProfileRequest.fromBuffer(value),
            ($0.SwitchProfileResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.SetConfigRequest, $0.SetConfigResponse>(
        'SetConfig',
        setConfig_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.SetConfigRequest.fromBuffer(value),
        ($0.SetConfigResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.AddProfileRequest, $0.AddProfileResponse>(
        'AddProfile',
        addProfile_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.AddProfileRequest.fromBuffer(value),
        ($0.AddProfileResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.RemoveProfileRequest, $0.RemoveProfileResponse>(
            'RemoveProfile',
            removeProfile_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.RemoveProfileRequest.fromBuffer(value),
            ($0.RemoveProfileResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.ListProfilesRequest, $0.ListProfilesResponse>(
            'ListProfiles',
            listProfiles_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.ListProfilesRequest.fromBuffer(value),
            ($0.ListProfilesResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.GetActiveProfileRequest,
            $0.GetActiveProfileResponse>(
        'GetActiveProfile',
        getActiveProfile_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.GetActiveProfileRequest.fromBuffer(value),
        ($0.GetActiveProfileResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.LogoutRequest, $0.LogoutResponse>(
        'Logout',
        logout_Pre,
        false,
        false,
        ($core.List<$core.int> value) => $0.LogoutRequest.fromBuffer(value),
        ($0.LogoutResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.GetFeaturesRequest, $0.GetFeaturesResponse>(
            'GetFeatures',
            getFeatures_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.GetFeaturesRequest.fromBuffer(value),
            ($0.GetFeaturesResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.TriggerUpdateRequest, $0.TriggerUpdateResponse>(
            'TriggerUpdate',
            triggerUpdate_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.TriggerUpdateRequest.fromBuffer(value),
            ($0.TriggerUpdateResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.GetPeerSSHHostKeyRequest,
            $0.GetPeerSSHHostKeyResponse>(
        'GetPeerSSHHostKey',
        getPeerSSHHostKey_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.GetPeerSSHHostKeyRequest.fromBuffer(value),
        ($0.GetPeerSSHHostKeyResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.RequestJWTAuthRequest,
            $0.RequestJWTAuthResponse>(
        'RequestJWTAuth',
        requestJWTAuth_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.RequestJWTAuthRequest.fromBuffer(value),
        ($0.RequestJWTAuthResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.WaitJWTTokenRequest, $0.WaitJWTTokenResponse>(
            'WaitJWTToken',
            waitJWTToken_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.WaitJWTTokenRequest.fromBuffer(value),
            ($0.WaitJWTTokenResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.StartCPUProfileRequest,
            $0.StartCPUProfileResponse>(
        'StartCPUProfile',
        startCPUProfile_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.StartCPUProfileRequest.fromBuffer(value),
        ($0.StartCPUProfileResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.StopCPUProfileRequest,
            $0.StopCPUProfileResponse>(
        'StopCPUProfile',
        stopCPUProfile_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.StopCPUProfileRequest.fromBuffer(value),
        ($0.StopCPUProfileResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.OSLifecycleRequest, $0.OSLifecycleResponse>(
            'NotifyOSLifecycle',
            notifyOSLifecycle_Pre,
            false,
            false,
            ($core.List<$core.int> value) =>
                $0.OSLifecycleRequest.fromBuffer(value),
            ($0.OSLifecycleResponse value) => value.writeToBuffer()));
    $addMethod($grpc.ServiceMethod<$0.InstallerResultRequest,
            $0.InstallerResultResponse>(
        'GetInstallerResult',
        getInstallerResult_Pre,
        false,
        false,
        ($core.List<$core.int> value) =>
            $0.InstallerResultRequest.fromBuffer(value),
        ($0.InstallerResultResponse value) => value.writeToBuffer()));
    $addMethod(
        $grpc.ServiceMethod<$0.ExposeServiceRequest, $0.ExposeServiceEvent>(
            'ExposeService',
            exposeService_Pre,
            false,
            true,
            ($core.List<$core.int> value) =>
                $0.ExposeServiceRequest.fromBuffer(value),
            ($0.ExposeServiceEvent value) => value.writeToBuffer()));
  }

  $async.Future<$0.LoginResponse> login_Pre(
      $grpc.ServiceCall $call, $async.Future<$0.LoginRequest> $request) async {
    return login($call, await $request);
  }

  $async.Future<$0.LoginResponse> login(
      $grpc.ServiceCall call, $0.LoginRequest request);

  $async.Future<$0.WaitSSOLoginResponse> waitSSOLogin_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.WaitSSOLoginRequest> $request) async {
    return waitSSOLogin($call, await $request);
  }

  $async.Future<$0.WaitSSOLoginResponse> waitSSOLogin(
      $grpc.ServiceCall call, $0.WaitSSOLoginRequest request);

  $async.Future<$0.UpResponse> up_Pre(
      $grpc.ServiceCall $call, $async.Future<$0.UpRequest> $request) async {
    return up($call, await $request);
  }

  $async.Future<$0.UpResponse> up($grpc.ServiceCall call, $0.UpRequest request);

  $async.Future<$0.StatusResponse> status_Pre(
      $grpc.ServiceCall $call, $async.Future<$0.StatusRequest> $request) async {
    return status($call, await $request);
  }

  $async.Future<$0.StatusResponse> status(
      $grpc.ServiceCall call, $0.StatusRequest request);

  $async.Future<$0.DownResponse> down_Pre(
      $grpc.ServiceCall $call, $async.Future<$0.DownRequest> $request) async {
    return down($call, await $request);
  }

  $async.Future<$0.DownResponse> down(
      $grpc.ServiceCall call, $0.DownRequest request);

  $async.Future<$0.GetConfigResponse> getConfig_Pre($grpc.ServiceCall $call,
      $async.Future<$0.GetConfigRequest> $request) async {
    return getConfig($call, await $request);
  }

  $async.Future<$0.GetConfigResponse> getConfig(
      $grpc.ServiceCall call, $0.GetConfigRequest request);

  $async.Future<$0.ListNetworksResponse> listNetworks_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.ListNetworksRequest> $request) async {
    return listNetworks($call, await $request);
  }

  $async.Future<$0.ListNetworksResponse> listNetworks(
      $grpc.ServiceCall call, $0.ListNetworksRequest request);

  $async.Future<$0.SelectNetworksResponse> selectNetworks_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.SelectNetworksRequest> $request) async {
    return selectNetworks($call, await $request);
  }

  $async.Future<$0.SelectNetworksResponse> selectNetworks(
      $grpc.ServiceCall call, $0.SelectNetworksRequest request);

  $async.Future<$0.SelectNetworksResponse> deselectNetworks_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.SelectNetworksRequest> $request) async {
    return deselectNetworks($call, await $request);
  }

  $async.Future<$0.SelectNetworksResponse> deselectNetworks(
      $grpc.ServiceCall call, $0.SelectNetworksRequest request);

  $async.Future<$0.ForwardingRulesResponse> forwardingRules_Pre(
      $grpc.ServiceCall $call, $async.Future<$0.EmptyRequest> $request) async {
    return forwardingRules($call, await $request);
  }

  $async.Future<$0.ForwardingRulesResponse> forwardingRules(
      $grpc.ServiceCall call, $0.EmptyRequest request);

  $async.Future<$0.DebugBundleResponse> debugBundle_Pre($grpc.ServiceCall $call,
      $async.Future<$0.DebugBundleRequest> $request) async {
    return debugBundle($call, await $request);
  }

  $async.Future<$0.DebugBundleResponse> debugBundle(
      $grpc.ServiceCall call, $0.DebugBundleRequest request);

  $async.Future<$0.GetLogLevelResponse> getLogLevel_Pre($grpc.ServiceCall $call,
      $async.Future<$0.GetLogLevelRequest> $request) async {
    return getLogLevel($call, await $request);
  }

  $async.Future<$0.GetLogLevelResponse> getLogLevel(
      $grpc.ServiceCall call, $0.GetLogLevelRequest request);

  $async.Future<$0.SetLogLevelResponse> setLogLevel_Pre($grpc.ServiceCall $call,
      $async.Future<$0.SetLogLevelRequest> $request) async {
    return setLogLevel($call, await $request);
  }

  $async.Future<$0.SetLogLevelResponse> setLogLevel(
      $grpc.ServiceCall call, $0.SetLogLevelRequest request);

  $async.Future<$0.ListStatesResponse> listStates_Pre($grpc.ServiceCall $call,
      $async.Future<$0.ListStatesRequest> $request) async {
    return listStates($call, await $request);
  }

  $async.Future<$0.ListStatesResponse> listStates(
      $grpc.ServiceCall call, $0.ListStatesRequest request);

  $async.Future<$0.CleanStateResponse> cleanState_Pre($grpc.ServiceCall $call,
      $async.Future<$0.CleanStateRequest> $request) async {
    return cleanState($call, await $request);
  }

  $async.Future<$0.CleanStateResponse> cleanState(
      $grpc.ServiceCall call, $0.CleanStateRequest request);

  $async.Future<$0.DeleteStateResponse> deleteState_Pre($grpc.ServiceCall $call,
      $async.Future<$0.DeleteStateRequest> $request) async {
    return deleteState($call, await $request);
  }

  $async.Future<$0.DeleteStateResponse> deleteState(
      $grpc.ServiceCall call, $0.DeleteStateRequest request);

  $async.Future<$0.SetSyncResponsePersistenceResponse>
      setSyncResponsePersistence_Pre($grpc.ServiceCall $call,
          $async.Future<$0.SetSyncResponsePersistenceRequest> $request) async {
    return setSyncResponsePersistence($call, await $request);
  }

  $async.Future<$0.SetSyncResponsePersistenceResponse>
      setSyncResponsePersistence(
          $grpc.ServiceCall call, $0.SetSyncResponsePersistenceRequest request);

  $async.Future<$0.TracePacketResponse> tracePacket_Pre($grpc.ServiceCall $call,
      $async.Future<$0.TracePacketRequest> $request) async {
    return tracePacket($call, await $request);
  }

  $async.Future<$0.TracePacketResponse> tracePacket(
      $grpc.ServiceCall call, $0.TracePacketRequest request);

  $async.Stream<$0.SystemEvent> subscribeEvents_Pre($grpc.ServiceCall $call,
      $async.Future<$0.SubscribeRequest> $request) async* {
    yield* subscribeEvents($call, await $request);
  }

  $async.Stream<$0.SystemEvent> subscribeEvents(
      $grpc.ServiceCall call, $0.SubscribeRequest request);

  $async.Future<$0.GetEventsResponse> getEvents_Pre($grpc.ServiceCall $call,
      $async.Future<$0.GetEventsRequest> $request) async {
    return getEvents($call, await $request);
  }

  $async.Future<$0.GetEventsResponse> getEvents(
      $grpc.ServiceCall call, $0.GetEventsRequest request);

  $async.Future<$0.SwitchProfileResponse> switchProfile_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.SwitchProfileRequest> $request) async {
    return switchProfile($call, await $request);
  }

  $async.Future<$0.SwitchProfileResponse> switchProfile(
      $grpc.ServiceCall call, $0.SwitchProfileRequest request);

  $async.Future<$0.SetConfigResponse> setConfig_Pre($grpc.ServiceCall $call,
      $async.Future<$0.SetConfigRequest> $request) async {
    return setConfig($call, await $request);
  }

  $async.Future<$0.SetConfigResponse> setConfig(
      $grpc.ServiceCall call, $0.SetConfigRequest request);

  $async.Future<$0.AddProfileResponse> addProfile_Pre($grpc.ServiceCall $call,
      $async.Future<$0.AddProfileRequest> $request) async {
    return addProfile($call, await $request);
  }

  $async.Future<$0.AddProfileResponse> addProfile(
      $grpc.ServiceCall call, $0.AddProfileRequest request);

  $async.Future<$0.RemoveProfileResponse> removeProfile_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.RemoveProfileRequest> $request) async {
    return removeProfile($call, await $request);
  }

  $async.Future<$0.RemoveProfileResponse> removeProfile(
      $grpc.ServiceCall call, $0.RemoveProfileRequest request);

  $async.Future<$0.ListProfilesResponse> listProfiles_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.ListProfilesRequest> $request) async {
    return listProfiles($call, await $request);
  }

  $async.Future<$0.ListProfilesResponse> listProfiles(
      $grpc.ServiceCall call, $0.ListProfilesRequest request);

  $async.Future<$0.GetActiveProfileResponse> getActiveProfile_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.GetActiveProfileRequest> $request) async {
    return getActiveProfile($call, await $request);
  }

  $async.Future<$0.GetActiveProfileResponse> getActiveProfile(
      $grpc.ServiceCall call, $0.GetActiveProfileRequest request);

  $async.Future<$0.LogoutResponse> logout_Pre(
      $grpc.ServiceCall $call, $async.Future<$0.LogoutRequest> $request) async {
    return logout($call, await $request);
  }

  $async.Future<$0.LogoutResponse> logout(
      $grpc.ServiceCall call, $0.LogoutRequest request);

  $async.Future<$0.GetFeaturesResponse> getFeatures_Pre($grpc.ServiceCall $call,
      $async.Future<$0.GetFeaturesRequest> $request) async {
    return getFeatures($call, await $request);
  }

  $async.Future<$0.GetFeaturesResponse> getFeatures(
      $grpc.ServiceCall call, $0.GetFeaturesRequest request);

  $async.Future<$0.TriggerUpdateResponse> triggerUpdate_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.TriggerUpdateRequest> $request) async {
    return triggerUpdate($call, await $request);
  }

  $async.Future<$0.TriggerUpdateResponse> triggerUpdate(
      $grpc.ServiceCall call, $0.TriggerUpdateRequest request);

  $async.Future<$0.GetPeerSSHHostKeyResponse> getPeerSSHHostKey_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.GetPeerSSHHostKeyRequest> $request) async {
    return getPeerSSHHostKey($call, await $request);
  }

  $async.Future<$0.GetPeerSSHHostKeyResponse> getPeerSSHHostKey(
      $grpc.ServiceCall call, $0.GetPeerSSHHostKeyRequest request);

  $async.Future<$0.RequestJWTAuthResponse> requestJWTAuth_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.RequestJWTAuthRequest> $request) async {
    return requestJWTAuth($call, await $request);
  }

  $async.Future<$0.RequestJWTAuthResponse> requestJWTAuth(
      $grpc.ServiceCall call, $0.RequestJWTAuthRequest request);

  $async.Future<$0.WaitJWTTokenResponse> waitJWTToken_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.WaitJWTTokenRequest> $request) async {
    return waitJWTToken($call, await $request);
  }

  $async.Future<$0.WaitJWTTokenResponse> waitJWTToken(
      $grpc.ServiceCall call, $0.WaitJWTTokenRequest request);

  $async.Future<$0.StartCPUProfileResponse> startCPUProfile_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.StartCPUProfileRequest> $request) async {
    return startCPUProfile($call, await $request);
  }

  $async.Future<$0.StartCPUProfileResponse> startCPUProfile(
      $grpc.ServiceCall call, $0.StartCPUProfileRequest request);

  $async.Future<$0.StopCPUProfileResponse> stopCPUProfile_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.StopCPUProfileRequest> $request) async {
    return stopCPUProfile($call, await $request);
  }

  $async.Future<$0.StopCPUProfileResponse> stopCPUProfile(
      $grpc.ServiceCall call, $0.StopCPUProfileRequest request);

  $async.Future<$0.OSLifecycleResponse> notifyOSLifecycle_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.OSLifecycleRequest> $request) async {
    return notifyOSLifecycle($call, await $request);
  }

  $async.Future<$0.OSLifecycleResponse> notifyOSLifecycle(
      $grpc.ServiceCall call, $0.OSLifecycleRequest request);

  $async.Future<$0.InstallerResultResponse> getInstallerResult_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.InstallerResultRequest> $request) async {
    return getInstallerResult($call, await $request);
  }

  $async.Future<$0.InstallerResultResponse> getInstallerResult(
      $grpc.ServiceCall call, $0.InstallerResultRequest request);

  $async.Stream<$0.ExposeServiceEvent> exposeService_Pre(
      $grpc.ServiceCall $call,
      $async.Future<$0.ExposeServiceRequest> $request) async* {
    yield* exposeService($call, await $request);
  }

  $async.Stream<$0.ExposeServiceEvent> exposeService(
      $grpc.ServiceCall call, $0.ExposeServiceRequest request);
}
