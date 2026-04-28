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

import 'package:protobuf/protobuf.dart' as $pb;

class LogLevel extends $pb.ProtobufEnum {
  static const LogLevel UNKNOWN =
      LogLevel._(0, _omitEnumNames ? '' : 'UNKNOWN');
  static const LogLevel PANIC = LogLevel._(1, _omitEnumNames ? '' : 'PANIC');
  static const LogLevel FATAL = LogLevel._(2, _omitEnumNames ? '' : 'FATAL');
  static const LogLevel ERROR = LogLevel._(3, _omitEnumNames ? '' : 'ERROR');
  static const LogLevel WARN = LogLevel._(4, _omitEnumNames ? '' : 'WARN');
  static const LogLevel INFO = LogLevel._(5, _omitEnumNames ? '' : 'INFO');
  static const LogLevel DEBUG = LogLevel._(6, _omitEnumNames ? '' : 'DEBUG');
  static const LogLevel TRACE = LogLevel._(7, _omitEnumNames ? '' : 'TRACE');

  static const $core.List<LogLevel> values = <LogLevel>[
    UNKNOWN,
    PANIC,
    FATAL,
    ERROR,
    WARN,
    INFO,
    DEBUG,
    TRACE,
  ];

  static final $core.List<LogLevel?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 7);
  static LogLevel? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const LogLevel._(super.value, super.name);
}

class ExposeProtocol extends $pb.ProtobufEnum {
  static const ExposeProtocol EXPOSE_HTTP =
      ExposeProtocol._(0, _omitEnumNames ? '' : 'EXPOSE_HTTP');
  static const ExposeProtocol EXPOSE_HTTPS =
      ExposeProtocol._(1, _omitEnumNames ? '' : 'EXPOSE_HTTPS');
  static const ExposeProtocol EXPOSE_TCP =
      ExposeProtocol._(2, _omitEnumNames ? '' : 'EXPOSE_TCP');
  static const ExposeProtocol EXPOSE_UDP =
      ExposeProtocol._(3, _omitEnumNames ? '' : 'EXPOSE_UDP');
  static const ExposeProtocol EXPOSE_TLS =
      ExposeProtocol._(4, _omitEnumNames ? '' : 'EXPOSE_TLS');

  static const $core.List<ExposeProtocol> values = <ExposeProtocol>[
    EXPOSE_HTTP,
    EXPOSE_HTTPS,
    EXPOSE_TCP,
    EXPOSE_UDP,
    EXPOSE_TLS,
  ];

  static final $core.List<ExposeProtocol?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 4);
  static ExposeProtocol? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const ExposeProtocol._(super.value, super.name);
}

/// avoid collision with loglevel enum
class OSLifecycleRequest_CycleType extends $pb.ProtobufEnum {
  static const OSLifecycleRequest_CycleType UNKNOWN =
      OSLifecycleRequest_CycleType._(0, _omitEnumNames ? '' : 'UNKNOWN');
  static const OSLifecycleRequest_CycleType SLEEP =
      OSLifecycleRequest_CycleType._(1, _omitEnumNames ? '' : 'SLEEP');
  static const OSLifecycleRequest_CycleType WAKEUP =
      OSLifecycleRequest_CycleType._(2, _omitEnumNames ? '' : 'WAKEUP');

  static const $core.List<OSLifecycleRequest_CycleType> values =
      <OSLifecycleRequest_CycleType>[
    UNKNOWN,
    SLEEP,
    WAKEUP,
  ];

  static final $core.List<OSLifecycleRequest_CycleType?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 2);
  static OSLifecycleRequest_CycleType? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const OSLifecycleRequest_CycleType._(super.value, super.name);
}

class SystemEvent_Severity extends $pb.ProtobufEnum {
  static const SystemEvent_Severity INFO =
      SystemEvent_Severity._(0, _omitEnumNames ? '' : 'INFO');
  static const SystemEvent_Severity WARNING =
      SystemEvent_Severity._(1, _omitEnumNames ? '' : 'WARNING');
  static const SystemEvent_Severity ERROR =
      SystemEvent_Severity._(2, _omitEnumNames ? '' : 'ERROR');
  static const SystemEvent_Severity CRITICAL =
      SystemEvent_Severity._(3, _omitEnumNames ? '' : 'CRITICAL');

  static const $core.List<SystemEvent_Severity> values = <SystemEvent_Severity>[
    INFO,
    WARNING,
    ERROR,
    CRITICAL,
  ];

  static final $core.List<SystemEvent_Severity?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 3);
  static SystemEvent_Severity? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const SystemEvent_Severity._(super.value, super.name);
}

class SystemEvent_Category extends $pb.ProtobufEnum {
  static const SystemEvent_Category NETWORK =
      SystemEvent_Category._(0, _omitEnumNames ? '' : 'NETWORK');
  static const SystemEvent_Category DNS =
      SystemEvent_Category._(1, _omitEnumNames ? '' : 'DNS');
  static const SystemEvent_Category AUTHENTICATION =
      SystemEvent_Category._(2, _omitEnumNames ? '' : 'AUTHENTICATION');
  static const SystemEvent_Category CONNECTIVITY =
      SystemEvent_Category._(3, _omitEnumNames ? '' : 'CONNECTIVITY');
  static const SystemEvent_Category SYSTEM =
      SystemEvent_Category._(4, _omitEnumNames ? '' : 'SYSTEM');

  static const $core.List<SystemEvent_Category> values = <SystemEvent_Category>[
    NETWORK,
    DNS,
    AUTHENTICATION,
    CONNECTIVITY,
    SYSTEM,
  ];

  static final $core.List<SystemEvent_Category?> _byValue =
      $pb.ProtobufEnum.$_initByValueList(values, 4);
  static SystemEvent_Category? valueOf($core.int value) =>
      value < 0 || value >= _byValue.length ? null : _byValue[value];

  const SystemEvent_Category._(super.value, super.name);
}

const $core.bool _omitEnumNames =
    $core.bool.fromEnvironment('protobuf.omit_enum_names');
