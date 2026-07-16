import 'dart:ffi';
import 'dart:io';
import 'package:ffi/ffi.dart';

import 'vcknots_wallet_dart_wrapper_bindings_generated.dart';

/// The dynamic library in which the symbols for [VcknotsWalletBindings] can be found.
final DynamicLibrary _dylib = () {
  if (Platform.isMacOS || Platform.isIOS) {
    return DynamicLibrary.process();
  }
  if (Platform.isAndroid) {
    return DynamicLibrary.open('libvcknots_wallet.so');
  }
  throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
}();

/// The bindings to the native functions in [_dylib].
final VcknotsWalletDartWrapperBindings bindings = VcknotsWalletDartWrapperBindings(_dylib);

// TODO: Controller logic to be implemented
