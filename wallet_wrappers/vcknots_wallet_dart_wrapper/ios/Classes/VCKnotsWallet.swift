import Flutter
import UIKit

// This is a dummy method to ensure that the plugin is bundled correctly
// Without this, the lib-archive file may not include the plugin
public class VCKnotsWalletCorePlugin: NSObject, FlutterPlugin {
  public static func register(with registrar: FlutterPluginRegistrar) {
  }

  public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
    result(nil)
  }

  public func dummyMethodToEnforceBundling() {
    enforceBundling()
  }
}
