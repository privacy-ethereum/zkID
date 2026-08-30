import 'dart:io';

import 'package:crypto/crypto.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/services.dart' show rootBundle;

import 'mdoc_ffi.dart'
    show generateSharedBlinds, proveMdoc, setupMdocKeys, setupShowKeys;

/// One step of first-run provisioning, in the order they run.
enum ProvisioningStage {
  settingUpCredentialKeys,
  settingUpPresentationKeys,
  generatingBlinds,
  attestingCredential,
}

extension ProvisioningStageLabel on ProvisioningStage {
  String get label => switch (this) {
        ProvisioningStage.settingUpCredentialKeys =>
          'Setting up credential keys',
        ProvisioningStage.settingUpPresentationKeys =>
          'Setting up presentation keys',
        ProvisioningStage.generatingBlinds => 'Generating blinds',
        ProvisioningStage.attestingCredential => 'Attesting credential',
      };
}

/// Drives the wallet's first-run provisioning pipeline: circuit key setup,
/// shared blinds, and the initial credential (MDOC) proof. A marker file
/// hashing the bundled circuit inputs lets a later run with unchanged inputs
/// skip straight to [isReady]; a changed hash re-runs the blind/proof stages,
/// since a stale proof over new inputs is exactly what the marker guards
/// against. Progress and errors are exposed to the UI via [ChangeNotifier].
class ProvisioningController extends ChangeNotifier {
  ProvisioningStage? _currentStage;
  final Set<ProvisioningStage> _completed = {};
  bool _ready = false;
  bool _running = false;
  String? _error;

  ProvisioningStage? get currentStage => _currentStage;
  bool get isReady => _ready;
  bool get isRunning => _running;
  String? get error => _error;
  bool isCompleted(ProvisioningStage stage) => _completed.contains(stage);

  /// Runs provisioning against `documentsPath` (`{ApplicationDocuments}/circom`).
  /// No-ops while already running or once ready; call again after an error
  /// to retry.
  Future<void> start(String documentsPath) async {
    if (_running || _ready) return;
    _running = true;
    _error = null;
    _completed.clear();
    notifyListeners();

    try {
      final keysDir = '$documentsPath/keys';
      final markerFile = File('$keysDir/.provisioned');
      final expectedHash = await _bundledInputHash();

      final markerMatches = await markerFile.exists() &&
          (await markerFile.readAsString()).trim() == expectedHash;
      if (markerMatches) {
        _ready = true;
        return;
      }

      final mdocKeysExist = await File('$keysDir/mdoc_proving.key').exists() &&
          await File('$keysDir/mdoc_verifying.key').exists();
      if (!mdocKeysExist) {
        await _runStage(ProvisioningStage.settingUpCredentialKeys,
            () => setupMdocKeys(documentsPath: documentsPath));
      } else {
        _completed.add(ProvisioningStage.settingUpCredentialKeys);
      }

      final showKeysExist = await File('$keysDir/show_proving.key').exists() &&
          await File('$keysDir/show_verifying.key').exists();
      if (!showKeysExist) {
        await _runStage(ProvisioningStage.settingUpPresentationKeys,
            () => setupShowKeys(documentsPath: documentsPath));
      } else {
        _completed.add(ProvisioningStage.settingUpPresentationKeys);
      }

      // Marker mismatched, so blinds and the credential proof are always
      // regenerated even when the keys above were reusable.
      await _runStage(ProvisioningStage.generatingBlinds,
          () => generateSharedBlinds(documentsPath: documentsPath));
      await _runStage(ProvisioningStage.attestingCredential,
          () => proveMdoc(documentsPath: documentsPath));

      await Directory(keysDir).create(recursive: true);
      await markerFile.writeAsString(expectedHash);
      _ready = true;
    } catch (e) {
      _error = '$e';
    } finally {
      _running = false;
      _currentStage = null;
      notifyListeners();
    }
  }

  Future<T> _runStage<T>(
      ProvisioningStage stage, Future<T> Function() run) async {
    _currentStage = stage;
    notifyListeners();
    final result = await run();
    _completed.add(stage);
    return result;
  }

  Future<String> _bundledInputHash() async {
    final mdoc = await rootBundle.load('assets/circom/mdoc_input.json');
    final show = await rootBundle.load('assets/circom/show_input.json');
    final bytes = [
      ...mdoc.buffer.asUint8List(),
      ...show.buffer.asUint8List(),
    ];
    return sha256.convert(bytes).toString();
  }
}
