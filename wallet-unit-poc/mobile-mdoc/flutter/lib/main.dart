import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:path_provider/path_provider.dart';

import 'package:mopro_flutter_bindings/src/rust/frb_generated.dart';

import 'demo/theme.dart';
import 'demo/wallet_home.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await _copyAssetsToDocuments();
  runApp(const MyApp());
}

/// Copy circuit files from Flutter assets into the app's documents directory,
/// mirroring the layout used by Rust's PathConfig::mobile:
///
///   {docs}/circom/build/mdoc/mdoc_js/mdoc.r1cs  ← decompressed from mdoc.r1cs.gz
///   {docs}/circom/build/show/show_js/show.r1cs  ← decompressed from show.r1cs.gz
///   {docs}/circom/mdoc_input.json               ← prove_mdoc
///   {docs}/circom/show_input.json               ← prove_show
Future<void> _copyAssetsToDocuments() async {
  try {
    final documentsDir = await getApplicationDocumentsDirectory();
    final circomDir = Directory('${documentsDir.path}/circom');

    final mdocBuildDir = Directory('${circomDir.path}/build/mdoc/mdoc_js');
    final showBuildDir = Directory('${circomDir.path}/build/show/show_js');
    await mdocBuildDir.create(recursive: true);
    await showBuildDir.create(recursive: true);

    // Decompress r1cs files — skip if already extracted (mdoc's is ~414 MiB).
    final compressedAssets = {
      'assets/circom/mdoc.r1cs.gz': '${mdocBuildDir.path}/mdoc.r1cs',
      'assets/circom/show.r1cs.gz': '${showBuildDir.path}/show.r1cs',
    };
    for (final entry in compressedAssets.entries) {
      final target = File(entry.value);
      if (!await target.exists()) {
        debugPrint('Decompressing ${entry.key}');
        final data = await rootBundle.load(entry.key);
        // Streamed rather than gzip.decode(): decoding in one shot holds the
        // compressed buffer and the ~414 MiB result in the Dart heap at once,
        // before first frame.
        final sink = target.openWrite();
        final Stream<List<int>> compressed =
            Stream.value(data.buffer.asUint8List());
        await sink.addStream(compressed.transform(gzip.decoder));
        await sink.close();
        debugPrint(
            '  → ${(await target.length() / 1024 / 1024).toStringAsFixed(2)} MB');
      }
    }

    // Always overwrite input JSON so a stale cached copy from a previous
    // install never causes a witness synthesis mismatch.
    final inputAssets = {
      'assets/circom/mdoc_input.json': '${circomDir.path}/mdoc_input.json',
      'assets/circom/show_input.json': '${circomDir.path}/show_input.json',
    };
    for (final entry in inputAssets.entries) {
      final data = await rootBundle.load(entry.key);
      await File(entry.value).writeAsBytes(data.buffer.asUint8List());
      debugPrint('Wrote ${entry.key} → ${entry.value}');
    }
  } catch (e) {
    debugPrint('Error copying assets: $e');
  }
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      debugShowCheckedModeBanner: false,
      theme: buildWalletTheme(),
      home: const WalletHome(),
    );
  }
}
