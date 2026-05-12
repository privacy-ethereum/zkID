import 'dart:io';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart' show rootBundle;
import 'package:path_provider/path_provider.dart';

import 'package:mopro_flutter_bindings/src/rust/frb_generated.dart';
import 'package:flutter_rust_bridge/flutter_rust_bridge.dart' show AnyhowException;
import 'package:mopro_flutter_bindings/src/rust/third_party/openac_mobile_app.dart'
    show
        BenchmarkResults,
        ProofResult,
        setupKeys,
        proveCertChainRs4096,
        proveUserSigRs2048,
        verifyCertChainRs4096,
        verifyUserSigRs2048,
        runCompleteBenchmark,
        linkVerify;

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await RustLib.init();
  await _copyAssetsToDocuments();
  runApp(const MyApp());
}

/// Copy circuit R1CS files and input data from Flutter assets to documents directory.
///
/// Assets are stored flat in the documents directory:
///   Documents/certChainRS4096.r1cs        (decompressed from .gz)
///   Documents/cert_chain_rs4096_input.json
///   Documents/userSigRS2048.r1cs          (decompressed from .gz)
///   Documents/user_sig_rs2048_input.json
Future<void> _copyAssetsToDocuments() async {
  try {
    final documentsDir = await getApplicationDocumentsDirectory();
    final basePath = documentsDir.path;

    final assets = {
      'assets/circom/certChainRS4096.r1cs.gz': 'certChainRS4096.r1cs',
      'assets/circom/userSigRS2048.r1cs.gz': 'userSigRS2048.r1cs',
      'assets/circom/cert_chain_rs4096_input.json': 'cert_chain_rs4096_input.json',
      'assets/circom/user_sig_rs2048_input.json': 'user_sig_rs2048_input.json',
    };

    for (final entry in assets.entries) {
      final targetFile = File('$basePath/${entry.value}');
      if (!await targetFile.exists()) {
        final data = await rootBundle.load(entry.key);
        final bytes = data.buffer.asUint8List();

        if (entry.key.endsWith('.gz')) {
          debugPrint('Decompressing: ${entry.key}');
          final decompressed = gzip.decode(bytes);
          await targetFile.writeAsBytes(decompressed);
          debugPrint(
              'Decompressed ${entry.value}: ${(bytes.length / 1024 / 1024).toStringAsFixed(2)}MB -> ${(decompressed.length / 1024 / 1024).toStringAsFixed(2)}MB');
        } else {
          debugPrint('Copying: ${entry.key}');
          await targetFile.writeAsBytes(bytes);
        }
      }
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
      theme: ThemeData(
        primarySwatch: Colors.blue,
        useMaterial3: true,
      ),
      home: const E2EProofWorkflowScreen(),
    );
  }
}

class E2EProofWorkflowScreen extends StatefulWidget {
  const E2EProofWorkflowScreen({super.key});

  @override
  State<E2EProofWorkflowScreen> createState() =>
      _E2EProofWorkflowScreenState();
}

enum ProofTaskType {
  setup,
  prove,
  verify,
}

class TaskResult {
  final ProofTaskType taskType;
  final bool success;
  final String? error;
  final ProofResult? proofResult;
  final ProofResult? deviceSigProofResult;
  final String? message;
  final bool? verifyResult;
  final bool? deviceSigVerifyResult;
  final bool? linkVerifyResult;
  final int? clientTimingMs;

  TaskResult({
    required this.taskType,
    required this.success,
    this.error,
    this.proofResult,
    this.deviceSigProofResult,
    this.message,
    this.verifyResult,
    this.deviceSigVerifyResult,
    this.linkVerifyResult,
    this.clientTimingMs,
  });

  BigInt? get totalMs =>
      proofResult?.proveMs ??
      (clientTimingMs != null ? BigInt.from(clientTimingMs!) : null);
  BigInt? get proofSizeBytes => proofResult?.proofSizeBytes;
}

class _E2EProofWorkflowScreenState extends State<E2EProofWorkflowScreen> {
  // Operation state
  bool _isOperating = false;
  Exception? _error;

  // Step results
  Map<String, TaskResult> _results = {};
  Map<String, bool> _completedSteps = {};

  BenchmarkResults? _benchmarkResults;

  Future<String> _getDocumentsPath() async {
    final directory = await getApplicationDocumentsDirectory();
    return directory.path;
  }

  Future<void> _runOperation(ProofTaskType taskType) async {
    setState(() {
      _isOperating = true;
      _error = null;
    });

    try {
      final documentsPath = await _getDocumentsPath();
      TaskResult result;

      switch (taskType) {
        case ProofTaskType.setup:
          final startTime = DateTime.now();
          final message = await setupKeys(
            documentsPath: documentsPath,
          );
          final elapsed = DateTime.now().difference(startTime).inMilliseconds;
          result = TaskResult(
            taskType: taskType,
            success: true,
            message: message,
            clientTimingMs: elapsed,
          );
          break;

        case ProofTaskType.prove:
          final proofResult = await proveCertChainRs4096(
            documentsPath: documentsPath,
          );
          final deviceSigProofResult = await proveUserSigRs2048(
            documentsPath: documentsPath,
          );
          result = TaskResult(
            taskType: taskType,
            success: true,
            proofResult: proofResult,
            deviceSigProofResult: deviceSigProofResult,
          );
          break;

        case ProofTaskType.verify:
          final startTime = DateTime.now();
          final verifyResult = await verifyCertChainRs4096(
            documentsPath: documentsPath,
          );
          final deviceSigVerifyResult = await verifyUserSigRs2048(
            documentsPath: documentsPath,
          );
          final linkVerifyResult = await linkVerify(
            documentsPath: documentsPath,
          );
          final elapsed = DateTime.now().difference(startTime).inMilliseconds;
          result = TaskResult(
            taskType: taskType,
            success: verifyResult,
            verifyResult: verifyResult,
            deviceSigVerifyResult: deviceSigVerifyResult,
            linkVerifyResult: linkVerifyResult,
            clientTimingMs: elapsed,
          );
          break;
      }

      setState(() {
        _results[taskType.name] = result;
        _completedSteps[taskType.name] = result.success;
        _isOperating = false;
      });
    } catch (e) {
      final errorMsg = e is AnyhowException ? e.message : e.toString();
      setState(() {
        final result = TaskResult(
          taskType: taskType,
          success: false,
          error: errorMsg,
        );
        _results[taskType.name] = result;
        _completedSteps[taskType.name] = false;
        _error = Exception('${_taskTypeToDisplayName(taskType)} failed: $errorMsg');
        _isOperating = false;
      });
    }
  }

  Future<void> _runBenchmark() async {
    setState(() {
      _isOperating = true;
      _error = null;
      _benchmarkResults = null;
    });

    try {
      final documentsPath = await _getDocumentsPath();
      final startTime = DateTime.now();

      final results = await runCompleteBenchmark(
        documentsPath: documentsPath,
      );

      final clientTimingMs =
          DateTime.now().difference(startTime).inMilliseconds;

      setState(() {
        _benchmarkResults = results;
        _isOperating = false;
      });

      print('Benchmark completed in ${clientTimingMs}ms');
    } catch (e) {
      final errorMsg = e is AnyhowException ? e.message : e.toString();
      setState(() {
        _error = Exception('Benchmark failed: $errorMsg');
        _isOperating = false;
      });
    }
  }

  void _reset() {
    setState(() {
      _results = {};
      _completedSteps = {};
      _error = null;
      _isOperating = false;
      _benchmarkResults = null;
    });
  }

  String _taskTypeToDisplayName(ProofTaskType type) {
    return switch (type) {
      ProofTaskType.setup => 'Setup Keys',
      ProofTaskType.prove => 'Prove',
      ProofTaskType.verify => 'Verify',
    };
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('zkID - Cert Chain & Device Sig Proof'),
        actions: [
          if (_results.isNotEmpty && !_isOperating)
            IconButton(
              icon: const Icon(Icons.refresh),
              onPressed: _reset,
              tooltip: 'Reset',
            ),
        ],
      ),
      body: SingleChildScrollView(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            if (_error != null)
              Card(
                color: Colors.red.shade50,
                child: Padding(
                  padding: const EdgeInsets.all(16),
                  child: Row(
                    children: [
                      Icon(Icons.error, color: Colors.red.shade700),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _error.toString(),
                          style: TextStyle(color: Colors.red.shade900),
                        ),
                      ),
                      IconButton(
                        icon: const Icon(Icons.close),
                        onPressed: () => setState(() => _error = null),
                      ),
                    ],
                  ),
                ),
              ),

            const SizedBox(height: 16),

            // Benchmark Section
            Card(
              elevation: 4,
              child: Padding(
                padding: const EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.speed, color: Colors.deepPurple),
                        const SizedBox(width: 8),
                        const Text(
                          'Complete Benchmark',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 8),
                    const Text(
                      'Run complete Cert Chain & Device Sig benchmark: setup, prove, and verify. Results include timing and artifact sizes.',
                      style: TextStyle(fontSize: 12, color: Colors.grey),
                    ),
                    const SizedBox(height: 12),
                    SizedBox(
                      width: double.infinity,
                      child: ElevatedButton.icon(
                        onPressed: _isOperating ? null : _runBenchmark,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: Colors.deepPurple,
                          foregroundColor: Colors.white,
                          padding: const EdgeInsets.all(16),
                        ),
                        icon: _isOperating
                            ? const SizedBox(
                                width: 20,
                                height: 20,
                                child: CircularProgressIndicator(
                                  strokeWidth: 2,
                                  valueColor: AlwaysStoppedAnimation<Color>(
                                      Colors.white),
                                ),
                              )
                            : const Icon(Icons.speed),
                        label: Text(_isOperating
                            ? 'Running Benchmark...'
                            : 'Run Complete Benchmark'),
                      ),
                    ),
                  ],
                ),
              ),
            ),

            if (_benchmarkResults != null) ...[
              const SizedBox(height: 16),
              _buildBenchmarkResults(),
            ],

            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 16),

            // Step 1: Setup Keys
            _buildSectionHeader('Step 1: Setup Keys', Icons.key),
            const SizedBox(height: 12),
            _buildOperationButton(
              taskType: ProofTaskType.setup,
              label: 'Setup Cert Chain & Device Sig Keys',
              icon: Icons.key,
              color: Colors.blue,
            ),

            const SizedBox(height: 24),

            // Step 2: Prove
            _buildSectionHeader('Step 2: Prove', Icons.calculate),
            const SizedBox(height: 12),
            _buildOperationButton(
              taskType: ProofTaskType.prove,
              label: 'Prove Cert Chain & Device Sig',
              icon: Icons.calculate,
              color: Colors.green,
            ),

            const SizedBox(height: 24),

            // Step 3: Verify
            _buildSectionHeader('Step 3: Verify', Icons.check_circle),
            const SizedBox(height: 12),
            _buildOperationButton(
              taskType: ProofTaskType.verify,
              label: 'Verify Cert Chain & Device Sig',
              icon: Icons.check_circle,
              color: Colors.teal,
            ),

            const SizedBox(height: 24),
            const Divider(),
            const SizedBox(height: 16),

            // Results Display
            if (_results.isNotEmpty) ...[
              _buildSectionHeader('Results', Icons.assessment),
              const SizedBox(height: 12),
              ..._results.entries
                  .map((entry) => _buildResultCard(entry.key, entry.value)),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildSectionHeader(String title, IconData icon) {
    return Row(
      children: [
        Icon(icon, color: Colors.grey.shade700),
        const SizedBox(width: 8),
        Text(
          title,
          style: TextStyle(
            fontSize: 18,
            fontWeight: FontWeight.bold,
            color: Colors.grey.shade800,
          ),
        ),
      ],
    );
  }

  Widget _buildOperationButton({
    required ProofTaskType taskType,
    required String label,
    required IconData icon,
    required MaterialColor color,
  }) {
    final isCompleted = _completedSteps[taskType.name] == true;
    final result = _results[taskType.name];

    return SizedBox(
      width: double.infinity,
      child: ElevatedButton.icon(
        onPressed: _isOperating ? null : () => _runOperation(taskType),
        style: ElevatedButton.styleFrom(
          backgroundColor: isCompleted ? color.shade100 : color,
          foregroundColor: isCompleted ? color.shade900 : Colors.white,
          padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 16),
        ),
        icon: isCompleted
            ? Icon(Icons.check_circle, color: color.shade700)
            : Icon(icon),
        label: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(label),
            if (result?.totalMs != null)
              Text(
                '${result!.totalMs}ms',
                style: TextStyle(
                  fontSize: 11,
                  color: isCompleted ? color.shade700 : Colors.white70,
                ),
              ),
          ],
        ),
      ),
    );
  }

  Widget _buildResultCard(String taskName, TaskResult result) {
    final taskType =
        ProofTaskType.values.firstWhere((e) => e.name == taskName);
    final displayName = _taskTypeToDisplayName(taskType);

    return Card(
      margin: const EdgeInsets.only(bottom: 12),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Icon(
                  result.success ? Icons.check_circle : Icons.error,
                  color: result.success ? Colors.green : Colors.red,
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Text(
                    displayName,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 12),

            // Error message
            if (result.error != null) ...[
              Text(
                'Error: ${result.error}',
                style: TextStyle(color: Colors.red.shade700),
              ),
              const SizedBox(height: 8),
            ],

            // Success message
            if (result.message != null) ...[
              Text(result.message!),
              const SizedBox(height: 8),
            ],

            // Timings
            if (result.totalMs != null) ...[
              const Text(
                'Timing:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              const SizedBox(height: 4),
              Text('Total: ${result.totalMs}ms'),
              const SizedBox(height: 8),
            ],

            // Proof size
            if (result.proofSizeBytes != null) ...[
              Text(
                'Proof Size: ${(result.proofSizeBytes!.toInt() / 1024).toStringAsFixed(2)} KB',
                style: TextStyle(color: Colors.grey.shade700),
              ),
              const SizedBox(height: 8),
            ],

            // Verification result
            if (result.verifyResult != null) ...[
              const SizedBox(height: 8),
              Text(
                result.verifyResult! ? 'Verification passed' : 'Verification failed',
                style: TextStyle(
                  color: result.verifyResult!
                      ? Colors.green.shade700
                      : Colors.red.shade700,
                  fontWeight: FontWeight.bold,
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  Widget _buildBenchmarkResults() {
    if (_benchmarkResults == null) return const SizedBox.shrink();

    final results = _benchmarkResults!;

    return Card(
      elevation: 4,
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceBetween,
              children: [
                const Row(
                  children: [
                    Icon(Icons.assessment, color: Colors.deepPurple),
                    SizedBox(width: 8),
                    Text(
                      'Benchmark Results',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                  ],
                ),
                IconButton(
                  icon: const Icon(Icons.close, size: 20),
                  onPressed: () {
                    setState(() {
                      _benchmarkResults = null;
                    });
                  },
                  tooltip: 'Clear results',
                ),
              ],
            ),
            const SizedBox(height: 16),

            // Timing Metrics Section
            const Text(
              'Timing Metrics',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: Colors.deepPurple,
              ),
            ),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: Colors.grey.shade300),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _buildTableHeader(['Operation', 'Time (ms)']),
                _buildTimingRow('Setup', results.setupMs),
                _buildTimingRow('Prove', results.proveMs),
                _buildTimingRow('Verify', results.verifyMs),
              ],
            ),

            const SizedBox(height: 24),

            // Size Metrics Section
            const Text(
              'Artifact Sizes',
              style: TextStyle(
                fontSize: 16,
                fontWeight: FontWeight.bold,
                color: Colors.deepPurple,
              ),
            ),
            const SizedBox(height: 8),
            Table(
              border: TableBorder.all(color: Colors.grey.shade300),
              columnWidths: const {
                0: FlexColumnWidth(2),
                1: FlexColumnWidth(1),
              },
              children: [
                _buildTableHeader(['Artifact', 'Size']),
                _buildSizeRow('Proving Key', results.provingKeyBytes),
                _buildSizeRow('Verifying Key', results.verifyingKeyBytes),
                _buildSizeRow('Proof', results.proofBytes),
                _buildSizeRow('Witness', results.witnessBytes),
              ],
            ),
          ],
        ),
      ),
    );
  }

  TableRow _buildTableHeader(List<String> headers) {
    return TableRow(
      decoration: BoxDecoration(color: Colors.grey.shade200),
      children: headers
          .map((header) => Padding(
                padding: const EdgeInsets.all(8.0),
                child: Text(
                  header,
                  style: const TextStyle(
                    fontWeight: FontWeight.bold,
                    fontSize: 14,
                  ),
                ),
              ))
          .toList(),
    );
  }

  TableRow _buildTimingRow(String operation, BigInt milliseconds) {
    return TableRow(
      children: [
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Text(operation),
        ),
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Text(
            milliseconds.toString(),
            style: const TextStyle(fontFamily: 'monospace'),
            textAlign: TextAlign.right,
          ),
        ),
      ],
    );
  }

  TableRow _buildSizeRow(String artifact, BigInt bytes) {
    String formattedSize;
    final bytesInt = bytes.toInt();
    if (bytesInt < 1024) {
      formattedSize = '$bytesInt B';
    } else if (bytesInt < 1024 * 1024) {
      formattedSize = '${(bytesInt / 1024).toStringAsFixed(2)} KB';
    } else {
      formattedSize = '${(bytesInt / (1024 * 1024)).toStringAsFixed(2)} MB';
    }

    return TableRow(
      children: [
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Text(artifact),
        ),
        Padding(
          padding: const EdgeInsets.all(8.0),
          child: Text(
            formattedSize,
            style: const TextStyle(fontFamily: 'monospace'),
            textAlign: TextAlign.right,
          ),
        ),
      ],
    );
  }
}
