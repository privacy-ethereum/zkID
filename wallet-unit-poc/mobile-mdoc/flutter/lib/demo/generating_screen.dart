import 'package:flutter/material.dart';

import 'mdoc_ffi.dart' show proveShow, reblindMdoc, reblindShow;

import 'paths.dart';
import 'proof_uploader.dart';
import 'receipt_screen.dart';
import 'theme.dart';
import 'wallet_link.dart';

/// Wall-clock time of one pipeline step, shown in the receipt's stats strip.
class StepTiming {
  final String label;
  final int ms;

  const StepTiming(this.label, this.ms);
}

/// Trail row copy, in pipeline order. Distinct from [StepTiming.label] above,
/// which feeds the receipt's compact stat tiles and keeps its own shorter
/// strings.
const _trailLabels = [
  'Rerandomizing credential proof',
  'Proving age predicate',
  'Rerandomizing presentation',
  'Sending to social.example.com',
];

/// Runs the presentation pipeline after Accept: rerandomize the credential
/// proof, prove the age predicate, rerandomize that proof, then upload both.
/// Crypto-step failures are shown here with a retry. An upload failure hands
/// off to [ReceiptScreen]'s failed variant, since the proofs themselves are
/// already valid and sitting on disk.
class GeneratingScreen extends StatefulWidget {
  final VerificationRequest request;

  const GeneratingScreen({super.key, required this.request});

  @override
  State<GeneratingScreen> createState() => _GeneratingScreenState();
}

class _GeneratingScreenState extends State<GeneratingScreen> {
  bool _running = true;
  final List<StepTiming> _timings = [];
  String? _error;

  @override
  void initState() {
    super.initState();
    _run();
  }

  Future<void> _run() async {
    setState(() {
      _running = true;
      _error = null;
      _timings.clear();
    });

    try {
      final documentsPath = await resolveDocumentsPath();

      await _step('Rerandomizing credential proof…',
          () => reblindMdoc(documentsPath: documentsPath));
      final showResult = await _step('Proving age predicate…',
          () => proveShow(documentsPath: documentsPath));
      await _step(
          'Rerandomizing…', () => reblindShow(documentsPath: documentsPath));

      final upload = await _step(
        'Sending…',
        () => uploadProofs(
          server: widget.request.server,
          sessionId: widget.request.sessionId,
          documentsPath: documentsPath,
        ),
      );

      if (!mounted) return;
      Navigator.of(context).pushReplacement(MaterialPageRoute(
        builder: (_) => ReceiptScreen(
          request: widget.request,
          documentsPath: documentsPath,
          timings: List.of(_timings),
          showProofSizeBytes: showResult.proofSizeBytes.toInt(),
          mdocProofSizeBytes: upload.mdocProofBytes,
          uploadOk: upload.ok,
          uploadError: upload.ok
              ? null
              : (upload.error ?? 'Upload failed (${upload.status})'),
        ),
      ));
    } catch (e) {
      setState(() {
        _error = '$e';
        _running = false;
      });
    }
  }

  Future<T> _step<T>(
    String caption,
    Future<T> Function() run, {
    String? statLabel,
  }) async {
    final stopwatch = Stopwatch()..start();
    final result = await run();
    stopwatch.stop();
    setState(() => _timings
        .add(StepTiming(statLabel ?? caption, stopwatch.elapsedMilliseconds)));
    return result;
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: !_running,
      child: Scaffold(
        body: SafeArea(
          child: Center(
            child: Padding(
              padding: const EdgeInsets.all(space5),
              child: _error != null ? _buildError(context) : _buildTrail(),
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildTrail() {
    return Column(
      mainAxisSize: MainAxisSize.min,
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        for (var i = 0; i < _trailLabels.length; i++)
          _TrailRow(
            label: _trailLabels[i],
            done: i < _timings.length,
            active: i == _timings.length,
            ms: i < _timings.length ? _timings[i].ms : null,
          ),
      ],
    );
  }

  Widget _buildError(BuildContext context) {
    return Column(
      mainAxisSize: MainAxisSize.min,
      children: [
        const Icon(Icons.error_outline, color: walletError, size: 48),
        const SizedBox(height: space4),
        Text('Something went wrong',
            style: Theme.of(context).textTheme.titleMedium),
        const SizedBox(height: space2),
        Text(
          _error!,
          textAlign: TextAlign.center,
          style: const TextStyle(color: walletMuted),
        ),
        const SizedBox(height: space5),
        ElevatedButton(onPressed: _run, child: const Text('Retry')),
      ],
    );
  }
}

/// One row of the step trail: done rows show a check and their measured
/// time; the active row spins; pending rows are outlined and muted. Never
/// shows a number for a step that hasn't completed, since an estimate would
/// be a lie on a screen whose whole point is proving real work happened.
class _TrailRow extends StatelessWidget {
  final String label;
  final bool done;
  final bool active;
  final int? ms;

  const _TrailRow({
    required this.label,
    required this.done,
    required this.active,
    required this.ms,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: space2),
      child: Row(
        children: [
          SizedBox(
            width: 20,
            height: 20,
            child: done
                ? const Icon(Icons.check_circle, color: walletSuccess, size: 18)
                : active
                    ? const CircularProgressIndicator(strokeWidth: 2)
                    : const Icon(Icons.circle_outlined,
                        color: walletMuted, size: 18),
          ),
          const SizedBox(width: space3),
          Expanded(
            child: Text(
              label,
              style: TextStyle(
                fontSize: 17,
                color: done || active ? walletTextPrimary : walletMuted,
              ),
            ),
          ),
          if (ms != null)
            Text(
              '$ms ms',
              style: const TextStyle(
                fontFamily: 'monospace',
                color: walletMuted,
                fontSize: 12,
              ),
            ),
        ],
      ),
    );
  }
}
