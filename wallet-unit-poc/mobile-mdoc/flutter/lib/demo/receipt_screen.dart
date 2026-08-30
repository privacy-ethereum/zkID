import 'package:flutter/material.dart';

import 'credential_data.dart';
import 'generating_screen.dart';
import 'privacy_callout.dart';
import 'proof_uploader.dart';
import 'theme.dart';
import 'wallet_link.dart';

/// Confirms what was shared. In the failed-upload variant the primary action
/// retries the upload rather than returning to the browser, since the proofs
/// are already generated and sitting on disk, so only the network step
/// repeats.
class ReceiptScreen extends StatefulWidget {
  final VerificationRequest request;
  final String documentsPath;
  final List<StepTiming> timings;
  final int showProofSizeBytes;
  final int mdocProofSizeBytes;
  final bool uploadOk;
  final String? uploadError;

  const ReceiptScreen({
    super.key,
    required this.request,
    required this.documentsPath,
    required this.timings,
    required this.showProofSizeBytes,
    required this.mdocProofSizeBytes,
    required this.uploadOk,
    this.uploadError,
  });

  @override
  State<ReceiptScreen> createState() => _ReceiptScreenState();
}

class _ReceiptScreenState extends State<ReceiptScreen> {
  late bool _ok;
  late List<StepTiming> _timings;
  late int _showProofSizeBytes;
  late int _mdocProofSizeBytes;
  String? _error;
  bool _retrying = false;
  String? _birthDate;

  @override
  void initState() {
    super.initState();
    _ok = widget.uploadOk;
    _timings = widget.timings;
    _showProofSizeBytes = widget.showProofSizeBytes;
    _mdocProofSizeBytes = widget.mdocProofSizeBytes;
    _error = widget.uploadError;
    loadCredentialBirthDate().then((date) {
      if (mounted) setState(() => _birthDate = date);
    });
  }

  Future<void> _retryUpload() async {
    setState(() => _retrying = true);
    final stopwatch = Stopwatch()..start();
    final upload = await uploadProofs(
      server: widget.request.server,
      sessionId: widget.request.sessionId,
      documentsPath: widget.documentsPath,
    );
    stopwatch.stop();
    setState(() {
      _retrying = false;
      _ok = upload.ok;
      _error = upload.ok
          ? null
          : (upload.error ?? 'Upload failed (${upload.status})');
      _mdocProofSizeBytes = upload.mdocProofBytes;
      _timings = [
        ..._timings,
        StepTiming('Sending…', stopwatch.elapsedMilliseconds)
      ];
    });
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('Receipt'),
        automaticallyImplyLeading: false,
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              const SizedBox(height: space3),
              Icon(
                _ok ? Icons.check_circle : Icons.error,
                color: _ok ? walletSuccess : walletError,
                size: 64,
              ),
              const SizedBox(height: space4),
              Text(
                _ok
                    ? 'Proof sent to social.example.com'
                    : 'Failed to send proof',
                style: Theme.of(context)
                    .textTheme
                    .titleMedium
                    ?.copyWith(fontSize: 18),
                textAlign: TextAlign.center,
              ),
              if (!_ok && _error != null) ...[
                const SizedBox(height: space2),
                Container(
                  padding: const EdgeInsets.symmetric(
                      horizontal: space3, vertical: space2),
                  decoration: BoxDecoration(
                    color: walletErrorBg,
                    borderRadius: BorderRadius.circular(radiusSm),
                  ),
                  child: Text(
                    _error!,
                    style: const TextStyle(color: walletError, fontSize: 12),
                    textAlign: TextAlign.center,
                  ),
                ),
              ],
              const SizedBox(height: space5),
              _receiptCard(context),
              const SizedBox(height: space4),
              _statsStrip(),
              const Spacer(),
              SizedBox(
                width: double.infinity,
                child: ElevatedButton(
                  onPressed: _retrying
                      ? null
                      : (_ok
                          ? () => returnToBrowser(widget.request)
                          : _retryUpload),
                  child: _retrying
                      ? const SizedBox(
                          width: 20,
                          height: 20,
                          child: CircularProgressIndicator(
                            strokeWidth: 2,
                            valueColor:
                                AlwaysStoppedAnimation<Color>(Colors.white),
                          ),
                        )
                      : Text(_ok ? 'Return to Example Social' : 'Retry'),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _receiptCard(BuildContext context) {
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(space4),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'SHARED DATA RECEIPT',
              style: sectionLabelStyle.copyWith(
                color: walletSecondary,
                fontSize: 11,
              ),
            ),
            const Divider(height: 20),
            Container(
              padding: const EdgeInsets.symmetric(
                  horizontal: space3, vertical: space2),
              decoration: BoxDecoration(
                color: walletSuccessBg,
                borderRadius: BorderRadius.circular(radiusSm),
              ),
              child: const ListTile(
                contentPadding: EdgeInsets.zero,
                leading: Icon(Icons.check_circle, color: walletSuccess),
                title: Text('Age 18 or older'),
                subtitle: Text('Proven in zero knowledge'),
              ),
            ),
            if (_birthDate != null) ...[
              const SizedBox(height: space2),
              PrivacyCallout(
                child: ListTile(
                  contentPadding: EdgeInsets.zero,
                  leading: const Icon(Icons.lock_outline, color: walletPrimary),
                  title: Text(
                    'birth_date · $_birthDate',
                    style: const TextStyle(
                      fontWeight: FontWeight.w600,
                      color: walletPrimary,
                    ),
                  ),
                  subtitle: const Text('Stays on your device'),
                ),
              ),
            ],
          ],
        ),
      ),
    );
  }

  /// The trail records a timing per pipeline step, plus one more per retried
  /// upload, but the receipt only spotlights the proving step alongside the
  /// two proof sizes. Matched by label rather than position so a retry's
  /// extra 'Sending…' entries don't shift anything.
  Widget _statsStrip() {
    final tiles = <Widget>[];
    for (final t in _timings) {
      final label = t.label.replaceAll('…', '');
      if (label == 'Proving age predicate') {
        tiles.add(_statTile('Proving', '${t.ms} ms'));
      }
    }
    tiles.add(_statTile('MDOC proof', '${_kb(_mdocProofSizeBytes)} KB'));
    tiles.add(_statTile('Age proof', '${_kb(_showProofSizeBytes)} KB'));
    return SingleChildScrollView(
      scrollDirection: Axis.horizontal,
      child: Row(children: tiles),
    );
  }

  String _kb(int bytes) => (bytes / 1024).toStringAsFixed(1);

  Widget _statTile(String label, String value) {
    return Container(
      margin: const EdgeInsets.only(right: space2),
      padding: const EdgeInsets.symmetric(horizontal: space3, vertical: space2),
      decoration: BoxDecoration(
        color: walletSurface,
        borderRadius: BorderRadius.circular(radiusSm),
      ),
      child: Column(
        children: [
          Text(value,
              style:
                  const TextStyle(fontWeight: FontWeight.w600, fontSize: 16)),
          Text(label,
              style: sectionLabelStyle.copyWith(
                  fontSize: 11, color: walletSecondary)),
        ],
      ),
    );
  }
}
