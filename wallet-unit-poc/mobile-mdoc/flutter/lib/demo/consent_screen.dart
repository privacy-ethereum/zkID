import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';

import 'credential_data.dart';
import 'generating_screen.dart';
import 'privacy_callout.dart';
import 'provisioning.dart';
import 'theme.dart';
import 'wallet_link.dart';

/// Shown when a verification request arrives (deep link or already-running
/// app). The requester is a fixed demo identity — "Example Social" — since
/// the storyboard is a scripted flow, not a real relying-party lookup.
class ConsentScreen extends StatefulWidget {
  final VerificationRequest request;
  final ProvisioningController provisioning;

  const ConsentScreen({
    super.key,
    required this.request,
    required this.provisioning,
  });

  @override
  State<ConsentScreen> createState() => _ConsentScreenState();
}

class _ConsentScreenState extends State<ConsentScreen> {
  String? _birthDate;

  @override
  void initState() {
    super.initState();
    loadCredentialBirthDate().then((date) {
      if (mounted) setState(() => _birthDate = date);
    });
    unawaited(_warmUpConnection());
  }

  /// Fires a throwaway GET at the verifier while the user is still reading
  /// the consent screen. The first socket opened on the phone's local
  /// network — after a fresh install or a USB-cable wake — is the one that
  /// races iOS's local-network permission prompt / interface wake-up;
  /// spending that race here, during consent dwell time, means the real
  /// proof upload later doesn't have to eat it. The result and any error
  /// are both irrelevant, so neither is awaited by the caller nor reported.
  Future<void> _warmUpConnection() async {
    final client = HttpClient();
    try {
      final uri = widget.request.server.replace(
        path: '/api/session/${widget.request.sessionId}',
      );
      await client
          .getUrl(uri)
          .then((req) => req.close())
          .timeout(const Duration(seconds: 5));
    } catch (_) {
      // Ignored — see the doc comment above.
    } finally {
      client.close(force: true);
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: widget.provisioning,
      builder: (context, _) {
        final ready = widget.provisioning.isReady;
        return Scaffold(
          appBar: AppBar(title: const Text('Request to share')),
          body: SafeArea(
            child: Padding(
              padding: const EdgeInsets.all(20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'social.example.com is requesting:',
                    style: Theme.of(context).textTheme.bodyLarge,
                  ),
                  const SizedBox(height: space4),
                  Card(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const ListTile(
                          leading: Icon(Icons.verified_user_outlined,
                              color: walletPrimary),
                          title: Text('18+ Age Proof'),
                          subtitle: Text('Derived from your PID'),
                        ),
                        Padding(
                          padding: const EdgeInsets.fromLTRB(
                              space4, 0, space4, space3),
                          child: Text(
                            widget.request.policyDisplay,
                            style: condensedHeading(
                                fontSize: 22, color: walletTextPrimary),
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(height: space4),
                  _CredentialDataCard(birthDate: _birthDate),
                  const Spacer(),
                  if (!ready)
                    const Padding(
                      padding: EdgeInsets.only(bottom: space3),
                      child: Text(
                        'Wallet is still provisioning…',
                        style: TextStyle(
                          color: walletMuted,
                          fontSize: 13,
                        ),
                      ),
                    ),
                  Row(
                    children: [
                      Expanded(
                        child: OutlinedButton(
                          onPressed: () => Navigator.of(context).pop(),
                          child: const Text('Decline'),
                        ),
                      ),
                      const SizedBox(width: space3),
                      Expanded(
                        child: ElevatedButton(
                          onPressed: ready
                              ? () => Navigator.of(context).pushReplacement(
                                    MaterialPageRoute(
                                      builder: (_) => GeneratingScreen(
                                          request: widget.request),
                                    ),
                                  )
                              : null,
                          child: const Text('Accept'),
                        ),
                      ),
                    ],
                  ),
                ],
              ),
            ),
          ),
        );
      },
    );
  }
}

/// What the credential actually contains, shown alongside the tile above so
/// the contrast with what gets proved (not shared) is visible before Accept.
/// Renders nothing until the bundled birth date has loaded.
class _CredentialDataCard extends StatelessWidget {
  final String? birthDate;

  const _CredentialDataCard({required this.birthDate});

  @override
  Widget build(BuildContext context) {
    final birthDate = this.birthDate;
    if (birthDate == null) return const SizedBox.shrink();

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(space4),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'YOUR CREDENTIAL DATA',
              style: sectionLabelStyle.copyWith(
                color: walletSecondary,
                fontSize: 11,
              ),
            ),
            const SizedBox(height: space3),
            Text(
              'birth_date · $birthDate',
              style: const TextStyle(fontFamily: 'monospace', fontSize: 15),
            ),
            const SizedBox(height: space2),
            const PrivacyCallout(
              child: Text(
                "Only the proof that you're 18 or older is shared. Never "
                "your birth date.",
                style: TextStyle(
                  fontSize: 15,
                  fontWeight: FontWeight.w600,
                  color: walletPrimary,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }
}
