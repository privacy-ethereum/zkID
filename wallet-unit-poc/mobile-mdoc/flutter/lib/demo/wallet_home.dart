import 'dart:async';

import 'package:flutter/material.dart';

import '../engineering_screen.dart';
import 'consent_screen.dart';
import 'paths.dart';
import 'provisioning.dart';
import 'theme.dart';
import 'wallet_link.dart';

/// The wallet's landing screen: the demo PID credential, first-run
/// provisioning progress, and the entry point for an incoming verification
/// request (via deep link) or the engineering pipeline rig.
class WalletHome extends StatefulWidget {
  const WalletHome({super.key});

  @override
  State<WalletHome> createState() => _WalletHomeState();
}

class _WalletHomeState extends State<WalletHome> {
  final ProvisioningController _provisioning = ProvisioningController();
  StreamSubscription<VerificationRequest>? _linkSubscription;

  @override
  void initState() {
    super.initState();
    _provisioning.addListener(_onProvisioningChanged);
    _bootstrap();
    _linkSubscription = walletLinkRequests().listen(_handleRequest);
    initialWalletLink().then((request) {
      if (request != null) _handleRequest(request);
    });
  }

  Future<void> _bootstrap() async {
    final documentsPath = await resolveDocumentsPath();
    await _provisioning.start(documentsPath);
  }

  void _onProvisioningChanged() => setState(() {});

  void _handleRequest(VerificationRequest request) {
    Navigator.of(context).push(MaterialPageRoute(
      builder: (_) =>
          ConsentScreen(request: request, provisioning: _provisioning),
    ));
  }

  @override
  void dispose() {
    _linkSubscription?.cancel();
    _provisioning.removeListener(_onProvisioningChanged);
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('OpenAC Wallet'),
        actions: [
          IconButton(
            icon: const Icon(Icons.build_outlined),
            tooltip: 'Engineering tools',
            onPressed: () => Navigator.of(context).push(
              MaterialPageRoute(
                builder: (_) => const E2EProofWorkflowScreen(),
              ),
            ),
          ),
        ],
      ),
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Your credentials',
                style: condensedHeading(fontSize: 13, color: walletSecondary),
              ),
              const SizedBox(height: space3),
              const _PidCard(),
              const SizedBox(height: 28),
              Expanded(child: _ProvisioningPanel(controller: _provisioning)),
            ],
          ),
        ),
      ),
    );
  }
}

class _PidCard extends StatelessWidget {
  const _PidCard();

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: walletDarkChip,
        borderRadius: BorderRadius.circular(radiusLg),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.badge_outlined, color: walletDarkChipAccent),
              const SizedBox(width: space2),
              Text(
                'PID',
                style: Theme.of(context).textTheme.titleMedium?.copyWith(
                      color: walletDarkChipAccent,
                      fontWeight: FontWeight.bold,
                    ),
              ),
            ],
          ),
          const SizedBox(height: 40),
          const Text(
            'Personal ID Document',
            style: TextStyle(color: Colors.white, fontSize: 16),
          ),
        ],
      ),
    );
  }
}

/// Shows first-run provisioning progress, or a compact ready state once the
/// wallet has credential keys, presentation keys, blinds, and a credential
/// proof on disk.
class _ProvisioningPanel extends StatelessWidget {
  final ProvisioningController controller;

  const _ProvisioningPanel({required this.controller});

  @override
  Widget build(BuildContext context) {
    if (controller.isReady) {
      return const Card(
        child: Padding(
          padding: EdgeInsets.all(space4),
          child: Row(
            children: [
              Icon(Icons.check_circle, color: walletSuccess),
              SizedBox(width: space3),
              Text('Wallet ready'),
            ],
          ),
        ),
      );
    }

    return Card(
      child: Padding(
        padding: const EdgeInsets.all(space4),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          mainAxisSize: MainAxisSize.min,
          children: [
            Text(
              'Setting up your wallet',
              style: Theme.of(context)
                  .textTheme
                  .titleSmall
                  ?.copyWith(fontWeight: FontWeight.bold),
            ),
            const SizedBox(height: space3),
            for (final stage in ProvisioningStage.values)
              _StageRow(
                label: stage.label,
                done: controller.isCompleted(stage),
                active: controller.currentStage == stage,
              ),
            if (controller.error != null) ...[
              const SizedBox(height: space2),
              Text(
                controller.error!,
                style: const TextStyle(color: walletError, fontSize: 12),
              ),
              const SizedBox(height: space2),
              TextButton(
                onPressed: () async {
                  final documentsPath = await resolveDocumentsPath();
                  await controller.start(documentsPath);
                },
                child: const Text('Retry'),
              ),
            ],
          ],
        ),
      ),
    );
  }
}

class _StageRow extends StatelessWidget {
  final String label;
  final bool done;
  final bool active;

  const _StageRow({
    required this.label,
    required this.done,
    required this.active,
  });

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 6),
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
                        color: walletDivider, size: 18),
          ),
          const SizedBox(width: space3),
          Text(
            label,
            style: TextStyle(
              color: done || active ? walletTextPrimary : walletSecondary,
            ),
          ),
        ],
      ),
    );
  }
}
