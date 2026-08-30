import 'package:app_links/app_links.dart';
import 'package:url_launcher/url_launcher.dart';

/// A verification request handed to the wallet by the browser session via an
/// `openacmdoc://verify` deep link.
class VerificationRequest {
  final String sessionId;
  final Uri server;
  final String policy;
  final String policyDisplay;

  const VerificationRequest({
    required this.sessionId,
    required this.server,
    required this.policy,
    required this.policyDisplay,
  });

  /// Parses an `openacmdoc://verify?session=...&server=...&policy=...&label=...`
  /// link. `label` is optional — falls back to a fixed display string for an
  /// old server that doesn't send it. Returns null for any other scheme/host
  /// or missing/malformed required params.
  static VerificationRequest? tryParse(Uri uri) {
    if (uri.scheme != 'openacmdoc' || uri.host != 'verify') return null;

    final sessionId = uri.queryParameters['session'];
    final serverParam = uri.queryParameters['server'];
    final policy = uri.queryParameters['policy'];
    if (sessionId == null || sessionId.isEmpty) return null;
    if (serverParam == null || serverParam.isEmpty) return null;
    if (policy == null || policy.isEmpty) return null;

    final server = Uri.tryParse(serverParam);
    if (server == null || !server.hasScheme) return null;

    final label = uri.queryParameters['label'];
    final policyDisplay =
        (label == null || label.isEmpty) ? 'Age 18 or older' : label;

    return VerificationRequest(
      sessionId: sessionId,
      server: server,
      policy: policy,
      policyDisplay: policyDisplay,
    );
  }
}

/// Deep links delivered while the app is already running.
Stream<VerificationRequest> walletLinkRequests() {
  return AppLinks()
      .uriLinkStream
      .map(VerificationRequest.tryParse)
      .where((r) => r != null)
      .cast<VerificationRequest>();
}

/// The deep link that cold-started the app, if any.
Future<VerificationRequest?> initialWalletLink() async {
  final uri = await AppLinks().getInitialLink();
  return uri == null ? null : VerificationRequest.tryParse(uri);
}

/// Hands control back to the browser session that started verification.
Future<void> returnToBrowser(VerificationRequest r) async {
  final target = r.server.replace(
    path: '/',
    queryParameters: {'session': r.sessionId},
  );
  await launchUrl(target, mode: LaunchMode.externalApplication);
}
