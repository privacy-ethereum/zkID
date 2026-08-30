import 'dart:async';
import 'dart:convert';
import 'dart:io';

/// Result of uploading the mdoc/show proofs for one session to the verifier.
class UploadResult {
  final bool ok;
  final String status;
  final int mdocProofBytes;
  final int showProofBytes;
  final String? error;

  const UploadResult({
    required this.ok,
    required this.status,
    required this.mdocProofBytes,
    required this.showProofBytes,
    this.error,
  });

  factory UploadResult.failed(
    String error, {
    int mdocProofBytes = 0,
    int showProofBytes = 0,
  }) {
    return UploadResult(
      ok: false,
      status: 'failed',
      mdocProofBytes: mdocProofBytes,
      showProofBytes: showProofBytes,
      error: error,
    );
  }
}

/// Reads the proofs the Rust FFI wrote under `$documentsPath/keys/` and POSTs
/// them, base64-encoded, to the verifier's session endpoint. Never throws:
/// missing files, network errors, timeouts, and non-2xx responses all come
/// back as a failed [UploadResult].
Future<UploadResult> uploadProofs({
  required Uri server,
  required String sessionId,
  required String documentsPath,
}) async {
  final List<int> mdocBytes;
  final List<int> showBytes;
  try {
    mdocBytes = await File('$documentsPath/keys/mdoc_proof.bin').readAsBytes();
    showBytes = await File('$documentsPath/keys/show_proof.bin').readAsBytes();
  } catch (e) {
    return UploadResult.failed('Failed to read proof files: $e');
  }

  final body = jsonEncode({
    'mdoc_proof': base64Encode(mdocBytes),
    'show_proof': base64Encode(showBytes),
  });

  try {
    final status = await _postProofsWithRetry(server, sessionId, body);
    return UploadResult(
      ok: status == 'verified',
      status: status,
      mdocProofBytes: mdocBytes.length,
      showProofBytes: showBytes.length,
    );
  } catch (e) {
    return UploadResult.failed(
      '$e',
      mdocProofBytes: mdocBytes.length,
      showProofBytes: showBytes.length,
    );
  }
}

/// Retries once, after a short delay, on a socket-level failure — a fresh
/// install or a USB-cable wake can leave the first socket on the local
/// network racing iOS's local-network permission prompt / interface wake,
/// which the consent screen's warm-up request usually already absorbs, but
/// not always. A non-socket failure (e.g. a non-2xx response) surfaces
/// immediately without retrying.
Future<String> _postProofsWithRetry(
  Uri server,
  String sessionId,
  String body,
) async {
  try {
    return await _postProofsOnce(server, sessionId, body);
  } on SocketException {
    return _retryAfterDelay(server, sessionId, body);
  } on TimeoutException {
    return _retryAfterDelay(server, sessionId, body);
  }
}

Future<String> _retryAfterDelay(
  Uri server,
  String sessionId,
  String body,
) async {
  await Future.delayed(const Duration(milliseconds: 1500));
  return _postProofsOnce(server, sessionId, body);
}

/// Opens a fresh connection and sends the payload, timing the whole
/// attempt out at 30s.
Future<String> _postProofsOnce(
  Uri server,
  String sessionId,
  String body,
) async {
  final client = HttpClient();
  try {
    return await _postProofs(client, server, sessionId, body)
        .timeout(const Duration(seconds: 30));
  } finally {
    client.close(force: true);
  }
}

/// Sends the payload and returns the server's `status` field. Throws on
/// network failure or a non-2xx response; [uploadProofs] converts that into
/// a failed [UploadResult] rather than letting it propagate.
Future<String> _postProofs(
  HttpClient client,
  Uri server,
  String sessionId,
  String body,
) async {
  final uri = Uri.parse('$server/api/session/$sessionId/proofs');
  final request = await client.postUrl(uri);
  request.headers.set(HttpHeaders.contentTypeHeader, 'application/json');
  request.write(body);

  final response = await request.close();
  final responseBody = await response.transform(utf8.decoder).join();

  if (response.statusCode < 200 || response.statusCode >= 300) {
    throw HttpException(
      'Server returned ${response.statusCode}: $responseBody',
      uri: uri,
    );
  }

  final decoded = jsonDecode(responseBody) as Map<String, dynamic>;
  return decoded['status'] as String? ?? 'failed';
}
