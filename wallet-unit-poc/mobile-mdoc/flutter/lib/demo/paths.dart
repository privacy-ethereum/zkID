import 'package:path_provider/path_provider.dart';

/// The `documentsPath` every FFI call takes: `{ApplicationDocuments}/circom`.
/// Proof artifacts live under `{documentsPath}/keys/`.
Future<String> resolveDocumentsPath() async {
  final dir = await getApplicationDocumentsDirectory();
  return '${dir.path}/circom';
}
