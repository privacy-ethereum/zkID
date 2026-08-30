import 'dart:convert';

import 'package:flutter/services.dart' show rootBundle;

/// The birth date the bundled circuit inputs commit to
/// (`claimValues[0]` in `assets/circom/show_input.json`, `YYYYMMDD`),
/// formatted `YYYY-MM-DD`. This is the actual data the age predicate is
/// derived from — read from the asset rather than hardcoded so the
/// consent and receipt screens can't drift from what the circuit proves.
Future<String> loadCredentialBirthDate() async {
  final raw = await rootBundle.loadString('assets/circom/show_input.json');
  final claimValues =
      (jsonDecode(raw) as Map<String, dynamic>)['claimValues'] as List;
  final yyyymmdd = claimValues[0] as String;
  return '${yyyymmdd.substring(0, 4)}-${yyyymmdd.substring(4, 6)}-'
      '${yyyymmdd.substring(6, 8)}';
}
