import 'package:flutter/material.dart';

import 'theme.dart';

/// The box treatment for a line the wallet wants to spotlight as staying on
/// the device. Callers style their own text/icon (walletPrimary, w600) —
/// this only supplies the tinted, left-bordered container around them.
class PrivacyCallout extends StatelessWidget {
  final Widget child;

  const PrivacyCallout({super.key, required this.child});

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: space4, vertical: space3),
      decoration: BoxDecoration(
        color: walletPrivacyBg,
        border: const Border(left: BorderSide(color: walletPrimary, width: 3)),
        borderRadius: BorderRadius.circular(radiusSm),
      ),
      child: child,
    );
  }
}
