import 'package:flutter/material.dart';

/// Wallet demo storyboard palette. Light theme only.
const walletScaffoldBackground = Color(0xFFF2F2F3);
const walletSurface = Color(0xFFE9E9EA);
const walletTextPrimary = Color(0xFF1D1F20);
const walletPrimary = Color(0xFF1C4587);
const walletSecondary = Color(0xFF5980A6);
const walletDarkChip = Color(0xFF1D2D3D);
const walletDarkChipAccent = Color(0xFF94BCE3);
const walletDivider = Color(0xFFD2D3D6);
const walletMuted = Color(0xFF6B6F73);
const walletSuccess = Color(0xFF1E7D4A);
const walletSuccessBg = Color(0xFFE3F3EA);
const walletError = Color(0xFFA02F2F);
const walletErrorBg = Color(0xFFF6E6E6);
const walletPrivacyBg = Color(0xFFE9EFF7);

const radiusSm = 10.0;
const radiusMd = 14.0;
const radiusLg = 16.0;

const space1 = 4.0;
const space2 = 8.0;
const space3 = 12.0;
const space4 = 16.0;
const space5 = 24.0;
const space6 = 32.0;

const sectionLabelStyle = TextStyle(
  fontFamily: 'BarlowCondensed',
  fontWeight: FontWeight.w600,
  letterSpacing: 0.5,
);

TextStyle condensedHeading({double? fontSize, Color? color}) {
  return TextStyle(
    fontFamily: 'BarlowCondensed',
    fontWeight: FontWeight.w600,
    letterSpacing: 0.5,
    fontSize: fontSize,
    color: color,
  );
}

ThemeData buildWalletTheme() {
  return ThemeData(
    useMaterial3: true,
    brightness: Brightness.light,
    fontFamily: 'Barlow',
    scaffoldBackgroundColor: walletScaffoldBackground,
    colorScheme: ColorScheme.fromSeed(
      seedColor: walletPrimary,
      brightness: Brightness.light,
      primary: walletPrimary,
      secondary: walletSecondary,
      surface: walletSurface,
    ),
    cardTheme: CardThemeData(
      color: walletSurface,
      elevation: 0,
      shape:
          RoundedRectangleBorder(borderRadius: BorderRadius.circular(radiusMd)),
    ),
    dividerColor: walletDivider,
    textTheme: ThemeData.light().textTheme.apply(
          bodyColor: walletTextPrimary,
          displayColor: walletTextPrimary,
        ),
    appBarTheme: const AppBarTheme(
      backgroundColor: walletScaffoldBackground,
      foregroundColor: walletTextPrimary,
      elevation: 0,
      surfaceTintColor: Colors.transparent,
    ),
    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: walletPrimary,
        foregroundColor: Colors.white,
        disabledBackgroundColor: walletPrimary.withValues(alpha: 0.35),
        disabledForegroundColor: Colors.white.withValues(alpha: 0.8),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(radiusSm)),
        padding: const EdgeInsets.symmetric(vertical: 16),
      ),
    ),
    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: walletTextPrimary,
        side: const BorderSide(color: walletDivider),
        shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(radiusSm)),
        padding: const EdgeInsets.symmetric(vertical: 16),
      ),
    ),
  );
}
