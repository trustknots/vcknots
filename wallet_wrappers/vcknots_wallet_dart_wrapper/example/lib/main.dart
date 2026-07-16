import 'package:flutter/material.dart';
import 'dart:async';

import 'package:vcknots_wallet_dart_wrapper/vcknots_wallet_dart_wrapper_bindings_generated.dart';
import 'package:vcknots_wallet_dart_wrapper/vcknots_wallet.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  late int addResult;

  @override
  void initState() {
    super.initState();
    addResult = bindings.add(10, 20);
  }

  @override
  Widget build(BuildContext context) {
    const textStyle = TextStyle(fontSize: 20);
    const spacerSmall = SizedBox(height: 20);
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(
          title: const Text('Example Wallet'),
        ),
        body: SingleChildScrollView(
          child: Container(
            padding: const EdgeInsets.all(10),
            child: Column(
              children: [
                const Text(
                  'This is a example wallet app based on VCKnots Wallet library.',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
                Text(
                  'add(10, 20) = $addResult',
                  style: textStyle,
                  textAlign: TextAlign.center,
                ),
                spacerSmall,
              ],
            ),
          ),
        ),
      ),
    );
  }
}
