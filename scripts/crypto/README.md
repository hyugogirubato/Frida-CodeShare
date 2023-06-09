# Android Crypto Interceptor

Android Crypto Interceptor is a Frida script that intercepts cryptographic operations in Android applications. It can be
used to capture encryption and decryption keys, algorithm parameters, and other relevant information during runtime.

## Usage

To use the script, follow these steps:

1. Install Frida on your device or emulator.

2. Connect your device or emulator to your computer.

3. Run the following command to start the script:

````shell
frida -D "DEVICE" -l "crypto.js" -f "PACKAGE"
````

Replace "DEVICE" with the device or emulator ID and "PACKAGE" with the package name of the target application.

## Features

The script supports interception of the following cryptographic modules:

- `javax.crypto.KeyGenerator`
- `java.security.KeyPairGenerator`
- `javax.crypto.spec.SecretKeySpec`
- `java.security.MessageDigest`
- `javax.crypto.SecretKeyFactory`
- `java.security.Signature`
- `javax.crypto.Cipher`
- `javax.crypto.Mac`
- `javax.crypto.spec.IvParameterSpec`

You can customize the interception behavior by modifying the `MODE` object in the script.

## Output

The script will log intercepted method calls along with relevant information such as algorithm names, key values,
input/output data, and providers used. The output will be color-coded for better readability.

## License

This project is licensed under the [GPL v3 License](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE).
