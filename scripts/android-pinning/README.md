# Android SSL Pinning

Android SSL Pinning is a Frida script designed to bypass SSL pinning in Android applications. It uses the Frida
framework to dynamically patch the SSL pinning methods in the target app and allow interception of SSL/TLS traffic.

## Usage

To use the script, follow these steps:

1. Install Frida on your device or emulator.

2. Connect your device or emulator to your computer.

3. Run the following command to start the script:

````shell
frida -D "DEVICE" -l "pinning.js" -f "PACKAGE"
````

Replace "DEVICE" with the device or emulator ID and "PACKAGE" with the package name of the target application.

## Customization

The script provides a `MODE` object that allows you to customize which SSL pinning methods to target. By setting the
corresponding property to `true`, you can enable or disable the patching for specific SSL pinning methods.

```javascript
const MODE = {
    SSLPeerUnverifiedException: true,
    HttpsURLConnection: true,
    SSLContext: true,
    TrustManagerImpl: true,
    OkHTTPv3: true,
    // Add or remove other SSL pinning methods as needed
};
```

You can modify the `MODE` object to fit your specific needs.

## Output

The script will print detailed information about the patched SSL pinning methods to the console. Each intercepted SSL
pinning method will be displayed with its corresponding class and method name.

Example output:

```
--> SSLPeerUnverifiedException [com.example.app.MainActivity.login]
--> HttpsURLConnection [DefaultHostnameVerifier]
--> HttpsURLConnection [SSLSocketFactory]
--> HttpsURLConnection [HostnameVerifier]
--> TrustManager [SSLContext] (Android < 7)
--> TrustManagerImpl [TrustedRecursive] (Android > 7): example.com
--> TrustManagerImpl [verifyChain] (Android > 7): example.com
--> OkHTTPv3 [List]: example.com
--> OkHTTPv3 [Certificate]: example.com
--> OkHTTPv3 [Array]: example.com
--> OkHTTPv3 [Function]: example.com
```

This output indicates the SSL pinning methods that have been successfully intercepted and patched.

## License

This project is licensed under the [GPL v3 License](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE).