# Android Java Interceptor

[![Version](https://img.shields.io/badge/Version-v1.1-blue)](https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.2.1)

Android Java Interceptor is a Frida script that allows you to intercept and modify function calls in Android Java
applications. With this script, you can monitor and manipulate the behavior of specific functions within the target
application.

## Usage

To use the script, follow these steps:

1. Install Frida on your device or emulator.

2. Connect your device or emulator to your computer.

3. Run the following command to start the script:

   ```shell
   frida -D "DEVICE" -l "java.js" -f "PACKAGE"
   ```

Replace "DEVICE" with the device or emulator ID and "PACKAGE" with the package name of the target application. You can
also specify the binary path of the application if needed.

## Configuration

### Libraries and Methods

- Customize the `LIBRARIES` array to specify the libraries and methods you want to intercept. Use an empty list to
  capture everything or specify function names to filter.

  Example:
   ```javascript
   const LIBRARIES = [
       {
           "name": "com.android.example.ui.service",
           "methods": ["loadNative"]
       },
       {
           "name": "android.webkit.WebView",
           "methods": []
       }
   ];
   ```

### Target Selection

- Use the `PACKAGE` variable to specify the target package name. Set it to "undefined" to intercept all processes,
  including system processes.

  Example:
   ```javascript
   const PACKAGE = undefined;
   ```

### Output Configuration

- Customize the script's output by modifying the following variables:
    - `COLOR`: Colorize the output for better visibility.
    - `TIMEOUT`: Set a waiting time before attaching processes.
    - `DEBUG`: Display additional information on the current process.

  Example:
   ```javascript
   const COLOR = true;
   const TIMEOUT = 0;
   const DEBUG = false;
   ```

## Output

When the script intercepts a Java function call, it will print information to the console, including the method name,
arguments, and return values.

Example:

```shell
[+] onEnter: com.android.example.ui.service.loadNative
  --> [0] String: exampleArgument
[-] onLeave: com.android.example.ui.service.loadNative
  --> [0] Integer: 42
```

This output indicates that the `loadNative` method in the `com.android.example.ui.service` class was intercepted,
capturing a string argument "exampleArgument," and the method returned an integer value of `42`.

## License

This project is licensed under the GPL v3 License. See
the [LICENSE](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE) file for details.