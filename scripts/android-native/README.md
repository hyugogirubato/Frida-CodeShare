# Android Native Interceptor

Android Native Interceptor is a Frida script that allows you to intercept and monitor function calls in native libraries
of Android applications. With this script, you can capture and analyze the behavior of specific functions within the
target application.

## Usage

To use the script, follow these steps:

1. Install Frida on your device or emulator.

2. Connect your device or emulator to your computer.

3. Run the following command to start the script:

````shell
frida -D "DEVICE" -l "native.js" -f "PACKAGE"
````

Replace "DEVICE" with the device or emulator ID and "PACKAGE" with the package name of the target application.

## Customization

- Set the `PACKAGE` variable to specify the target package name. Leave it undefined to intercept all packages.
- Modify the `LIBRARIES` array to specify the libraries you want to intercept. Leave it empty to intercept all
  libraries.
- Modify the `INCLUDES` array to specify the function names you want to intercept. Leave it empty to intercept all
  functions.
- Modify the `EXCLUDES` array to exclude specific function names from interception.
- Set the `VARIABLE` variable to `true` if you want to attach and display variable values.
- Set the `FUNCTION` variable to `true` if you want to intercept and display function calls.
- Set the `RECURSIVE` variable to `true` if you want to display function arguments on output.
- Set the `DEBUG` variable to `true` if you want to display debug output.

## Output

When the script intercepts a function call, it will print the following information to the console:

- **onEnter**: Indicates that the intercepted function is being entered.
- **[i] Type**: The type and value of the function argument at index `i`.
- **onLeave**: Indicates that the intercepted function is being exited.
- **[0] Type**: The type and value of the function's return value.

For example:

````shell
[+] onEnter: libnative.so!functionName
  --> [0] String: exampleArgument
[-] onLeave: libnative.so!functionName
  --> [0] Integer: 42
````

This output shows that the function `functionName` in the `libnative.so` library was intercepted. The function was
called with a string argument `"exampleArgument"` and returned an integer value of `42`.

## License

This project is licensed under the [GPL v3 License](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE).
