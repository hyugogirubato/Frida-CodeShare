# Native Interceptor

[![Version](https://img.shields.io/badge/Version-v2.1-blue)](https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.2.2)

Native Interceptor is a frida script that allows you to intercept and monitor function calls in native libraries and
processes. This script provides a wide range of customization options to help you capture and analyze the behavior of
specific functions within the target application.

## Usage

To use the script, follow these steps:

1. Install Frida on your device or emulator.

2. Connect your device or emulator to your computer.

3. Run the following command to start the script:

   ```shell
   frida -D "DEVICE" -l "native.js" -f "PACKAGE"
   ```

Replace "DEVICE" with the device or emulator ID and "PACKAGE" with the package name of the target application. You can
also specify the binary path of the application if needed.

## Configuration

### Libraries

- Modify the `LIBRARIES` array to specify the libraries you want to intercept. You can include both shared
  libraries (`.so`) and executables (`.exe`) as targets. You can also specify individual functions within an executable.

  Example:
   ```javascript
   const LIBRARIES = [
       "libnative.so",
       "libcrypto.so",
       {
           "name": "Software.exe",
           "modules": [
               {"type": "function", "name": "sub_14000BC30", "address": "0x14000BC30"},
               {"type": "function", "name": "sub_14000BCA0", "address": "0x14000BCA0"}
           ]
       }
   ];
   ```

### Target Selection

- Use the `PACKAGE` variable to specify the target package name to intercept only application-related processes.
  Alternatively, you can use the binary path to intercept only specific binary-related processes. Use "undefined" to
  intercept all running processes, including system processes.

  Example:
   ```javascript
   const PACKAGE = "com.example.app";
   ```

### Function Filters

- Customize which functions to intercept using the `EXTENSIONS`, `INCLUDES` and `EXCLUDES` arrays. The `INCLUDES` array
  specifies the
  function names you want to intercept, while the `EXCLUDES` array allows you to exclude specific function names from
  interception.

  Example:
   ```javascript
   const INCLUDES = ["selectedFunction", /^md5$/, "anotherNativeFunction"];
   const EXCLUDES = [/create.*token$/];
   const EXTENSIONS = [".so", ".dll", /\.exe$/];
   ```

### Output Configuration

- Customize the script's output by modifying the following variables:
    - `COLOR`: Colorize the output for better visibility.
    - `TIMEOUT`: Set a waiting time before attaching processes.
    - `VARIABLE`: Attach variable values.
    - `FUNCTION`: Attach function calls.
    - `RECURSIVE`: Display function arguments in the output.
    - `DEBUG`: Display additional information on the current process.

  Example:
   ```javascript
   const COLOR = true;
   const TIMEOUT = 0;
   const VARIABLE = true;
   const FUNCTION = true;
   const RECURSIVE = false;
   const DEBUG = false;
   ```

## Output

When the script intercepts a function call, it will print the following information to the console:

- **VarEnter**: Indicates that a variable is being intercepted.
- **[i] Type**: The type and value of the variable at index `i`.
- **VarLeave**: Indicates that the variable interception is complete.

- **onEnter**: Indicates that a function is being entered.
- **[i] Type**: The type and value of the function argument at index `i`.
- **onLeave**: Indicates that the function is being exited.
- **[0] Type**: The type and value of the function's return value.

  Example:
   ```shell
   [+] VarEnter: libnative.so!variableName
     --> [0] String: exampleVariable
   [-] VarLeave: libnative.so!variableName
     --> [0] Integer: 42
   ```

  This output shows that a variable interception occurred in the `libnative.so` library, capturing a string
  variable `"exampleVariable"`. Additionally, a function interception took place, and the function returned an integer
  value of `42`.

## License

This project is licensed under the GPL v3 License. See
the [LICENSE](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE) file for details.