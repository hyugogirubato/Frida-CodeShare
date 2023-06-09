# Android Java Interceptor

Android Java Interceptor is a Frida script that allows you to intercept and modify function calls in Android Java
applications. With this script, you can monitor and manipulate the behavior of specific functions within the target
application.

## Usage

To use the script, follow these steps:

1. Install Frida on your device or emulator.

2. Connect your device or emulator to your computer.

3. Run the following command to start the script:

````shell
frida -D "DEVICE" -l "java.js" -f "PACKAGE"
````

Replace "DEVICE" with the device or emulator ID and "PACKAGE" with the package name of the target application.

## Customization

Modify the `FUNCTIONS` array in the `java.js` script to specify the functions you want to intercept. You can define the
package, class, and function names as needed. Leave the `function` array empty to intercept all methods within a class.

## Output

When the script intercepts a function call, it will print the following information to the console:

- **onEnter**: Indicates that the intercepted function is being entered.
- **[i] argType**: The type and value of the function argument at index `i`.
- **onLeave**: Indicates that the intercepted function is being exited.
- **[0] returnType**: The type and value of the function's return value.

For example:

````shell
[+] onEnter: com.example.ui.fragment.LoginFragment.login
  --> [0] String: john.doe@example.com
  --> [1] String: password123
[-] onLeave: com.example.ui.fragment.LoginFragment.login
  --> [0] Boolean: true
````

This output shows that the `login` function in the `LoginFragment` class of the `com.example.ui.fragment` package was
intercepted. The function was called with two arguments: a string representing the email and a string representing the
password. The function returned a boolean value of `true`.

## License

This project is licensed under the [GPL v3 License](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE).
