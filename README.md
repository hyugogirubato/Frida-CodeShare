<div align="center">

<img src="https://github.com/hyugogirubato/Frida-CodeShare/blob/main/docs/images/icon.png" width="40%">

# Frida-CodeShare

[![License](https://img.shields.io/github/license/hyugogirubato/Frida-CodeShare)](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE)
[![Release](https://img.shields.io/github/release-date/hyugogirubato/Frida-CodeShare)](https://github.com/hyugogirubato/Frida-CodeShare/releases)

</div>

This repository contains a collection of Frida scripts for intercepting and modifying the behavior of Android apps at
runtime. These scripts leverage the power of Frida, a dynamic instrumentation tool, to hook into the target app's Java
and native code and perform various actions such as logging function calls, modifying function parameters, capturing
network traffic, and more.

## Getting Started

To use the Frida scripts in this repository, follow these steps:

1. **Prerequisites**: Make sure you have the following installed on your system:
    - Frida: The Frida framework should be installed on your device or emulator. You can find installation instructions
      at the [Frida website](https://frida.re/).
    - Python: Some of the scripts may require Python for additional functionality or setup. Make sure you have Python
      installed on your system.

2. **Clone the Repository**: Clone this repository to your local machine using the following command:
   ```
   git clone https://github.com/hyugogirubato/Frida-CodeShare.git
   ```
3. **Choose a Script**: Browse the repository and choose the Frida script that suits your needs. Each script is located
   in its own directory and is accompanied by a README file that provides usage instructions and additional details.

4. **Run the Script**: Follow the instructions in the script's README file to run it using Frida. Typically, you will
   need to specify the target package or process ID and the path to the script file.

## Disclaimer

These scripts are intended for educational and research purposes only. Use them responsibly and at your own risk. The
authors of this repository are not responsible for any misuse or damage caused by the use of these scripts.

### License

This project is licensed under the [GPL v3 License](https://github.com/hyugogirubato/Frida-CodeShare/blob/main/LICENSE).
