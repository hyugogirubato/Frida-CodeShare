/**@@@+++@@@@******************************************************************
 **
 ** Native Interceptor frida script v2.1 hyugogirubato
 **
 ** frida -D "DEVICE" -l "native.js" -f "PACKAGE"
 ** frida -p "PID" -l "native.js"
 ** frida "C:\Program Files\Producer\Software.exe" -l native.js
 **
 ** Update: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.2.2
 **
 ***@@@---@@@@******************************************************************
 */


/**
 * Use only the name for a classic interception.
 * Using an object when manually adding modules.
 */
const LIBRARIES = [
    "libnative.so",
    "libcrypto.so",
    {
        "name": "Software.exe",
        "modules": [
            {"type": "function", "name": "sub_14000BC30", "address": "0x14000BC30"},
            {"type": "function", "name": "sub_14000BCA0", "address": "0x14000BCA0"},
            {"type": "function", "name": "sub_14000DF50", "address": "0x14000DF50"}
        ]
    }
];

/**
 * Use the application package name to intercept only application-related processes.
 * Using the Binary Path to only intercept binary-related processes.
 * Use "undefined" to intercept all running processes (system included).
 */
const PACKAGE = "PACKAGE";


/**
 * Filter processes attached to a string or regex value.
 * Using an empty field to catch everything.
 */
const INCLUDES = ["selectedFunction", /^md5$/, "anotherNativeFunction"];
const EXCLUDES = [/create.*token$/];
const EXTENSIONS = [".so", ".dll", /\.exe$/];


/**
 * Customize output display:
 * - COLOR: Colorize the output.
 * - TIMEOUT: Waiting time before attaching processes.
 * - VARIABLE: Attach variables.
 * - FUNCTION: Attach functions.
 * - RECURSIVE: Arguments of the function in output.
 * - DEBUG: Additional information on the current process.
 */
const COLOR = true;
const TIMEOUT = 0;
const VARIABLE = true;
const FUNCTION = true;
const RECURSIVE = false;
const DEBUG = false;

// Constants
let current = 0;
const COLORS = {
    reset: '\x1b[0m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    // white: '\x1b[37m'
};


const Color = () => {
    const keys = Object.keys(COLORS).filter(key => key !== "reset" && key !== "red");
    current = (current + 1) % keys.length;
    return keys[current];
}

const print = (data, color) => {
    console.log(color && COLOR ? `${COLORS[color]}${data}${COLORS.reset}` : data);
}

const searchLibraries = () => {
    // Package
    let libraries = Process.enumerateModules().filter((l) =>
        PACKAGE ? l["path"].toLowerCase().includes(PACKAGE.toLowerCase()) : true
    );

    // Extensions
    if (EXTENSIONS.length > 0) {
        libraries = libraries.filter((l) =>
            EXTENSIONS.some((e) =>
                e instanceof RegExp
                    ? l["path"].match(e)
                    : l["path"].toLowerCase().endsWith(e.toLowerCase())
            )
        );
    }

    // Libraries
    if (LIBRARIES.length > 0) {
        libraries = libraries.filter((l) =>
            LIBRARIES.some((L) =>
                L instanceof Object
                    ? l["name"].toLowerCase().includes(L["name"].toLowerCase())
                    : l["name"].toLowerCase().includes(L.toLowerCase())
            )
        );
    }
    return libraries;
}

const filterModules = (modules, filters) => {
    return modules.filter((m) => {
        return filters.some((f) => {
            if (f instanceof RegExp) {
                return m["name"].match(f);
            } else {
                return m["name"].toLowerCase().includes(f.toLowerCase());
            }
        })
    });
}

const searchModules = (library) => {
    let modules = library.enumerateExports();

    // Libraries
    if (LIBRARIES.length > 0) {
        for (const l of LIBRARIES) {
            if (l instanceof Object) {
                if (library["name"].toLowerCase().includes(l["name"].toLowerCase())) {
                    l["modules"].forEach((m) => {
                        if (!modules.some((obj) => JSON.stringify(obj) === JSON.stringify(m))) {
                            modules.push(m);
                        }
                    });
                }
            }
        }
    }

    // Address
    modules = modules.map(m => ({...m, address: ptr(m["address"])}));

    // Includes
    if (INCLUDES.length > 0) {
        modules = filterModules(modules, INCLUDES);
    }

    // Excludes
    if (EXCLUDES.length > 0) {
        const excludes = filterModules(modules, EXCLUDES);
        modules = modules.filter(m => !excludes.some(e => e["name"] === m["name"]));
    }

    return modules;
}

const printMemory = (address, index, color) => {
    if (DEBUG) {
        print(JSON.stringify({
            address: address,
            ...Process.findRangeByAddress(address)
        }, null, 2));
    }

    // Fix Access violation
    let stringData;
    try {
        stringData = Memory.readCString(address);
    } catch (e) {
        print(e, "red");
    }

    if (stringData) {
        // String
        print(`  --> [${index}] String: ${stringData}`, color);

        // Bytes
        let ptr = new NativePointer(address);
        let size = 0;
        while (ptr.add(size).readU8() !== 0) {
            size++;
        }

        const byteArray = ptr.readByteArray(size);
        const byteArrayView = new Uint8Array(byteArray);

        // Integer
        let intValue = 0;
        for (let i = 0; i < byteArrayView.length; i++) {
            const byte = byteArrayView[i];
            if (!(byte >= 48 && byte <= 57)) {
                intValue = NaN;
                break;
            }

            const digitValue = byte - 48;
            intValue = intValue * 10 + digitValue;
        }

        if (!isNaN(intValue)) {
            print(`  --> [${index}] Integer: ${intValue}`, color);
        }

        // Pointer
        const hexData = Array.from(byteArrayView, byte => byte.toString(16).padStart(2, "0")).join("");
        if (hexData.length === 10) {
            print(`  --> [${index}] Pointer: 0x${hexData}`, color);
        }

        // Base64
        let hexValue = false;
        if (Java.available) {
            Java.perform(function () {
                const byteBuffer = Java.array("byte", byteArrayView);
                const base64Data = Java.use("java.util.Base64").getEncoder().encodeToString(byteBuffer);
                print(`  --> [${index}] Base64: ${base64Data}`, color);
            });
        } else {
            hexValue = true;
        }

        // Hex
        if ((!hexData.includes("-") && [32, 40, 48, 64].includes(hexData.length)) || hexValue) {
            print(`  --> [${index}] Hex: ${hexData}`, color);
        }
    } else {
        print(`  --> [${index}] Integer: ${parseInt(address, 16)}`, color);
    }
}

const attachVariable = (module) => {
    const color = Color();
    print(`[+] VarEnter: ${module["name"]}`, color);
    printMemory(module["address"], 0, color);
    print(`[-] VarLeave: ${module["name"]}`, color);
}

const paramsCount = (args) => {
    let count = 0;
    while (true) {
        try {
            const tmp = new NativePointer(args[count]);
            tmp.readPointer();
            count += 1;
        } catch (e) {
            break;
        }
    }
    return count;
}

const attachFunction = (module) => {
    print(`[*] Module attached: ${module["name"]}`);
    const color = Color();
    const address = module["address"];
    const params = {};

    Interceptor.attach(address, {
        onEnter: function (args) {
            print(`[+] onEnter: ${module["name"]}`, color);

            // Fix RangeError
            params[address] = [];
            for (let i = 0; i < paramsCount(args); i++) {
                printMemory(args[i], i, color);
                params[address].push(args[i]);
            }
        },
        onLeave: function (retval) {
            print(`[-] onLeave: ${module["name"]}`, color);

            if (RECURSIVE) {
                for (let i = 0; i < params[address].length; i++) {
                    printMemory(params[address][i], i, color);
                }
            }

            printMemory(retval, RECURSIVE ? params[address].length : 0, color);
            delete params[address];
        }
    });
}


setTimeout(function () {
    print("Capturing Native process...\n---");

    const libraries = searchLibraries();
    if (libraries.length > 0) {
        print(`[*] Native libraries found (${libraries.length})`);
        let variableCount = 0;
        let functionCount = 0;
        for (const library of libraries) {
            if (DEBUG) {
                print(JSON.stringify(library, null, 2));
            }
            const modules = searchModules(library);
            print(`[>] Attach: ${library["name"]} (${modules.length})`);
            for (const module of modules) {
                if (DEBUG) {
                    print(JSON.stringify({
                        library: library["name"],
                        ...module,
                        ...Process.findRangeByAddress(module["address"])
                    }, null, 2));
                }

                try {
                    if (module["type"] === "variable" && (VARIABLE || FUNCTION)) {
                        variableCount++;
                        attachVariable(module);
                    } else if (FUNCTION) {
                        functionCount++;
                        attachFunction(module);
                    }
                } catch (e) {
                    print(e, "red");
                }
            }
        }

        print(`[>] Variables count: ${variableCount}`);
        print(`[>] Functions count: ${functionCount}`);
    } else {
        print("[!] No native library found", "red");
    }

    print("Capturing setup completed\n---");
}, TIMEOUT);
