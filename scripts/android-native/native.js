/**@@@+++@@@@******************************************************************
 **
 ** Android Native Interceptor frida script v1.5 hyugogirubato
 **
 ** frida -D "DEVICE" -l "native.js" -f "PACKAGE"
 **
 ** Update: Added multi-thread support for base64 conversion.
 **
 ***@@@---@@@@******************************************************************
 */


// Custom params
const PACKAGE = "PACKAGE"; // undefined for intercept everything
const LIBRARIES = ["libnative.so"]; // empty for intercept everything
const INCLUDES = ["selectedFunction"]; // empty for intercept everything
const EXCLUDES = []; // empty for intercept everything
const VARIABLE = true;  // attach variables
const FUNCTION = true; // attach functions


let index = 0; // color index
const COLORS = {
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    blue: '\x1b[34m',
    magenta: '\x1b[35m',
    cyan: '\x1b[36m',
    reset: '\x1b[0m'
};

const randomColor = () => {
    const colorKeys = Object.keys(COLORS).filter(key => key !== "reset" && key !== "red");
    index = (index + 1) % colorKeys.length;
    return COLORS[colorKeys[index]];
}

const isUUID = (hex) => {
    const uuidPattern = /^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/;
    return uuidPattern.test(hex);
}

const searchLibraries = () => {
    let libraries = Process.enumerateModules().filter(lib => PACKAGE ? lib["path"].toLowerCase().includes(PACKAGE.toLowerCase()) : true);
    if (LIBRARIES.length > 0) {
        return libraries.filter(lib => LIBRARIES.some(library => lib["path"].toLowerCase().includes(library) && lib["path"].toLowerCase().endsWith(".so")));
    } else {
        return libraries.filter(lib => lib["path"].toLowerCase().endsWith(".so"));
    }
}

const searchModules = (library) => {
    let modules = library.enumerateExports();
    if (INCLUDES.length > 0) {
        modules = modules.filter(mod => INCLUDES.some(include => mod["name"].toLowerCase().includes(include.toLowerCase())));
    }
    if (EXCLUDES.length > 0) {
        modules = modules.filter(mod => EXCLUDES.every(exclude => !mod["name"].toLowerCase().includes(exclude.toLowerCase())));
    }
    return modules;
}


const showVariable = (address, colorKey, argIndex = 0, hexValue = false) => {
    let stringData;
    try {
        stringData = Memory.readCString(address);
    } catch (e) {
        console.log(`${COLORS.red}${e}${COLORS.reset}`);
    }

    // avoid access violation
    if (stringData) {
        // String
        console.log(`${colorKey}  --> [${argIndex}] String: ${stringData}${COLORS.reset}`);

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
            console.log(`${colorKey}  --> [${argIndex}] Integer: ${intValue}${COLORS.reset}`);
        }

        const hexData = Array.from(byteArrayView, byte => byte.toString(16).padStart(2, "0")).join("");
        if (hexData.length === 10) {
            // Pointer
            console.log(`${colorKey}  --> [${argIndex}] Pointer: 0x${hexData}${COLORS.reset}`);
        } else {
            // Hex
            if ((!hexData.includes("-") && [32, 40, 48, 64].includes(hexData.length)) || isUUID(hexData) || hexValue) {
                console.log(`${colorKey}  --> [${argIndex}] Hex: ${hexData}${COLORS.reset}`);
            }

            // Base64
            Java.perform(function () {
                const byteBuffer = Java.array("byte", byteArrayView);
                const base64Data = Java.use("java.util.Base64").getEncoder().encodeToString(byteBuffer);
                console.log(`${colorKey}  --> [${argIndex}] Base64: ${base64Data}${COLORS.reset}`);
            });
        }
    }
}

const attachFunction = (module) => {
    console.log(`[*] Module attached: ${module["name"]}`);
    const colorKey = randomColor();
    Interceptor.attach(module["address"], {
        onEnter: function (args) {
            console.log(`${colorKey}[+] onEnter: ${module["name"]}${COLORS.reset}`);

            // RangeError Patch
            for (let i = 0; i < 10; i++) {
                if (args[i].toString().length !== 12) {
                    break;
                }
                showVariable(args[i], colorKey, i, false);
            }
        },
        onLeave: function (retval) {
            console.log(`${colorKey}[-] onLeave: ${module["name"]}${COLORS.reset}`);
            showVariable(retval, colorKey, 0, false);
        }
    });
}

const attachVariable = (module) => {
    const colorKey = randomColor();
    console.log(`${colorKey}[+] VarEnter: ${module["name"]}${COLORS.reset}`);
    showVariable(module["address"], colorKey, 0, false);
    console.log(`${colorKey}[-] VarLeave: ${module["name"]}${COLORS.reset}`);
}


setTimeout(function () {
    console.log("---");
    console.log("Capturing Android app...");

    // Native
    const libraries = searchLibraries();
    if (libraries.length > 0) {
        console.log(`[*] Native libraries found (${libraries.length})`);

        let variableCount = 0;
        let functionCount = 0;
        for (const library of libraries) {
            const modules = searchModules(library);
            const fileName = library["path"].substring(library["path"].lastIndexOf("/") + 1);
            console.log(`[>] Attach: ${fileName} (${modules.length})`);
            for (const module of modules) {
                try {
                    if (module["type"] === "variable" && (VARIABLE || FUNCTION)) {
                        variableCount++;
                        attachVariable(module);
                    } else if (FUNCTION) {
                        functionCount++;
                        attachFunction(module);
                    }
                } catch (e) {
                    console.log(`${COLORS.red}${e}${COLORS.reset}`);
                }
            }
        }
        console.log(`[>] Variables count: ${variableCount}`);
        console.log(`[>] Functions count: ${functionCount}`);
    } else {
        console.log(`${COLORS.red}[!] No native library found${COLORS.reset}`);
    }

    console.log("Capturing setup completed");
    console.log("---");
}, 0);