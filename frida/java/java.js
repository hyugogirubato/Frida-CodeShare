/**@@@+++@@@@******************************************************************
 **
 ** Android Java Interceptor frida script v1.0 hyugogirubato
 **
 ** frida -D "DEVICE" -l "java.js" -f "PACKAGE"
 **
 ** Update: Syntax upgrade to the latest JS version
 **
 ***@@@---@@@@******************************************************************
 */

// Custom params
const FUNCTIONS = [
    {
        "package": "com.example.ui.services",
        "class": "MainService",
        "function": [] // empty for intercept everything
    },
    {
        "package": "com.example.ui.fragment",
        "class": "LoginFragment",
        "function": ["login"]
    }
]


let index = 0; // color index
const BASE64 = Java.use("java.util.Base64");
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


const searchFunction = (_package, _class, _func = undefined) => {
    const items = [];
    Java.enumerateMethods(`*${_package}.${_class}*!*`).forEach((method) => {
        method["classes"].forEach((module) => {
            if (_func) {
                if (module["methods"].includes(_func)) {
                    items.push({key: module["name"], value: _func});
                }
            } else {
                module["methods"].forEach((func) => {
                    items.push({key: module["name"], value: func});
                });
            }
        });
    });
    return items;
};


const getArgument = (arg) => {
    let value = arg;
    let type = arg.constructor.name;

    if (Array.isArray(value)) {
        try {
            value = BASE64.getEncoder().encodeToString(value);
            type = "[B";
        } catch (e) {
            // Ignore the error and keep the original values
        }
    } else if (type === "Object") {
        value = JSON.stringify(value, null, 2);
    } else if (type === "Date") {
        value = value.toString();
    } else if (type === "Error") {
        value = value.stack || value.toString();
    } else if (type === "RegExp") {
        value = value.toString();
    } else if (type === "Function") {
        value = value.toString();
    } else if (type === "I") {
        value = value.toString();
        type = "Function";
    }
    return [type, value];
};


const attachFunction = (_class, _method) => {
    console.log(`[*] Module attached: ${_class}.${_method}`);

    const colorKey = randomColor();
    const targetClass = Java.use(_class);

    // Get all method overloads
    const targetMethodOverloads = targetClass[_method].overloads;

    // Iterate over each method overload
    targetMethodOverloads.forEach((method) => {
        method.implementation = function () {
            console.log(`${colorKey}[+] onEnter: ${_class}.${_method}${COLORS.reset}`);

            for (let i = 0; i < arguments.length; i++) {
                const arg = getArgument(arguments[i]);
                console.log(`${colorKey}  --> [${i}] ${arg[0]}: ${arg[1]}${COLORS.reset}`);
            }

            console.log(`${colorKey}[-] onLeave: ${_class}.${_method}${COLORS.reset}`);
            const result = method.apply(this, arguments);
            if (result) {
                const arg = getArgument(result);
                console.log(`${colorKey}  --> [0] ${arg[0]}: ${arg[1]}${COLORS.reset}`);
                return result;
            }
        };
    });
};


setTimeout(function () {
    console.log("---");
    console.log("Capturing Android app...");
    if (Java.available) {
        console.log("[*] Java available");

        let presentCount = 0;
        let absentCount = 0;
        Java.perform(function () {
            for (const module of FUNCTIONS) {
                if (module["function"].length > 0) {
                    for (const func of module["function"]) {
                        const items = searchFunction(module["package"], module["class"], func);
                        if (items.length > 0) {
                            presentCount += items.length
                            items.forEach(item => attachFunction(item.key, item.value));
                        } else {
                            absentCount += 1;
                            console.log(`${COLORS.red}[!] No function found: ${module["package"]}.${module["class"]}.${func}${COLORS.reset}`);
                        }
                    }
                } else {
                    const items = searchFunction(module["package"], module["class"], undefined);
                    presentCount += items.length
                    items.forEach(item => attachFunction(item.key, item.value));
                }
            }
        });
        console.log(`[>] Present count: ${presentCount}`);
        console.log(`[>] Absent count: ${absentCount}`);
    } else {
        console.log(`${COLORS.red}[!] Java unavailable${COLORS.reset}`);
    }

    console.log("Capturing setup completed");
    console.log("---");
}, 0);