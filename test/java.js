/**@@@+++@@@@******************************************************************
 **
 ** Android Java Interceptor frida script v1.1 hyugogirubato (Test)
 **
 ** frida -D "DEVICE" -l "java.js" -f "com.crunchyroll.crunchyroid"
 **
 ** Update: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.2.1
 **
 ***@@@---@@@@******************************************************************
 */


/**
 * Use an empty list to catch everything.
 * Use function names to filter.
 * Filter modules attached to a string or regex value.
 */
const LIBRARIES = [
    {
        "name": "com.ellation.crunchyroll.api.etp.content.EtpContentServiceDecorator",
        "methods": []
    },
    {
        "name": "android.webkit.WebView",
        "methods": []
    }
];

/**
 * Use to filter loaders.
 * Use "undefined" to intercept all loader processes (system included).
 */
const PACKAGE = undefined;

/**
 * Customize output display:
 * - COLOR: Colorize the output.
 * - TIMEOUT: Waiting time before attaching processes.
 * - DEBUG: Additional information on the current process.
 */
const COLOR = true;
const TIMEOUT = 0;
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
    let libraries = Java.enumerateMethods(`**!*`);

    // Package
    if (PACKAGE) {
        const tmp = libraries.filter((l) =>
            l["loader"]?.toString().toLowerCase().includes(PACKAGE.toLowerCase())
        );

        if (tmp.length > 0) {
            libraries = tmp;
        } else {
            print("Error: Cannot filter by package.", "red");
        }
    }

    // Libraries
    if (LIBRARIES.length > 0) {
        libraries = libraries.map((l) => ({
            ...l,
            classes: l["classes"].filter((c) => LIBRARIES.some((L) =>
                (L["name"] instanceof RegExp && c["name"].match(L["name"])) ||
                c["name"].toLowerCase().includes(L["name"].toLowerCase())
            ))
        })).filter(l => l["classes"].length > 0);
    }
    return libraries;
}

const searchModules = (library) => {
    let classes = library["classes"];
    if (LIBRARIES.length > 0) {
        const tmp = [];
        for (const c of classes) {
            for (const L of LIBRARIES) {
                let match;
                if (L["name"] instanceof RegExp) {
                    match = c["name"].match(L["name"]);
                } else {
                    match = c["name"].toLowerCase().includes(L["name"].toLowerCase());
                }

                // Methods
                if (match) {
                    let methods = c["methods"];
                    if (L["methods"].length > 0) {
                        methods = methods.filter((m) => {
                            return L["methods"].some((M) => {
                                if (M instanceof RegExp) {
                                    return m.match(M);
                                } else {
                                    return m.toLowerCase().includes(M.toLowerCase());
                                }
                            });
                        });
                    }

                    if (methods.length > 0) {
                        tmp.push({...c, methods: methods});
                    }
                }
            }
        }
        classes = tmp;
    }

    return classes;
}

const methodParams = (method) => {
    const params = [];
    try {
        method.overload().implementation;
    } catch (e) {
        const pattern = /\.overload\((.*?)\)/g;
        let match;
        while ((match = pattern.exec(e.toString())) !== null) {
            params.push(match[1].replace(/'/g, '').split(',').map(type => type.trim()));
        }
    }
    return params;
}

const bytesToBase64 = (bytes) => {
    const instance = Java.use("java.util.Base64");
    try {
        return instance.getEncoder().encodeToString(bytes);
    } catch {
        return instance.getEncoder().encodeToString([bytes & 0xff]);
    }
}

const Base64ToHex = (base64) => {
    const bytes = Java.use("java.util.Base64").getDecoder().decode(base64);
    let hexData = "";
    for (let i = 0; i < bytes.length; i++) {
        let value = bytes[i].toString(16);
        if (value.length % 2 === 1) {
            value = "0" + value;
        }
        hexData += value;
    }
    return hexData;
}

const parseType = (value) => {
    value = JSON.stringify(value);
    const classNameMatch = value.match(/\$className:\s*([^,>]+)/);
    const instanceMatch = value.match(/<instance:\s*([^,>]+)/);
    return classNameMatch ? classNameMatch[1] : instanceMatch[1];
}

const parseMemory = (type, value) => {
    const result = {};
    if (value) {
        switch (type) {
            case "java.lang.Integer":
                result[type] = value.intValue();
                break;
            case "java.util.Map":
                // https://github.com/frida/frida/issues/1201#issuecomment-594243390
                result[type] = {};
                Object.keys(value).forEach((k) => {
                    result[type][k] = parseMemory(parseType(value), value[k]);
                });
                break;
            case "java.security.cert.X509Certificate":
            case "java.security.cert.Certificate":
            case "java.security.Key":
                value = value.getEncoded();
            case "[B":
                result[type] = value;
                const b64Value = bytesToBase64(value);
                result["Base64"] = b64Value;
                const hexValue = Base64ToHex(b64Value);
                if (!hexValue.includes("-") && [32, 40, 48, 64].includes(hexValue.length)) {
                    result["Hex"] = hexValue;
                }
                break;
            case "java.util.List":
            case "java.util.Set":
            case "java.util.ArrayList":
            case "org.json.JSONArray":
                value = value.toArray();
                result[type] = [];
                value.forEach((e) => {
                    const items = Object.entries(parseMemory(parseType(value), e));
                    for (const [key, value] of items) {
                        result[type].push(value);
                    }
                });
                break;
            case "pointer":
            case "[Ljava.lang.String;":
            case "[Ljava.lang.Long;":
            case "[Ljava.security.cert.Certificate;":
            case "[Ljava.security.cert.X509Certificate;":
            case "java.lang.Long":
            case "java.lang.String":
            case "boolean":
            case "org.apache.cordova.CallbackContext":
            case "javax.net.ssl.SSLSession":
            case "kotlin.jvm.functions.Function0":
            case "android.webkit.WebView":
            case "android.webkit.SslErrorHandler":
            case "android.webkit.WebResourceRequest":
            case "android.webkit.WebResourceError":
            case "android.net.http.SslError":
            case "java.util.Date":
            case "java.security.Provider":
            case "int":
            case "java.security.AlgorithmParameters":
            default:
                if (type.match(/^\[L.*;$/)) {
                    result[type] = [];
                    value.forEach((e) => {
                        const match = type.match(/^\[L(.+?);$/);
                        result[type].push(parseMemory(match ? match[1] : parseType(type), e));
                    });
                } else {
                    try {
                        result[type] = value.toString() === "[object Object]" ? JSON.stringify(value) : value.toString();
                    } catch (e) {
                        result[type] = value;
                    }
                }
                break;
        }
    } else {
        result[type] = value;
    }
    return result;
}

const printMemory = (type, value, index, color) => {
    const items = Object.entries(parseMemory(type, value));
    for (let [key, value] of items) {
        // Value
        try {
            value = value instanceof Object ? JSON.stringify(value) : value;
        } catch (e) {
            // pass
        }

        // Type
        if (key.startsWith("java.")) {
            const match = key.match(/[^.]+$/);
            key = match ? match[0] : key;
        }
        print(`  --> [${index}] ${key}: ${value}`, color);
    }
}

const attachFunction = (module) => {
    const instance = Java.use(module["name"]);
    for (const m of module["methods"]) {
        const color = Color();
        const method = instance[m];
        if (!method) {
            print(`[!] Unable to attach: ${module["name"]}.${m}`, "red");
            continue;
        }

        print(`[*] Module attached: ${module["name"]}.${m}`);
        const params = methodParams(method);
        for (const p of params) {
            const returnType = method.overload(...p).returnType.type;
            if (DEBUG) {
                print(JSON.stringify({
                    instance: module["name"],
                    method: m,
                    params: p,
                    returnType: returnType
                }, null, 2));
            }

            method.overload(...p).implementation = function (...args) {
                print(`[+] onEnter: ${module["name"]}.${m}`, color);
                for (let i = 0; i < p.length; i++) {
                    printMemory(p[i], args[i], i, color);
                }

                print(`[-] onLeave: ${module["name"]}.${m}`, color);
                const retval = method.overload(...p).call(this, ...args);
                if (returnType !== "void") {
                    printMemory(returnType, retval, 0, color);
                    return retval;
                }
            }
        }
    }

}


setTimeout(function () {
    print("Capturing Java process...\n---");
    if (Java.available) {
        let libraries = searchLibraries();
        if (libraries.length > 0) {
            print(`[*] Java libraries found (${libraries.length})`);

            Java.perform(function () {
                for (const library of libraries) {
                    const modules = searchModules(library);
                    let loader;
                    try {
                        loader = library["loader"].toString().split(" ")[0];
                    } catch (e) {
                        loader = library["loader"];
                    }

                    print(`[>] Attach: ${loader} (${modules.length})`);
                    if (DEBUG) {
                        print(JSON.stringify({
                            ...library,
                            modules: modules
                        }, null, 2));
                    }
                    for (const module of modules) {
                        attachFunction(module);
                    }
                }
            });
        } else {
            print("[!] No Java library found", "red");
        }
    } else {
        print("[!] Java unavailable", "red");
    }

    print("Capturing setup completed\n---");
}, TIMEOUT);