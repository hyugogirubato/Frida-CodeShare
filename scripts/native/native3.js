/**@@@+++@@@@******************************************************************
 **
 ** Native Interceptor frida script v3.0 hyugogirubato
 **
 ** frida -D "DEVICE" -l "native.js" -f "PACKAGE"
 ** frida -D "DEVICE -l "native.js" -F
 ** frida -p "PID" -l "native.js"
 ** frida "C:\Program Files\Producer\Software.exe" -l native.js
 **
 ** Update: https://github.com/hyugogirubato/Frida-CodeShare/releases/tag/v1.2.2
 **
 ***@@@---@@@@******************************************************************
 */

// https://play.google.com/store/apps/details?id=com.apple.android.music
// frida -U -l native3.js -f com.apple.android.music

const METHODS = {
    static: {
        'libandroidappmusic.so': [
            // Hook by symbol name matching (resolved at runtime)
            'storeservicescore::FairPlaySubscriptionStatus *__fastcall storeservicescore::FairPlaySubscriptionStatus::status(storeservicescore::FairPlaySubscriptionStatus *this, __int64 a2)',
            '__int64 FootHillNative::FootHillGetID(FairPlayHWInfo_ *)',
            '__int64 __fastcall storeservicescore::FairPlay::getSubscriptionStatus(storeservicescore::FairPlay *this)',
            '__int64 __fastcall storeservicescore::FairPlay::getDeviceSupportInfo(storeservicescore::FairPlay *this)',
            '__int64 storeservicescore::FairPlay::anisetteRequest(std::shared_ptr<storeservicescore::FairPlayData> &,std::shared_ptr<storeservicescore::FairPlayData> &)',
            '__int64 __fastcall storeservicescore::FairPlayData::FairPlayData(storeservicescore::FairPlayData *this)',
            '__int64 __fastcall storeservicescore::FairPlayData::base64EncodedString(storeservicescore::FairPlayData *this)',

            // Hook by explicit offset - useful when symbol is stripped
            {0x686CB0: '__int64 __fastcall storeservicescore::RequestContext::fairPlay(storeservicescore::RequestContext *this)'},
            {0x686D80: '__int64 __fastcall storeservicescore::RequestContext::fairPlayDirectoryPath(storeservicescore::RequestContext *this)'},
            {0x686DB0: '__int64 storeservicescore::RequestContext::setFairPlayDirectoryPath(std::string const&)'},
            {0x686E60: '__int64 __fastcall storeservicescore::RequestContext::getFairPlaySubscriptionStatusDescription(storeservicescore::RequestContext *this)'}
        ],
        // Example: To hook ALL functions in another library:
        // 'lib2.so': []
    },
    dynamic: {
        includes: ['FairPlay'],     // Hook any function with "FairPlay" in name
        excludes: ['Java_']         // Skip JNI bridge functions
    }
};

const CONFIG = {
    /**
     * Filter libraries by package path. undefined = all libraries.
     */
    package: undefined,
    /**
     * File extensions to consider as native libraries.
     */
    extension: ['.so', '.dll', '.exe'],
    /**
     * Delay (ms) before hooking. Increase if libraries load late.
     */
    timeout: 0,
    interceptor: {
        /** Hook variable symbols (not implemented). */
        variable: false,
        /** Hook function symbols. */
        function: true,
        /**
         * IDA/Ghidra image base to subtract from offsets.
         * Set to 0 if offsets are already relative.
         */
        base_address: 0x0,
        /** Re-read pointer args in onLeave to detect mutations. */
        recursive: true,
        /**
         * Maximum bytes to read when probing memory for readable data.
         * Prevents reading huge blobs when a null terminator is far away.
         */
        max_read_bytes: 4096,
        /** Min/max args to probe for dynamic hooks (no signature). */
        min_param_count: 2,
        max_param_count: 6
    },
    /**
     * Enable ANSI colors in output.
     * Red=failed, Yellow=not found, Green=static, White=dynamic.
     */
    color: true,
    /** Print detailed debug info (descriptors, library metadata). */
    debug: false
};

// Color codes for terminal output
const MSG_RESET = '\x1b[0m';
const MSG_COLOR = {
    RED: '\x1b[31m',
    GREEN: '\x1b[32m',
    YELLOW: '\x1b[33m',
    BLUE: '\x1b[34m',
    MAGENTA: '\x1b[35m',
    CYAN: '\x1b[36m',
    WHITE: '\x1b[37m'
};

function print(message, color) {
    // message = message instanceof Object ? JSON.stringify(message, null, 2) : message;
    console.log(color && CONFIG.color ? `${color}${message}${MSG_RESET}` : message);
}

// ---------------------------------------------
// @Utils - Human-readable memory reader
// ---------------------------------------------

/** Read raw bytes from a pointer address. Returns a Uint8Array or null if unreadable. */
function readBytes(address) {
    try {
        const p = new NativePointer(address);
        // First try to find the null terminator within MAX_READ_BYTES
        let size = 0;
        while (size < CONFIG.function.max_read_bytes) {
            try {
                if (p.add(size).readU8() === 0) break;
            } catch (e) {
                break;
            }
            size++;
        }
        if (size === 0) return null;
        return new Uint8Array(p.readByteArray(size));
    } catch (e) {
        return null;
    }
}

/** Check if bytes are mostly printable ASCII/UTF-8 (>80% threshold). */
function isPrintable(bytes) {
    if (!bytes || bytes.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < bytes.length; i++) {
        const b = bytes[i];
        // Printable ASCII + common UTF-8 continuation bytes
        if ((b >= 0x20 && b <= 0x7E) || b === 0x0A || b === 0x0D || b === 0x09 || b >= 0x80) {
            printable++;
        }
    }
    return (printable / bytes.length) > 0.8;
}

/** Convert bytes to hex string with optional separator. */
function toHex(bytes, sep = '') {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(sep);
}

/** Parse function signature string or {offset: signature} into descriptor object. */
function parseDescriptor(method) {
    let funcOffset = undefined;
    let funcString = method;

    if (method instanceof Object) {
        const entries = Object.entries(method);
        if (entries.length !== 1) {
            throw new Error('Descriptor object must contain exactly one entry');
        }
        [funcOffset, funcString] = entries[0];
        funcOffset -= CONFIG.interceptor.base_address;
    }

    // Split the function string into return type and the rest of the signature
    let [returnType, ...rest] = funcString.split(/(__fastcall|__usercall)/);

    // Support for simple functions (without calling conventions or arguments)
    if (!rest.length) {
        returnType = funcString.split('(')[0].split(/\s+/).slice(0, -1).join(' ');
        rest = ['', funcString.replaceAll(returnType, '')];
    }

    // Extract function name and arguments
    const [funcName, args] = rest[1].split('(');

    // Clean argument list (remove closing parenthesis)
    const cleanArgs = args.slice(0, -1);

    // Parse arguments into type and variable name pairs
    const argDetails = cleanArgs === 'void' ? [{type: 'void', name: 'this'}] : cleanArgs.split(',')
        .map(arg => arg.trim())     // Remove extra spaces
        .filter(Boolean)            // Remove empty strings
        .map(arg => {
            const parts = arg.split(/\s+/);
            const varName = parts.pop();    // Last part is the variable name
            const type = parts.join(' ');   // Remaining parts are the type
            return {type: type.trim(), name: varName.trim()};
        });

    return {
        offset: funcOffset,
        ret: returnType.trim(),    // Return type (e.g., 'void')
        name: funcName.trim(),      // Function name (e.g., '~__shared_ptr_emplace')
        args: argDetails            // Array of { type, name } for each argument
    };
}

/** Attach interceptor to function. Logs entry args and exit return value. */
function hookFunction(funcObj) {
    if (CONFIG.debug) {
        /*
        {
          "type": "function",
          "name": "storeservicescore::FairPlaySubscriptionStatus::status",
          "address": "0x7c6289a9f8",
          "method": "static",
          "library": "libandroidappmusic.so",
          "offset": 4188664,
          "ret": "storeservicescore::FairPlaySubscriptionStatus *",
          "args": [
            {
              "type": "storeservicescore::FairPlaySubscriptionStatus",
              "name": "*this"
            },
            {
              "type": "__int64",
              "name": "a2"
            }
          ],
          "pattern": [
            "storeservicescore",
            "FairPlaySubscriptionStatus",
            "status"
          ]
        }
         */
        print(JSON.stringify(funcObj, null, 2), MSG_COLOR.BLUE);
    }

    Interceptor.attach(funcObj.address, {
        onEnter: function (args) {
            print(`[+] onEnter: ${funcObj.name}`);
            this.params = [];

            // TODO: setup params array and keep type

            if (funcObj.method === 'static') {
                for (let i = 0; i < funcObj.args.length; i++) {
                    this.params = args[i];
                    print(`\t-> [${i}](${funcObj.args[i].type}) ${funcObj.args[i].name} = ${args[i]}`);
                }
            } else {
                // TODO: impl dynamic params count detection
            }

            // TODO: printHumanReadable
        },
        onLeave: function (retval) {
            print(`[-] onLeave: ${funcObj.name}`);
            print(`\t<- [-1](${funcObj.ret}) ret = ${retval}`);

            // Show args after call (RECURSIVE mode - detect mutations)
            if (CONFIG.interceptor.recursive) {
                for (let i = 0; i < this.params.length; i++) {
                    // TODO: print memory
                }
            }
        }
    });

    print(
        `[${funcObj.library}](${funcObj.address}) ${funcObj.name}`,
        funcObj.method === 'static' ? MSG_COLOR.GREEN : MSG_COLOR.WHITE
    );
}


// ---------------------------------------------
// @Core
// ---------------------------------------------

/** Get loaded libraries filtered by package and extension. */
function getLibraries() {
    try {
        let libraries = Process.enumerateModules();
        // Filter by package if specified
        libraries = CONFIG.package ? libraries.filter(l => l.path.includes(CONFIG.package)) : libraries;
        // Filter libraries by extensions
        return libraries.filter(l =>
            CONFIG.extension.some(e => l.path.endsWith(e))
        );
    } catch (e) {
        print(e.message);
        return [];
    }
}

/** Find library by exact name. */
function getLibrary(name) {
    const libraries = getLibraries().filter(l => l.name === name);
    return libraries.length === 1 ? libraries[0] : undefined;
}

/** Enumerate symbols + exports from library. */
function getFunctions(library) {
    try {
        // https://frida.re/news/2025/01/09/frida-16-6-0-released/
        const functions = library.enumerateSymbols().map(item => ({
            type: item.type,
            name: item.name,
            address: item.address
        }));

        library.enumerateExports().forEach(item => {
            if (!functions.includes(item)) {
                functions.push(item);
            }
        });

        return functions;
    } catch (e) {
        print(e.message);
        return [];
    }
}

/** Build descriptors from METHODS.static for a library. */
function getStaticDescriptors(name) {
    const staticDescriptors = Object.entries(METHODS.static)
        .filter(([libName]) => libName === name)
        .flatMap(([libName, methods]) =>
            methods.map(method => ({
                method: 'static',
                library: libName,
                ...parseDescriptor(method)
            }))
        );

    const descriptors = staticDescriptors.map(desc => ({
        ...desc,
        pattern: ['::', 'std', '<', '>', '~']
            .reduce((acc, ph) => acc.split(ph).join('|&|'), desc.name.replaceAll(/@<[A-Za-z0-9]+>/g, ''))
            .split('|&|')
            .filter(Boolean)
    }));

    return descriptors.sort((a, b) => b.name.localeCompare(a.name));
}

/** Build descriptors from METHODS.dynamic by filtering library functions. */
function getDynamicDescriptors(library, items) {
    /*
    {
      "type": "function",
      "name": "_ZNK17storeservicescore26FairPlaySubscriptionStatus6statusEv",
      "address": "0x7c59c0f9f8"
    }
     */
    const {includes, excludes} = METHODS.dynamic;
    const baseAddr = parseInt(library.base, 16);

    return items
        .filter(item =>
            item.type === 'function' &&
            includes.some(i => item.name.includes(i)) &&
            !excludes.some(e => item.name.includes(e))
        )
        .map(item => ({
            name: item.name,
            method: 'dynamic',
            library: library.name,
            offset: parseInt(item.address, 16) - baseAddr,
            ret: undefined,
            args: [],
            pattern: []
        }));
}


// ---------------------------------------------
// @Main
// ---------------------------------------------

setTimeout(() => {
    print('Capturing Native process...\n---');

    const hooked = new Set();  // To track hooked function addresses
    const libraries = getLibraries();  // Get the list of libraries to hook

    // Iterate over each library
    libraries.forEach(lib => {
        const libName = lib.name;
        const libAddr = parseInt(lib.base, 16);
        const functions = getFunctions(lib);  // Get functions for the current library

        const globalHook = METHODS.static[libName]?.length === 0;  // Determine if global hook is needed

        // Get descriptors for static and dynamic functions
        let descriptors = [...getStaticDescriptors(libName), ...getDynamicDescriptors(lib, functions)]

        // Skip if no descriptors for the library and no global hook needed
        if (!globalHook && !descriptors.length) return;

        if (CONFIG.debug) {
            /*
            {
              "name": "libasyncio.so",
              "version": null,
              "base": "0x7d781c6000",
              "size": 36864,
              "path": "/system/lib64/libasyncio.so"
            }
             */
            print(JSON.stringify(lib, null, 2), MSG_COLOR.BLUE);
        }

        // Iterate over each function in the library
        functions.forEach(func => {
            // Skip early if there is nothing left to hook for this library:
            if (!globalHook && !descriptors.length) return;

            // Skip functions that were already hooked to avoid duplicate hooks
            if (hooked.has(func.address)) return;

            // Handle variable symbols separately (if variable interception is enabled)
            if (func.type === 'variable' && CONFIG.interceptor.variable) {
                // TODO: attachVariable(func)
                // hooked.add(func.address); // Mark variable as handled
            }

            // Skip anything that is not a function, or if function interception is disabled
            if (func.type !== 'function' || !CONFIG.interceptor.function) {
                return;
            }

            let descriptor;

            // If not a global hook, check if the function matches any descriptor
            if (!globalHook) {
                const funcAddr = parseInt(func.address, 16);

                // Check if the function name matches the pattern in any of the descriptors
                for (const desc of descriptors) {
                    const funcOffset = desc.offset ? libAddr + desc.offset : undefined;

                    if (desc.pattern.every(p => func.name.includes(p)) || funcAddr === funcOffset) {
                        descriptor = desc;
                        break;
                    }
                }

                // If no descriptor found, skip this function
                if (!descriptor) return;
            }

            // Hook the function and mark it as hooked
            try {
                hookFunction({...func, ...descriptor, library: libName});  // Hook the function
                hooked.add(func.address);
            } catch (e) {
                print(`[!] ${e.message}: ${descriptor.name} (${descriptor.library})`, MSG_COLOR.RED);
            }

            // Remove the hooked descriptor from all lists
            descriptors = descriptors.filter(d => d !== descriptor);
        });

        // Report any descriptors that didn't match a function in the library
        descriptors.forEach(desc => print(`[!] Function not found: ${desc.name} (${desc.library})`, MSG_COLOR.YELLOW));
    });

    print('---\nCapturing setup completed (' + hooked.size + ' hooks active)');
}, CONFIG.timeout);
