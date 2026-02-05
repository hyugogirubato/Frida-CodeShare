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
            'void __fastcall std::__shared_ptr_emplace<storeservicescore::FairPlayData>::~__shared_ptr_emplace(std::__shared_weak_count *a1)',
            'void __usercall storeservicescore::FairPlaySubscriptionStatus::status(storeservicescore::FairPlaySubscriptionStatus *this@<X0>, __int64 a2@<X8>)',
            '__int64 FootHillNative::FootHillGetID()'
        ],
        'libstoreservicescore.so': [
            // Hook by explicit offset - useful when symbol is stripped
            {0x00000000001851C4: '__int64 __usercall storeservicescore::FairPlay::subscriptionSyncData@<X0>(storeservicescore::FairPlay *this@<X0>, const unsigned __int8 *a2@<X3>, __int64 a3@<X1>, unsigned int a4@<W2>, unsigned int a5@<W4>, _QWORD *a6@<X8>)'},
            {0x0000000000184124: 'void __fastcall storeservicescore::FairPlay::FairPlay(storeservicescore *a1, __int128 *a2, __int128 *a3, int a4, int a5, int a6, int a7, int a8, int a9, int a10, char a11, int a12, void *a13)'},
            {0x0000000000184EE0: '__int64 __fastcall storeservicescore::FairPlay::subscriptionRequest(storeservicescore::FairPlay *a1, __int64 a2, unsigned int a3, mediaplatform::Data **a4, __int64 a5, _QWORD *a6)'},
            {0x0000000000184C40: 'unsigned __int8 *__usercall storeservicescore::FairPlay::keybagSyncData@<X0>(storeservicescore::FairPlay *this@<X0>, __int64 a2@<X1>, unsigned int a3@<W2>, _QWORD *a4@<X8>)'},
            {0x0000000000184D48: 'unsigned __int8 *__usercall storeservicescore::FairPlay::keybagSyncData@<X0>(__int64 a1@<X0>, __int64 a2@<X1>, unsigned int a3@<W2>, __int64 a4@<X3>, _QWORD *a5@<X8>)'},
            {0x000000000018F648: '__int64 __usercall storeservicescore::RequestContext::getFairPlaySubscriptionStatusDescription@<X0>(storeservicescore::RequestContext *this@<X0>, _QWORD *a2@<X8>)'},
            {0x000000000018C180: '__int64 __usercall storeservicescore::RequestContext::fairPlayDirectoryPath@<X0>(storeservicescore::RequestContext *this@<X0>, _QWORD *a2@<X8>)'},
            {0x00000000001849E8: 'bool __fastcall storeservicescore::FairPlay::importKeybagData(storeservicescore::FairPlay *this, const unsigned __int8 *a2, unsigned int a3)'},
            {0x00000000001572C4: '__int64 __usercall storeservicescore::FairPlayData::base64EncodedCFString@<X0>(storeservicescore::FairPlayData *this@<X0>, _QWORD *a2@<X8>)'},
            {0x0000000000157120: '__int64 __usercall storeservicescore::FairPlayData::base64EncodedString@<X0>(storeservicescore::FairPlayData *this@<X0>, __int64 a2@<X8>)'},
            {0x000000000018C010: '__int64 __usercall storeservicescore::RequestContext::fairPlay@<X0>(storeservicescore::RequestContext *this@<X0>, _QWORD *a2@<X8>)'},
            {0x0000000000171814: 'void __fastcall storeservicescore::PlaybackLeaseSession::_logFairPlaySubscriptionStatus(storeservicescore::RequestContext **this)'},
            {0x0000000000118948: '__int64 __fastcall storeservicescore::RequestContextConfig::fairPlayDirectoryPath(storeservicescore::RequestContextConfig *this)'},
            {0x00000000001A71F0: 'void __fastcall storeservicescore::FairPlayErrorCategory::~FairPlayErrorCategory(storeservicescore::FairPlayErrorCategory *this)'},
            {0x0000000000185318: 'void __usercall storeservicescore::FairPlay::getSubscriptionStatus(storeservicescore::FairPlay *this@<X0>, _QWORD *a2@<X8>)'},
            {0x00000000001BB030: '__int64 __usercall storeservicescore::PlaybackLeaseMessage::fairPlayCertificate@<X0>(__int64 this@<X0>, _QWORD *a2@<X8>)'},
            {0x0000000000184B1C: '__int64 __fastcall storeservicescore::FairPlay::importSubscriptionResponse(storeservicescore::FairPlay *a1, __int64 a2)'},
            {0x00000000001A6848: '__int64 *__fastcall storeservicescore::FairPlayErrorCategory::name(storeservicescore::FairPlayErrorCategory *this)'},
            {0x0000000000157034: '__int64 __fastcall storeservicescore::FairPlayData::FairPlayData(__int64 this, const unsigned __int8 *a2, int a3)'},
            {0x00000000001846D8: '__int64 __fastcall storeservicescore::FairPlay::anisetteRequest(__int64 a1, __int64 a2, _QWORD *a3, _QWORD *a4)'},
            {0x000000000018D620: '__int64 __fastcall storeservicescore::RequestContext::setFairPlayDirectoryPath(__int64 a1, unsigned __int8 *a2)'},
            {0x00000000001BB19C: '__int64 __fastcall storeservicescore::PlaybackLeaseMessage::setFairPlayCertificate(__int64 result, __int64 *a2)'},
            {0x00000000000EE36C: '__int64 __usercall storeservicescore::FairPlayConfig::paddedId@<X0>(unsigned __int8 *a1@<X0>, __int64 a2@<X8>)'},
            {0x0000000000157074: '__int64 __fastcall storeservicescore::FairPlayData::FairPlayData(__int64 result, __int64 a2, int a3, int a4)'},
            {0x0000000000184878: '__int64 __fastcall storeservicescore::FairPlay::defaultContextIdentifier(storeservicescore::FairPlay *this)'},
            {0x0000000000184A74: 'bool __fastcall storeservicescore::FairPlay::importKeybagData(storeservicescore::FairPlay *a1, __int64 a2)'},
            {0x00000000001570B4: 'void __fastcall storeservicescore::FairPlayData::~FairPlayData(storeservicescore::FairPlayData *this)'},
            {0x0000000000184E54: 'bool __fastcall storeservicescore::FairPlay::stopSubscriptionLease(storeservicescore::FairPlay *this)'},
            {0x00000000001BE304: 'void __usercall storeservicescore::FairPlaySinf::_dataWithValue(const void *a1@<X1>, _QWORD *a2@<X8>)'},
            {0x00000000001BE444: '__int64 __fastcall storeservicescore::FairPlaySinf::DPInfoData(storeservicescore::FairPlaySinf *this)'},
            {0x00000000001BE480: '__int64 __fastcall storeservicescore::FairPlaySinf::identifier(storeservicescore::FairPlaySinf *this)'},
            {0x00000000001BE4F8: '__int64 __fastcall storeservicescore::FairPlaySinf::sinf2Data(storeservicescore::FairPlaySinf *this)'},
            {0x0000000000184694: '__int64 __fastcall storeservicescore::FairPlay::anisetteRequest(__int64 a1, __int64 a2, __int64 a3)'},
            {0x00000000001BE4BC: '__int64 __fastcall storeservicescore::FairPlaySinf::sinfData(storeservicescore::FairPlaySinf *this)'},
            {0x00000000001573A0: '__int64 __fastcall storeservicescore::FairPlayData::length(storeservicescore::FairPlayData *this)'},
            {0x000000000011890C: '__int64 __fastcall storeservicescore::RequestContextConfig::setFairPlayDirectoryPath(__int64 a1)'},
            {0x0000000000157364: '__int64 __fastcall storeservicescore::FairPlayData::bytes(storeservicescore::FairPlayData *this)'},
            {0x00000000001875FC: 'void __usercall storeservicescore::RequestContext::_defaultFairPlayDirectoryPath(_WORD *a1@<X8>)'},
            {0x0000000000184394: '__int64 __fastcall storeservicescore::FairPlay::setLibraryDirectoryPath(__int64 a1, __int64 a2)'},
            {0x00000000001845B0: '__int64 __fastcall storeservicescore::FairPlay::contextIdentifierWithPath(__int64 a1, char *a2)'},
            {0x00000000001849AC: '__int64 __fastcall storeservicescore::FairPlay::hardwareInfo(storeservicescore::FairPlay *this)'},
            {0x00000000001856BC: '_DWORD *__usercall storeservicescore::FairPlay::getDeviceSupportInfo@<X0>(_QWORD *a1@<X8>)'},
            {0x00000000001BE09C: '__int64 *__fastcall storeservicescore::FairPlaySinf::FairPlaySinf(__int64 a1, __int64 a2)'},
            {0x000000000018448C: '__int64 __fastcall storeservicescore::FairPlay::setFileDirectoryPath(__int64 a1, int a2)'},
            {0x00000000001A6898: 'void __usercall storeservicescore::FairPlayErrorCategory::message(_WORD *a1@<X8>)'},
            {0x0000000000156FF8: '_QWORD *__fastcall storeservicescore::FairPlayData::FairPlayData(_QWORD *this)'},
            {0x00000000000EE1D0: '__int64 __fastcall storeservicescore::FairPlayConfig::config(__int64 a1)'}
        ]
        // Example: To hook ALL functions in another library:
        // 'lib2.so': []
    },
    dynamic: {
        includes: [],     // Hook any function with "FairPlay" in name
        excludes: ['Java_']         // Skip JNI bridge functions
    }
};


const CONFIG = {
    /** Filter libraries by package path. undefined = all libraries. */
    package: undefined,
    /** File extensions to consider as native libraries. */
    extension: ['.so', '.dll', '.exe'],
    /** Delay (ms) before hooking. Increase if libraries load late. */
    timeout: 1,
    interceptor: {
        /** Hook variable symbols (not implemented). */
        variable: false,
        /** Hook function symbols. */
        function: true,
        /** IDA/Ghidra image base to subtract from offsets. */
        base_address: 0x0,
        /** Re-read pointer args in onLeave to detect mutations. */
        recursive: false,
        /** Maximum bytes to read when probing memory. */
        max_read_bytes: 4096,
        /** Min/max args to probe for dynamic hooks (no signature). */
        min_param_count: 2,
        max_param_count: 6,
    },
    formater: {
        raw: false,
        base64: true,
        hex: false
    },
    /** Enable ANSI colors in output. */
    color: true,
    /** Print detailed debug info (descriptors, library metadata). */
    debug: false
};

// ---------------------------------------------
// @Logger - Colored console output
// ---------------------------------------------

class Logger {
    static COLOR = {
        RESET: '\x1b[0m',
        // BLACK: '\x1b[30m',
        RED: '\x1b[31m',
        GREEN: '\x1b[32m',
        YELLOW: '\x1b[33m',
        BLUE: '\x1b[34m',
        MAGENTA: '\x1b[35m',
        CYAN: '\x1b[36m',
        WHITE: '\x1b[37m'
    };

    static #colorIndex = 0;
    static #availableColors = Object.keys(Logger.COLOR).filter(k => !['RESET', 'RED'].includes(k));

    constructor(cycle = false) {
        if (cycle) {
            const key = Logger.#availableColors[Logger.#colorIndex];
            Logger.#colorIndex = (Logger.#colorIndex + 1) % Logger.#availableColors.length;
            this.color = Logger.COLOR[key];
        } else {
            this.color = Logger.COLOR.WHITE;
        }
    }

    static print(message, color) {
        console.log(color && CONFIG.color ? `${color}${message}${Logger.COLOR.RESET}` : message);

    }

    log(message) {
        Logger.print(message, this.color);
    }
}

// ---------------------------------------------
// @Utils - Base64 encoder/decoder
// https://github.com/frida/gumjs-base64/blob/master/index.js
// ---------------------------------------------

class Base64Encoder {
    constructor(value = null) {
        this.input = value;
        this.lookup = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
        this.revLookup = Object.fromEntries([...this.lookup].map((char, i) => [char, i]));
        this.revLookup['-'] = 62; // URL-safe base64
        this.revLookup['_'] = 63;
    }

    // Initialize with a value (string or int array)
    static from(value) {
        // String input
        if (typeof value === 'string') {
            return new Base64Encoder(value);
        }

        // Uint8Array or other TypedArray
        if (value instanceof Uint8Array || ArrayBuffer.isView(value)) {
            return new Base64Encoder(Array.from(value));
        }


        // ArrayBuffer
        if (value instanceof ArrayBuffer) {
            return new Base64Encoder(Array.from(new Uint8Array(value)));
        }

        // Regular array of integers
        if (Array.isArray(value) && value.every(num => Number.isInteger(num) && num >= 0 && num <= 255)) {
            return new Base64Encoder(value);
        }

        throw new Error('Input must be a string, Uint8Array, ArrayBuffer, or array of integers (0-255).');
    }

    // Encode to Base64
    encode() {
        const bytes = typeof this.input === 'string' ? this.#stringToBytes(this.input) : this.input;

        let base64 = '';
        for (let i = 0; i < bytes.length; i += 3) {
            const triplet = ((bytes[i] << 16) & 0xFF0000) |
                ((bytes[i + 1] << 8) & 0xFF00) |
                (bytes[i + 2] & 0xFF);

            base64 += this.lookup[(triplet >> 18) & 0x3F] +
                this.lookup[(triplet >> 12) & 0x3F] +
                (i + 1 < bytes.length ? this.lookup[(triplet >> 6) & 0x3F] : '=') +
                (i + 2 < bytes.length ? this.lookup[triplet & 0x3F] : '=');
        }

        return base64;
    }

    // Decode from Base64
    decode() {
        if (typeof this.input !== 'string') {
            throw new Error('Decode input must be a Base64 string.');
        }

        const b64 = this.input.replace(/[^A-Za-z0-9+/=_-]/g, '');
        const bytes = [];

        for (let i = 0; i < b64.length; i += 4) {
            const chunk = (this.revLookup[b64[i]] << 18) |
                (this.revLookup[b64[i + 1]] << 12) |
                (this.revLookup[b64[i + 2]] << 6) |
                this.revLookup[b64[i + 3]];

            bytes.push((chunk >> 16) & 0xFF);
            if (b64[i + 2] !== '=') bytes.push((chunk >> 8) & 0xFF);
            if (b64[i + 3] !== '=') bytes.push(chunk & 0xFF);
        }

        return this.#intArrayToString(bytes);
    }

    // Convert int array to string
    #intArrayToString(intArray) {
        if (!Array.isArray(intArray) || !intArray.every(num => Number.isInteger(num) && num >= 0 && num <= 255)) {
            throw new Error('Input must be an array of integers (0-255).');
        }

        return String.fromCharCode(...intArray);
    }

    // Convert string to UTF-8 byte array
    #stringToBytes(string) {
        const bytes = [];
        for (let i = 0; i < string.length; i++) {
            const codePoint = string.codePointAt(i);
            if (codePoint <= 0x7F) {
                bytes.push(codePoint);
            } else if (codePoint <= 0x7FF) {
                bytes.push(0xC0 | (codePoint >> 6), 0x80 | (codePoint & 0x3F));
            } else if (codePoint <= 0xFFFF) {
                bytes.push(0xE0 | (codePoint >> 12), 0x80 | ((codePoint >> 6) & 0x3F), 0x80 | (codePoint & 0x3F));
            } else {
                bytes.push(0xF0 | (codePoint >> 18), 0x80 | ((codePoint >> 12) & 0x3F), 0x80 | ((codePoint >> 6) & 0x3F), 0x80 | (codePoint & 0x3F));
                i++; // Skip next char for surrogate pairs
            }
        }
        return bytes;
    }
}

// ---------------------------------------------
// @Utils - Memory Readers (IDA/Ghidra types)
// ---------------------------------------------


/** Check if pointer looks valid (not null, not small int) */
function isValidPointer(ptr) {
    try {
        const val = typeof ptr === 'string' ? parseInt(ptr, 16) : ptr.toInt32 ? parseInt(ptr, 16) : ptr;
        return val > 0x10000 && val < 0x7FFFFFFFFFFF;
    } catch (e) {
        return false;
    }
}

/** Check if bytes are mostly printable ASCII/UTF-8 (>80% threshold). */
function isPrintable(bytes) {
    if (!bytes || bytes.length === 0) return false;
    let printable = 0;
    for (let i = 0; i < Math.min(bytes.length, 256); i++) {
        const b = bytes[i];
        // Printable ASCII + common UTF-8 continuation bytes
        if ((b >= 0x20 && b <= 0x7E) || b === 0x0A || b === 0x0D || b === 0x09) {
            printable++;
        }
    }
    return (printable / Math.min(bytes.length, 256)) > 0.75;
}

/** Convert bytes to hex string with optional separator. */
function toHex(bytes, sep = '') {
    return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join(sep);
}

/** Convert Uint8Array to string. */
function bytesToString(bytes) {
    try {
        return String.fromCharCode.apply(null, bytes);
    } catch (e) {
        // Fallback for large arrays
        let str = '';
        for (let i = 0; i < bytes.length; i++) {
            str += String.fromCharCode(bytes[i]);
        }
        return str;
    }
}

/**
 * Read std::string from memory (handles SSO - Small String Optimization)
 * @param {NativePointer} address - Pointer to std::string
 * @returns {Uint8Array|null} - String data as byte array
 */
function readStdString(address) {
    try {
        const p = new NativePointer(address);
        // Read string size at offset pointerSize
        const size = p.add(Process.pointerSize).readU16();
        if (size === 0 || size > CONFIG.interceptor.max_read_bytes) return null;

        // Check LSB for SSO (Small String Optimization)
        const LSB = p.readU8() & 1;
        let data;
        if (LSB === 0) {
            // SSO: data stored inline at address + 1
            data = p.add(1).readByteArray(size);
        } else {
            // Non-SSO: pointer to data at address + (pointerSize * 2)
            const dataPtr = p.add(Process.pointerSize * 2).readPointer();
            if (dataPtr.isNull()) return null;
            data = dataPtr.readByteArray(size);
        }
        return data ? new Uint8Array(data) : null;
    } catch (e) {
        return null;
    }
}

/**
 * Read std::vector from memory
 * @param {NativePointer} address - Pointer to std::vector
 * @returns {Uint8Array|null} - Vector data as byte array
 */
function readStdVector(address) {
    try {
        const p = new NativePointer(address);
        // Vector layout: [begin_ptr, end_ptr, capacity_ptr] or similar
        const beginPtr = p.readPointer();
        const endPtr = p.add(Process.pointerSize).readPointer();

        if (beginPtr.isNull() || endPtr.isNull()) return null;

        const size = endPtr.sub(beginPtr).toInt32();
        if (size <= 0 || size > CONFIG.interceptor.max_read_bytes) return null;

        const data = beginPtr.readByteArray(size);
        return data ? new Uint8Array(data) : null;
    } catch (e) {
        // Fallback: try alternative layout (size at offset 8)
        try {
            const p = new NativePointer(address);
            const size = p.add(8).readU16();
            if (size === 0 || size > CONFIG.interceptor.max_read_bytes) return null;
            const dataPtr = p.readPointer();
            if (dataPtr.isNull()) return null;
            const data = dataPtr.readByteArray(size);
            return data ? new Uint8Array(data) : null;
        } catch (e2) {
            return null;
        }
    }
}

/** Read shared_ptr managed object */
function readSharedPtr(address) {
    try {
        const p = new NativePointer(address);
        // shared_ptr: [T* ptr, control_block*]
        const objPtr = p.readPointer();
        if (objPtr.isNull() || !isValidPointer(objPtr)) return null;
        return {ptr: objPtr, address: objPtr.toString()};
    } catch (e) {
        return null;
    }
}

/**
 * Read raw bytes from address until null terminator or max limit.
 * @param {NativePointer|string} address
 * @returns {Uint8Array|null}
 */
function readBytes(address) {
    try {
        const p = new NativePointer(address);
        // First try to find the null terminator within max read bytes
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

/**
 * Read fixed-size buffer from memory.
 * @param {NativePointer} address
 * @param {number} size
 * @returns {Uint8Array|null}
 */
function readBuffer(address, size) {
    try {
        if (size <= 0 || size > CONFIG.interceptor.max_read_bytes) return null;
        const p = new NativePointer(address);
        const data = p.readByteArray(size);
        return data ? new Uint8Array(data) : null;
    } catch (e) {
        return null;
    }
}

// ---------------------------------------------
// @readValue - IDA/Ghidra Type Handler
// ---------------------------------------------

/**
 * Universal memory value interpreter with context awareness.
 * Attempts multiple interpretations and returns all successful ones.
 *
 * @param {NativePointer|string} address - Memory address to read
 * @param {string} [argType=''] - Type hint from function signature
 * @param {object} [context={}] - Context for size/type hints
 * @param {number} [context.nextArgValue] - Next argument value (often buffer size)
 * @param {number} [context.prevArgValue] - Previous argument value
 * @param {number} [context.sizeHint] - Explicit size hint for buffers
 * @param {number} [depth=0] - Recursion depth (prevents infinite loops)
 * @returns {Array<{type: string, value: any, size?: number}>}
 */
function readValue(address, argType = '', context = {}, depth = 0) {
    const results = [];
    const p = new NativePointer(address);
    const ptrVal = parseInt(address, 16);
    const typeLower = (argType || '').trim().toLowerCase();

    // Prevent infinite recursion
    const MAX_DEPTH = 3;
    if (depth > MAX_DEPTH) {
        results.push({type: 'max_depth', value: address.toString()});
        return results;
    }

    // ---------------------------------------------
    // 1. SCALAR VALUES (small integers, not pointers)
    // ---------------------------------------------
    if (!isValidPointer(p)) {
        results.push({type: 'Integer', value: ptrVal});
        if (ptrVal === 0 || ptrVal === 1) {
            results.push({type: 'Bool', value: ptrVal !== 0});
            return results;
        }
    }

    // ---------------------------------------------
    // 2. DOUBLE POINTER (Type **) - Recursive dereference
    // ---------------------------------------------
    const isDoublePtr = /\*\s*\*/.test(typeLower) || typeLower.endsWith('**');
    if (isDoublePtr || depth === 0) {
        try {
            const innerPtr = p.readPointer();
            if (isValidPointer(innerPtr)) {
                if (isDoublePtr) {
                    results.push({type: 'DoublePtr', value: address.toString()});
                    results.push({type: 'DoublePtr->Inner', value: innerPtr.toString()});
                }

                // Recursively read what the pointer points to
                const innerResults = readValue(innerPtr, '', context, depth + 1);
                for (const r of innerResults) {
                    results.push({
                        type: isDoublePtr ? `**->${r.type}` : `Ptr->${r.type}`,
                        value: r.value,
                        size: r.size
                    });
                }
            }
        } catch (e) {
        }
    }

    // ---------------------------------------------
    // 3. C STRING
    // ---------------------------------------------
    try {
        const cstring = Memory.readCString(p);
        if (cstring && cstring.length > 0) {
            results.push({
                type: 'CString',
                value: cstring,
                size: cstring.length
            });
        }
    } catch (e) {
    }

    // ---------------------------------------------
    // 4. STD::STRING (libc++ with SSO)
    // ---------------------------------------------
    try {
        const stdstring = readStdString(p);
        if (stdstring && stdstring.length > 0) {
            results.push({
                type: 'StdString',
                value: bytesToString(stdstring),
                size: stdstring.length
            });

            if (CONFIG.formater.raw) {
                results.push({
                    type: 'StdString Raw',
                    value: stdstring,
                    size: stdstring.length
                });
            }

            if (isPrintable(stdstring)) return results;

            if (CONFIG.formater.hex) {
                results.push({
                    type: 'StdString Hex',
                    value: toHex(stdstring),
                    size: stdstring.length
                });
            }

            if (CONFIG.formater.base64) {
                results.push({
                    type: 'StdString Base64',
                    value: Base64Encoder.from(stdstring).encode(),
                    size: stdstring.length
                });
            }
        }
    } catch (e) {
    }

    // ---------------------------------------------
    // 5. STD::VECTOR
    // ---------------------------------------------
    try {
        const stdvector = readStdVector(p);
        if (stdvector && stdvector.length > 0) {
            results.push({
                type: 'StdVector',
                value: bytesToString(stdvector),
                size: stdvector.length
            });

            if (CONFIG.formater.raw) {
                results.push({
                    type: 'StdVector Raw',
                    value: stdvector,
                    size: stdvector.length
                });
            }

            if (CONFIG.formater.hex) {
                results.push({
                    type: 'StdVector Hex',
                    value: toHex(stdvector),
                    size: stdvector.length
                });
            }

            if (CONFIG.formater.base64) {
                results.push({
                    type: 'StdVector Base64',
                    value: Base64Encoder.from(stdvector).encode(),
                    size: stdvector.length
                });
            }
        }
    } catch (e) {
    }

    // ---------------------------------------------
    // 6. SHARED_PTR / UNIQUE_PTR - Recursive read of managed object
    // ---------------------------------------------
    /*
    try {
        const sharedPtr = readSharedPtr(p);
        if (sharedPtr && sharedPtr.ptr) {
            results.push({type: 'SharedPtr', value: sharedPtr.address});

            // Recursively read the managed object
            const managedResults = readValue(sharedPtr.ptr, '', context, depth + 1);
            for (const r of managedResults) {
                results.push({
                    type: `SharedPtr→${r.type}`,
                    value: r.value,
                    size: r.size
                });
            }
        }
    } catch (e) {
    }
     */

    // ---------------------------------------------
    // 7. BUFFER WITH SIZE FROM CONTEXT
    // ---------------------------------------------
    const bufferSize = context.nextArgValue || context.sizeHint || context.prevArgValue;

    if (bufferSize && bufferSize > 0 && bufferSize <= CONFIG.interceptor.max_read_bytes) {
        try {
            const buffer = readBuffer(p, bufferSize);
            if (buffer) {
                results.push({
                    type: 'Buffer',
                    value: bytesToString(buffer),
                    size: buffer.length
                });

                if (CONFIG.formater.raw) {
                    results.push({
                        type: 'Buffer Raw',
                        value: buffer,
                        size: buffer.length
                    });
                }

                if (isPrintable(buffer)) return results;

                if (CONFIG.formater.hex) {
                    results.push({
                        type: 'Buffer Hex',
                        value: toHex(buffer),
                        size: buffer.length
                    });
                }

                if (CONFIG.formater.base64) {
                    results.push({
                        type: 'Buffer Base64',
                        value: Base64Encoder.from(buffer).encode(),
                        size: buffer.length
                    });
                }
            }
        } catch (e) {
        }
    }

    // ---------------------------------------------
    // 8. RAW BYTES (null-terminated or preview)
    // ---------------------------------------------
    try {
        const bytes = readBytes(p);
        if (bytes && bytes.length > 0) {
            // Only add if no better interpretation found
            const hasString = results.some(r =>
                r.type.includes('String') || r.type.includes('CString')
            );

            if (!hasString) {
                results.push({
                    type: 'Bytes',
                    value: bytesToString(bytes),
                    size: bytes.length
                });

                if (CONFIG.formater.raw) {
                    results.push({
                        type: 'Bytes Raw',
                        value: bytes,
                        size: bytes.length
                    });
                }

                if (isPrintable(bytesToString(bytes))) return results;

                if (CONFIG.formater.hex) {
                    results.push({
                        type: 'Bytes Hex',
                        value: toHex(bytes),
                        size: bytes.length
                    });
                }

                if (CONFIG.formater.base64) {
                    results.push({
                        type: 'Bytes Base64',
                        value: Base64Encoder.from(bytes).encode(),
                        size: bytes.length
                    });
                }
            }
        }
    } catch (e) {
    }

    // ---------------------------------------------
    // 9. QWORD/DWORD VALUES (read numeric value at pointer)
    // ---------------------------------------------
    if (/_qword|__int64/.test(typeLower) && typeLower.includes('*')) {
        try {
            const qword = p.readU64();
            results.push({type: '_QWORD*', value: '0x' + qword.toString(16)});
        } catch (e) {
        }
    }

    if (/_dword/.test(typeLower) && typeLower.includes('*')) {
        try {
            const dword = p.readU32();
            results.push({type: '_DWORD*', value: dword});
        } catch (e) {
        }
    }

    if (/_word/.test(typeLower) && typeLower.includes('*')) {
        try {
            const word = p.readU16();
            results.push({type: '_WORD*', value: word});
        } catch (e) {
        }
    }

    // ---------------------------------------------
    // 10. FALLBACK: Raw pointer address
    // ---------------------------------------------
    if (results.length === 0) {
        results.push({type: 'Pointer', value: address.toString()});
    }

    return results;
}

/** Format a readValue result into human-readable lines. */
function formatValue(index, argDesc, address, direction, context = {}) {
    if (CONFIG.debug) {
        try {
            /*
            {
              "address": "0xb400007c802f4cf8",
              "context": {},
              "type": "_QWORD",
              "name": "*a1@<X8>"
            }
             */
            Logger.print(JSON.stringify({
                address: address,
                context: context,
                ...argDesc,
                ...Process.findRangeByAddress(address)
            }, null, 2), Logger.COLOR.BLUE);
        } catch (e) {
        }
    }

    const arrow = direction === 'in' ? '->' : '<-';
    const prefix = ` ${arrow} [${index}] `;
    const lines = [];


    lines.push(`${prefix}(${argDesc.type}) ${argDesc.name} = ${address}`);

    // const interpretations = readValue(address, argDesc.type, context);
    const interpretations = readValue(address, argDesc.type, context);
    for (const interp of interpretations) {
        const sizeInfo = interp.size ? `[${interp.size}]` : '';
        lines.push(`${prefix}  ${interp.type}${sizeInfo}: ${interp.value}`);
    }

    return lines.join('\n');
}

// ---------------------------------------------
// @Descriptor - Parse function signatures
// ---------------------------------------------

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

// ---------------------------------------------
// @Interceptor - Hook functions
// ---------------------------------------------

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
        Logger.print(JSON.stringify(funcObj, null, 2), Logger.COLOR.BLUE);
    }

    const logger = new Logger(true);

    Interceptor.attach(funcObj.address, {
        onEnter: function (args) {
            logger.log(`[+] onEnter: ${funcObj.name}`);
            this.params = [];
            this.argDescs = [];

            const argCount = funcObj.method === 'static' && funcObj.args
                ? funcObj.args.length
                : CONFIG.interceptor.max_param_count;

            for (let i = 0; i < argCount; i++) {
                try {
                    const arg = args[i];
                    if (!arg) break;

                    this.params.push(arg);

                    const argDesc = funcObj.args && funcObj.args[i]
                        ? funcObj.args[i]
                        : {type: 'unknown', name: `arg${i}`};
                    this.argDescs.push(argDesc);

                    // Build context with next arg value (for size params)
                    const context = {};
                    if (i + 1 < argCount) {
                        try {
                            const nextArg = args[i + 1];
                            const nextVal = parseInt(nextArg, 16);
                            if (nextVal > 0 && nextVal < 0x10000) {
                                context.nextArgValue = nextVal;
                            }
                        } catch (e) {
                        }
                    }

                    logger.log(formatValue(i, argDesc, arg, 'in', context));
                } catch (e) {
                    break;
                }
            }

        },
        onLeave: function (retval) {
            logger.log(`[-] onLeave: ${funcObj.name}`);

            // Return value
            logger.log(formatValue(-1, {
                type: funcObj.ret || 'void',
                name: 'retval'
            }, retval, 'out'));

            // Check output params (recursive mode)
            if (CONFIG.interceptor.recursive && this.params.length > 0) {
                for (let i = 0; i < this.params.length; i++) {
                    const argDesc = this.argDescs[i];
                    // Only re-read likely output params
                    if (argDesc.type.includes('*') &&
                        (argDesc.type.includes('_QWORD') ||
                            argDesc.type.includes('__int64') ||
                            argDesc.type.includes('**'))) {
                        logger.log(formatValue(i, argDesc, this.params[i], 'out'));
                    }
                }
            }
        }
    });

    const tag = funcObj.method.toUpperCase()[0];
    Logger.print(`[${tag}][${funcObj.library}](${funcObj.address}) ${funcObj.name}`);
}

// ---------------------------------------------
// @Core - Library/function enumeration
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
        Logger.print(e.message, Logger.COLOR.RED);
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
        Logger.print(e.message, Logger.COLOR.RED);
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
    const logger = new Logger(false);
    logger.log('Capturing Native process...\n---');

    const hooked = new Set();  // To track hooked function addresses
    const libraries = getLibraries();  // Get the list of libraries to hook

    // Iterate over each library
    libraries.forEach(lib => {
        const libName = lib.name;
        const libAddr = parseInt(lib.base, 16);
        const functions = getFunctions(lib);  // Get functions for the current library

        const globalHook = METHODS.static[libName]?.length === 0;  // Determine if global hook is needed

        // Get descriptors for static and dynamic functions
        let descriptors = [
            ...getStaticDescriptors(libName),
            ...getDynamicDescriptors(lib, functions)
        ]

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
            Logger.print(JSON.stringify(lib, null, 2), Logger.COLOR.BLUE);
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
                Logger.print(`[!] ${e.message}: ${descriptor.name} (${descriptor.library})`, Logger.COLOR.RED);
            }

            // Remove the hooked descriptor from all lists
            descriptors = descriptors.filter(d => d !== descriptor);
        });

        // Report any descriptors that didn't match a function in the library
        descriptors.forEach(desc => Logger.print(`[?] Function not found: ${desc.name} (${desc.library})`, Logger.COLOR.YELLOW));
    });

    logger.log(`---\nCapturing setup completed (${hooked.size} hooks active)`);
}, CONFIG.timeout);
