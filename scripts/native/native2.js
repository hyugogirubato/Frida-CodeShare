/**
 * Use only the name for a classic interception.
 * Using an object when manually adding modules.
 */
const METHODS = {
    static: {
        /*
        'libandroidappmusic.so': [
            'void __fastcall std::__shared_ptr_emplace<storeservicescore::FairPlayData>::~__shared_ptr_emplace(__int64 a1)',
            'void __fastcall std::__shared_ptr_emplace<storeservicescore::FairPlayData>::__on_zero_shared(__int64 a1)',
            'void __fastcall std::__shared_ptr_emplace<storeservicescore::FairPlayData>::__on_zero_shared_weak(void *a1)',
            'void __usercall storeservicescore::FairPlaySubscriptionStatus::status(storeservicescore::FairPlaySubscriptionStatus *this@<X0>,__int64 a2@<X8>)',
            '__int64 __fastcall std::shared_ptr<storeservicescore::FairPlay>::~shared_ptr(__int64 result)',
            '__int64 __fastcall std::shared_ptr<storeservicescore::FairPlayData>::~shared_ptr(__int64 result)',
            '__int64 FootHillNative::FootHillGetID()',
            '__int64 __fastcall storeservicescore::FairPlay::getSubscriptionStatus(storeservicescore::FairPlay *this)',
            '__int64 __fastcall storeservicescore::FairPlay::getDeviceSupportInfo(storeservicescore::FairPlay *this)',
            '__int64 __fastcall storeservicescore::FairPlay::anisetteRequest()',
            '__int64 __fastcall storeservicescore::FairPlayData::FairPlayData(storeservicescore::FairPlayData *this)',
            '__int64 __fastcall storeservicescore::FairPlayData::base64EncodedString(storeservicescore::FairPlayData *this)',
            '__int64 __fastcall storeservicescore::RequestContext::getFairPlaySubscriptionStatusDescription(    storeservicescore::RequestContext *this)',
            '__int64 __fastcall Java_com_apple_android_storeservices_javanative_account_FairPlay_00024FairPlayNative_getDeviceSupportInfo(__int64 a1,__int64 a2)'
        ],

         */
        /*
        'libCoreFoundation.so': [
            'size_t __fastcall CFStringGetBytes(__int64 a1, __int64 a2, signed __int64 a3, unsigned int a4, int a5, int a6, void *dest, signed __int64 a8, size_t *a9)',
            'unsigned __int64 __fastcall CFStringGetCStringPtr(__int64 a1, unsigned int a2)',
            'bool __fastcall CFStringGetCString(unsigned __int64 *a1, void *dest, __int64 a3, unsigned int a4)',
            '__int64 __fastcall CFStringGetLength2(__int64 a1)',
            '__int64 __fastcall CFStringGetLength(__int64 a1)'
        ]

         */
        'libwvhidl.so': [
            // @Keybox
            '__int64 __fastcall wvcdm::CryptoSession::GetTokenFromKeybox(__int64 a1, __int64 *a2)',
            '__int64 __fastcall wvcdm::Properties::GetFactoryKeyboxPath(__int64 a1)',
            '__int64 wvcdm::CryptoSession::GetTokenFromKeybox(void)',
            '__int64 __fastcall wvcdm::Properties::GetFactoryKeyboxPath(__int64 a1)',
            // @Token
            //  'bool __fastcall wvcdm::CdmSession::has_provider_session_token(wvcdm::CdmSession *this)',
            '__int64 __fastcall wvcdm::CdmLicense::Init(__int64 a1,unsigned __int8 *a2,int a3,__int64 a4,char a5,unsigned __int8 *a6,__int64 a7,__int64 a8)',
            '__int64 __fastcall wvcdm::CdmLicense::ExtractProviderSessionToken(unsigned __int8 *a1, __int64 a2)',
            '__int64 __usercall wvcdm::CdmLicense::provider_session_token@<X0>(wvcdm::CdmLicense *this@<X0>, __int64 a2@<X8>)',
            '__int64 __fastcall wvcdm::ClientIdentification::GetProvisioningTokenType(__int64 a1, _DWORD *a2)',
            '__int64 __fastcall video_widevine_client::sdk::UsageInfo_ProviderSession::set_token(video_widevine_client::sdk::UsageInfo_ProviderSession *this,const void *src,size_t n)',
            '__int64 __fastcall wvcdm::DeviceFiles::GetProviderSessionToken(__int64 a1, __int64 a2, unsigned __int8 *a3, __int64 a4)',
            '__int64 __fastcall wvcdm::CryptoSession::GetProvisioningMethod(__int64 a1, unsigned int a2, _DWORD *a3)',
            // '__int64 __fastcall wvcdm::CryptoSession::GetTokenFromKeybox(__int64 a1, __int64 *a2)',
            '__int64 __fastcall wvcdm::CryptoSession::GetTokenFromOemCert(__int64 a1, __int64 a2)',
            '__int64 __fastcall wvcdm::CryptoSession::GetProvisioningToken(__int64 a1, __int64 a2)',
            '__int64 __fastcall wvcdm::CryptoSession::GetPreProvisionTokenType(wvcdm::CryptoSession *this)',
            'bool __fastcall video_widevine::ClientIdentification_TokenType_IsValid(video_widevine *this)',
            // '__int64 __fastcall wvcdm::DeviceFiles::GetProviderSessionToken(__int64 a1, __int64 a2, unsigned __int8 *a3, __int64 a4)',
            // '__int64 __fastcall wvcdm::CdmLicense::ExtractProviderSessionToken(unsigned __int8 *a1, __int64 a2)',
            // '__int64 wvcdm::CryptoSession::GetTokenFromKeybox(void)',
            // '__int64 __fastcall wvcdm::CryptoSession::GetTokenFromOemCert(__int64 a1, __int64 a2)'
        ]
    },
    dynamic: [
        // '__int64 __fastcall CFStringCompare(unsigned __int64 *a1, __int64 a2, __int64 a3)'
    ]
    // TODO: include & exclude using regex
}


/**
 * Use the application package name to intercept only application-related processes.
 * Using the Binary Path to only intercept binary-related processes.
 * Use "undefined" to intercept all running processes (system included).
 */
const PACKAGE = undefined; // 'com.apple.android.music';
const TIMEOUT = 0;
const RECURSIVE = false;
const EXTENSIONS = ['.so', '.dll', '.exe'];


// @Utils
// https://github.com/frida/gumjs-base64/blob/master/index.js
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
        if (typeof value === 'string' || (Array.isArray(value) && value.every(num => Number.isInteger(num) && num >= 0 && num <= 255))) {
            return new Base64Encoder(value);
        }
        throw new Error('Input must be a string or an array of integers (0-255).');
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

function print(message) {
    message = message instanceof Object ? JSON.stringify(message, null, 2) : message;
    console.log(message);
}

function parseDescriptor(funcString) {
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
        type: returnType.trim(),    // Return type (e.g., 'void')
        name: funcName.trim(),      // Function name (e.g., '~__shared_ptr_emplace')
        args: argDetails            // Array of { type, name } for each argument
    };
}


// @Core
function getLibraries() {
    try {
        let libraries = Process.enumerateModules();
        // Filter by package if specified
        libraries = PACKAGE ? libraries.filter(l => l.path.includes(PACKAGE)) : libraries;
        // Filter libraries by extensions
        return libraries.filter(l =>
            EXTENSIONS.some(e => l.path.endsWith(e))
        );

    } catch (e) {
        print(e.message);
        return [];
    }
}

function getLibrary(name) {
    const libraries = getLibraries().filter(l => l.name === name);
    return libraries.length === 1 ? libraries[0] : undefined;
}

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

function getDescriptors() {
    const staticDescriptors = Object.entries(METHODS.static).flatMap(([libName, methods]) =>
        methods.map(method => ({
            library: libName,
            ...parseDescriptor(method)
        }))
    );

    const dynamicDescriptors = METHODS.dynamic.map(method => ({
        library: undefined,
        ...parseDescriptor(method)
    }));

    // Combine static and dynamic descriptors and sort
    const descriptors = [...staticDescriptors, ...dynamicDescriptors].map(desc => ({
        ...desc,
        pattern: ['::', 'std', '<', '>', '~']
            .reduce((acc, ph) => acc.split(ph).join('|&|'), desc.name.replaceAll(/@<[A-Za-z0-9]+>/g, ''))  // Remove annotations like @<X0>
            .split('|&|')
            .filter(Boolean)
            // .map(p => p.startsWith('get') || p.startsWith('set') ? p.slice(3) : p)  // Optional: Remove 'get' or 'set' prefixes if desired
    }));

    return descriptors.sort((a, b) => b.name.localeCompare(a.name));
}


function hookFunction(funcObj) {
    /*
    {
      "type": "size_t",
      "name": "CFStringGetBytes",
      "address": "0x7bd9f811a8",
      "library": "libCoreFoundation.so",
      "args": [
        "__int64",
        "__int64",
        "signed __int64",
        "unsigned int",
        "int",
        "int",
        "void *",
        "signed __int64",
        "size_t *"
      ]
    }
     */

    const prefix = '[' + funcObj.library + '](';
    Interceptor.attach(funcObj.address, {
        onEnter: function (args) {
            print('[+] onEnter: ' + funcObj.name);
            this.params = [];

            for (let i=0; i < funcObj.args.length; i++) {
                print('\t-> [' + i + '](' + funcObj.args[i].type + ') ' + funcObj.args[i].name + ' = ' + args[i]);

                /*
                try {
                    const value = Memory.readCString(args[i]);
                    print('\t[' + i + '](CString) ' + funcObj.args[i].name + ' ->  ' + value);
                } catch (e) {

                }

                 */
            }
        },
        onLeave: function (retval) {
            print('[-] onLeave: ' + funcObj.name);
            print('\t<- [-1](' + funcObj.type + ') ret = ' + retval);

            if (RECURSIVE) {
                for (let i =0; i < this.params.length; i++) {
                    // TODO: print memory
                }
            }
        }
    });

    // print(funcObj)
    print('[' + funcObj.library + '](' + funcObj.address + ') Function: ' + funcObj.name);
}


setTimeout(() => {
    print('Capturing Native process...\n---');

    const hooked = new Set();  // To track hooked function addresses
    const libraries = getLibraries();  // Get the list of libraries to hook
    let descriptors = getDescriptors();  // Get descriptors for static and dynamic functions

    // Group descriptors by library and track pending descriptors (those with no specific library)
    const descriptorsByLibrary = descriptors.reduce((acc, desc) => {
        const key = desc.library || 'pending';  // Group by library or 'pending' if no library
        (acc[key] ??= []).push(desc);
        return acc;
    }, {});

    // Iterate over each library
    libraries.forEach(lib => {
        const libName = lib.name;
        const globalHook = METHODS.static[libName]?.length === 0;  // Determine if global hook is needed
        let selection = descriptorsByLibrary[libName] ?? [];  // Get library-specific descriptors
        let pending = descriptorsByLibrary['pending'] ?? [];  // Get pending descriptors

        // Skip if no descriptors for the library and no global hook needed
        if (!globalHook && !selection.length && !pending.length) return;

        const functions = getFunctions(lib);  // Get functions for the current library

        // Iterate over each function in the library
        functions.forEach(func => {
            if (!globalHook && !selection.length && !pending.length) return;

            // Skip if the function is not a 'function' or is already hooked
            if (func.type !== 'function' || hooked.has(func.address)) return;
            let descriptor;

            // If not a global hook, check if the function matches any descriptor
            if (!globalHook) {
                // Check if the function name matches the pattern in any of the descriptors
                for (const desc of [...selection, ...pending]) {
                    if (desc.pattern.every(p => func.name.includes(p))) {
                        descriptor = desc;
                        break;
                    }
                }

                // If no descriptor found, skip this function
                if (!descriptor) return;
            }

            // Hook the function and mark it as hooked
            hooked.add(func.address);
            try {
                hookFunction({...func, ...descriptor, library: libName});  // Hook the function
            } catch (e) {
                print(e.message);
            }

            // Remove the hooked descriptor from all lists
            descriptors = descriptors.filter(d => d !== descriptor);
            descriptorsByLibrary[libName] = descriptorsByLibrary[libName]?.filter(d => d !== descriptor);
            descriptorsByLibrary['pending'] = descriptorsByLibrary['pending']?.filter(d => d !== descriptor);

            // Re-fetch the descriptors for optimization (in case they were updated)
            selection = descriptorsByLibrary[libName] ?? [];
            pending = descriptorsByLibrary['pending'] ?? [];
        });

        // Report any descriptors that didn't match a function in the library
        selection.forEach(desc => print('[!] Function not found: ' + desc.name));
    });

    // Report remaining unmatched descriptors in the 'pending' category
    (descriptorsByLibrary['pending'] ?? []).forEach(desc => print('[!] Function not found: ' + desc.name));

    print('Capturing setup completed\n---');
}, TIMEOUT);