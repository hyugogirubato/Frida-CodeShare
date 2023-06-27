/**@@@+++@@@@******************************************************************
 **
 ** Android SSL Pinning frida script v1.0 hyugogirubato
 **
 ** frida -D "DEVICE" -l "pinning.js" -f "PACKAGE"
 **
 ** Update: Dynamic error support.
 **
 ***@@@---@@@@******************************************************************
 */

// Custom params
const MODE = {
    SSLPeerUnverifiedException: true,
    HttpsURLConnection: true,
    SSLContext: true,
    TrustManagerImpl: true,
    OkHTTPv3: true,
    Trustkit: true,
    TitaniumPinningTrustManager: true,
    FabricPinningTrustManager: true,
    ConscryptOpenSSLSocketImpl: true,
    ConscryptOpenSSLEngineSocketImpl: true,
    ApacheOpenSSLSocketImpl: true,
    PhoneGapsslCertificateChecker: true,
    IBMMobileFirst: true,
    IBMWorkLight: true,
    ConscryptCertPinManager: true,
    NetsecurityCertPinManager: true,
    AndroidgapWorkLight: true,
    NettyFingerprintTrustManagerFactory: true,
    SquareupCertificatePinner: true,
    SquareupOkHostnameVerifier: true,
    AndroidWebViewClient: true,
    ApacheWebViewClient: true,
    BoyeAbstractVerifier: true,
    ApacheAbstractVerifier: true,
    Appmattus: true,
    ChromiumCronet: true,
    Flutter: true
};


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


const rudimentaryFix = (typeName) => {
    if (typeName === "boolean") {
        return true;
    } else if (typeName !== "void") {
        return null;
    }
}

const loadJava = (library) => {
    try {
        return Java.use(library);
    } catch (e) {
        return undefined;
    }
}


setTimeout(function () {
    console.log("---");
    console.log("Capturing Android app...");
    if (Java.available) {
        console.log("[*] Java available");
        Java.perform(function () {

                if (MODE.SSLPeerUnverifiedException) {
                    const colorKey = randomColor();
                    try {
                        const UnverifiedCertError = Java.use("javax.net.ssl.SSLPeerUnverifiedException");
                        UnverifiedCertError.$init.implementation = function (str) {
                            console.log(`${COLORS.red}[!] Unexpected SSLPeerUnverifiedException occurred, trying to patch it dynamically...${COLORS.reset}`);

                            let className, methodName, callingMethod, returnTypeName;
                            try {
                                const stackTrace = Java.use("java.lang.Thread").currentThread().getStackTrace();
                                const exceptionStackIndex = stackTrace.findIndex(stack =>
                                    stack.getClassName() === "javax.net.ssl.SSLPeerUnverifiedException"
                                );

                                if (exceptionStackIndex === -1) {
                                    console.log(`${COLORS.yellow}[-] SSLPeerUnverifiedException not found in the stack trace.${COLORS.reset}`);
                                    return this.$init(str);
                                }

                                // Retrieve the method raising the SSLPeerUnverifiedException
                                const callingFunctionStack = stackTrace[exceptionStackIndex + 1];
                                className = callingFunctionStack.getClassName();
                                methodName = callingFunctionStack.getMethodName();
                                const callingClass = Java.use(className);
                                callingMethod = callingClass[methodName];

                                // Skip it when already patched by Frida
                                if (callingMethod.implementation) {
                                    return;
                                }

                                // Trying to patch the uncommon SSL Pinning method via implementation
                                returnTypeName = callingMethod.returnType.type;
                                callingMethod.implementation = function () {
                                    rudimentaryFix(returnTypeName);
                                };
                                console.log(`${colorKey}  --> SSLPeerUnverifiedException [${className}.${methodName}]${COLORS.reset}`);
                            } catch (e) {
                                // Dynamic patching via implementation does not works, then trying via function overloading
                                console.log(`${COLORS.red}[!] The uncommon SSL Pinning method has more than one overload${COLORS.reset}`);
                                if (String(e).includes(".overload")) {
                                    const splittedList = String(e).split(".overload");
                                    for (let i = 2; i < splittedList.length; i++) {
                                        const extractedOverload = splittedList[i].trim().split("(")[1].slice(0, -1).replaceAll("'", "");
                                        // Check if extractedOverload has multiple arguments
                                        if (extractedOverload.includes(",")) {
                                            // Go here if overloaded method has multiple arguments (NOTE: max 6 args are covered here)
                                            const argList = extractedOverload.split(", ");

                                            // Overload the method based on the number of arguments
                                            callingMethod.overload(...argList).implementation = function (...args) {
                                                rudimentaryFix(returnTypeName);
                                            };
                                            // Go here if overloaded method has a single argument
                                        } else {
                                            callingMethod.overload(extractedOverload).implementation = function (a) {
                                                rudimentaryFix(returnTypeName);
                                            };
                                        }
                                    }
                                    console.log(`${colorKey}  --> SSLPeerUnverifiedException [${className}.${methodName}]${COLORS.reset}`);
                                } else {
                                    console.log(`${COLORS.red}[!] Failed to dynamically patch SSLPeerUnverifiedException ${e}${COLORS.reset}`);
                                }
                            }
                            return this.$init(str);
                        }
                    } catch (e) {
                        console.log(`${COLORS.red}[!] Failed to dynamically patch SSLPeerUnverifiedException ${e}${COLORS.reset}`);
                    }
                }

                if (MODE.HttpsURLConnection) {
                    const colorKey = randomColor();
                    const HttpsURLConnection = loadJava("javax.net.ssl.HttpsURLConnection");
                    try {
                        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                            console.log(`${colorKey}  --> HttpsURLConnection [DefaultHostnameVerifier]${COLORS.reset}`);
                        };
                        console.log("[+] HttpsURLConnection [DefaultHostnameVerifier]");
                    } catch (e) {
                        console.log("[ ] HttpsURLConnection [DefaultHostnameVerifier]");
                    }

                    try {
                        HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
                            console.log(`${colorKey}  --> HttpsURLConnection [SSLSocketFactory]${COLORS.reset}`);
                        };
                        console.log("[+] HttpsURLConnection [SSLSocketFactory]");
                    } catch (e) {
                        console.log("[ ] HttpsURLConnection [SSLSocketFactory]");
                    }

                    try {
                        HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
                            console.log(`${colorKey}  --> HttpsURLConnection [HostnameVerifier]${COLORS.reset}`);
                        };
                        console.log("[+] HttpsURLConnection [HostnameVerifier]");
                    } catch (e) {
                        console.log("[ ] HttpsURLConnection [HostnameVerifier]");
                    }

                }

                if (MODE.SSLContext) {
                    // TrustManager (Android < 7)
                    const colorKey = randomColor();
                    try {
                        const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
                        const SSLContext = Java.use("javax.net.ssl.SSLContext");

                        const TrustManager = Java.registerClass({
                            // Implement a custom TrustManager
                            name: "dev.asd.test.TrustManager",
                            implements: [X509TrustManager],
                            methods: {
                                checkClientTrusted: function (chain, authType) {
                                },
                                checkServerTrusted: function (chain, authType) {
                                },
                                getAcceptedIssuers: function () {
                                    return [];
                                }
                            }
                        });

                        // Prepare the TrustManager array to pass to SSLContext.init()
                        const TrustManagers = [TrustManager.$new()];
                        // Get a handle on the init() on the SSLContext class
                        const SSLContext_init = SSLContext.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
                        // Override the init method, specifying the custom TrustManager
                        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {
                            console.log(`${colorKey}  --> TrustManager [SSLContext] (Android < 7)${COLORS.reset}`);
                            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                        };
                        console.log("[+] TrustManager [SSLContext] (Android < 7)");
                    } catch (e) {
                        console.log("[ ] TrustManager [SSLContext] (Android < 7)");
                    }
                }

                if (MODE.TrustManagerImpl) {
                    // TrustManagerImpl (Android > 7)
                    const colorKey = randomColor();
                    const TrustManagerImpl = loadJava("com.android.org.conscrypt.TrustManagerImpl");
                    try {
                        const ArrayList = Java.use("java.util.ArrayList");
                        TrustManagerImpl.checkTrustedRecursive.implementation = function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                            console.log(`${colorKey}  --> TrustManagerImpl [TrustedRecursive] (Android > 7): ${host}${COLORS.reset}`);
                            return ArrayList.$new();
                        };
                        console.log("[+] TrustManagerImpl [TrustedRecursive] (Android > 7)");
                    } catch (e) {
                        console.log("[ ] TrustManagerImpl [TrustedRecursive] (Android > 7)");
                    }

                    try {
                        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                            console.log(`${colorKey}  --> TrustManagerImpl [verifyChain] (Android > 7): ${host}${COLORS.reset}`);
                            return untrustedChain;
                        };
                        console.log("[+] TrustManagerImpl [verifyChain] (Android > 7)");
                    } catch (e) {
                        console.log("[ ] TrustManagerImpl [verifyChain] (Android > 7)");
                    }
                }

                if (MODE.OkHTTPv3) {
                    const colorKey = randomColor();
                    const CertificatePinner = loadJava("okhttp3.CertificatePinner");
                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log(`${colorKey}  --> OkHTTPv3 [List]: ${a}${COLORS.reset}`);
                        };
                        console.log("[+] OkHTTPv3 [List]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [List]");
                    }

                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function (a, b) {
                            console.log(`${colorKey}  --> OkHTTPv3 [Certificate]: ${a}${COLORS.reset}`);
                        };
                        console.log("[+] OkHTTPv3 [Certificate]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [Certificate]");
                    }

                    try {
                        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (a, b) {
                            console.log(`${colorKey}  --> OkHTTPv3 [Array]: ${a}${COLORS.reset}`);
                        };
                        console.log("[+] OkHTTPv3 [Array]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [Array]");
                    }

                    try {
                        CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (a, b) {
                            console.log(`${colorKey}  --> OkHTTPv3 [Function]: ${a}${COLORS.reset}`);
                        };
                        console.log("[+] OkHTTPv3 [Function]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [Function]");
                    }
                }

                if (MODE.Trustkit) {
                    const colorKey = randomColor();
                    const OkHostnameVerifier = loadJava("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
                    const PinningTrustManager = loadJava("com.datatheorem.android.trustkit.pinning.PinningTrustManager");
                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Trustkit OkHostnameVerifier [SSLSession]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Trustkit OkHostnameVerifier [SSLSession]");
                    } catch (e) {
                        console.log("[ ] Trustkit OkHostnameVerifier [SSLSession]");
                    }

                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Trustkit OkHostnameVerifier [X509Certificate]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Trustkit OkHostnameVerifier [X509Certificate]");
                    } catch (e) {
                        console.log("[ ] Trustkit OkHostnameVerifier [X509Certificate]");
                    }

                    try {
                        PinningTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function (chain, authType) {
                            console.log(`${colorKey}  --> Trustkit PinningTrustManager${COLORS.reset}`);
                        };
                        console.log("[+] Trustkit PinningTrustManager");
                    } catch (e) {
                        console.log("[ ] Trustkit PinningTrustManager");
                    }
                }

                if (MODE.TitaniumPinningTrustManager) {
                    const colorKey = randomColor();
                    const PinningTrustManager = loadJava("appcelerator.https.PinningTrustManager");
                    try {
                        PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                            console.log(`${colorKey}  --> Titanium [PinningTrustManager]${COLORS.reset}`);
                        };
                        console.log("[+] Titanium [PinningTrustManager]");
                    } catch (e) {
                        console.log("[ ] Titanium [PinningTrustManager]");
                    }
                }

                if (MODE.FabricPinningTrustManager) {
                    const colorKey = randomColor();
                    const PinningTrustManager = loadJava("io.fabric.sdk.android.services.network.PinningTrustManager");
                    try {
                        PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                            console.log(`${colorKey}  --> Fabric [PinningTrustManager]${COLORS.reset}`);
                        };
                        console.log("[+] Fabric [PinningTrustManager]");
                    } catch (e) {
                        console.log("[ ] Fabric [PinningTrustManager]");
                    }
                }

                if (MODE.ConscryptOpenSSLSocketImpl) {
                    const colorKey = randomColor();
                    const OpenSSLSocketImpl = loadJava("com.android.org.conscrypt.OpenSSLSocketImpl");
                    try {
                        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                            console.log(`${colorKey}  --> Conscrypt [OpenSSLSocketImpl] (Refs)${COLORS.reset}`);
                        };
                        console.log("[+] Conscrypt [OpenSSLSocketImpl] (Refs)");
                    } catch (e) {
                        console.log("[ ] Conscrypt [OpenSSLSocketImpl] (Refs)");
                    }

                    try {
                        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certChain, authMethod) {
                            console.log(`${colorKey}  --> Conscrypt [OpenSSLSocketImpl] (Chain)${COLORS.reset}`);
                        };
                        console.log("[+] Conscrypt [OpenSSLSocketImpl] (Chain)");
                    } catch (e) {
                        console.log("[ ] Conscrypt [OpenSSLSocketImpl] (Chain)");
                    }
                }

                if (MODE.ConscryptOpenSSLEngineSocketImpl) {
                    const colorKey = randomColor();
                    const OpenSSLEngineSocketImpl = loadJava("com.android.org.conscrypt.OpenSSLEngineSocketImpl");
                    try {
                        OpenSSLEngineSocketImpl.verifyCertificateChain.overload("[Ljava.lang.Long;", "java.lang.String").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Conscrypt [OpenSSLEngineSocketImpl]: ${b}${COLORS.reset}`);
                        };
                        console.log("[+] Conscrypt [OpenSSLEngineSocketImpl]");
                    } catch (e) {
                        console.log("[ ] Conscrypt [OpenSSLEngineSocketImpl]");
                    }
                }

                if (MODE.ApacheOpenSSLSocketImpl) {
                    const colorKey = randomColor();
                    const OpenSSLSocketImpl = loadJava("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl");
                    try {
                        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                            console.log(`${colorKey}  --> Apache [OpenSSLSocketImpl]${COLORS.reset}`);
                        };
                        console.log("[+] Apache [OpenSSLSocketImpl]");
                    } catch (e) {
                        console.log("[ ] Apache [OpenSSLSocketImpl]");
                    }
                }

                if (MODE.PhoneGapsslCertificateChecker) {
                    const colorKey = randomColor();
                    const sslCertificateChecker = loadJava("nl.xservices.plugins.sslCertificateChecker");
                    try {
                        sslCertificateChecker.execute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation = function (a, b, c) {
                            console.log(`${colorKey}  --> PhoneGap [sslCertificateChecker]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] PhoneGap [sslCertificateChecker]");
                    } catch (e) {
                        console.log("[ ] PhoneGap [sslCertificateChecker]");
                    }
                }

                if (MODE.IBMMobileFirst) {
                    const colorKey = randomColor();
                    const MobileFirst = loadJava("com.worklight.wlclient.api.WLClient");
                    try {
                        MobileFirst.getInstance().pinTrustedCertificatePublicKey.overload("java.lang.String").implementation = function (cert) {
                            console.log(`${colorKey}  --> IBM [MobileFirst] (String): ${cert}${COLORS.reset}`);
                        };
                        console.log("[+] IBM [MobileFirst] (String)");
                    } catch (e) {
                        console.log("[ ] IBM [MobileFirst] (String)");
                    }

                    try {
                        MobileFirst.getInstance().pinTrustedCertificatePublicKey.overload("[Ljava.lang.String;").implementation = function (cert) {
                            console.log(`${colorKey}  --> IBM [MobileFirst] (Array): ${cert}${COLORS.reset}`);
                        };
                        console.log("[+] IBM [MobileFirst] (Array)");
                    } catch (e) {
                        console.log("[ ] IBM [MobileFirst] (Array)");
                    }
                }

                if (MODE.IBMWorkLight) {
                    const colorKey = randomColor();
                    const WorkLight = loadJava("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning");
                    try {
                        WorkLight.verify.overload("java.lang.String", "javax.net.ssl.SSLSocket").implementation = function (a, b) {
                            console.log(`${colorKey}  --> IBM [WorkLight] (SSLSocket): ${a}${COLORS.reset}`);
                        };
                        console.log("[+] IBM [WorkLight] (SSLSocket)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (SSLSocket)");
                    }

                    try {
                        WorkLight.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (a, b) {
                            console.log(`${colorKey}  --> IBM [WorkLight] (X509Certificate): ${a}${COLORS.reset}`);
                        };
                        console.log("[+] IBM [WorkLight] (X509Certificate)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (X509Certificate)");
                    }

                    try {
                        WorkLight.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;").implementation = function (a, b) {
                            console.log(`${colorKey}  --> IBM [WorkLight] (String): ${a}${COLORS.reset}`);
                        };
                        console.log("[+] IBM [WorkLight] (String)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (String)");
                    }

                    try {
                        WorkLight.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (a, b) {
                            console.log(`${colorKey}  --> IBM [WorkLight] (SSLSession): ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] IBM [WorkLight] (SSLSession)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (SSLSession)");
                    }
                }

                if (MODE.ConscryptCertPinManager) {
                    const colorKey = randomColor();
                    const CertPinManager = loadJava("com.android.org.conscrypt.CertPinManager");
                    try {
                        CertPinManager.checkChainPinning.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Conscrypt [CertPinManager] (List): ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Conscrypt [CertPinManager] (List)");
                    } catch (e) {
                        console.log("[ ] Conscrypt [CertPinManager] (List)");
                    }

                    try {
                        CertPinManager.isChainValid.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Conscrypt [CertPinManager] (Legacy): ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Conscrypt [CertPinManager] (Legacy)");
                    } catch (e) {
                        console.log("[ ] Conscrypt [CertPinManager] (Legacy)");
                    }
                }

                if (MODE.NetsecurityCertPinManager) {
                    const colorKey = randomColor();
                    const CertPinManager = loadJava("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager");
                    try {
                        CertPinManager.isChainValid.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Netsecurity [CertPinManager]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Netsecurity [CertPinManager]");
                    } catch (e) {
                        console.log("[ ] Netsecurity [CertPinManager]");
                    }
                }

                if (MODE.AndroidgapWorkLight) {
                    const colorKey = randomColor();
                    const Worklight = loadJava("com.worklight.androidgap.plugin.WLCertificatePinningPlugin");
                    try {
                        Worklight.execute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation = function (a, b, c) {
                            console.log(`${colorKey}  --> Android [WorkLight]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Android [WorkLight]");
                    } catch (e) {
                        console.log("[ ] Android [WorkLight]");
                    }
                }

                if (MODE.NettyFingerprintTrustManagerFactory) {
                    const colorKey = randomColor();
                    const FingerprintTrustManagerFactory = loadJava("io.netty.handler.ssl.util.FingerprintTrustManagerFactory");
                    try {
                        FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                            console.log(`${colorKey}  --> Netty [FingerprintTrustManagerFactory]${COLORS.reset}`);
                        };
                        console.log("[+] Netty [FingerprintTrustManagerFactory]");
                    } catch (e) {
                        console.log("[ ] Netty [FingerprintTrustManagerFactory]");
                    }
                }

                if (MODE.SquareupCertificatePinner) {
                    // OkHTTP < v3
                    const colorKey = randomColor();
                    const CertificatePinner = loadJava("com.squareup.okhttp.CertificatePinner");
                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Squareup [CertificatePinner] (Certificate): ${a}${COLORS.reset}`);
                        };
                        console.log("[+] Squareup [CertificatePinner] (Certificate)");
                    } catch (e) {
                        console.log("[ ] Squareup [CertificatePinner] (Certificate)");
                    }

                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Squareup [CertificatePinner] (List): ${a}${COLORS.reset}`);
                        };
                        console.log("[+] Squareup [CertificatePinner] (List)");
                    } catch (e) {
                        console.log("[ ] Squareup [CertificatePinner] (List)");
                    }
                }

                if (MODE.SquareupOkHostnameVerifier) {
                    // OkHTTP v3
                    const colorKey = randomColor();
                    const OkHostnameVerifier = loadJava("com.squareup.okhttp.internal.tls.OkHostnameVerifier");
                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Squareup [OkHostnameVerifier] (X509Certificate): ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Squareup [OkHostnameVerifier] (X509Certificate)");
                    } catch (e) {
                        console.log("[ ] Squareup [OkHostnameVerifier] (X509Certificate)");
                    }

                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (a, b) {
                            console.log(`${colorKey}  --> Squareup [OkHostnameVerifier] (SSLSession): ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Squareup [OkHostnameVerifier] (SSLSession)");
                    } catch (e) {
                        console.log("[ ] Squareup [OkHostnameVerifier] (SSLSession)");
                    }
                }

                if (MODE.AndroidWebViewClient) {
                    const colorKey = randomColor();
                    const WebViewClient = loadJava("android.webkit.WebViewClient");

                    try {
                        WebViewClient.onReceivedSslError.overload("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError").implementation = function (obj1, obj2, obj3) {
                            console.log(`${colorKey}  --> Android [WebViewClient] (SslErrorHandler)${COLORS.reset}`);
                        };
                        console.log("[+] Android [WebViewClient] (SslErrorHandler)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (SslErrorHandler)");
                    }

                    try {
                        WebViewClient.onReceivedSslError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function (obj1, obj2, obj3) {
                            console.log(`${colorKey}  --> Android [WebViewClient] (SSLWebResourceError)${COLORS.reset}`);
                        };
                        console.log("[+] Android [WebViewClient] (SSLWebResourceError)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (SSLWebResourceError)");
                    }

                    try {
                        WebViewClient.onReceivedError.overload("android.webkit.WebView", "int", "java.lang.String", "java.lang.String").implementation = function (obj1, obj2, obj3, obj4) {
                            console.log(`${colorKey}  --> Android [WebViewClient] (String)${COLORS.reset}`);
                        };
                        console.log("[+] Android [WebViewClient] (String)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (String)");
                    }

                    try {
                        WebViewClient.onReceivedError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function (obj1, obj2, obj3) {
                            console.log(`${colorKey}  --> Android [WebViewClient] (WebResourceError)${COLORS.reset}`);
                        };
                        console.log("[+] Android [WebViewClient] (WebResourceError)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (WebResourceError)");
                    }
                }

                if (MODE.ApacheWebViewClient) {
                    const colorKey = randomColor();
                    const CordovaWebViewClient = loadJava("org.apache.cordova.CordovaWebViewClient");
                    try {
                        CordovaWebViewClient.onReceivedSslError.overload("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError").implementation = function (obj1, obj2, obj3) {
                            console.log(`${colorKey}  --> Apache [WebViewClient]${COLORS.reset}`);
                            obj3.proceed();
                        };
                        console.log("[+] Apache [WebViewClient]");
                    } catch (e) {
                        console.log("[ ] Apache [WebViewClient]");
                    }
                }

                if (MODE.BoyeAbstractVerifier) {
                    const colorKey = randomColor();
                    const AbstractVerifier = loadJava("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
                    try {
                        AbstractVerifier.verify.implementation = function (host, ssl) {
                            console.log(`${colorKey}  --> Boye [AbstractVerifier]: ${host}${COLORS.reset}`);
                        };
                        console.log("[+] Boye [AbstractVerifier]");
                    } catch (e) {
                        console.log("[ ] Boye [AbstractVerifier]");
                    }
                }

                if (MODE.ApacheAbstractVerifier) {
                    const colorKey = randomColor();
                    const AbstractVerifier = loadJava("org.apache.http.conn.ssl.AbstractVerifier");
                    try {
                        AbstractVerifier.verify.implementation = function (a, b, c, d) {
                            console.log(`${colorKey}  --> Apache [AbstractVerifier]: ${a}${COLORS.reset}`);
                        };
                        console.log("[+] Apache [AbstractVerifier]");
                    } catch (e) {
                        console.log("[ ] Apache [AbstractVerifier]");
                    }
                }

                if (MODE.Appmattus) {
                    const colorKey = randomColor();
                    const Transparency = loadJava("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor");
                    try {
                        Transparency.intercept.implementation = function (a) {
                            console.log(`${colorKey}  --> Appmattus [Transparency]${COLORS.reset}`);
                            return a.proceed(a.request());
                        };
                        console.log("[+] Appmattus [Transparency]");
                    } catch (e) {
                        console.log("[ ] Appmattus [Transparency]");
                    }
                }

                if (MODE.ChromiumCronet) {
                    const colorKey = randomColor();
                    const CronetEngineBuilderImpl = loadJava("org.chromium.net.impl.CronetEngineBuilderImpl");
                    try {
                        CronetEngineBuilderImpl.enablePublicKeyPinningBypassForLocalTrustAnchors.overload("boolean").implementation = function (a) {
                            console.log(`${colorKey}  --> Chromium [CronetEngineBuilderImpl] (LocalTrustAnchors)${COLORS.reset}`);
                            return CronetEngineBuilderImpl.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                        };
                        console.log("[+] Chromium [CronetEngineBuilderImpl] (LocalTrustAnchors)");
                    } catch (e) {
                        console.log("[ ] Chromium [CronetEngineBuilderImpl] (LocalTrustAnchors)");
                    }

                    try {
                        CronetEngineBuilderImpl.addPublicKeyPins.overload("java.lang.String", "java.util.Set", "boolean", "java.util.Date").implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                            console.log(`${colorKey}  --> Chromium [CronetEngineBuilderImpl] (PublicKey): ${hostName}${COLORS.reset}`);
                            return CronetEngineBuilderImpl.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
                        };
                        console.log("[+] Chromium [CronetEngineBuilderImpl] (PublicKey)");
                    } catch (e) {
                        console.log("[ ] Chromium [CronetEngineBuilderImpl] (PublicKey)");
                    }
                }

                if (MODE.Flutter) {
                    const colorKey = randomColor();
                    const HttpCertificatePinning = loadJava("diefferson.http_certificate_pinning.HttpCertificatePinning");
                    const SslPinningPlugin = loadJava("com.macif.plugin.sslpinningplugin.SslPinningPlugin");
                    try {
                        HttpCertificatePinning.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                            console.log(`${colorKey}  --> Flutter [HttpCertificatePinning]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Flutter [HttpCertificatePinning]");
                    } catch (e) {
                        console.log("[ ] Flutter [HttpCertificatePinning]");
                    }

                    try {
                        SslPinningPlugin.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                            console.log(`${colorKey}  --> Flutter [SslPinningPlugin]: ${a}${COLORS.reset}`);
                            return true;
                        };
                        console.log("[+] Flutter [SslPinningPlugin]");
                    } catch (e) {
                        console.log("[ ] Flutter [SslPinningPlugin]");
                    }
                }

            }
        );
    } else {
        console.log(`${COLORS.red}[!] Java unavailable${COLORS.reset}`);
    }

    console.log("Capturing setup completed");
    console.log("---");
}, 0);