/**@@@+++@@@@******************************************************************
 **
 ** Android SSL Pinning frida script vBETA hyugogirubato
 **
 ** frida -D "DEVICE" -l "pinning.js" -f "PACKAGE"
 **
 ** Update: Beta version preview.
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
                                const className = callingFunctionStack.getClassName();
                                const methodName = callingFunctionStack.getMethodName();
                                const callingClass = Java.use(className);
                                const callingMethod = callingClass[methodName];
                                console.log(`${COLORS.red}[!] Attempting to bypass uncommon SSL Pinning method on: ${className}.${methodName}${COLORS.reset}`);

                                // Skip it when already patched by Frida
                                if (callingMethod.implementation) {
                                    return;
                                }

                                // Trying to patch the uncommon SSL Pinning method via implementation
                                const returnTypeName = callingMethod.returnType.type;
                                callingMethod.implementation = function () {
                                    rudimentaryFix(returnTypeName);
                                };
                            } catch (e) {
                                // Dynamic patching via implementation does not works, then trying via function overloading
                                // console.log("[!] The uncommon SSL Pinning method has more than one overload");
                                if (String(e).includes(".overload")) {
                                    const splittedList = String(e).split(".overload");
                                    for (let i = 2; i < splittedList.length; i++) {
                                        const extractedOverload = splittedList[i].trim().split("(")[1].slice(0, -1).replaceAll("'", "");
                                        // Check if extractedOverload has multiple arguments
                                        if (extractedOverload.includes(",")) {
                                            // Go here if overloaded method has multiple arguments (NOTE: max 6 args are covered here)
                                            const argList = extractedOverload.split(", ");
                                            console.log(`${COLORS.red}[!] Attempting overload of ${className}.${methodName} with arguments: ${extractedOverload}${COLORS.reset}`);

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
                                } else {
                                    console.log(`${COLORS.yellow}[-] Failed to dynamically patch SSLPeerUnverifiedException ${e}${COLORS.reset}`);
                                }
                            }
                            return this.$init(str);
                        }
                        console.log("[+] SSLPeerUnverifiedException");
                    } catch (e) {
                        console.log("[ ] SSLPeerUnverifiedException");
                    }
                }

                if (MODE.HttpsURLConnection) {
                    const colorKey = randomColor();
                    try {
                        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function (hostnameVerifier) {
                            console.log("  --> Bypassing HttpsURLConnection (setDefaultHostnameVerifier)");
                        };
                        console.log("[+] HttpsURLConnection [DefaultHostnameVerifier]");
                    } catch (e) {
                        console.log("[ ] HttpsURLConnection [DefaultHostnameVerifier]");
                    }

                    try {
                        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                        HttpsURLConnection.setSSLSocketFactory.implementation = function (SSLSocketFactory) {
                            console.log("  --> Bypassing HttpsURLConnection (setSSLSocketFactory)");
                        };
                        console.log("[+] HttpsURLConnection [SSLSocketFactory]");
                    } catch (err) {
                        console.log("[ ] HttpsURLConnection [SSLSocketFactory]");
                    }

                    try {
                        const HttpsURLConnection = Java.use("javax.net.ssl.HttpsURLConnection");
                        HttpsURLConnection.setHostnameVerifier.implementation = function (hostnameVerifier) {
                            console.log("  --> Bypassing HttpsURLConnection (setHostnameVerifier)");
                        };
                        console.log("[+] HttpsURLConnection [HostnameVerifier]");
                    } catch (err) {
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
                            console.log("[+] Bypassing Trustmanager (Android < 7) pinner");
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
                    const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
                    try {
                        const array_list = Java.use("java.util.ArrayList");
                        TrustManagerImpl.checkTrustedRecursive.implementation = function (certs, ocspData, tlsSctData, host, clientAuth, untrustedChain, trustAnchorChain, used) {
                            console.log(`[+] Bypassing TrustManagerImpl (Android > 7) checkTrustedRecursive check: ${host}`);
                            return array_list.$new();
                        };
                        console.log("[+] TrustManagerImpl [TrustedRecursive] (Android > 7)");
                    } catch (e) {
                        console.log("[ ] TrustManagerImpl [TrustedRecursive] (Android > 7)");
                    }

                    try {
                        TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
                            console.log(`[+] Bypassing TrustManagerImpl (Android > 7) verifyChain check: ${host}`);
                            return untrustedChain;
                        };
                        console.log("[+] TrustManagerImpl (Android > 7) [verifyChain]");
                    } catch (e) {
                        console.log("[ ] TrustManagerImpl (Android > 7) [verifyChain]");
                    }
                }

                if (MODE.OkHTTPv3) {
                    const colorKey = randomColor();
                    const CertificatePinner = Java.use("okhttp3.CertificatePinner");

                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log("[+] Bypassing OkHTTPv3 {1}: " + a);
                        };
                        console.log("[+] OkHTTPv3 [List]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [List]");
                    }

                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function (a, b) {
                            console.log("[+] Bypassing OkHTTPv3 {2}: " + a);
                        };
                        console.log("[+] OkHTTPv3 [Certificate]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [Certificate]");
                    }

                    try {
                        CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (a, b) {
                            console.log("[+] Bypassing OkHTTPv3 {3}: " + a);
                        };
                        console.log("[+] OkHTTPv3 [Array]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [Array]");
                    }

                    try {
                        CertificatePinner.check$okhttp.overload("java.lang.String", "kotlin.jvm.functions.Function0").implementation = function (a, b) {
                            console.log("[+] Bypassing OkHTTPv3 {4}: " + a);
                        };
                        console.log("[+] OkHTTPv3 [Function]");
                    } catch (e) {
                        console.log("[ ] OkHTTPv3 [Function]");
                    }
                }

                if (MODE.Trustkit) {
                    const colorKey = randomColor();
                    const OkHostnameVerifier = Java.use("com.datatheorem.android.trustkit.pinning.OkHostnameVerifier");
                    const PinningTrustManager = Java.use("com.datatheorem.android.trustkit.pinning.PinningTrustManager");

                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (a, b) {
                            console.log("[+] Bypassing Trustkit {1}: " + a);
                            return true;
                        };
                        console.log("[+] Trustkit OkHostnameVerifier [SSLSession]");
                    } catch (e) {
                        console.log("[ ] Trustkit OkHostnameVerifier [SSLSession]");
                    }

                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (a, b) {
                            console.log("[+] Bypassing Trustkit {2}: " + a);
                            return true;
                        };
                        console.log("[+] Trustkit OkHostnameVerifier [X509Certificate]");
                    } catch (e) {
                        console.log("[ ] Trustkit OkHostnameVerifier [X509Certificate]");
                    }

                    try {
                        PinningTrustManager.checkServerTrusted.overload("[Ljava.security.cert.X509Certificate;", "java.lang.String").implementation = function (chain, authType) {
                            console.log("[+] Bypassing Trustkit {3}");
                        };
                        console.log("[+] Trustkit PinningTrustManager");
                    } catch (e) {
                        console.log("[ ] Trustkit PinningTrustManager");
                    }
                }

                if (MODE.TitaniumPinningTrustManager) {
                    const colorKey = randomColor();
                    try {
                        const PinningTrustManager = Java.use("appcelerator.https.PinningTrustManager");
                        PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                            console.log("[+] Bypassing Appcelerator PinningTrustManager");
                        };
                        console.log("[+] Titanium [PinningTrustManager]");
                    } catch (e) {
                        console.log("[ ] Titanium [PinningTrustManager]");
                    }
                }

                if (MODE.FabricPinningTrustManager) {
                    const colorKey = randomColor();
                    try {
                        const PinningTrustManager = Java.use("io.fabric.sdk.android.services.network.PinningTrustManager");
                        PinningTrustManager.checkServerTrusted.implementation = function (chain, authType) {
                            console.log("[+] Bypassing Fabric PinningTrustManager");
                        };
                        console.log("[+] Fabric [PinningTrustManager]");
                    } catch (e) {
                        console.log("[ ] Fabric [PinningTrustManager]");
                    }
                }

                if (MODE.ConscryptOpenSSLSocketImpl) {
                    const colorKey = randomColor();
                    const OpenSSLSocketImpl = Java.use("com.android.org.conscrypt.OpenSSLSocketImpl");
                    try {
                        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certRefs, JavaObject, authMethod) {
                            console.log("[+] Bypassing OpenSSLSocketImpl Conscrypt");
                        };
                        console.log("[+] Conscrypt (Refs) [OpenSSLSocketImpl]");
                    } catch (e) {
                        console.log("[ ] Conscrypt (Refs) [OpenSSLSocketImpl]");
                    }

                    try {
                        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (certChain, authMethod) {
                            console.log("[+] Bypassing OpenSSLSocketImpl Conscrypt");
                        };
                        console.log("[+] Conscrypt (Chain) [OpenSSLSocketImpl]");
                    } catch (e) {
                        console.log("[ ] Conscrypt (Chain) [OpenSSLSocketImpl]");
                    }
                }

                if (MODE.ConscryptOpenSSLEngineSocketImpl) {
                    const colorKey = randomColor();
                    try {
                        const OpenSSLEngineSocketImpl = Java.use("com.android.org.conscrypt.OpenSSLEngineSocketImpl");
                        OpenSSLEngineSocketImpl.verifyCertificateChain.overload("[Ljava.lang.Long;", "java.lang.String").implementation = function (a, b) {
                            console.log("[+] Bypassing OpenSSLEngineSocketImpl Conscrypt: " + b);
                        };
                        console.log("[+] Conscrypt [OpenSSLEngineSocketImpl]");
                    } catch (e) {
                        console.log("[ ] Conscrypt [OpenSSLEngineSocketImpl]");
                    }
                }

                if (MODE.ApacheOpenSSLSocketImpl) {
                    const colorKey = randomColor();
                    try {
                        const OpenSSLSocketImpl = Java.use("org.apache.harmony.xnet.provider.jsse.OpenSSLSocketImpl");
                        OpenSSLSocketImpl.verifyCertificateChain.implementation = function (asn1DerEncodedCertificateChain, authMethod) {
                            console.log("[+] Bypassing OpenSSLSocketImpl Apache Harmony");
                        };
                        console.log("[+] Apache [OpenSSLSocketImpl]");
                    } catch (e) {
                        console.log("[ ] Apache [OpenSSLSocketImpl]");
                    }
                }

                if (MODE.PhoneGapsslCertificateChecker) {
                    const colorKey = randomColor();
                    try {
                        const sslCertificateChecker = Java.use("nl.xservices.plugins.sslCertificateChecker");
                        sslCertificateChecker.execute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation = function (a, b, c) {
                            console.log("[+] Bypassing PhoneGap sslCertificateChecker: " + a);
                            return true;
                        };
                        console.log("[+] PhoneGap [sslCertificateChecker]");
                    } catch (e) {
                        console.log("[ ] PhoneGap [sslCertificateChecker]");
                    }
                }

                if (MODE.IBMMobileFirst) {
                    const colorKey = randomColor();
                    const MobileFirst = Java.use("com.worklight.wlclient.api.WLClient");
                    try {
                        MobileFirst.getInstance().pinTrustedCertificatePublicKey.overload("java.lang.String").implementation = function (cert) {
                            console.log("[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {1}: " + cert);
                        };
                        console.log("[+] IBM [MobileFirst] (String)");
                    } catch (e) {
                        console.log("[ ] IBM [MobileFirst] (String)");
                    }

                    try {
                        MobileFirst.getInstance().pinTrustedCertificatePublicKey.overload("[Ljava.lang.String;").implementation = function (cert) {
                            console.log("[+] Bypassing IBM MobileFirst pinTrustedCertificatePublicKey {2}: " + cert);
                        };
                        console.log("[+] IBM [MobileFirst] (Array)");
                    } catch (e) {
                        console.log("[ ] IBM [MobileFirst] (Array)");
                    }
                }

                if (MODE.IBMWorkLight) {
                    const colorKey = randomColor();
                    const WorkLight = Java.use("com.worklight.wlclient.certificatepinning.HostNameVerifierWithCertificatePinning");
                    try {
                        WorkLight.verify.overload("java.lang.String", "javax.net.ssl.SSLSocket").implementation = function (a, b) {
                            console.log("[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {1}: " + a);
                        };
                        console.log("[+] IBM [WorkLight] (SSLSocket)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (SSLSocket)");
                    }

                    try {
                        WorkLight.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (a, b) {
                            console.log("[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {2}: " + a);
                        };
                        console.log("[+] IBM [WorkLight] (X509Certificate)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (X509Certificate)");
                    }

                    try {
                        WorkLight.verify.overload("java.lang.String", "[Ljava.lang.String;", "[Ljava.lang.String;").implementation = function (a, b) {
                            console.log("[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {3}: " + a);
                        };
                        console.log("[+] IBM [WorkLight] (String)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (String)");
                    }

                    try {
                        WorkLight.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (a, b) {
                            console.log("[+] Bypassing IBM WorkLight HostNameVerifierWithCertificatePinning {4}: " + a);
                            return true;
                        };
                        console.log("[+] IBM [WorkLight] (SSLSession)");
                    } catch (e) {
                        console.log("[ ] IBM [WorkLight] (SSLSession)");
                    }
                }

                if (MODE.ConscryptCertPinManager) {
                    const colorKey = randomColor();
                    const CertPinManager = Java.use("com.android.org.conscrypt.CertPinManager");
                    try {
                        CertPinManager.checkChainPinning.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log("[+] Bypassing Conscrypt CertPinManager: " + a);
                            return true;
                        };
                        console.log("[+] Conscrypt [CertPinManager] (List)");
                    } catch (e) {
                        console.log("[ ] Conscrypt [CertPinManager] (List)");
                    }

                    try {
                        CertPinManager.isChainValid.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log("[+] Bypassing Conscrypt CertPinManager (Legacy): " + a);
                            return true;
                        };
                        console.log("[+] Conscrypt [CertPinManager] (Legacy)");
                    } catch (e) {
                        console.log("[ ] Conscrypt [CertPinManager] (Legacy)");
                    }
                }

                if (MODE.NetsecurityCertPinManager) {
                    const colorKey = randomColor();
                    try {
                        const CertPinManager = Java.use("com.commonsware.cwac.netsecurity.conscrypt.CertPinManager");
                        CertPinManager.isChainValid.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log("[+] Bypassing CWAC-Netsecurity CertPinManager: " + a);
                            return true;
                        };
                        console.log("[+] Netsecurity [CertPinManager]");
                    } catch (e) {
                        console.log("[ ] Netsecurity [CertPinManager]");
                    }
                }

                if (MODE.AndroidgapWorkLight) {
                    const colorKey = randomColor();
                    try {
                        const Worklight = Java.use("com.worklight.androidgap.plugin.WLCertificatePinningPlugin");
                        Worklight.execute.overload("java.lang.String", "org.json.JSONArray", "org.apache.cordova.CallbackContext").implementation = function (a, b, c) {
                            console.log("[+] Bypassing Worklight Androidgap WLCertificatePinningPlugin: " + a);
                            return true;
                        };
                        console.log("[+] Android [WorkLight]");
                    } catch (e) {
                        console.log("[ ] Android [WorkLight]");
                    }
                }

                if (MODE.NettyFingerprintTrustManagerFactory) {
                    const colorKey = randomColor();
                    try {
                        const FingerprintTrustManagerFactory = Java.use("io.netty.handler.ssl.util.FingerprintTrustManagerFactory");
                        FingerprintTrustManagerFactory.checkTrusted.implementation = function (type, chain) {
                            console.log("[+] Bypassing Netty FingerprintTrustManagerFactory");
                        };
                        console.log("[+] Netty [FingerprintTrustManagerFactory]");
                    } catch (e) {
                        console.log("[ ] Netty [FingerprintTrustManagerFactory]");
                    }
                }

                if (MODE.SquareupCertificatePinner) {
                    // OkHTTP < v3
                    const colorKey = randomColor();
                    const CertificatePinner = Java.use("com.squareup.okhttp.CertificatePinner");
                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.security.cert.Certificate").implementation = function (a, b) {
                            console.log("[+] Bypassing Squareup CertificatePinner {1}: " + a);
                        };
                        console.log("[+] Squareup [CertificatePinner] (Certificate)");
                    } catch (e) {
                        console.log("[ ] Squareup [CertificatePinner] (Certificate)");
                    }

                    try {
                        CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (a, b) {
                            console.log("  --> Bypassing Squareup CertificatePinner (list): " + a);
                        };
                        console.log("[+] Squareup [CertificatePinner] (List)");
                    } catch (e) {
                        console.log("[ ] Squareup [CertificatePinner] (List)");
                    }
                }

                if (MODE.SquareupOkHostnameVerifier) {
                    // OkHTTP v3
                    const colorKey = randomColor();
                    const OkHostnameVerifier = Java.use("com.squareup.okhttp.internal.tls.OkHostnameVerifier");
                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "java.security.cert.X509Certificate").implementation = function (a, b) {
                            console.log("[+] Bypassing Squareup OkHostnameVerifier {1}: " + a);
                            return true;
                        };
                        console.log("[+] Squareup [OkHostnameVerifier] (X509Certificate)");
                    } catch (e) {
                        console.log("[ ] Squareup [OkHostnameVerifier] (X509Certificate)");
                    }

                    try {
                        OkHostnameVerifier.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function (a, b) {
                            console.log("  --> Bypassing Squareup OkHostnameVerifier (SSLSession): " + a);
                            return true;
                        };
                        console.log("[+] Squareup [OkHostnameVerifier] (SSLSession)");
                    } catch (e) {
                        console.log("[ ] Squareup [OkHostnameVerifier] (SSLSession)");
                    }
                }

                if (MODE.AndroidWebViewClient) {
                    const colorKey = randomColor();
                    const WebViewClient = Java.use("android.webkit.WebViewClient");

                    try {
                        WebViewClient.onReceivedSslError.overload("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError").implementation = function (obj1, obj2, obj3) {
                            console.log("[+] Bypassing Android WebViewClient check {1}");
                        };
                        console.log("[+] Android [WebViewClient] (SslErrorHandler)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (SslErrorHandler)");
                    }

                    try {
                        WebViewClient.onReceivedSslError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function (obj1, obj2, obj3) {
                            console.log("[+] Bypassing Android WebViewClient check {2}");
                        };
                        console.log("[+] Android [WebViewClient] (SSLWebResourceError)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (SSLWebResourceError)");
                    }

                    try {
                        WebViewClient.onReceivedError.overload("android.webkit.WebView", "int", "java.lang.String", "java.lang.String").implementation = function (obj1, obj2, obj3, obj4) {
                            console.log("[+] Bypassing Android WebViewClient check {3}");
                        };
                        console.log("[+] Android [WebViewClient] (String)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (String)");
                    }

                    try {
                        WebViewClient.onReceivedError.overload("android.webkit.WebView", "android.webkit.WebResourceRequest", "android.webkit.WebResourceError").implementation = function (obj1, obj2, obj3) {
                            console.log("[+] Bypassing Android WebViewClient check {4}");
                        };
                        console.log("[+] Android [WebViewClient] (WebResourceError)");
                    } catch (e) {
                        console.log("[ ] Android [WebViewClient] (WebResourceError)");
                    }
                }

                if (MODE.ApacheWebViewClient) {
                    const colorKey = randomColor();
                    try {
                        const CordovaWebViewClient = Java.use("org.apache.cordova.CordovaWebViewClient");
                        CordovaWebViewClient.onReceivedSslError.overload("android.webkit.WebView", "android.webkit.SslErrorHandler", "android.net.http.SslError").implementation = function (obj1, obj2, obj3) {
                            console.log("[+] Bypassing Apache Cordova WebViewClient check");
                            obj3.proceed();
                        };
                        console.log("[+] Apache [WebViewClient]");
                    } catch (e) {
                        console.log("[ ] Apache [WebViewClient]");
                    }
                }

                if (MODE.BoyeAbstractVerifier) {
                    const colorKey = randomColor();
                    try {
                        const AbstractVerifier = Java.use("ch.boye.httpclientandroidlib.conn.ssl.AbstractVerifier");
                        AbstractVerifier.verify.implementation = function (host, ssl) {
                            console.log("[+] Bypassing Boye AbstractVerifier check: " + host);
                        };
                        console.log("[+] Boye [AbstractVerifier]");
                    } catch (e) {
                        console.log("[ ] Boye [AbstractVerifier]");
                    }
                }

                if (MODE.ApacheAbstractVerifier) {
                    const colorKey = randomColor();
                    try {
                        const AbstractVerifier = Java.use("org.apache.http.conn.ssl.AbstractVerifier");
                        AbstractVerifier.verify.implementation = function (a, b, c, d) {
                            console.log("[+] Bypassing Apache AbstractVerifier check: " + a);
                        };
                        console.log("[+] Apache [AbstractVerifier]");
                    } catch (e) {
                        console.log("[ ] Apache [AbstractVerifier]");
                    }
                }

                if (MODE.Appmattus) {
                    const colorKey = randomColor();
                    try {
                        const Transparency = Java.use("com.appmattus.certificatetransparency.internal.verifier.CertificateTransparencyInterceptor");
                        Transparency.intercept.implementation = function (a) {
                            console.log("  --> Bypassing Appmattus (Transparency)");
                            return a.proceed(a.request());
                        };
                        console.log("[+] Appmattus [Transparency]");
                    } catch (e) {
                        console.log("[ ] Appmattus [Transparency]");
                    }
                }

                if (MODE.ChromiumCronet) {
                    const colorKey = randomColor();
                    const CronetEngineBuilderImpl = Java.use("org.chromium.net.impl.CronetEngineBuilderImpl");
                    try {
                        CronetEngineBuilderImpl.enablePublicKeyPinningBypassForLocalTrustAnchors.overload("boolean").implementation = function (a) {
                            console.log("[+] Disabling Public Key pinning for local trust anchors in Chromium Cronet");
                            return CronetEngineBuilderImpl.enablePublicKeyPinningBypassForLocalTrustAnchors.call(this, true);
                        };
                        console.log("[+] Chromium [CronetEngineBuilderImpl] (LocalTrustAnchors)");
                    } catch (e) {
                        console.log("[ ] Chromium [CronetEngineBuilderImpl] (LocalTrustAnchors)");
                    }

                    try {
                        CronetEngineBuilderImpl.addPublicKeyPins.overload("java.lang.String", "java.util.Set", "boolean", "java.util.Date").implementation = function (hostName, pinsSha256, includeSubdomains, expirationDate) {
                            console.log("[+] Bypassing Chromium Cronet pinner: " + hostName);
                            return CronetEngineBuilderImpl.addPublicKeyPins.call(this, hostName, pinsSha256, includeSubdomains, expirationDate);
                        };
                        console.log("[+] Chromium [CronetEngineBuilderImpl] (PublicKey)");
                    } catch (e) {
                        console.log("[ ] Chromium [CronetEngineBuilderImpl] (PublicKey)");
                    }
                }

                if (MODE.Flutter) {
                    const colorKey = randomColor();
                    try {
                        const HttpCertificatePinning = Java.use("diefferson.http_certificate_pinning.HttpCertificatePinning");
                        HttpCertificatePinning.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                            console.log("[+] Bypassing Flutter HttpCertificatePinning : " + a);
                            return true;
                        };
                        console.log("[+] Flutter [HttpCertificatePinning]");
                    } catch (e) {
                        console.log("[ ] Flutter [HttpCertificatePinning]");
                    }

                    try {
                        const SslPinningPlugin = Java.use("com.macif.plugin.sslpinningplugin.SslPinningPlugin");
                        SslPinningPlugin.checkConnexion.overload("java.lang.String", "java.util.List", "java.util.Map", "int", "java.lang.String").implementation = function (a, b, c, d, e) {
                            console.log("[+] Bypassing Flutter SslPinningPlugin: " + a);
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