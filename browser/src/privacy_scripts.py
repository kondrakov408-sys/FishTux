"""
TuxBrowser - Anti-Fingerprinting & Privacy Scripts Engine
Injects sandboxed scripts into web pages to defeat Canvas, Audio, WebRTC, Hardware, and Timezone fingerprinting.
"""

from PySide6.QtWebEngineCore import QWebEngineScript, QWebEngineProfile


def get_anti_fingerprint_js(target_tz: str = "Europe/Amsterdam") -> str:
    """Generates the full anti-fingerprint JS payload with dynamic GeoIP Timezone matching."""
    return f"""
(function() {{
    'use strict';

    // 0. Anti-Detection Engine: Native function camouflage & descriptor compliance
    const nativeToStringMap = new WeakMap();
    const origToString = Function.prototype.toString;

    function makeNative(wrapper, orig, customName) {{
        const name = customName || (orig ? orig.name : '');
        nativeToStringMap.set(wrapper, `function ${{name}}() {{ [native code] }}`);
        try {{
            Object.defineProperty(wrapper, 'name', {{ value: name, configurable: true }});
            if (orig) {{
                Object.defineProperty(wrapper, 'length', {{ value: orig.length, configurable: true }});
            }}
        }} catch(e) {{}}
        return wrapper;
    }}

    Function.prototype.toString = makeNative(function() {{
        if (nativeToStringMap.has(this)) {{
            return nativeToStringMap.get(this);
        }}
        return origToString.apply(this, arguments);
    }}, origToString, 'toString');

    // Helper to create authentic native getters with strict 'Illegal invocation' checks
    function makeNativeGetter(proto, prop, val) {{
        const getter = function() {{
            if (this !== proto && !(this instanceof (proto.constructor || Object))) {{
                throw new TypeError("Illegal invocation");
            }}
            return typeof val === 'function' ? val.call(this) : val;
        }};
        makeNative(getter, null, `get ${{prop}}`);
        try {{
            Object.defineProperty(proto, prop, {{
                get: getter,
                set: undefined,
                enumerable: true,
                configurable: true
            }});
        }} catch(e) {{}}
        return getter;
    }}

    // 1. Hardware & Device Properties (Authentic native prototype descriptors)
    try {{
        makeNativeGetter(Navigator.prototype, 'hardwareConcurrency', 4);
        makeNativeGetter(Navigator.prototype, 'deviceMemory', 8);
        makeNativeGetter(Navigator.prototype, 'globalPrivacyControl', true);
        makeNativeGetter(Navigator.prototype, 'doNotTrack', '1');
        makeNativeGetter(Navigator.prototype, 'language', 'en-US');
        makeNativeGetter(Navigator.prototype, 'languages', Object.freeze(['en-US', 'en']));
    }} catch(e) {{}}

    // 2. Iframe Interception (Neutralizes clean-iframe prototype reflection attacks)
    try {{
        const protectWindow = (w) => {{
            if (!w || w.__tux_secured__) return;
            try {{
                w.__tux_secured__ = true;
                w.Function.prototype.toString = Function.prototype.toString;
                if (w.Navigator && w.Navigator.prototype) {{
                    makeNativeGetter(w.Navigator.prototype, 'hardwareConcurrency', 4);
                    makeNativeGetter(w.Navigator.prototype, 'deviceMemory', 8);
                    makeNativeGetter(w.Navigator.prototype, 'language', 'en-US');
                    makeNativeGetter(w.Navigator.prototype, 'languages', Object.freeze(['en-US', 'en']));
                }}
            }} catch(e) {{}}
        }};

        const origContentWindowDesc = Object.getOwnPropertyDescriptor(HTMLIFrameElement.prototype, 'contentWindow');
        if (origContentWindowDesc && origContentWindowDesc.get) {{
            const origGet = origContentWindowDesc.get;
            Object.defineProperty(HTMLIFrameElement.prototype, 'contentWindow', {{
                get: makeNative(function() {{
                    const w = origGet.apply(this, arguments);
                    if (w) protectWindow(w);
                    return w;
                }}, origGet, 'get contentWindow'),
                configurable: true,
                enumerable: true
            }});
        }}
    }} catch(e) {{}}

    // 3. Web Worker & SharedWorker Interception
    try {{
        const workerHookPayload = `
            try {{
                Object.defineProperty(navigator, 'hardwareConcurrency', {{ value: 4, configurable: true }});
                Object.defineProperty(navigator, 'deviceMemory', {{ value: 8, configurable: true }});
                Object.defineProperty(navigator, 'language', {{ value: 'en-US', configurable: true }});
            }} catch(e) {{}}
        `;
        const origWorker = window.Worker;
        if (origWorker) {{
            const workerProxy = function(scriptURL, options) {{
                let finalURL = scriptURL;
                if (typeof scriptURL === 'string' && !scriptURL.startsWith('blob:')) {{
                    try {{
                        const blob = new Blob([workerHookPayload + '\\nimportScripts("' + scriptURL + '");'], {{ type: 'application/javascript' }});
                        finalURL = URL.createObjectURL(blob);
                    }} catch(e) {{}}
                }}
                return new origWorker(finalURL, options);
            }};
            workerProxy.prototype = origWorker.prototype;
            window.Worker = makeNative(workerProxy, origWorker, 'Worker');
        }}
    }} catch(e) {{}}

    // 4. WebRTC Leak Prevention (Total JS surface removal)
    try {{
        delete window.RTCPeerConnection;
        delete window.webkitRTCPeerConnection;
        delete window.RTCSessionDescription;
        delete window.RTCIceCandidate;
    }} catch(e) {{}}

    // 5. Canvas Farbling (Subtle deterministic noise)
    try {{
        const origToDataURL = HTMLCanvasElement.prototype.toDataURL;
        HTMLCanvasElement.prototype.toDataURL = makeNative(function(type, ...args) {{
            if (this.width > 0 && this.height > 0 && (!type || type === 'image/png')) {{
                try {{
                    const ctx = this.getContext('2d');
                    if (ctx) {{
                        const imgData = ctx.getImageData(0, 0, Math.min(this.width, 16), Math.min(this.height, 16));
                        for (let i = 0; i < imgData.data.length; i += 8) {{
                            imgData.data[i] = (imgData.data[i] ^ 1);
                        }}
                        ctx.putImageData(imgData, 0, 0);
                    }}
                }} catch(e) {{}}
            }}
            return origToDataURL.apply(this, [type, ...args]);
        }}, origToDataURL, 'toDataURL');

        const origGetImageData = CanvasRenderingContext2D.prototype.getImageData;
        CanvasRenderingContext2D.prototype.getImageData = makeNative(function(x, y, w, h) {{
            const imgData = origGetImageData.apply(this, arguments);
            try {{
                if (imgData && imgData.data && imgData.data.length > 0) {{
                    for (let i = 0; i < Math.min(imgData.data.length, 32); i += 4) {{
                        imgData.data[i] = (imgData.data[i] ^ 1);
                    }}
                }}
            }} catch(e) {{}}
            return imgData;
        }}, origGetImageData, 'getImageData');
    }} catch(e) {{}}

    // 6. WebGL Fingerprint Spoofing
    try {{
        const UNMASKED_VENDOR_WEBGL = 0x9245;
        const UNMASKED_RENDERER_WEBGL = 0x9246;
        const MAX_TEXTURE_SIZE = 0x0D33;

        const spoofWebGL = function(proto) {{
            if (!proto || !proto.getParameter) return;
            const origGetParameter = proto.getParameter;
            proto.getParameter = makeNative(function(param) {{
                if (param === UNMASKED_VENDOR_WEBGL) return 'Intel Inc.';
                if (param === UNMASKED_RENDERER_WEBGL) return 'Intel Iris OpenGL Engine';
                if (param === MAX_TEXTURE_SIZE) return 8192;
                return origGetParameter.apply(this, arguments);
            }}, origGetParameter, 'getParameter');
        }};

        if (window.WebGLRenderingContext) spoofWebGL(WebGLRenderingContext.prototype);
        if (window.WebGL2RenderingContext) spoofWebGL(WebGL2RenderingContext.prototype);
    }} catch(e) {{}}

    // 7. AudioContext Farbling
    try {{
        if (window.AudioBuffer && AudioBuffer.prototype.getChannelData) {{
            const origGetChannelData = AudioBuffer.prototype.getChannelData;
            AudioBuffer.prototype.getChannelData = makeNative(function(channel) {{
                const data = origGetChannelData.apply(this, arguments);
                for (let i = 0; i < Math.min(data.length, 100); i += 10) {{
                    data[i] += 0.0000001;
                }}
                return data;
            }}, origGetChannelData, 'getChannelData');
        }}
    }} catch(e) {{}}

    // 8. Navigator Plugins & MimeTypes Emulation
    try {{
        const fakePlugins = Object.freeze([
            {{ name: "PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" }},
            {{ name: "Chrome PDF Viewer", filename: "internal-pdf-viewer", description: "Portable Document Format" }}
        ]);
        makeNativeGetter(Navigator.prototype, 'plugins', fakePlugins);
        makeNativeGetter(Navigator.prototype, 'mimeTypes', Object.freeze([]));
    }} catch(e) {{}}

    // 9. Precision Timezone Alignment (Matches Active IP GeoIP Timezone: {target_tz})
    try {{
        const TARGET_TZ = "{target_tz}";

        function getTzOffsetMinutes(date, tz) {{
            try {{
                const str = date.toLocaleString('en-US', {{ timeZone: tz, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' }});
                const parts = str.match(/(\\d+)\\/(\\d+)\\/(\\d+),\\s+(\\d+):(\\d+):(\\d+)/);
                if (parts) {{
                    const targetDate = new Date(Date.UTC(+parts[3], +parts[1] - 1, +parts[2], +parts[4], +parts[5], +parts[6]));
                    return Math.round((date.getTime() - targetDate.getTime()) / 60000);
                }}
            }} catch(e) {{}}
            return 0;
        }}

        function getTargetParts(date) {{
            try {{
                const str = date.toLocaleString('en-US', {{ timeZone: TARGET_TZ, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric', weekday: 'short' }});
                const parts = str.match(/([A-Za-z]+),\\s+(\\d+)\\/(\\d+)\\/(\\d+),\\s+(\\d+):(\\d+):(\\d+)/);
                if (parts) {{
                    return {{
                        weekday: parts[1],
                        month: +parts[2] - 1,
                        day: +parts[3],
                        year: +parts[4],
                        hour: +parts[5],
                        minute: +parts[6],
                        second: +parts[7]
                    }};
                }}
            }} catch(e) {{}}
            return null;
        }}

        // Spoof Date.prototype.getTimezoneOffset
        const origOffset = Date.prototype.getTimezoneOffset;
        Date.prototype.getTimezoneOffset = makeNative(function() {{
            return getTzOffsetMinutes(this, TARGET_TZ);
        }}, origOffset, 'getTimezoneOffset');

        // Spoof Date getters to return TARGET_TZ local values
        const origGetHours = Date.prototype.getHours;
        Date.prototype.getHours = makeNative(function() {{
            const p = getTargetParts(this);
            return p ? p.hour : origGetHours.apply(this, arguments);
        }}, origGetHours, 'getHours');

        const origGetMinutes = Date.prototype.getMinutes;
        Date.prototype.getMinutes = makeNative(function() {{
            const p = getTargetParts(this);
            return p ? p.minute : origGetMinutes.apply(this, arguments);
        }}, origGetMinutes, 'getMinutes');

        const origGetSeconds = Date.prototype.getSeconds;
        Date.prototype.getSeconds = makeNative(function() {{
            const p = getTargetParts(this);
            return p ? p.second : origGetSeconds.apply(this, arguments);
        }}, origGetSeconds, 'getSeconds');

        const origGetDate = Date.prototype.getDate;
        Date.prototype.getDate = makeNative(function() {{
            const p = getTargetParts(this);
            return p ? p.day : origGetDate.apply(this, arguments);
        }}, origGetDate, 'getDate');

        const origGetMonth = Date.prototype.getMonth;
        Date.prototype.getMonth = makeNative(function() {{
            const p = getTargetParts(this);
            return p ? p.month : origGetMonth.apply(this, arguments);
        }}, origGetMonth, 'getMonth');

        const origGetFullYear = Date.prototype.getFullYear;
        Date.prototype.getFullYear = makeNative(function() {{
            const p = getTargetParts(this);
            return p ? p.year : origGetFullYear.apply(this, arguments);
        }}, origGetFullYear, 'getFullYear');

        const origGetDay = Date.prototype.getDay;
        Date.prototype.getDay = makeNative(function() {{
            const p = getTargetParts(this);
            if (p && p.weekday) {{
                const map = {{ 'Sun': 0, 'Mon': 1, 'Tue': 2, 'Wed': 3, 'Thu': 4, 'Fri': 5, 'Sat': 6 }};
                return map[p.weekday.slice(0, 3)] ?? origGetDay.apply(this, arguments);
            }}
            return origGetDay.apply(this, arguments);
        }}, origGetDay, 'getDay');

        // Spoof Date toDateString
        const origToDateString = Date.prototype.toDateString;
        Date.prototype.toDateString = makeNative(function() {{
            try {{
                const p = getTargetParts(this);
                if (p) {{
                    const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                    const dayStr = String(p.day).padStart(2, '0');
                    return `${{p.weekday.slice(0, 3)}} ${{months[p.month]}} ${{dayStr}} ${{p.year}}`;
                }}
            }} catch(e) {{}}
            return origToDateString.apply(this, arguments);
        }}, origToDateString, 'toDateString');

        // Spoof Date toLocaleString / toLocaleDateString / toLocaleTimeString
        const origToLocaleString = Date.prototype.toLocaleString;
        Date.prototype.toLocaleString = makeNative(function(locales, options) {{
            const opts = Object.assign({{}}, options);
            if (!opts.timeZone) opts.timeZone = TARGET_TZ;
            return origToLocaleString.call(this, locales, opts);
        }}, origToLocaleString, 'toLocaleString');

        const origToLocaleDateString = Date.prototype.toLocaleDateString;
        Date.prototype.toLocaleDateString = makeNative(function(locales, options) {{
            const opts = Object.assign({{}}, options);
            if (!opts.timeZone) opts.timeZone = TARGET_TZ;
            return origToLocaleDateString.call(this, locales, opts);
        }}, origToLocaleDateString, 'toLocaleDateString');

        const origToLocaleTimeString = Date.prototype.toLocaleTimeString;
        Date.prototype.toLocaleTimeString = makeNative(function(locales, options) {{
            const opts = Object.assign({{}}, options);
            if (!opts.timeZone) opts.timeZone = TARGET_TZ;
            return origToLocaleTimeString.call(this, locales, opts);
        }}, origToLocaleTimeString, 'toLocaleTimeString');

        // Spoof Date toString & toTimeString
        const origDateToString = Date.prototype.toString;
        Date.prototype.toString = makeNative(function() {{
            try {{
                const p = getTargetParts(this);
                const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                const dStr = p ? `${{p.weekday.slice(0, 3)}} ${{months[p.month]}} ${{String(p.day).padStart(2, '0')}} ${{p.year}}` : this.toDateString();
                const tStr = p ? `${{String(p.hour).padStart(2, '0')}}:${{String(p.minute).padStart(2, '0')}}:${{String(p.second).padStart(2, '0')}}` : "00:00:00";
                const offMin = getTzOffsetMinutes(this, TARGET_TZ);
                const sign = offMin <= 0 ? '+' : '-';
                const absMin = Math.abs(offMin);
                const offHoursStr = String(Math.floor(absMin / 60)).padStart(2, '0');
                const offMinStr = String(absMin % 60).padStart(2, '0');
                const gmtStr = `GMT${{sign}}${{offHoursStr}}${{offMinStr}}`;
                return `${{dStr}} ${{tStr}} ${{gmtStr}} (${{TARGET_TZ}})`;
            }} catch(e) {{
                return origDateToString.apply(this, arguments);
            }}
        }}, origDateToString, 'toString');

        const origDateToTimeString = Date.prototype.toTimeString;
        Date.prototype.toTimeString = makeNative(function() {{
            try {{
                const p = getTargetParts(this);
                const tStr = p ? `${{String(p.hour).padStart(2, '0')}}:${{String(p.minute).padStart(2, '0')}}:${{String(p.second).padStart(2, '0')}}` : "00:00:00";
                const offMin = getTzOffsetMinutes(this, TARGET_TZ);
                const sign = offMin <= 0 ? '+' : '-';
                const absMin = Math.abs(offMin);
                const offHoursStr = String(Math.floor(absMin / 60)).padStart(2, '0');
                const offMinStr = String(absMin % 60).padStart(2, '0');
                const gmtStr = `GMT${{sign}}${{offHoursStr}}${{offMinStr}}`;
                return `${{tStr}} ${{gmtStr}} (${{TARGET_TZ}})`;
            }} catch(e) {{
                return origDateToTimeString.apply(this, arguments);
            }}
        }}, origDateToTimeString, 'toTimeString');

        // Spoof Intl.DateTimeFormat
        if (typeof Intl !== 'undefined' && Intl.DateTimeFormat) {{
            const OrigDateTimeFormat = Intl.DateTimeFormat;
            const PatchedDateTimeFormat = makeNative(function(locales, options) {{
                const opts = Object.assign({{}}, options);
                if (!opts.timeZone) {{
                    opts.timeZone = TARGET_TZ;
                }}
                return new OrigDateTimeFormat(locales, opts);
            }}, OrigDateTimeFormat, 'DateTimeFormat');

            PatchedDateTimeFormat.prototype = OrigDateTimeFormat.prototype;

            if (OrigDateTimeFormat.supportedLocalesOf) {{
                PatchedDateTimeFormat.supportedLocalesOf = makeNative(function(locales, options) {{
                    return OrigDateTimeFormat.supportedLocalesOf(locales, options);
                }}, OrigDateTimeFormat.supportedLocalesOf, 'supportedLocalesOf');
            }}

            const origResolved = OrigDateTimeFormat.prototype.resolvedOptions;
            OrigDateTimeFormat.prototype.resolvedOptions = makeNative(function() {{
                const res = origResolved.apply(this, arguments);
                res.timeZone = TARGET_TZ;
                return res;
            }}, origResolved, 'resolvedOptions');

            makeNative(PatchedDateTimeFormat, OrigDateTimeFormat, 'DateTimeFormat');
            Intl.DateTimeFormat = PatchedDateTimeFormat;
        }}
    }} catch(e) {{}}

    // 10. Geolocation Neutralization
    try {{
        if (navigator.geolocation) {{
            navigator.geolocation.getCurrentPosition = function(success, error, options) {{
                if (error) {{
                    error({{ code: 1, message: "User denied Geolocation" }});
                }}
            }};
            navigator.geolocation.watchPosition = function() {{ return 0; }};
        }}
    }} catch(e) {{}}

    // 11. Battery Status Neutralization
    try {{
        delete Navigator.prototype.getBattery;
    }} catch(e) {{}}

}})();
"""


ANTI_FINGERPRINT_JS = get_anti_fingerprint_js("Europe/Amsterdam")


def install_privacy_scripts(profile: QWebEngineProfile, target_tz: str = "Europe/Amsterdam"):
    """Installs the anti-fingerprinting script globally into the WebEngine profile."""
    # Remove existing script if any
    scripts = profile.scripts()
    for s in scripts.toList():
        if s.name() == "TuxAntiFingerprintShield":
            scripts.remove(s)
            break

    script = QWebEngineScript()
    script.setName("TuxAntiFingerprintShield")
    script.setSourceCode(get_anti_fingerprint_js(target_tz))
    script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
    script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
    script.setRunsOnSubFrames(True)
    scripts.insert(script)
