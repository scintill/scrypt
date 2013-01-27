/*
* Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved (https://github.com/cheongwy/node-scrypt-js)
* Copyright (c) 2013 Joey Hewitt
*
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/
(function(exports) {
"use strict";
var MAX_VALUE = 2147483647;
var workerUrl = null;

//function scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen)
/*
 * N = Cpu cost
 * r = Memory cost
 * p = parallelization cost
 *
 */
exports.Crypto_scrypt = function(passwd, salt, N, r, p, dkLen, callback, maxThreads) {
    if (N == 0 || (N & (N - 1)) != 0) throw new Error("N must be > 0 and a power of 2");

    if (N > MAX_VALUE / 128 / r) throw new Error("Parameter N is too large");
    if (r > MAX_VALUE / 128 / p) throw new Error("Parameter r is too large");

    var PBKDF2_opts = {iterations: 1, hasher: exports.Crypto.SHA256, asBytes: true};

    var B = exports.Crypto.PBKDF2(passwd, salt, p * 128 * r, PBKDF2_opts);

    try {
        var workerI = 0;
        var worksDone = 0;
        var makeWorker = function() {
            if (!workerUrl) {
                var code = '('+scryptCore.toString()+')()';
                var blob;
                try {
                    blob = new Blob([code], {type: "text/javascript"});
                } catch(e) {
                    window.BlobBuilder = window.BlobBuilder || window.WebKitBlobBuilder || window.MozBlobBuilder || window.MSBlobBuilder;
                    blob = new BlobBuilder();
                    blob.append(code);
                    blob = blob.getBlob("text/javascript");
                }
                workerUrl = URL.createObjectURL(blob);
            }
            var worker = new Worker(workerUrl);
            worker.onmessage = function(event) {
                var Bi = event.data[0], Bslice = event.data[1];

                if (workerI < p) {
                    worker.postMessage([N, r, p, B, workerI++]);
                }

                var length = Bslice.length, destPos = Bi * 128 * r, srcPos = 0;
                while (length--) {
                    B[destPos++] = Bslice[srcPos++];
                }

                if (++worksDone == p) {
                    callback(exports.Crypto.PBKDF2(passwd, B, dkLen, PBKDF2_opts));
                }
            };
            return worker;
        };
        for (var threadN = Math.min(maxThreads || 2, p); threadN > 0; threadN--) {
            makeWorker().postMessage([N, r, p, B, workerI++]);
        }
    } catch (e) {
        setTimeout(function() {
            scryptCore();
            callback(exports.Crypto.PBKDF2(passwd, B, dkLen, PBKDF2_opts));
        }, 0);
    }

    // using this function to enclose everything needed to create a worker (but also invokable directly for synchronous use)
    function scryptCore() {
        var XY, V;

        if (typeof B === 'undefined') {
            onmessage = function(event) {
                var data = event.data;
                var N = data[0], r = data[1], p = data[2], B = data[3], i = data[4];

                if (!XY) {
                    alloc(r, N);
                }

                var Bslice = [];
                arraycopy32(B, i * 128 * r, Bslice, 0, 128 * r);
                smix(Bslice, 0, r, N, V, XY);

                postMessage([i, Bslice]);
            };
        } else {
            if (!XY) {
                alloc(r, N);
            }
            for(var i = 0; i < p; i++) {
                smix(B, i * 128 * r, r, N, V, XY);
            }
        }

        function alloc(r, N) {
            try {
                if (navigator.userAgent.match(/Chrome/)) {
                    // with Uint8Array, unit tests go almost a second faster in Chrome, but 2x slower in Firefox... ?
                    XY = new Uint8Array(256 * r);
                    V = new Uint8Array(128 * r * N);
                } else {
                    throw "use standard arrays";
                }
            } catch (e) {
                XY = [], V = [];
            }
        }

        function smix(B, Bi, r, N, V, XY) {
            var Xi = 0;
            var Yi = 128 * r;
            var i;

            arraycopy32(B, Bi, XY, Xi, Yi);

            for (i = 0; i < N; i++) {
                arraycopy32(XY, Xi, V, i * Yi, Yi);
                blockmix_salsa8(XY, Xi, Yi, r);
            }

            for (i = 0; i < N; i++) {
                var j = integerify(XY, Xi, r) & (N - 1);
                blockxor(V, j * Yi, XY, Xi, Yi);
                blockmix_salsa8(XY, Xi, Yi, r);
            }

            arraycopy32(XY, Xi, B, Bi, Yi);
        }

        function blockmix_salsa8(BY, Bi, Yi, r) {
            var X = [];
            var i;

            arraycopy32(BY, Bi + (2 * r - 1) * 64, X, 0, 64);

            for (i = 0; i < 2 * r; i++) {
                blockxor(BY, i * 64, X, 0, 64);
                salsa20_8(X);
                arraycopy32(X, 0, BY, Yi + (i * 64), 64);
            }

            for (i = 0; i < r; i++) {
                arraycopy32(BY, Yi + (i * 2) * 64, BY, Bi + (i * 64), 64);
            }

            for (i = 0; i < r; i++) {
                arraycopy32(BY, Yi + (i * 2 + 1) * 64, BY, Bi + (i + r) * 64, 64);
            }
        }

        function R(a, b) {
            return (a << b) | (a >>> (32 - b));
        }

        function salsa20_8(B) {
            var B32 = new Array(32);
            var x   = new Array(32);
            var i;

            for (i = 0; i < 16; i++) {
                B32[i]  = (B[i * 4 + 0] & 0xff) << 0;
                B32[i] |= (B[i * 4 + 1] & 0xff) << 8;
                B32[i] |= (B[i * 4 + 2] & 0xff) << 16;
                B32[i] |= (B[i * 4 + 3] & 0xff) << 24;
            }

            arraycopy(B32, 0, x, 0, 16);

            for (i = 8; i > 0; i -= 2) {
                x[ 4] ^= R(x[ 0]+x[12], 7);  x[ 8] ^= R(x[ 4]+x[ 0], 9);
                x[12] ^= R(x[ 8]+x[ 4],13);  x[ 0] ^= R(x[12]+x[ 8],18);
                x[ 9] ^= R(x[ 5]+x[ 1], 7);  x[13] ^= R(x[ 9]+x[ 5], 9);
                x[ 1] ^= R(x[13]+x[ 9],13);  x[ 5] ^= R(x[ 1]+x[13],18);
                x[14] ^= R(x[10]+x[ 6], 7);  x[ 2] ^= R(x[14]+x[10], 9);
                x[ 6] ^= R(x[ 2]+x[14],13);  x[10] ^= R(x[ 6]+x[ 2],18);
                x[ 3] ^= R(x[15]+x[11], 7);  x[ 7] ^= R(x[ 3]+x[15], 9);
                x[11] ^= R(x[ 7]+x[ 3],13);  x[15] ^= R(x[11]+x[ 7],18);
                x[ 1] ^= R(x[ 0]+x[ 3], 7);  x[ 2] ^= R(x[ 1]+x[ 0], 9);
                x[ 3] ^= R(x[ 2]+x[ 1],13);  x[ 0] ^= R(x[ 3]+x[ 2],18);
                x[ 6] ^= R(x[ 5]+x[ 4], 7);  x[ 7] ^= R(x[ 6]+x[ 5], 9);
                x[ 4] ^= R(x[ 7]+x[ 6],13);  x[ 5] ^= R(x[ 4]+x[ 7],18);
                x[11] ^= R(x[10]+x[ 9], 7);  x[ 8] ^= R(x[11]+x[10], 9);
                x[ 9] ^= R(x[ 8]+x[11],13);  x[10] ^= R(x[ 9]+x[ 8],18);
                x[12] ^= R(x[15]+x[14], 7);  x[13] ^= R(x[12]+x[15], 9);
                x[14] ^= R(x[13]+x[12],13);  x[15] ^= R(x[14]+x[13],18);
            }

            for (i = 0; i < 16; ++i) B32[i] = x[i] + B32[i];

            for (i = 0; i < 16; i++) {
                var bi = i * 4;
                B[bi + 0] = (B32[i] >> 0  & 0xff);
                B[bi + 1] = (B32[i] >> 8  & 0xff);
                B[bi + 2] = (B32[i] >> 16 & 0xff);
                B[bi + 3] = (B32[i] >> 24 & 0xff);
            }
        }

        function blockxor(S, Si, D, Di, len) {
            var i = len>>6;
            while (i--) {
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
                D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
            }
        }

        function integerify(B, bi, r) {
            var n;

            bi += (2 * r - 1) * 64;

            n  = (B[bi + 0] & 0xff) << 0;
            n |= (B[bi + 1] & 0xff) << 8;
            n |= (B[bi + 2] & 0xff) << 16;
            n |= (B[bi + 3] & 0xff) << 24;

            return n;
        }

        function arraycopy(src, srcPos, dest, destPos, length) {
             while (length-- ){
                 dest[destPos++] = src[srcPos++];
             }
        }

        function arraycopy32(src, srcPos, dest, destPos, length) {
            var i = length>>5;
            while(i--) {
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];

                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];

                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];

                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
                dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
            }
        }
    } // scryptCore
}; // Crypto_scrypt



/*
 * Crypto-JS v2.5.4
 * http://code.google.com/p/crypto-js/
 * (c) 2009-2012 by Jeff Mott. All rights reserved.
 * http://code.google.com/p/crypto-js/wiki/License
 */
(typeof Crypto=="undefined"||!Crypto.util)&&function(){var d=exports.Crypto={},k=d.util={rotl:function(b,a){return b<<a|b>>>32-a},rotr:function(b,a){return b<<32-a|b>>>a},endian:function(b){if(b.constructor==Number)return k.rotl(b,8)&16711935|k.rotl(b,24)&4278255360;for(var a=0;a<b.length;a++)b[a]=k.endian(b[a]);return b},randomBytes:function(b){for(var a=[];b>0;b--)a.push(Math.floor(Math.random()*256));return a},bytesToWords:function(b){for(var a=[],c=0,e=0;c<b.length;c++,e+=8)a[e>>>5]|=(b[c]&255)<<
24-e%32;return a},wordsToBytes:function(b){for(var a=[],c=0;c<b.length*32;c+=8)a.push(b[c>>>5]>>>24-c%32&255);return a},bytesToHex:function(b){for(var a=[],c=0;c<b.length;c++)a.push((b[c]>>>4).toString(16)),a.push((b[c]&15).toString(16));return a.join("")},hexToBytes:function(b){for(var a=[],c=0;c<b.length;c+=2)a.push(parseInt(b.substr(c,2),16));return a},bytesToBase64:function(b){for(var a=[],c=0;c<b.length;c+=3)for(var e=b[c]<<16|b[c+1]<<8|b[c+2],t=0;t<4;t++)c*8+t*6<=b.length*8?a.push("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(e>>>
6*(3-t)&63)):a.push("=");return a.join("")},base64ToBytes:function(b){for(var b=b.replace(/[^A-Z0-9+\/]/ig,""),a=[],c=0,e=0;c<b.length;e=++c%4)e!=0&&a.push(("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(b.charAt(c-1))&Math.pow(2,-2*e+8)-1)<<e*2|"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(b.charAt(c))>>>6-e*2);return a}},d=d.charenc={};d.UTF8={stringToBytes:function(b){return f.stringToBytes(unescape(encodeURIComponent(b)))},bytesToString:function(b){return decodeURIComponent(escape(f.bytesToString(b)))}};
var f=d.Binary={stringToBytes:function(b){for(var a=[],c=0;c<b.length;c++)a.push(b.charCodeAt(c)&255);return a},bytesToString:function(b){for(var a=[],c=0;c<b.length;c++)a.push(String.fromCharCode(b[c]));return a.join("")}}}();
(function(){var d=exports.Crypto,k=d.util,f=d.charenc,b=f.UTF8,a=f.Binary,c=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,
2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298],e=d.SHA256=function(b,c){var g=k.wordsToBytes(e._sha256(b));return c&&c.asBytes?g:c&&c.asString?a.bytesToString(g):k.bytesToHex(g)};e._sha256=function(a){a.constructor==String&&(a=b.stringToBytes(a));var e=k.bytesToWords(a),g=a.length*8,a=[1779033703,3144134277,
1013904242,2773480762,1359893119,2600822924,528734635,1541459225],d=[],f,i,r,h,m,q,n,u,j,o,l;e[g>>5]|=128<<24-g%32;e[(g+64>>9<<4)+15]=g;for(u=0;u<e.length;u+=16){g=a[0];f=a[1];i=a[2];r=a[3];h=a[4];m=a[5];q=a[6];n=a[7];for(j=0;j<64;j++){j<16?d[j]=e[j+u]:(o=d[j-15],l=d[j-2],d[j]=((o<<25|o>>>7)^(o<<14|o>>>18)^o>>>3)+(d[j-7]>>>0)+((l<<15|l>>>17)^(l<<13|l>>>19)^l>>>10)+(d[j-16]>>>0));l=g&f^g&i^f&i;var w=(g<<30|g>>>2)^(g<<19|g>>>13)^(g<<10|g>>>22);o=(n>>>0)+((h<<26|h>>>6)^(h<<21|h>>>11)^(h<<7|h>>>25))+
(h&m^~h&q)+c[j]+(d[j]>>>0);l=w+l;n=q;q=m;m=h;h=r+o>>>0;r=i;i=f;f=g;g=o+l>>>0}a[0]+=g;a[1]+=f;a[2]+=i;a[3]+=r;a[4]+=h;a[5]+=m;a[6]+=q;a[7]+=n}return a};e._blocksize=16;e._digestsize=32})();
(function(){var d=exports.Crypto,k=d.util,f=d.charenc,b=f.UTF8,a=f.Binary;d.HMAC=function(c,e,d,f){e.constructor==String&&(e=b.stringToBytes(e));d.constructor==String&&(d=b.stringToBytes(d));d.length>c._blocksize*4&&(d=c(d,{asBytes:!0}));for(var g=d.slice(0),d=d.slice(0),s=0;s<c._blocksize*4;s++)g[s]^=92,d[s]^=54;c=c(g.concat(c(d.concat(e),{asBytes:!0})),{asBytes:!0});return f&&f.asBytes?c:f&&f.asString?a.bytesToString(c):k.bytesToHex(c)}})();
(function(){var d=exports.Crypto,k=d.util,f=d.charenc,b=f.UTF8,a=f.Binary;d.PBKDF2=function(c,e,f,p){function g(a,b){return d.HMAC(s,b,a,{asBytes:!0})}c.constructor==String&&(c=b.stringToBytes(c));e.constructor==String&&(e=b.stringToBytes(e));for(var s=p&&p.hasher||d.SHA1,v=p&&p.iterations||1,i=[],r=1;i.length<f;){for(var h=g(c,e.concat(k.wordsToBytes([r]))),m=h,q=1;q<v;q++)for(var m=g(c,m),n=0;n<h.length;n++)h[n]^=m[n];i=i.concat(h);r++}i.length=f;return p&&p.asBytes?i:p&&p.asString?a.bytesToString(i):k.bytesToHex(i)}})();


})(typeof exports != 'undefined' ? exports : window);
