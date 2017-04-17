/*
 A JavaScript implementation of the SHA family of hashes, as
 defined in FIPS PUB 180-2 as well as the corresponding HMAC implementation
 as defined in FIPS PUB 198a
 Copyright Brian Turek 2008-2015
 Distributed under the BSD License
 See http://caligatio.github.com/jsSHA/ for more information
 Several functions taken from Paul Johnston
*/
'use strict';(function(H){function v(c,a,b){var g=0,d=[],f=0,e,h,n,l,m,F,r,p=!1,k=!1,q=[],t=[],u,y=!1;b=b||{};e=b.encoding||"UTF8";u=b.numRounds||1;n=z(a,e);if(u!==parseInt(u,10)||1>u)throw Error("numRounds must a integer >= 1");F=function(a,b){return A(a,b,c)};r=function(a,b,f,d){var g,e;if("SHA-224"===c||"SHA-256"===c)g=(b+65>>>9<<4)+15,e=16;else throw Error("Unexpected error in SHA-2 implementation");for(;a.length<=g;)a.push(0);a[b>>>5]|=128<<24-b%32;a[g]=b+f;f=a.length;for(b=0;b<f;b+=e)d=A(a.slice(b,
b+e),d,c);if("SHA-224"===c)a=[d[0],d[1],d[2],d[3],d[4],d[5],d[6]];else if("SHA-256"===c)a=d;else throw Error("Unexpected error in SHA-2 implementation");return a};if("SHA-224"===c)m=512,l=224;else if("SHA-256"===c)m=512,l=256;else throw Error("Chosen SHA variant is not supported");h=w(c);this.setHMACKey=function(a,b,d){var f;if(!0===k)throw Error("HMAC key already set");if(!0===p)throw Error("Cannot set HMAC key after finalizing hash");if(!0===y)throw Error("Cannot set HMAC key after calling update");
e=(d||{}).encoding||"UTF8";b=z(b,e)(a);a=b.binLen;b=b.value;f=m>>>3;d=f/4-1;if(f<a/8){for(b=r(b,a,0,w(c));b.length<=d;)b.push(0);b[d]&=4294967040}else if(f>a/8){for(;b.length<=d;)b.push(0);b[d]&=4294967040}for(a=0;a<=d;a+=1)q[a]=b[a]^909522486,t[a]=b[a]^1549556828;h=F(q,h);g=m;k=!0};this.update=function(a){var b,c,e,l=0,p=m>>>5;b=n(a,d,f);a=b.binLen;c=b.value;b=a>>>5;for(e=0;e<b;e+=p)l+m<=a&&(h=F(c.slice(e,e+p),h),l+=m);g+=l;d=c.slice(l>>>5);f=a%m;y=!0};this.getHash=function(a,b){var e,m,n;if(!0===
k)throw Error("Cannot call getHash after setting HMAC key");n=B(b);switch(a){case "HEX":e=function(a){return C(a,n)};break;case "B64":e=function(a){return D(a,n)};break;case "BYTES":e=E;break;default:throw Error("format must be HEX, B64, or BYTES");}if(!1===p)for(h=r(d,f,g,h),m=1;m<u;m+=1)h=r(h,l,0,w(c));p=!0;return e(h)};this.getHMAC=function(a,b){var e,n,q;if(!1===k)throw Error("Cannot call getHMAC without first setting HMAC key");q=B(b);switch(a){case "HEX":e=function(a){return C(a,q)};break;case "B64":e=
function(a){return D(a,q)};break;case "BYTES":e=E;break;default:throw Error("outputFormat must be HEX, B64, or BYTES");}!1===p&&(n=r(d,f,g,h),h=F(t,w(c)),h=r(n,l,m,h));p=!0;return e(h)}}function k(){}function I(c,a,b){var g=c.length,d,f,e,h,n;a=a||[0];b=b||0;n=b>>>3;if(0!==g%2)throw Error("String of HEX type must be in byte increments");for(d=0;d<g;d+=2){f=parseInt(c.substr(d,2),16);if(isNaN(f))throw Error("String of HEX type contains invalid characters");h=(d>>>1)+n;for(e=h>>>2;a.length<=e;)a.push(0);
a[e]|=f<<8*(3-h%4)}return{value:a,binLen:4*g+b}}function J(c,a,b){var g=[],d,f,e,h,g=a||[0];b=b||0;f=b>>>3;for(d=0;d<c.length;d+=1)a=c.charCodeAt(d),h=d+f,e=h>>>2,g.length<=e&&g.push(0),g[e]|=a<<8*(3-h%4);return{value:g,binLen:8*c.length+b}}function K(c,a,b){var g=[],d=0,f,e,h,n,l,m,g=a||[0];b=b||0;a=b>>>3;if(-1===c.search(/^[a-zA-Z0-9=+\/]+$/))throw Error("Invalid character in base-64 string");e=c.indexOf("=");c=c.replace(/\=/g,"");if(-1!==e&&e<c.length)throw Error("Invalid '=' found in base-64 string");
for(e=0;e<c.length;e+=4){l=c.substr(e,4);for(h=n=0;h<l.length;h+=1)f="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".indexOf(l[h]),n|=f<<18-6*h;for(h=0;h<l.length-1;h+=1){m=d+a;for(f=m>>>2;g.length<=f;)g.push(0);g[f]|=(n>>>16-8*h&255)<<8*(3-m%4);d+=1}}return{value:g,binLen:8*d+b}}function C(c,a){var b="",g=4*c.length,d,f;for(d=0;d<g;d+=1)f=c[d>>>2]>>>8*(3-d%4),b+="0123456789abcdef".charAt(f>>>4&15)+"0123456789abcdef".charAt(f&15);return a.outputUpper?b.toUpperCase():b}function D(c,
a){var b="",g=4*c.length,d,f,e;for(d=0;d<g;d+=3)for(e=d+1>>>2,f=c.length<=e?0:c[e],e=d+2>>>2,e=c.length<=e?0:c[e],e=(c[d>>>2]>>>8*(3-d%4)&255)<<16|(f>>>8*(3-(d+1)%4)&255)<<8|e>>>8*(3-(d+2)%4)&255,f=0;4>f;f+=1)8*d+6*f<=32*c.length?b+="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(e>>>6*(3-f)&63):b+=a.b64Pad;return b}function E(c){var a="",b=4*c.length,g,d;for(g=0;g<b;g+=1)d=c[g>>>2]>>>8*(3-g%4)&255,a+=String.fromCharCode(d);return a}function B(c){var a={outputUpper:!1,b64Pad:"="};
c=c||{};a.outputUpper=c.outputUpper||!1;a.b64Pad=c.b64Pad||"=";if("boolean"!==typeof a.outputUpper)throw Error("Invalid outputUpper formatting option");if("string"!==typeof a.b64Pad)throw Error("Invalid b64Pad formatting option");return a}function z(c,a){var b;switch(a){case "UTF8":case "UTF16BE":case "UTF16LE":break;default:throw Error("encoding must be UTF8, UTF16BE, or UTF16LE");}switch(c){case "HEX":b=I;break;case "TEXT":b=function(b,c,f){var e=[],h=[],n=0,l,m,k,r,p,e=c||[0];c=f||0;k=c>>>3;if("UTF8"===
a)for(l=0;l<b.length;l+=1)for(f=b.charCodeAt(l),h=[],128>f?h.push(f):2048>f?(h.push(192|f>>>6),h.push(128|f&63)):55296>f||57344<=f?h.push(224|f>>>12,128|f>>>6&63,128|f&63):(l+=1,f=65536+((f&1023)<<10|b.charCodeAt(l)&1023),h.push(240|f>>>18,128|f>>>12&63,128|f>>>6&63,128|f&63)),m=0;m<h.length;m+=1){p=n+k;for(r=p>>>2;e.length<=r;)e.push(0);e[r]|=h[m]<<8*(3-p%4);n+=1}else if("UTF16BE"===a||"UTF16LE"===a)for(l=0;l<b.length;l+=1){f=b.charCodeAt(l);"UTF16LE"===a&&(m=f&255,f=m<<8|f>>>8);p=n+k;for(r=p>>>
2;e.length<=r;)e.push(0);e[r]|=f<<8*(2-p%4);n+=2}return{value:e,binLen:8*n+c}};break;case "B64":b=K;break;case "BYTES":b=J;break;default:throw Error("format must be HEX, TEXT, B64, or BYTES");}return b}function t(c,a){return c>>>a|c<<32-a}function L(c,a,b){return c&a^~c&b}function M(c,a,b){return c&a^c&b^a&b}function N(c){return t(c,2)^t(c,13)^t(c,22)}function O(c){return t(c,6)^t(c,11)^t(c,25)}function P(c){return t(c,7)^t(c,18)^c>>>3}function Q(c){return t(c,17)^t(c,19)^c>>>10}function R(c,a){var b=
(c&65535)+(a&65535);return((c>>>16)+(a>>>16)+(b>>>16)&65535)<<16|b&65535}function S(c,a,b,g){var d=(c&65535)+(a&65535)+(b&65535)+(g&65535);return((c>>>16)+(a>>>16)+(b>>>16)+(g>>>16)+(d>>>16)&65535)<<16|d&65535}function T(c,a,b,g,d){var f=(c&65535)+(a&65535)+(b&65535)+(g&65535)+(d&65535);return((c>>>16)+(a>>>16)+(b>>>16)+(g>>>16)+(d>>>16)+(f>>>16)&65535)<<16|f&65535}function w(c){var a,b;a=[3238371032,914150663,812702999,4144912697,4290775857,1750603025,1694076839,3204075428];b=[1779033703,3144134277,
1013904242,2773480762,1359893119,2600822924,528734635,1541459225];switch(c){case "SHA-224":c=a;break;case "SHA-256":c=b;break;case "SHA-384":c=[new k,new k,new k,new k,new k,new k,new k,new k];break;case "SHA-512":c=[new k,new k,new k,new k,new k,new k,new k,new k];break;default:throw Error("Unknown SHA variant");}return c}function A(c,a,b){var g,d,f,e,h,n,l,m,k,r,p,t,q,v,u,y,w,z,A,B,C,D,x=[],E;if("SHA-224"===b||"SHA-256"===b)r=64,t=1,D=Number,q=R,v=S,u=T,y=P,w=Q,z=N,A=O,C=M,B=L,E=G;else throw Error("Unexpected error in SHA-2 implementation");
b=a[0];g=a[1];d=a[2];f=a[3];e=a[4];h=a[5];n=a[6];l=a[7];for(p=0;p<r;p+=1)16>p?(k=p*t,m=c.length<=k?0:c[k],k=c.length<=k+1?0:c[k+1],x[p]=new D(m,k)):x[p]=v(w(x[p-2]),x[p-7],y(x[p-15]),x[p-16]),m=u(l,A(e),B(e,h,n),E[p],x[p]),k=q(z(b),C(b,g,d)),l=n,n=h,h=e,e=q(f,m),f=d,d=g,g=b,b=q(m,k);a[0]=q(b,a[0]);a[1]=q(g,a[1]);a[2]=q(d,a[2]);a[3]=q(f,a[3]);a[4]=q(e,a[4]);a[5]=q(h,a[5]);a[6]=q(n,a[6]);a[7]=q(l,a[7]);return a}var G;G=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,
3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,
1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];"function"===typeof define&&define.amd?define(function(){return v}):"undefined"!==typeof exports?"undefined"!==typeof module&&module.exports?module.exports=exports=v:exports=v:H.jsSHA=v})(this);

/*
   Copyright 2017 Continusec Pty Ltd

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/**
 * Indicates network error.
 */
var CONTINUSEC_NETWORK_ERROR = "CONTINUSEC_NETWORK_ERROR";

/**
 * Indicates invalid size or range in the request, e.g. tree size too large or small.
 */
var CONTINUSEC_INVALID_RANGE_ERROR = "CONTINUSEC_INVALID_RANGE_ERROR";

/**
 * Indicates that either the wrong API Key is being used, or the account is suspended for other reasons (check billing status in console).
 */
var CONTINUSEC_UNAUTHORIZED_ERROR = "CONTINUSEC_UNAUTHORIZED_ERROR";

/**
 * Indicates the object cannot be found.
 */
var CONTINUSEC_NOT_FOUND_ERROR = "CONTINUSEC_NOT_FOUND_ERROR";

/**
 * Indicates internal error that occurred on the server.
 */
var CONTINUSEC_INTERNAL_ERROR = "CONTINUSEC_INTERNAL_ERROR";

/**
 * Indicates that object being modified already exists.
 */
var CONTINUSEC_OBJECT_CONFLICT_ERROR = "CONTINUSEC_OBJECT_CONFLICT_ERROR";

/**
 * Indicates the verification of a proof has failed.
 */
var CONTINUSEC_VERIFICATION_ERROR = "CONTINUSEC_VERIFICATION_ERROR";

/**
 * Indicates that not all entries were returned. Typically due to requesting Json, but not
 * storing as such.
 */
var CONTINUSEC_NOT_ALL_ENTRIES_RETURNED_ERROR = "CONTINUSEC_NOT_ALL_ENTRIES_RETURNED_ERROR";

/**
 * HEAD can be substituted for tree size in requests for fetch tree hashes. Specifying
 * this values means to fetch the latest tree hash present.
 */
var CONTINUSEC_HEAD = 0;

/**
 * Create a ContinusecClient for a given account with specified API Key.
 * baseURL is optional and normally only used for unit tests of the ContinusecClient API
 * that may wish to use a custom URL to send API requests to.
 *
 * @param {string} account the account number, found on the "Settings" tab in the console.
 * @param {string} apiKey the API Key, found on the "API Keys" tab in the console.
 * @param {string} baseURL the base URL to send API requests to.
 *
 * @constructor
 * @classdesc Main entry point for interacting with Continusec's Verifiable Data Structure APIs.
 */
var ContinusecClient = function (account, apiKey, baseURL) {
    this.account = account;
    this.apiKey = apiKey;
    if (baseURL == undefined) {
		this.baseURL = "https://api.continusec.com";
    } else {
		this.baseURL = baseURL;
	}
};

/**
 * Return a pointer to a verifiable map that belongs to this account.
 *
 * @param {string} name name of the map to access.
 * @return {VerifiableMap} an object that allows manipulation of the specified map.
 */
ContinusecClient.prototype.getVerifiableMap = function (name) {
    return new VerifiableMap(this, "/map/" + name);
};

/**
 * Return a pointer to a verifiable log that belongs to this account.
 *
 * @param {string} name name of the log to access.
 * @return {VerifiableLog} an object that allows manipulation of the specified log.
 */
ContinusecClient.prototype.getVerifiableLog = function (name) {
    return new VerifiableLog(this, "/log/" + name);
};

/**
 * @private
 */
ContinusecClient.prototype.makeRequest = function (method, path, data, success, failure) {
    var req = new XMLHttpRequest();
    req.onload = function (evt) {
        switch (req.status) {
        case 200:
            var b = binaryArrayToString(new Uint8Array(req.response));
            //console.log(b);
            success(b, req);
            break;
        case 400:
            failure(CONTINUSEC_INVALID_RANGE_ERROR);
            break;
        case 403:
            failure(CONTINUSEC_UNAUTHORIZED_ERROR);
            break;
        case 404:
            failure(CONTINUSEC_NOT_FOUND_ERROR);
            break;
        case 409:
            failure(CONTINUSEC_OBJECT_CONFLICT_ERROR);
            break;
        default:
            failure(CONTINUSEC_INTERNAL_ERROR);
        }
    };
    req.onerror = function (evt) {
        failure(CONTINUSEC_NETWORK_ERROR);
    };
    req.open(method, this.baseURL + "/v2/account/" + this.account + path, true);
    req.responseType = "arraybuffer";
    req.setRequestHeader("Authorization", 'Key ' + this.apiKey);
    req.send(data);
};

/**
 * Private constructor. Use {@link ContinusecClient#getVerifiableMap(String)} to instantiate.
 * @constructor
 * @classdesc Class to manage interactions with a Verifiable Map. Use {@link ContinusecClient#getVerifiableMap(String)} to instantiate.
 */
var VerifiableMap = function (client, path) {
    this.client = client;
    this.path = path;
};

/**
 * Get a pointer to the mutation log that underlies this verifiable map. Since the mutation log
 * is managed by the map, it cannot be directly modified, however all read operations are supported.
 * Note that mutations themselves are stored as {@link JsonEntry} format, so {@link JsonEntryFactory#getInstance()} should
 * be used for entry retrieval.
 * @return {VerifiableLog} the mutation log.
 */
VerifiableMap.prototype.getMutationLog = function () {
    return new VerifiableLog(this.client, this.path + "/log/mutation");
};

/**
 * Get a pointer to the tree head log that contains all map root hashes produced by this map. Since the tree head log
 * is managed by the map, it cannot be directly modified, however all read operations are supported.
 * Note that tree heaads themselves are stored as {@link JsonEntry} format, so {@link JsonEntryFactory#getInstance()} should
 * be used for entry retrieval.
 * @return {VerifiableLog} the tree head log.
 */
VerifiableMap.prototype.getTreeHeadLog = function () {
    return new VerifiableLog(this.client, this.path + "/log/treehead");
};


/**
 * protobuf helpfully skips encoding a value for 0, so we need to handle this when reading in.
 */
function protoNumber(n) {
    if (n == undefined) {
        return 0;
    } else {
        return Number(n);
    }
}


/**
 * Failure callback is called upon error. Typically the reason passed is one of the
 * error constants defined in this module.
 *
 * @callback failureCallback
 * @param {string} reason
 */

/**
 * Success callback is called upon success with no arguments passed to it.
 * @callback emptySuccessCallback
 */

/**
 * Success callback is called upon success with mapEntry passed to it.
 * @param {MapEntryResponse} mapEntry
 * @callback mapEntrySuccessCallback
 */

/**
 * Success callback is called upon success with an entry passed to it.
 * @param {VerifiableEntry} entry, ie once of RawDataEntry, JsonEntry, RedactedJsonEntry
 * @callback verifiableEntrySuccessCallback
 */

/**
 * Success callback is called upon success with an index and entry passed to it.
 * @param {int} idx the index
 * @param {VerifiableEntry} entry the value, of type RawDataEntry, JsonEntry or RedactedJsonEntry
 * @callback verifiableEntryIndexSuccessCallback
 */

/**
 * Success callback is called upon success with an entry passed to it.
 * @param {AddEntryResponse} entry
 * @callback addEntryResponseCallback
 */

/**
 * Success callback is called upon success with a MapTreeHead passed to it.
 * @param {MapTreeHead} entry
 * @callback mapTreeHeadSuccessCallback
 */

/**
 * Success callback is called upon success with a LogTreeHead passed to it.
 * @param {LogTreeHead} entry
 * @callback logTreeHeadSuccessCallback
 */

/**
 * Success callback is called upon success with a MapTreeState passed to it.
 * @param {MapTreeState} entry
 * @callback mapTreeStateSuccessCallback
 */

/**
 * Success callback is called upon success with a LogInclusionProof passed to it.
 * @param {LogInclusionProof} entry
 * @callback logInclusionProofSuccessCallback
 */

/**
 * Success callback is called upon success with a LogConsistencyProof passed to it.
 * @param {LogConsistencyProof} entry
 * @callback logConsistencyProofSuccessCallback
 */

/**
 * Success callback is called upon success with an array of LogInfo passed to it.
 * @param {LogInfo[]} logs
 * @callback listLogsSuccessCallback
 */

/**
 * Success callback is called upon success with an array of MapInfo passed to it.
 * @param {MapInfo[]} maps
 * @callback listMapsSuccessCallback
 */

/**
 * For a given key, return the value and inclusion proof for the given treeSize.
 * @param {string} key the key in the map.
 * @param {int} treeSize the tree size.
 * @param {VerifiableEntryFactory} factory the factory that should be used to instantiate the VerifiableEntry. Typically one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
 * @param {mapEntrySuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.getValue = function (key, treeSize, factory, success, failure) {
    this.client.makeRequest("GET", this.path + "/tree/" + treeSize + "/key/h/" + hexString(key) + "/extra", null, function (data, req) {
        var verifiedTreeSize = req.getResponseHeader("X-Verified-Treesize");
        if (verifiedTreeSize === null) {
            failure(CONTINUSEC_NOT_FOUND_ERROR);
            return;
        }
        verifiedTreeSize = Number(verifiedTreeSize);
        var proof = req.getResponseHeader("X-Verified-Proof");
        if (proof === null) {
            proof = "";
        }
        var parts = proof.split(",");
        var auditPath = [];
        var i;
        for (i = 0; i < 256; i++) {
            auditPath.push(null);
        }
        for (i = 0; i < parts.length; i++) {
            var pieces = parts[i].split("/");
            if (pieces.length == 2) {
                auditPath[Number(pieces[0].trim())] = decodeHex(pieces[1].trim());
            }
        }
        success(new MapEntryResponse(key, factory.createFromLeafData(JSON.parse(data)), verifiedTreeSize, auditPath));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * For a given key, retrieve the value and inclusion proof, verify the proof, then return the value.
 * @param {string} key the key in the map.
 * @param {MapStateHead} mapState a map tree state as previously returned by {@link #getVerifiedMapState(MapTreeState,int)}
 * @param {VerifiableEntryFactory} factory the factory that should be used to instantiate the VerifiableEntry. Typically one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
 * @param {verifiableEntrySuccessCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.getVerifiedValue = function (key, mapState, factory, success, failure) {
	this.getValue(key, mapState.getTreeSize(), factory, function(mapResp) {
		try {
			mapResp.verify(mapState.getMapHead());
		} catch (err) {
			failure(err);
			return;
		}
		success(mapResp.getValue());
	}, function (reason) {
		failure(reason);
	});
};

/**
 * Set the value for a given key in the map. Calling this has the effect of adding a mutation to the
 * mutation log for the map, which then reflects in the root hash for the map. This occurs asynchronously.
 * @param {string} key the key to set.
 * @param {value} value the entry to set to key to. Typically one of {@link RawDataEntry}, {@link JsonEntry} or {@link RedactableJsonEntry}.
 * @param {addEntryResponseCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.setValue = function (key, value, success, failure) {
    this.client.makeRequest("PUT", this.path + "/key/h/" + hexString(key) + value.getFormat(), value.getDataForUpload(), function (data, req) {
        var obj = JSON.parse(data);
        success(new AddEntryResponse(atob(obj.leaf_hash)));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Delete the value for a given key from the map. Calling this has the effect of adding a mutation to the
 * mutation log for the map, which then reflects in the root hash for the map. This occurs asynchronously.
 * @param {string} key the key to delete.
 * @param {addEntryResponseCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.deleteValue = function (key, success, failure) {
    this.client.makeRequest("DELETE", this.path + "/key/h/" + hexString(key), null, function (data, req) {
        var obj = JSON.parse(data);
        success(new AddEntryResponse(atob(obj.leaf_hash)));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Get the tree hash for given tree size.
 *
 * @param {int} treeSize the tree size to retrieve the hash for. Pass HEAD (0) to get the
 * latest tree size.
 * @param {mapTreeHeadSuccessCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.getTreeHead = function (treeSize, success, failure) {
    this.client.makeRequest("GET", this.path + "/tree/" + treeSize, null, function (data, req) {
        var obj = JSON.parse(data);
        success(new MapTreeHead(new LogTreeHead(protoNumber(obj.mutation_log.tree_size), atob(obj.mutation_log.root_hash)), atob(obj.root_hash)));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Block until the map has caught up to a certain size.
 * This polls getTreeHead(int) until
 * such time as a new tree hash is produced that is of at least this size.
 * This is intended for test use.
 * @param {int} treeSize the tree size that we should wait for.
 * @param {mapTreeHeadSuccessCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.blockUntilSize = function (treeSize, success, failure) {
    doMapBlockRound(this, -1, 0, treeSize, success, failure);
}

function doMapBlockRound(log, lastHead, secsToSleep, treeSize, success, failure) {
    log.getTreeHead(0, function (lth) {
        if (lth.getTreeSize() > lastHead) {
            if (lth.getTreeSize() >= treeSize) {
                success(lth);
            } else {
                secsToSleep = 1;
                setTimeout(function () { doMapBlockRound(log, lth.getTreeSize(), secsToSleep, treeSize, success, failure); }, secsToSleep * 1000);
            }
        } else {
            secsToSleep *= 2
            setTimeout(function () { doMapBlockRound(log, lastHead, secsToSleep, treeSize, success, failure); }, secsToSleep * 1000);
        }
    }, failure);
}

/**
 * getVerifiedLatestMapState fetches the latest MapTreeState, verifies it is consistent with,
 * and newer than, any previously passed state.
 *
 * @param {MapTreeState} prev previously held MapTreeState, may be null to skip consistency checks.
 * @param {mapTreeStateSuccessCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.getVerifiedLatestMapState = function (prev, success, failure) {
    this.getVerifiedMapState(prev, 0, function (head) {
        if ((prev != null) && (head.getTreeSize() <= prev.getTreeSize())) {
            success(prev);
        } else {
            success(head);
        }
    }, failure);
}

/**
 * getVerifiedMapState returns a wrapper for the MapTreeHead for a given tree size, along with
 * a LogTreeHead for the TreeHeadLog that has been verified to contain this map tree head.
 * The value returned by this will have been proven to be consistent with any passed prev value.
 * Note that the TreeHeadLogTreeHead returned may differ between calls, even for the same treeSize,
 * as all future LogTreeHeads can also be proven to contain the MapTreeHead.
 *
 * Typical clients that only need to access current data will instead use getVerifiedLatestMapState()
 * @param {MapTreeState} prev previously held MapTreeState, may be null to skip consistency checks.
 * @param {treeSize} treeSize the tree size to retrieve the hash for. Pass HEAD (0) to get the
 * latest tree size.
 * @param {mapTreeStateSuccessCallback} success called upon success
 * @param {failureCallback} failure called on failure
 */
VerifiableMap.prototype.getVerifiedMapState = function (prev, treeSize, success, failure) {
    if ((treeSize != 0) && (prev != null) && (prev.getTreeSize() == treeSize)) {
        success(prev);
    } else {
        var map = this;
        map.getTreeHead(treeSize, function (mapHead) {
            if (prev != null) {
                map.getMutationLog().verifyConsistency(prev.getMapHead().getMutationLogTreeHead(), mapHead.getMutationLogTreeHead(), function () {
                    secondStageMapVerified(map, prev, mapHead, success, failure);
                }, failure);
            } else {
                secondStageMapVerified(map, prev, mapHead, success, failure);
            }
        }, failure);
    }
};

/**
 * @private
 */
function secondStageMapVerified(map, prev, mapHead, success, failure) {
    var prevThlth = null;
    if (prev != null) {
        prevThlth = prev.getTreeHeadLogTreeHead();
    }
    map.getTreeHeadLog().getVerifiedLatestTreeHead(prevThlth, function (thlth) {
        map.getTreeHeadLog().verifyInclusion(thlth, mapHead, function () {
            success(new MapTreeState(mapHead, thlth));
        }, failure);
    }, failure);
}

/**
 * Private constructor. Use {@link ContinusecClient#getVerifiableLog(String)} to instantiate.
 * @constructor
 * @classdesc Class to interact with verifiable logs. Instantiate by callling {@link ContinusecClient#getVerifiableLog(String)} method
 */
var VerifiableLog = function (client, path) {
    this.client = client;
    this.path = path;
};

/**
 * Send API call to add an entry to the log. Note the entry is added asynchronously, so while
 * the library will return as soon as the server acknowledges receipt of entry, it may not be
 * reflected in the tree hash (or inclusion proofs) until the server has sequenced the entry.
 *
 * @param {VerifiableEntry} value the entry to add, often RawDataEntry, JsonEntry or RedactableJsonEntry.
 * @param {addEntryResponseCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.add = function (value, success, failure) {
    this.client.makeRequest("POST", this.path + "/entry" + value.getFormat(), value.getDataForUpload(), function (data, req) {
        var obj = JSON.parse(data);
        success(new AddEntryResponse(atob(obj.leaf_hash)));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Get the tree hash for given tree size.
 *
 * @param {int} treeSize the tree size to retrieve the hash for. Pass HEAD (0) to get the
 * latest tree size.
 * @param {logTreeHeadSuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getTreeHead = function (treeSize, success, failure) {
    this.client.makeRequest("GET", this.path + "/tree/" + treeSize, null, function (data, req) {
        var obj = JSON.parse(data);
        success(new LogTreeHead(protoNumber(obj.tree_size), obj.root_hash === null ? null : atob(obj.root_hash)));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Get the entry at the specified index.
 *
 * @param {int} idx the index to retrieve (starts at zero).
 * @param {VerifiableEntryFactory} factory the type of entry to return, usually one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
 * @param {verifiableEntrySuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getEntry = function (idx, factory, success, failure) {
    this.client.makeRequest("GET", this.path + "/entry/" + idx + "/extra", null, function (data, req) {
        success(factory.createFromLeafData(data, idx));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Returns an iterator to efficiently fetch a contiguous set of entries. If for any
 * reason not all entries are returned, the iterator will terminate early.
 *
 * @param {int} beginIdx the first entry to return
 * @param {int} endIdx the last entry to return
 * @param {VerifiableEntryFactory} factory the type of entry to return, usually one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
 * @param {verifiableEntryIndexSuccessCallback} each called for each entry
 * @param {emptySuccessCallback} success called on success (after all values processed).
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getEntries = function (startIdx, endIdx, factory, each, success, failure) {
    this.client.makeRequest("GET", this.path + "/entries/" + startIdx + "-" + endIdx + "/extra", null, function (data, req) {
    	try {
			var obj = JSON.parse(data);
			for (var i = 0; i < obj.values.length; i++) {
				each(startIdx + i, factory.createFromLeafData(obj.values[i]));
			}
		} catch (err) {
			failure(err);
			return
		}
		success();
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Utility method for auditors that wish to audit the full content of a log, as well as the log operation.
 * This method will retrieve all entries in batch from the log, and ensure that the root hash in head can be confirmed to accurately represent the contents
 * of all of the log entries. If prev is not null, then additionally it is proven that the root hash in head is consistent with the root hash in prev.
 * @param {LogTreeHead} prev a previous LogTreeHead representing the set of entries that have been previously audited. To indicate this is has not previously been audited, pass null,
 * @param {LogTreeHead} head the LogTreeHead up to which we wish to audit the log. Upon successful completion the caller should persist this for a future iteration.
 * @param {VerifiableEntryFactory} factory the type of entry to return, usually one of RawDataEntryFactory, JsonEntryFactory, RedactedJsonEntryFactory.
 * @param {verifiableEntryIndexSuccessCallback} each which is called sequentially for each log entry as it is encountered.
 * @param {emptySuccessCallback} success called on success (after all values processed).
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.verifyEntries = function (prev, head, factory, each, success, failure) {
    if ((prev == null) || (prev.getTreeSize() < head.getTreeSize())) {
        var log = this;
        var stack = [];
        if ((prev != null) && (prev.getTreeSize() > 0)) {
            this.getInclusionProofByIndex(prev.getTreeSize()+1, prev.getTreeSize(), function (proof) {
                var firstHash = null;
                for (var i = 0; i < proof.getAuditPath().length; i++) {
                    if (firstHash == null) {
                        firstHash = proof.getAuditPath()[i];
                    } else {
                        firstHash = nodeMerkleTreeHash(proof.getAuditPath()[i], firstHash);
                    }
                }
                if (firstHash != prev.getRootHash()) {
                    failure(CONTINUSEC_VERIFICATION_ERROR);
                } else {
                    for (var i = proof.getAuditPath().length - 1; i >= 0; i--) {
                        stack.push(proof.getAuditPath()[i]);
                    }
                    secondStageVerifyEntries(stack, log, prev, head, factory, each, success, failure);
                }
            }, failure);
        } else {
            secondStageVerifyEntries(stack, log, prev, head, factory, each, success, failure);
        }
    } else {
        success();
    }
};

/**
 * @private
 */
function secondStageVerifyEntries(stack, log, prev, head, factory, each, success, failure) {
    var parIdx = 0;
    if (prev != null) {
        parIdx = prev.getTreeSize();
    }
    log.getEntries(parIdx, head.getTreeSize(), factory, function (idx, entry) {
        each(idx, entry);

        stack.push(entry.getLeafHash());
        for (var z = idx; (z & 1) == 1; z >>= 1) {
            var right = stack.pop();
            var left = stack.pop();
            stack.push(nodeMerkleTreeHash(left, right));
        }

        parIdx += 1;
    }, function () {
        if (parIdx != head.getTreeSize()) {
            failure(CONTINUSEC_NOT_ALL_ENTRIES_RETURNED_ERROR);
        } else {
            var headHash = stack.pop();
            while (stack.length > 0) {
                headHash = nodeMerkleTreeHash(stack.pop(), headHash);
            }

            if (headHash != head.getRootHash()) {
                failure(CONTINUSEC_VERIFICATION_ERROR);
            } else {
                success();
            }
        }
    }, failure);
}

/**
 * Get an inclusion proof for a given item for a specific tree size. Most clients will commonly use {@link #verifyInclusion(LogTreeHead,MerkleTreeLeaf)} instead.
 * @param {int} treeSize the tree size for which the inclusion proof should be returned. This is usually as returned by {@link #getTreeHead(int)}.getTreeSize().
 * @param {MerkleTreeLeaf} leaf the entry for which the inclusion proof should be returned. Note that AddEntryResponse and RawDataEntry/JsonEntry/RedactedJsonEntry each implement MerkleTreeLeaf.
 * @param {logInclusionProofSuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getInclusionProof = function (treeSize, leaf, success, failure) {
	var lh = leaf.getLeafHash();
    this.client.makeRequest("GET", this.path + "/tree/" + treeSize + "/inclusion/h/" + hexString(lh), null, function (data, req) {
        var obj = JSON.parse(data);
        var auditPath = [];
        for (var i = 0; i < obj.audit_path.length; i++) {
            auditPath.push(atob(obj.audit_path[i]));
        }
        success(new LogInclusionProof(lh, protoNumber(obj.tree_size), protoNumber(obj.leaf_index), auditPath));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Get an inclusion proof for a specified tree size and leaf index. This is not used by typical clients,
 * however it can be useful for audit operations and debugging tools. Typical clients will use {@link #verifyInclusion(LogTreeHead,MerkleTreeLeaf)}.
 * @param {int} treeSize the tree size on which to base the proof.
 * @param {int} leafIndex the leaf index for which to retrieve the inclusion proof.
 * @param {logInclusionProofSuccessCallback} success called on success (note the proof is only partially filled in as it does not include the MerkleTreeLeaf hash for the item).
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getInclusionProofByIndex = function (treeSize, leafIndex, success, failure) {
    this.client.makeRequest("GET", this.path + "/tree/" + treeSize + "/inclusion/" + leafIndex, null, function (data, req) {
        var obj = JSON.parse(data);
        var auditPath = [];
        for (var i = 0; i < obj.proof.length; i++) {
            auditPath.push(atob(obj.proof[i]));
        }
        success(new LogInclusionProof(null, protoNumber(obj.tree_size), protoNumber(obj.leaf_index), auditPath));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * Get an inclusion proof for a given item and verify it.
 * @param {LogTreeHead} treeHead the tree head for which the inclusion proof should be returned. This is usually as returned by {@link #getTreeHead(int)}.
 * @param {MerkleTreeLeaf} leaf the entry for which the inclusion proof should be returned. Note that AddEntryResponse and RawDataEntry/JsonEntry/RedactedJsonEntry each implement MerkleTreeLeaf.
 * @param {emptySuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.verifyInclusion = function (head, leaf, success, failure) {
	this.getInclusionProof(head.getTreeSize(), leaf, function (proof) {
		try {
			proof.verify(head);
		} catch (err) {
			failure(err);
			return;
		}
		success();
	}, function (reason) {
		failure(reason);
	});
}

/**
 * ConsistencyProof returns an audit path which contains the set of Merkle Subtree hashes
 * that demonstrate how the root hash is calculated for both the first and second tree sizes.
 * @param {int} firstSize the size of the first tree.
 * @param {int} secondSize the size of the second tree.
 * @param {logConsistencyProofSuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getConsistencyProof = function (firstSize, secondSize, success, failure) {
    this.client.makeRequest("GET", this.path + "/tree/" + secondSize + "/consistency/" + firstSize, null, function (data, req) {
        var obj = JSON.parse(data);
        var auditPath = [];
        for (var i = 0; i < obj.audit_path.length; i++) {
            auditPath.push(atob(obj.audit_path[i]));
        }
        success(new LogConsistencyProof(protoNumber(obj.from_size), protoNumber(obj.tree_size), auditPath));
    }, function (reason) {
        failure(reason);
    });
};

/**
 * verifyConsistency takes two tree heads, retrieves a consistency proof and then verifies it.
 * The two tree heads may be in either order (even equal), but both must be greater than zero and non-nil.
 * @param {LogTreeHead} a one log tree head
 * @param {LogTreeHead} b another log tree head
 * @param {emptySuccessCallback} success called on success
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.verifyConsistency = function (a, b, success, failure) {
	if (a.getTreeSize() <= 0) {
		failure(CONTINUSEC_VERIFICATION_ERROR);
		return;
	}
	if (b.getTreeSize() <= 0) {
		failure(CONTINUSEC_VERIFICATION_ERROR);
		return;
	}

	if (a.getTreeSize() == b.getTreeSize()) {
		if (a.getRootHash() != b.getRootHash()) {
			failure(CONTINUSEC_VERIFICATION_ERROR);
			return;
		}
		success();
		return;
	}

	if (a.getTreeSize() > b.getTreeSize()) {
		var c = a;
		a = b;
		b = c;
	}

	this.getConsistencyProof(a.getTreeSize(), b.getTreeSize(), function (proof) {
		try {
			proof.verify(a, b);
		} catch (err) {
			failure(err);
			return;
		}
		success();
	}, function (reason) {
		failure(reason);
	});
}

/**
 * getVerifiedLatestTreeHead calls getVerifiedTreeHead() with HEAD to fetch the latest tree head,
 * and additionally verifies that it is newer than the previously passed tree head.
 * For first use, pass null to skip consistency checking.
 * @param {LogTreeHead} prev a previously persisted log tree head
 * @param {logTreeHeadSuccessCallback} success called on success, with a new LogTreeHead which has been verified to be consistent with the past tree head, or if no newer one present, the same value as passed in.
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getVerifiedLatestTreeHead = function (prev, success, failure) {
    this.getVerifiedTreeHead(prev, 0, function (head) {
        if (prev != null) {
            if (head.getTreeSize() <= prev.getTreeSize()) {
                head = prev;
            }
        }
        success(head);
    }, failure);
}

/**
 * getVerifiedTreeHead is a utility method to fetch a LogTreeHead and verifies that it is consistent with
 * a tree head earlier fetched and persisted. For first use, pass null for prev, which will
 * bypass consistency proof checking. Tree size may be older or newer than the previous head value.
 * @param {LogTreeHead} prev a previously persisted log tree head
 * @param {int} treeSize the tree size to fetch
 * @param {logTreeHeadSuccessCallback} success called on success, with a LogTreeHead which has been verified to be consistent with the past tree head and matches the size specified.
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.getVerifiedTreeHead = function (prev, treeSize, success, failure) {
    if ((treeSize != 0) && (prev != null) && (prev.getTreeSize() == treeSize)) {
        success(prev);
    } else {
        var log = this;
        this.getTreeHead(treeSize, function (head) {
            if (prev == null) {
                success(head);
            } else {
                log.verifyConsistency(prev, head, function () {
                    success(head);
                }, failure);
            }
        }, failure);
    }
}

/**
 * verifySuppliedInclusionProof is a utility method that fetches any required tree heads that are needed
 * to verify a supplied log inclusion proof. Additionally it will ensure that any fetched tree heads are consistent
 * with any prior supplied LogTreeHead. For first use, pass null for prev, which will
 * bypass consistency proof checking.
 * @param {LogTreeHead} prev a previously persisted log tree head, or null
 * @param {LogInclusionProof} proof an inclusion proof that may be for a different tree size than prev.getTreeSize()
 * @param {logTreeHeadSuccessCallback} success called on success, with the verified (for consistency) LogTreeHead that was used for successful verification (of inclusion) of the supplied proof. This may be older than the LogTreeHead passed in.
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.verifySuppliedInclusionProof = function (prev, proof, success, failure) {
    this.getVerifiedTreeHead(prev, proof.getTreeSize(), function (head) {
        try {
            proof.verify(head);
            success(head);
        } catch (err) {
            failure(err);
        }
    }, failure);
};


/**
 * Block until the log is able to produce a LogTreeHead that includes the specified MerkleTreeLeaf.
 * This polls {@link #getTreeHead(int)} and {@link #verifyInclusion(LogTreeHead, MerkleTreeLeaf)} until
 * such time as a new tree hash is produced that includes the given MerkleTreeLeaf. Exponential back-off
 * is used when no tree hash is available. This is intended for test use - the returned tree head is not verified for consistency.
 * @param {MerkleTreeLeaf} leaf the entry for which we should block until present. Note that AddEntryResponse and RawDataEntry/JsonEntry/RedactedJsonEntry each implement MerkleTreeLeaf.
 * @param {logTreeHeadSuccessCallback} success called on success, with the LogTreeHead that this leaf is included in.
 * @param {failureCallback} failure called on failure
 */
VerifiableLog.prototype.blockUntilPresent = function (leaf, success, failure) {
    doBlockRound(this, -1, 0, leaf, success, failure);
}

/**
 * @private
 */
function doBlockRound(log, lastHead, secsToSleep, leaf, success, failure) {
    log.getTreeHead(0, function (lth) {
        if (lth.getTreeSize() > lastHead) {
            log.verifyInclusion(lth, leaf, function () {
                success(lth);
            }, function (reason) {
                if (reason == CONTINUSEC_INVALID_RANGE_ERROR) {
                    secsToSleep = 1;
                    setTimeout(function () { doBlockRound(log, lth.getTreeSize(), secsToSleep, leaf, success, failure); }, secsToSleep * 1000);
                } else {
                    failure(reason);
                }
            });
        } else {
            secsToSleep *= 2
            setTimeout(function () { doBlockRound(log, lastHead, secsToSleep, leaf, success, failure); }, secsToSleep * 1000);
        }
    }, failure);
}

/**
 * Package private constructor. Use VerifiableLog.add(UploadableEntry) to instantiate.
 * @param {string} mtlHash leaf hash of the entry.
 * @constructor
 * @classdesc
 * Response from adding entries to a log/map.
 * Can be used in subsequent calls to {@link VerifiableLog#verifyInclusion(LogTreeHead, MerkleTreeLeaf)}.
 */
var AddEntryResponse = function (mtlHash) {
    this.mtlHash = mtlHash;
}

/**
 * Get the leaf hash for this entry.
 * @return {string} the leaf hash for this entry.
 */
AddEntryResponse.prototype.getLeafHash = function () { return this.mtlHash; };


/**
 * Constructor.
 * @param {string} name the name.
 * @constructor
 * @classdesc
 * Class to metadata about a log.
 */
var LogInfo = function (name) {
	this.name = name;
};

/**
 * Returns the name.
 * @return {string} the name.
 */
LogInfo.prototype.getName = function () { return this.name; };


/**
 * Constructor.
 * @param {string} name the name.
 * @constructor
 * @classdesc
 * Class to metadata about a map.
 */
var MapInfo = function (name) {
	this.name = name;
};

/**
 * Returns the name.
 * @return {string} the name.
 */
MapInfo.prototype.getName = function () { return this.name; };


/**
 * Creates a new LogConsistencyProof for given tree sizes and auditPath.
 * @param {int} firstSize the size of the first tree.
 * @param {int} secondSize the size of the second tree.
 * @param {string[]} auditPath the audit proof returned by the server.
 * @constructor
 * @classdesc
 * Class to represent the result of a call to {@link VerifiableLog#getConsistencyProof(int,int)}.
 */
var LogConsistencyProof = function (firstSize, secondSize, auditPath) {
	this.firstSize = firstSize;
	this.secondSize = secondSize;
	this.auditPath = auditPath;
};

/**
 * Returns the size of the first tree.
 * @return {int} the size of the first tree.
 */
LogConsistencyProof.prototype.getFirstSize = function () { return this.firstSize; };

/**
 * Returns the size of the second tree.
 * @return {int} the size of the second tree.
 */
LogConsistencyProof.prototype.getSecondSize = function () { return this.secondSize; };

/**
 * Returns the audit path.
 * @return {string[]} the audit path.
 */
LogConsistencyProof.prototype.getAuditPath = function () { return this.auditPath; };

/**
 * Verify that the consistency proof stored in this object can produce both the LogTreeHeads passed to this method.
 * i.e, verify the append-only nature of the log between first.getTreeSize() and second.getTreeSize().
 * @param {LogTreeHead} first the tree hash for the first tree size
 * @param {LogTreeHead} second the tree hash for the second tree size
 * @throws CONTINUSEC_VERIFICATION_ERROR if the verification fails for any reason.
 */
LogConsistencyProof.prototype.verify = function (first, second) {
	if (first.getTreeSize() != this.firstSize) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
	}
	if (second.getTreeSize() != this.secondSize) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
	}

    if ((this.firstSize < 1) || (this.firstSize >= this.secondSize)) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }

    var newProof = [];
    if (isPow2(this.firstSize)) {
        newProof.push(first.getRootHash());
    }
    var i;
    for (i = 0; i < this.auditPath.length; i++) {
        newProof.push(this.auditPath[i]);
    }

    var fn = this.firstSize - 1;
    var sn = this.secondSize - 1;
    while ((fn & 1) == 1) {
        fn >>= 1;
        sn >>= 1;
    }

    if (newProof.length === 0) {
        return false;
    }

    var fr = newProof[0];
    var sr = newProof[0];
    for (i = 1; i < newProof.length; i++) {
        if (sn === 0) {
            return false;
        }
        if (((fn & 1) == 1) || (fn == sn)) {
            fr = nodeMerkleTreeHash(newProof[i], fr);
            sr = nodeMerkleTreeHash(newProof[i], sr);
            while (!((fn === 0) || ((fn & 1) == 1))) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            sr = nodeMerkleTreeHash(sr, newProof[i]);
        }
        fn >>= 1;
        sn >>= 1;
    }

    if (sn != 0) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }

    if (fr != first.getRootHash()) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }

    if (sr != second.getRootHash()) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }
}

/**
 * Create new LogInclusionProof.
 *
 * @param {int} treeSize the tree size for which this proof is valid.
 * @param {string} leafHash the Merkle Tree Leaf hash of the entry this proof is valid for.
 * @param {int} leafIndex the index of this entry in the log.
 * @param {string[]} auditPath the list of Merkle Tree nodes that apply to this entry in order to generate the root hash and prove inclusion.
 * @constructor
 * @classdesc
 * Class to represent proof of inclusion of an entry in a log.
 */
var LogInclusionProof = function (leafHash, treeSize, leafIndex, auditPath) {
	this.leafHash = leafHash;
	this.treeSize = treeSize;
	this.leafIndex = leafIndex;
	this.auditPath = auditPath;
};

/**
 * Returns the leaf hash.
 * @return {string} the leaf hash.
 */
LogInclusionProof.prototype.getLeafHash = function () { return this.leafHash; };

/**
 * Returns the tree size.
 * @return {int} the tree size.
 */
LogInclusionProof.prototype.getTreeSize = function () { return this.treeSize; };

/**
 * Returns the leaf index.
 * @return {int} the leaf index.
 */
LogInclusionProof.prototype.getLeafIndex = function () { return this.leafIndex; };

/**
 * Returns the audit path.
 * @return {string[]} the audit path for this proof.
 */
LogInclusionProof.prototype.getAuditPath = function () { return this.auditPath; };

/**
 * For a given tree head, check to see if our proof can produce it for the same tree size.
 * @param {LogTreeHea} head the LogTreeHead to compare
 * @throws CONTINUSEC_VERIFICATION_ERROR if the verification fails for any reason.
 */
LogInclusionProof.prototype.verify = function (head) {
	if (head.getTreeSize() != this.treeSize) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
	}

    if ((this.leafIndex >= this.treeSize) || (this.leafIndex < 0)) {
        return false;
    }

    var fn = this.leafIndex;
    var sn = this.treeSize - 1;
    var r = this.leafHash;

    for (var i = 0; i < this.auditPath.length; i++) {
        if ((fn == sn) || ((fn & 1) == 1)) {
            r = nodeMerkleTreeHash(this.auditPath[i], r);
            while (!((fn === 0) || ((fn & 1) == 1))) {
                fn >>= 1;
                sn >>= 1;
            }
        } else {
            r = nodeMerkleTreeHash(r, this.auditPath[i]);
        }
        fn >>= 1;
        sn >>= 1;
    }

    if (sn != 0) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }

    if (r != head.getRootHash()) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }
};

/**
 * Constructor.
 * @param {string} key the key for which this value is valid.
 * @param {VerifiableEntry} value the value for this key (RawDataEntry, JsonEntry or RedactedJsonEntry).
 * @param {string[]} auditPath the inclusion proof for this value in the map for a given tree size.
 * @param {int} treeSize the tree size that the inclusion proof is valid for.
 * @constructor
 * @classdesc
 * Class to represent the response for getting an entry from a map. It contains both the value
 * itself, as well as an inclusion proof for how that value fits into the map root hash.
 */
var MapEntryResponse = function (key, value, treeSize, auditPath) {
    this.key = key;
    this.value = value;
    this.treeSize = treeSize;
    this.auditPath = auditPath;
};

/**
 * The key in this map entry response.
 * @return {string} the key
 */
MapEntryResponse.prototype.getKey = function () {
	return this.key;
}

/**
 * The value in this map entry response.
 * @return {VerifiableEntry} the value for this key (RawDataEntry, JsonEntry or RedactedJsonEntry).
 */
MapEntryResponse.prototype.getValue = function () {
	return this.value;
}

/**
 * The tree size that this map entry response is valid for.
 * @return {int} the tree size
 */
MapEntryResponse.prototype.getTreeSize = function () {
	return this.treeSize;
}

/**
 * The audit path that can be applied to the value to reach the root hash for the map at this tree size.
 * @return {string[]} the audit path - for a map this is always 256 values, null values indicate that the default leaf value for that index should be used.
 */
MapEntryResponse.prototype.getAuditPath = function () {
	return this.auditPath;
}

/**
 * For a given tree head, check to see if our proof can produce it for the same tree size.
 * @param {MapTreeHead} head the MapTreeHead to compare
 * @throws CONTINUSEC_VERIFICATION_ERROR if the verification fails for any reason.
 */
MapEntryResponse.prototype.verify = function (mapTreeHead) {
	if (this.treeSize != mapTreeHead.getTreeSize()) {
		throw CONTINUSEC_VERIFICATION_ERROR;
	}
    var kp = constructKeyPath(this.key);
    var t = this.value.getLeafHash();
    for (var i = kp.length - 1; i >= 0; i--) {
        var p = this.auditPath[i];
        if (p === null) {
            p = DEFAULT_LEAF_VALUES[i + 1];
        }
        if (kp[i]) {
            t = nodeMerkleTreeHash(p, t);
        } else {
            t = nodeMerkleTreeHash(t, p);
        }
    }
    if (t != mapTreeHead.getRootHash()) {
    	throw CONTINUSEC_VERIFICATION_ERROR;
    }
}

/**
 * Constructor - class is stateless so it takes no parameters.
 * @constructor
 * @classdesc
 * Factory that produces RawDataEntry instances upon request.
 */
var RawDataEntryFactory = function () {};

/**
 * Returns the suffix added to calls to GET /entry/xxx
 * @return {string} the suffix to add.
 */
RawDataEntryFactory.prototype.getFormat = function () { return ""; };

/**
 * Instantiate a new entry from bytes as returned by server.
 * @param {string} bytes the bytes as returned by the server.
 * @return {RawDataEntry} the new entry.
 */
RawDataEntryFactory.prototype.createFromLeafData = function (b) { return new RawDataEntry(b.leaf_input == undefined ? "" : atob(b.leaf_input)); };

/**
 * Singleton instance of RawDataEntryFactory ready for your use.
 */
var RAW_DATA_ENTRY_FACTORY = new RawDataEntryFactory();


/**
 * Constructor - class is stateless so it takes no parameters.
 * @constructor
 * @classdesc
 * Factory that produces JsonEntry instances upon request.
 */
var JsonEntryFactory = function () {};

/**
 * Returns the suffix added to calls to GET /entry/xxx
 * @return {string} the suffix to add.
 */
JsonEntryFactory.prototype.getFormat = function () { return "/xjson"; };

/**
 * Instantiate a new entry from bytes as returned by server.
 * @param {string} bytes the bytes as returned by the server.
 * @return {JsonEntry} the new entry.
 */
JsonEntryFactory.prototype.createFromLeafData = function (b) { return new JsonEntry(b.extra_data == undefined ? "" : atob(b.extra_data)); };

/**
 * Singleton instance of JsonEntryFactory ready for your use.
 */
var JSON_ENTRY_FACTORY = new JsonEntryFactory();


/**
 * Constructor - class is stateless so it takes no parameters.
 * @constructor
 * @classdesc
 * Factory that produces RedactedJsonEntry instances upon request.
 */
var RedactedJsonEntryFactory = function () {};

/**
 * Returns the suffix added to calls to GET /entry/xxx
 * @return {string} the suffix to add.
 */
RedactedJsonEntryFactory.prototype.getFormat = function () { return "/xjson"; };

/**
 * Instantiate a new entry from bytes as returned by server.
 * @param {string} bytes the bytes as returned by the server.
 * @return {RedactedJsonEntry} the new entry.
 */
RedactedJsonEntryFactory.prototype.createFromLeafData = function (b) { return new RedactedJsonEntry(atob(b.extra_data)); };

/**
 * Singleton instance of RedactedJsonEntryFactory ready for your use.
 */
var REDACTED_JSON_ENTRY_FACTORY = new RedactedJsonEntryFactory();


/**
 * Constructor.
 * @param {string} data the raw data to represent.
 * @constructor
 * @classdesc
 * Class to represent a log/map entry where no special processing is performed,
 * that is, the bytes specified are stored as-is, and are used as-is for input
 * to the Merkle Tree leaf function.
 */
var RawDataEntry = function (data) {
	this.data = data;
}

/**
 * Get the suffix that should be added to the PUT/POST request for this data format.
 * @return {string} the suffix
 */
RawDataEntry.prototype.getFormat = function () {
	return "";
}

/**
 * Get the data that should be stored.
 * @return {string} the data
 */
RawDataEntry.prototype.getDataForUpload = function () {
	return this.data;
}

/**
 * Get the data for processing.
 * @return {string} the data
 */
RawDataEntry.prototype.getData = function () {
	return this.data;
}

/**
 * Calculate the leaf hash for this entry.
 * @return {string} the Merkle Tree leaf hash for this entry.
 */
RawDataEntry.prototype.getLeafHash = function () {
	return leafMerkleTreeHash(this.data);
}

/**
 * Constructor.
 * @param {string} data the raw JSON data.
 * @constructor
 * @classdesc
 * Class to be used when entry MerkleTreeLeafs should be based on ObjectHash
 * rather than the JSON bytes directly. Since there is no canonical encoding for JSON,
 * it is useful to hash these objects in a more defined manner.
 */
var JsonEntry = function (data) {
	this.data = data;
}

/**
 * Get the suffix that should be added to the PUT/POST request for this data format.
 * @return {string} the suffix
 */
JsonEntry.prototype.getFormat = function () {
	return "/xjson";
}

/**
 * Get the data that should be stored.
 * @return {string} the data
 */
JsonEntry.prototype.getDataForUpload = function () {
	return this.data;
}

/**
 * Get the data for processing.
 * @return {string} the data
 */
JsonEntry.prototype.getData = function () {
	return this.data;
}

/**
 * Calculate the leaf hash for this entry.
 * @return {string} the Merkle Tree leaf hash for this entry.
 */
JsonEntry.prototype.getLeafHash = function () {
	return leafMerkleTreeHash(this.data == "" ? "" : objectHashWithStdRedaction(JSON.parse(this.data)));
}

/**
 * Constructor.
 * @param {string} data the raw data representing the JSON for this entry.
 * @constructor
 * @classdesc
 * Class to represent JSON data should be made Redactable by the server upon upload.
 * ie change all dictionary values to be nonce-value tuples and control access to fields
 * based on the API key used to make the request.
 */
var RedactableJsonEntry = function (data) {
	this.data = data;
}

/**
 * Get the suffix that should be added to the PUT/POST request for this data format.
 * @return {string} the suffix
 */
RedactableJsonEntry.prototype.getFormat = function () {
	return "/xjson/redactable";
}

/**
 * Get the data that should be stored.
 * @return {string} the data
 */
RedactableJsonEntry.prototype.getDataForUpload = function () {
	return this.data;
}

/**
 * Constructor.
 * @param {string} data the raw data respresenting the redacted JSON.
 * @constructor
 * @classdesc
 * Class to represent redacted entries as returned by the server. Not to be confused
 * with RedactableJsonEntry that should be used to represent objects that should
 * be made Redactable by the server when uploaded.
 */
var RedactedJsonEntry = function (data) {
	this.data = data;
}

/**
 * Get the underlying JSON for this entry, with all Redactable nonce-tuples and
 * redacted sub-objects stripped for ease of processing.
 * @return {string} the data
 */
RedactedJsonEntry.prototype.getData = function () {
	return JSON.stringify(shedRedactedWithStdRedaction(JSON.parse(this.data)));
}

/**
 * Calculate the leaf hash for this entry.
 * @return {string} the Merkle Tree leaf hash for this entry.
 */
RedactedJsonEntry.prototype.getLeafHash = function () {
	return leafMerkleTreeHash(this.data == "" ? "" : objectHashWithStdRedaction(JSON.parse(this.data)));
}




/**
 * Constructor.
 * @param {LogTreeHead} treeHeadLogTreeHead the tree head for the underlying tree head log that the mapTreeHead has been verified as being included.
 * @param {MapTreeHead} mapHead the map tree head for the map
 * @constructor
 * @classdesc
 * Class for MapTreeState as returned by VerifiableMap.getVerifiedMapState(MapTreeState,int).
 */
var MapTreeState = function (mapHead, treeHeadLogTreeHead) {
	this.mapHead = mapHead;
	this.treeHeadLogTreeHead = treeHeadLogTreeHead;
}

/**
 * Utility method for returning the size of the map that this state represents.
 * @return {int} the size
 */
MapTreeState.prototype.getTreeSize = function () {
	return this.mapHead.getTreeSize();
}

/**
 * Get the map tree head.
 * @return {MapTreeHead} the map tree head
 */
MapTreeState.prototype.getMapHead = function () {
	return this.mapHead;
}

/**
 * Get corresponding the tree head log tree head.
 * @return {LogTreeHead} the tree head log tree head.
 */
MapTreeState.prototype.getTreeHeadLogTreeHead = function () {
	return this.treeHeadLogTreeHead;
}

/**
 * Constructor.
 * @param {string} rootHash the root hash for the map of this tree size.
 * @param {LogTreeHead} logTreeHead the corresponding tree hash for the mutation log
 * @constructor
 * @classdesc
 * Class for Tree Hash as returned for a map with a given size.
 */
var MapTreeHead = function (logTreeHead, rootHash) {
	this.logTreeHead = logTreeHead;
	this.rootHash = rootHash;
}

/**
 * Returns the map size for this root hash.
 * @return {int} the map size for this root hash.
 */
MapTreeHead.prototype.getTreeSize = function () {
	return this.logTreeHead.getTreeSize();
}

/**
 * Get corresponding the mutation log tree hash.
 * @return {LogTreeHead} the mutation log tree hash.
 */
MapTreeHead.prototype.getMutationLogTreeHead = function () {
	return this.logTreeHead;
}

/**
 * Returns the map root hash for this map size.
 * @return {string} the map root hash for this map size.
 */
MapTreeHead.prototype.getRootHash = function () {
	return this.rootHash;
}

/**
 * Implementation of getLeafHash() so that MapTreeHead can be used easily with
 * VerifiableLog.verifyInclusion(LogTreeHead, MerkleTreeLeaf).
 * @return {string} leaf hash base on the Object Hash for this map root hash with corresponding mutation log.
 */
MapTreeHead.prototype.getLeafHash = function () {
	return leafMerkleTreeHash(objectHashWithStdRedaction({
	    "mutation_log": {
	        "tree_size": this.getMutationLogTreeHead().getTreeSize(),
	        "root_hash": btoa(this.getMutationLogTreeHead().getRootHash()),
	    },
	    "root_hash": btoa(this.getRootHash()),
	}));
}

/**
 * Constructor.
 * @param {int} treeSize the tree size the root hash is valid for.
 * @param {string} rootHash the root hash for the log of this tree size.
 * @constructor
 * @classdesc
 * Class for Tree Hash as returned for a log with a given size.
 */
var LogTreeHead = function (treeSize, rootHash) {
	this.treeSize = treeSize;
	this.rootHash = rootHash;
}

/**
 * Returns the tree size for this tree hash.
 * @return {int} the tree size for this tree hash.
 */
LogTreeHead.prototype.getTreeSize = function () {
	return this.treeSize;
}

/**
 * Returns the root hash for this tree size.
 * @return {string} the root hash for this tree size.
 */
LogTreeHead.prototype.getRootHash = function () {
	return this.rootHash;
}

/**
 * @private
 */
function binaryArrayToString(d) {
    var rv = "";
    for (var j = 0; j < d.length; j++) {
        rv += String.fromCharCode(d[j]);
    }
    return rv;
}

/**
 * @private
 */
function hexString(a) {
    var rv = "";
    for (var i = 0; i < a.length; i++) {
        var h = a.charCodeAt(i).toString(16);
        while (h.length < 2) {
            h = "0" + h;
        }
        rv += h;
    }
    return rv;
}

/**
 * @private
 */
function decodeHex(s) {
    var rv = "";
    for (var i = 0; (i + 1) < s.length; i += 2) {
        rv += String.fromCharCode(parseInt(s.substring(i, i+2), 16));
    }
    return rv;
}

/**
 * @private
 */
function isPow2(k) {
    while (((k % 2) == 0) && (k > 1)) {
        k /= 2;
    }
    return (k == 1);
}

/**
 * Create the path in a sparse merkle tree for a given key. ie a boolean array representing
 * the big-endian index of the the hash of the key.
 * @param {string} key the key
 * @return {boolean[]} a length 256 array of booleans representing left (false) and right (true) path in the Sparse Merkle Tree.
 */
function constructKeyPath(key) {
    var h = sha256(key);
    var rv = [];
    for (var i = 0; i < h.length; i++) {
        for (var j = 7; j >= 0; j--) {
            rv.push(((h.charCodeAt(i) >> j) & 1) == 1);
        }
    }
    return rv;
}

/**
 * @private
 */
function sha256(b) {
    var shaObj = new jsSHA("SHA-256", "BYTES");
    shaObj.update(b);
    return shaObj.getHash("BYTES");
}

/**
 * Calculate the Merkle Tree Node Hash for an existing left and right hash (HASH(chr(1) || l || r)).
 * @param {string} l the left node hash.
 * @param {string} r the right node hash.
 * @return {string{ the node hash for the combination.
 */
function nodeMerkleTreeHash(l, r) {
    return sha256(String.fromCharCode(1) + l + r);
}

/**
 * Calculate the Merkle Tree Leaf Hash for an object (HASH(chr(0) || b)).
 * @param {string} b the input to the leaf hash
 * @return {string} the leaf hash.
 */
function leafMerkleTreeHash(b) {
    return sha256(String.fromCharCode(0) + b);
}

/**
 * Generate the set of 257 default values for every level in a sparse Merkle Tree.
 * @return {string[]} array of length 257 default values.
 */
function generateMapDefaultLeafValues() {
    var rv = [];
    var i;
    for (i = 0; i < 257; i++) {
        rv.push(null);
    }

    rv[256] = leafMerkleTreeHash("");
    for (i = 255; i >= 0; i--) {
        rv[i] = nodeMerkleTreeHash(rv[i+1], rv[i+1]);
    }
    return rv;
}

/**
 * @private
 */
var DEFAULT_LEAF_VALUES = generateMapDefaultLeafValues();


/**
 * Prefix to indicate that this value should not be treated as a string, and instead
 * the remainder of the string is the hex encoded hash to use.
 */
var REDACTED_PREFIX = "***REDACTED*** Hash: ";

/**
 * Calculate the objecthash for an object, assuming no redaction.
 * @param {object} o the object to calculated the objecthash for.
 * @return {string} the objecthash for this object
 */
function objectHash(o) {
	return objectHashWithRedaction(o, "");
}

/**
 * Calculate the objecthash for a Gson JsonElement object, assuming the standard redaction prefix is used.
 * @param {object} o the object to calculated the objecthash for.
 * @return {string} the objecthash for this object
 */
function objectHashWithStdRedaction(o) {
	return objectHashWithRedaction(o, REDACTED_PREFIX);
}

/**
 * @private
 */
var normalizeFunction = null;
if (typeof "foo".normalize === 'function') {
    normalizeFunction = function(o) {
        return unescape(encodeURIComponent(o.normalize('NFC')));
    };
} else {
    // Safari does not support normalize() at time of writing (June 2016)
    console.warn("String.prototype.normalize() not found - will result in incorrect hashes for Unicode values.");
    normalizeFunction = function(o) {
        return o;
    };
}

/**
 * Calculate the objecthash for an object, with a custom redaction prefix string.
 * @param {object} o the object to calculated the objecthash for.
 * @param {prefix} the string to use as a prefix to indicate that a string should be treated as a redacted subobject.
 * @return {string} the objecthash for this object
 */
function objectHashWithRedaction(o, prefix) {
	if (o == null) {
		return sha256('n');
	} else if (o instanceof Array) {
		var input = "";
		for (var i = 0; i < o.length; i++) {
			input += objectHashWithRedaction(o[i], prefix);
		}
		return sha256('l' + input);
	} else if ((typeof o) == "string") {
		if (prefix.length > 0 && o.startsWith(prefix)) {
			return decodeHex(o.substring(prefix.length));
		} else {
			return sha256('u' + normalizeFunction(o));
		}
	} else if ((typeof o) == "number") { // we assume everything is a float (json doesn't distinguish)
		if (o == 0.0) { // special case 0
			return sha256('f+0:');
		}
		var s = "+";
		if (o < 0) {
			s = "-";
			o = -o;
		}
		var e = 0;
		while (o > 1) {
			o /= 2.0;
			e++;
		}
		while (o <= 0.5) {
			o *= 2.0;
			e--;
		}
		s += e + ":";
		if ((o > 1) || (o <= 0.5)) {
			return undefined;
		}
		while (o != 0) {
			if (o >= 1) {
				s += "1";
				o -= 1.0;
			} else {
				s += "0";
			}
			if (o >= 1) {
				return undefined;
			}
			if (s.length >= 1000) {
				return undefined;
			}
			o *= 2.0;
		}
		return sha256('f' + s);
	} else if ((typeof o) == "boolean") {
		return sha256('b' + (o ? "1" : "0"));
	} else { // object
		var kh = [];
		for (var k in o) {
			kh.push(objectHashWithRedaction(k, prefix) + objectHashWithRedaction(o[k], prefix));
		}
		kh.sort();
		return sha256("d"+kh.join(""));
	}
}

/**
 * Strip away object values that are marked as redacted, and switch nonce-tuples back to normal values.
 * This is useful when an object has been stored with Redactable nonces added, but now it has been retrieved
 * and normal processing needs to be performed on it. This method uses the standard redaction prefix.
 * @param {object} o the object that contains the redacted elements and nonce-tuples.
 * @return {object} a new cleaned up object
 */
function shedRedactedWithStdRedaction(o) {
	return shedRedacted(o, REDACTED_PREFIX);
}

/**
 * Strip away object values that are marked as redacted, and switch nonce-tuples back to normal values.
 * This is useful when an object has been stored with Redactable nonces added, but now it has been retrieved
 * and normal processing needs to be performed on it.
 * @param {object} o the object that contains the redacted elements and nonce-tuples.
 * @param {string} prefix the redaction prefix that indicates if a string represents a redacted sub-object.
 * @return {object} a new cleaned up object
 */
function shedRedacted(o, prefix) {
	if (o == null) {
		return null;
	} else if (o instanceof Array) {
		var rv = [];
		for (var i = 0; i < o.length; i++) {
			rv.push(shedRedacted(o[i], prefix));
		}
		return rv;
	} else if ((typeof o) == "object") {
		var rv = {};
		for (var k in o) {
			var v = o[k];
			if (v instanceof Array) {
				if (v.length == 2) {
					rv[k] = shedRedacted(v[1], prefix);
				} else {
					return undefined;
				}
			} else if ((typeof v) == "string") {
				if (v.startsWith(prefix)) {
					// good, do nothing
				} else {
					return undefined;
				}
			} else {
				return undefined;
			}
		}
		return rv;
	} else {
		return o;
	}
}
