// ../_tools_/src/GenerateRandom.js
import { Bases } from "@yaronkoresh/bases";

// ../_tools_/src/Charsets.js
var hex = "0123456789abcdef";
var base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// ../_tools_/src/GenerateRandom.js
var SecureRandom8U = function(count) {
  let bytes = new Uint8Array(count);
  return crypto.getRandomValues(bytes);
};
var SecureRandom16U = function(count) {
  let bytes = new Uint16Array(count);
  return crypto.getRandomValues(bytes);
};
var GenerateRandomNumber = function(len = 0) {
  if (len < 1) {
    len = SecureRandom8U(1)[0];
  }
  return SecureRandom16U(len).join("").slice(0, len);
};
var GenerateRandomBinary = function(len) {
  if (len < 1) {
    len = SecureRandom8U(1)[0];
  }
  let ret = "";
  while (true) {
    let rand = GenerateRandomNumber(3);
    ret += Bases(rand, "01", 11, "");
    if (ret.length >= len) {
      return ret.slice(0, len);
    }
  }
};

// ../_tools_/src/Zeros.js
var Zeros = function(str, len) {
  str = str.toString();
  while (str.length < len) {
    str = "0" + str;
  }
  return str;
};

// ../_tools_/src/Split.js
var Split = function(inp, num) {
  inp = inp.toString();
  var out = [];
  for (var i = 0; i < inp.length; i += num) {
    out.push(inp.substring(i, i + num));
  }
  return out;
};

// ../_tools_/src/Scrypt.js
var buffer = await import("buffer/index.js");
var Buffer = buffer.Buffer;
var MAX_VALUE = 2147483647;
function SHA256(m) {
  const K = new Uint32Array([
    1116352408,
    1899447441,
    3049323471,
    3921009573,
    961987163,
    1508970993,
    2453635748,
    2870763221,
    3624381080,
    310598401,
    607225278,
    1426881987,
    1925078388,
    2162078206,
    2614888103,
    3248222580,
    3835390401,
    4022224774,
    264347078,
    604807628,
    770255983,
    1249150122,
    1555081692,
    1996064986,
    2554220882,
    2821834349,
    2952996808,
    3210313671,
    3336571891,
    3584528711,
    113926993,
    338241895,
    666307205,
    773529912,
    1294757372,
    1396182291,
    1695183700,
    1986661051,
    2177026350,
    2456956037,
    2730485921,
    2820302411,
    3259730800,
    3345764771,
    3516065817,
    3600352804,
    4094571909,
    275423344,
    430227734,
    506948616,
    659060556,
    883997877,
    958139571,
    1322822218,
    1537002063,
    1747873779,
    1955562222,
    2024104815,
    2227730452,
    2361852424,
    2428436474,
    2756734187,
    3204031479,
    3329325298
  ]);
  let h0 = 1779033703, h1 = 3144134277, h2 = 1013904242, h3 = 2773480762;
  let h4 = 1359893119, h5 = 2600822924, h6 = 528734635, h7 = 1541459225;
  const w = new Uint32Array(64);
  function blocks(p2) {
    let off = 0, len = p2.length;
    while (len >= 64) {
      let a = h0, b = h1, c = h2, d = h3, e = h4, f = h5, g = h6, h = h7, u, i2, j, t1, t2;
      for (i2 = 0; i2 < 16; i2++) {
        j = off + i2 * 4;
        w[i2] = (p2[j] & 255) << 24 | (p2[j + 1] & 255) << 16 | (p2[j + 2] & 255) << 8 | p2[j + 3] & 255;
      }
      for (i2 = 16; i2 < 64; i2++) {
        u = w[i2 - 2];
        t1 = (u >>> 17 | u << 32 - 17) ^ (u >>> 19 | u << 32 - 19) ^ u >>> 10;
        u = w[i2 - 15];
        t2 = (u >>> 7 | u << 32 - 7) ^ (u >>> 18 | u << 32 - 18) ^ u >>> 3;
        w[i2] = (t1 + w[i2 - 7] | 0) + (t2 + w[i2 - 16] | 0) | 0;
      }
      for (i2 = 0; i2 < 64; i2++) {
        t1 = (((e >>> 6 | e << 32 - 6) ^ (e >>> 11 | e << 32 - 11) ^ (e >>> 25 | e << 32 - 25)) + (e & f ^ ~e & g) | 0) + (h + (K[i2] + w[i2] | 0) | 0) | 0;
        t2 = ((a >>> 2 | a << 32 - 2) ^ (a >>> 13 | a << 32 - 13) ^ (a >>> 22 | a << 32 - 22)) + (a & b ^ a & c ^ b & c) | 0;
        h = g;
        g = f;
        f = e;
        e = d + t1 | 0;
        d = c;
        c = b;
        b = a;
        a = t1 + t2 | 0;
      }
      h0 = h0 + a | 0;
      h1 = h1 + b | 0;
      h2 = h2 + c | 0;
      h3 = h3 + d | 0;
      h4 = h4 + e | 0;
      h5 = h5 + f | 0;
      h6 = h6 + g | 0;
      h7 = h7 + h | 0;
      off += 64;
      len -= 64;
    }
  }
  blocks(m);
  let i, bytesLeft = m.length % 64, bitLenHi = m.length / 536870912 | 0, bitLenLo = m.length << 3, numZeros = bytesLeft < 56 ? 56 : 120, p = m.slice(m.length - bytesLeft, m.length);
  p.push(128);
  for (i = bytesLeft + 1; i < numZeros; i++) {
    p.push(0);
  }
  p.push(bitLenHi >>> 24 & 255);
  p.push(bitLenHi >>> 16 & 255);
  p.push(bitLenHi >>> 8 & 255);
  p.push(bitLenHi >>> 0 & 255);
  p.push(bitLenLo >>> 24 & 255);
  p.push(bitLenLo >>> 16 & 255);
  p.push(bitLenLo >>> 8 & 255);
  p.push(bitLenLo >>> 0 & 255);
  blocks(p);
  return [
    h0 >>> 24 & 255,
    h0 >>> 16 & 255,
    h0 >>> 8 & 255,
    h0 >>> 0 & 255,
    h1 >>> 24 & 255,
    h1 >>> 16 & 255,
    h1 >>> 8 & 255,
    h1 >>> 0 & 255,
    h2 >>> 24 & 255,
    h2 >>> 16 & 255,
    h2 >>> 8 & 255,
    h2 >>> 0 & 255,
    h3 >>> 24 & 255,
    h3 >>> 16 & 255,
    h3 >>> 8 & 255,
    h3 >>> 0 & 255,
    h4 >>> 24 & 255,
    h4 >>> 16 & 255,
    h4 >>> 8 & 255,
    h4 >>> 0 & 255,
    h5 >>> 24 & 255,
    h5 >>> 16 & 255,
    h5 >>> 8 & 255,
    h5 >>> 0 & 255,
    h6 >>> 24 & 255,
    h6 >>> 16 & 255,
    h6 >>> 8 & 255,
    h6 >>> 0 & 255,
    h7 >>> 24 & 255,
    h7 >>> 16 & 255,
    h7 >>> 8 & 255,
    h7 >>> 0 & 255
  ];
}
function PBKDF2_HMAC_SHA256_OneIter(password, salt, dkLen) {
  password = password.length <= 64 ? password : SHA256(password);
  const innerLen = 64 + salt.length + 4;
  const inner = new Array(innerLen);
  const outerKey = new Array(64);
  let i;
  let dk = [];
  for (i = 0; i < 64; i++) {
    inner[i] = 54;
  }
  for (i = 0; i < password.length; i++) {
    inner[i] ^= password[i];
  }
  for (i = 0; i < salt.length; i++) {
    inner[64 + i] = salt[i];
  }
  for (i = innerLen - 4; i < innerLen; i++) {
    inner[i] = 0;
  }
  for (i = 0; i < 64; i++)
    outerKey[i] = 92;
  for (i = 0; i < password.length; i++)
    outerKey[i] ^= password[i];
  function incrementCounter() {
    for (let i2 = innerLen - 1; i2 >= innerLen - 4; i2--) {
      inner[i2]++;
      if (inner[i2] <= 255)
        return;
      inner[i2] = 0;
    }
  }
  while (dkLen >= 32) {
    incrementCounter();
    dk = dk.concat(SHA256(outerKey.concat(SHA256(inner))));
    dkLen -= 32;
  }
  if (dkLen > 0) {
    incrementCounter();
    dk = dk.concat(SHA256(outerKey.concat(SHA256(inner))).slice(0, dkLen));
  }
  return dk;
}
function blockmix_salsa8(BY, Yi, r, x, _X) {
  let i;
  arraycopy(BY, (2 * r - 1) * 16, _X, 0, 16);
  for (i = 0; i < 2 * r; i++) {
    blockxor(BY, i * 16, _X, 16);
    salsa20_8(_X, x);
    arraycopy(_X, 0, BY, Yi + i * 16, 16);
  }
  for (i = 0; i < r; i++) {
    arraycopy(BY, Yi + i * 2 * 16, BY, i * 16, 16);
  }
  for (i = 0; i < r; i++) {
    arraycopy(BY, Yi + (i * 2 + 1) * 16, BY, (i + r) * 16, 16);
  }
}
function R(a, b) {
  return a << b | a >>> 32 - b;
}
function salsa20_8(B, x) {
  arraycopy(B, 0, x, 0, 16);
  for (let i = 8; i > 0; i -= 2) {
    x[4] ^= R(x[0] + x[12], 7);
    x[8] ^= R(x[4] + x[0], 9);
    x[12] ^= R(x[8] + x[4], 13);
    x[0] ^= R(x[12] + x[8], 18);
    x[9] ^= R(x[5] + x[1], 7);
    x[13] ^= R(x[9] + x[5], 9);
    x[1] ^= R(x[13] + x[9], 13);
    x[5] ^= R(x[1] + x[13], 18);
    x[14] ^= R(x[10] + x[6], 7);
    x[2] ^= R(x[14] + x[10], 9);
    x[6] ^= R(x[2] + x[14], 13);
    x[10] ^= R(x[6] + x[2], 18);
    x[3] ^= R(x[15] + x[11], 7);
    x[7] ^= R(x[3] + x[15], 9);
    x[11] ^= R(x[7] + x[3], 13);
    x[15] ^= R(x[11] + x[7], 18);
    x[1] ^= R(x[0] + x[3], 7);
    x[2] ^= R(x[1] + x[0], 9);
    x[3] ^= R(x[2] + x[1], 13);
    x[0] ^= R(x[3] + x[2], 18);
    x[6] ^= R(x[5] + x[4], 7);
    x[7] ^= R(x[6] + x[5], 9);
    x[4] ^= R(x[7] + x[6], 13);
    x[5] ^= R(x[4] + x[7], 18);
    x[11] ^= R(x[10] + x[9], 7);
    x[8] ^= R(x[11] + x[10], 9);
    x[9] ^= R(x[8] + x[11], 13);
    x[10] ^= R(x[9] + x[8], 18);
    x[12] ^= R(x[15] + x[14], 7);
    x[13] ^= R(x[12] + x[15], 9);
    x[14] ^= R(x[13] + x[12], 13);
    x[15] ^= R(x[14] + x[13], 18);
  }
  for (let i = 0; i < 16; ++i) {
    B[i] += x[i];
  }
}
function blockxor(S, Si, D, len) {
  for (let i = 0; i < len; i++) {
    D[i] ^= S[Si + i];
  }
}
function arraycopy(src, srcPos, dest, destPos, length) {
  while (length--) {
    dest[destPos++] = src[srcPos++];
  }
}
function checkBufferish(o) {
  if (!o || typeof o.length !== "number") {
    return false;
  }
  for (let i = 0; i < o.length; i++) {
    const v = o[i];
    if (typeof v !== "number" || v % 1 || v < 0 || v >= 256) {
      return false;
    }
  }
  return true;
}
function ensureInteger(value, name) {
  if (typeof value !== "number" || value % 1) {
    throw new Error("invalid " + name);
  }
  return value;
}
var Scrypt = function(password, salt, len = 8, power = 1) {
  let N = Math.pow(2, power);
  let r = Math.pow(8, power);
  let p = Math.pow(4, power);
  let dkLen = len;
  let ret = {
    salt: salt ?? password,
    cost: N,
    memory: r,
    threads: p,
    octets: dkLen
  };
  let callback = false;
  password = Buffer.from(password.normalize("NFKC"));
  salt = Buffer.from(salt.normalize("NFKC"));
  N = ensureInteger(N, "N");
  r = ensureInteger(r, "r");
  p = ensureInteger(p, "p");
  dkLen = ensureInteger(dkLen, "dkLen");
  if (N === 0 || (N & N - 1) !== 0) {
    throw new Error("N must be power of 2");
  }
  if (N > MAX_VALUE / 128 / r) {
    throw new Error("N too large");
  }
  if (r > MAX_VALUE / 128 / p) {
    throw new Error("r too large");
  }
  if (!checkBufferish(password)) {
    throw new Error("password must be an array or buffer");
  }
  password = Array.prototype.slice.call(password);
  if (!checkBufferish(salt)) {
    throw new Error("salt must be an array or buffer");
  }
  salt = Array.prototype.slice.call(salt);
  let b = PBKDF2_HMAC_SHA256_OneIter(password, salt, p * 128 * r);
  const B = new Uint32Array(p * 32 * r);
  for (let i = 0; i < B.length; i++) {
    const j = i * 4;
    B[i] = (b[j + 3] & 255) << 24 | (b[j + 2] & 255) << 16 | (b[j + 1] & 255) << 8 | (b[j + 0] & 255) << 0;
  }
  const XY = new Uint32Array(64 * r);
  const V = new Uint32Array(32 * r * N);
  const Yi = 32 * r;
  const x = new Uint32Array(16);
  const _X = new Uint32Array(16);
  const totalOps = p * N * 2;
  let currentOp = 0;
  let lastPercent10 = null;
  let stop = false;
  let state = 0;
  let i0 = 0, i1;
  let Bi;
  const limit = callback ? parseInt(1e3 / r) : 4294967295;
  const nextTick = typeof setImmediate !== "undefined" ? setImmediate : setTimeout;
  const incrementalSMix = function() {
    if (stop) {
      return callback(new Error("cancelled"), currentOp / totalOps);
    }
    let steps;
    switch (state) {
      case 0:
        Bi = i0 * 32 * r;
        arraycopy(B, Bi, XY, 0, Yi);
        state = 1;
        i1 = 0;
      case 1:
        steps = N - i1;
        if (steps > limit) {
          steps = limit;
        }
        for (let i = 0; i < steps; i++) {
          arraycopy(XY, 0, V, (i1 + i) * Yi, Yi);
          blockmix_salsa8(XY, Yi, r, x, _X);
        }
        i1 += steps;
        currentOp += steps;
        if (callback) {
          const percent10 = parseInt(1e3 * currentOp / totalOps);
          if (percent10 !== lastPercent10) {
            stop = callback(null, currentOp / totalOps);
            if (stop) {
              break;
            }
            lastPercent10 = percent10;
          }
        }
        if (i1 < N) {
          break;
        }
        i1 = 0;
        state = 2;
      case 2:
        steps = N - i1;
        if (steps > limit) {
          steps = limit;
        }
        for (let i = 0; i < steps; i++) {
          const offset = (2 * r - 1) * 16;
          const j = XY[offset] & N - 1;
          blockxor(V, j * Yi, XY, Yi);
          blockmix_salsa8(XY, Yi, r, x, _X);
        }
        i1 += steps;
        currentOp += steps;
        if (callback) {
          const percent10 = parseInt(1e3 * currentOp / totalOps);
          if (percent10 !== lastPercent10) {
            stop = callback(null, currentOp / totalOps);
            if (stop) {
              break;
            }
            lastPercent10 = percent10;
          }
        }
        if (i1 < N) {
          break;
        }
        arraycopy(XY, 0, B, Bi, Yi);
        i0++;
        if (i0 < p) {
          state = 0;
          break;
        }
        b = [];
        for (let i = 0; i < B.length; i++) {
          b.push(B[i] >> 0 & 255);
          b.push(B[i] >> 8 & 255);
          b.push(B[i] >> 16 & 255);
          b.push(B[i] >> 24 & 255);
        }
        const derivedKey = PBKDF2_HMAC_SHA256_OneIter(password, b, dkLen);
        if (callback) {
          callback(null, 1, derivedKey);
        }
        return derivedKey;
    }
    if (callback) {
      nextTick(incrementalSMix);
    }
  };
  if (!callback) {
    while (true) {
      const derivedKey = incrementalSMix();
      if (derivedKey != void 0) {
        ret.hash = Buffer.from(derivedKey).toString("hex");
        return ret;
      }
    }
  }
  incrementalSMix();
};

// ../_tools_/src/Giselle.js
import { Add as Add2, Multiply as Multiply2, Power as Power2, Greater as Greater2, RangedOperation } from "@yaronkoresh/math";

// ../_tools_/src/Unicode.js
import { Multiply, Power, Add, Greater } from "@yaronkoresh/math";
var StringToBytes = function(str) {
  let e = new TextEncoder();
  let arr = e.encode(str);
  return [...arr];
};
var BytesToString = function(...bytes) {
  bytes = [bytes].flat().flat();
  bytes = new Uint8Array(bytes);
  let d = new TextDecoder();
  return d.decode(bytes);
};

// ../_tools_/src/Giselle.js
import { Bases as Bases2 } from "@yaronkoresh/bases";

// ../_tools_/src/Xor.js
var XorBinaryString = function(a, b) {
  a = a.split("");
  b = b.split("");
  let res = "";
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    res += (+(a[i] ?? 0) ^ +(b[i] ?? 0)).toString();
  }
  return res;
};

// ../_tools_/src/Giselle.js
import { Pad, Unpad } from "scrypt-padding";
var Encrypt = function(key, msg, power = 1) {
  power = Greater2(power, 1);
  power = power === true ? 1 : power;
  let loopPower = Greater2(RangedOperation(Power2(100, power - 1), 10, 10), 1);
  loopPower = loopPower === true ? 1 : loopPower;
  let pad = Pad(msg);
  let bytes = StringToBytes(pad);
  let bins = bytes.map((byte) => Bases2(byte, "01", 11, ""));
  let bin = bins.map((b) => Zeros(b, 8)).join("");
  let salt = GenerateRandomBinary(bin.length);
  let bin2 = XorBinaryString(salt, bin);
  for (let i = "0"; Greater2(i, loopPower) !== i.toString(); i = Add2(i, 1)) {
    key = ExpandKey(key, bin.length, power);
    bin2 = XorBinaryString(key, bin2);
  }
  let out64 = Split(bin2, 4);
  out64 = out64.map((b) => Bases2(b, "01", 10, ""));
  out64 = out64.map((b) => Bases2(b, base64, 11, ""));
  out64 = out64.join("");
  let salt64 = Split(salt, 4);
  salt64 = salt64.map((b) => Bases2(b, "01", 10, ""));
  salt64 = salt64.map((b) => Bases2(b, base64, 11, ""));
  salt64 = salt64.join("");
  return [out64, salt64].join(":");
};
var Decrypt = function(key, ciphertext, power = 1) {
  power = Greater2(power, 1);
  power = power === true ? 1 : power;
  let loopPower = Greater2(RangedOperation(Power2(100, power - 1), 10, 10), 1);
  loopPower = loopPower === true ? 1 : loopPower;
  let in64 = ciphertext.split(":")[0];
  let salt64 = ciphertext.split(":")[1];
  let salt = salt64.split("");
  salt = salt.map((b) => Bases2(b, base64, 10, ""));
  salt = salt.map((b) => Bases2(b, "01", 11, ""));
  salt = salt.map((b) => Zeros(b, 4));
  salt = salt.join("");
  let bin2 = in64.split("");
  bin2 = bin2.map((b) => Bases2(b, base64, 10, ""));
  bin2 = bin2.map((b) => Bases2(b, "01", 11, ""));
  bin2 = bin2.map((b) => Zeros(b, 4));
  bin2 = bin2.join("");
  for (let i = "0"; Greater2(i, loopPower) !== i.toString(); i = Add2(i, 1)) {
    key = ExpandKey(key, salt.length, power);
    bin2 = XorBinaryString(key, bin2);
  }
  let bin = XorBinaryString(salt, bin2);
  let bins = Split(bin, 8);
  let bytes = bins.map((b) => Bases2(b, "01", 10, ""));
  let pad = BytesToString(...bytes);
  let msg = Unpad(pad);
  return msg;
};
var ExpandKey = function(key, bits, power) {
  let bytes = parseInt(bits) / 8;
  key = Scrypt(key, key, bytes, Math.floor(power, 4)).hash.toString();
  key = Split(key, 1);
  key = key.map((hx) => Bases2(hx, hex, 10, ""));
  key = key.map((num) => Bases2(num, "01", 11, ""));
  key = key.map((b) => Zeros(b, 4));
  key = key.join("");
  return key;
};

// ../_tools_/src/SecureRandom.js
function Generate(arr) {
  let bytes = new Uint8Array(arr.length);
  crypto.getRandomValues(bytes);
  for (let i = 0; i < bytes.length; i++) {
    arr[i] = bytes[i];
  }
}
function SecureRandom() {
}
SecureRandom.prototype.nextBytes = Generate;

// ../_tools_/src/BigInteger.js
var dbits;
var canary = 244837814094590;
var j_lm = (canary & 16777215) == 15715070;
function BigInteger(a, b, c = new SecureRandom()) {
  if (a != null)
    if ("number" == typeof a)
      this.fromNumber(a, b, c);
    else if (b == null && "string" != typeof a)
      this.fromString(a, 256);
    else
      this.fromString(a, b);
}
function nbi() {
  return new BigInteger(null);
}
function am1(i, x, w, j, c, n) {
  while (--n >= 0) {
    var v = x * this[i++] + w[j] + c;
    c = Math.floor(v / 67108864);
    w[j++] = v & 67108863;
  }
  return c;
}
function am2(i, x, w, j, c, n) {
  var xl = x & 32767, xh = x >> 15;
  while (--n >= 0) {
    var l = this[i] & 32767;
    var h = this[i++] >> 15;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 32767) << 15) + w[j] + (c & 1073741823);
    c = (l >>> 30) + (m >>> 15) + xh * h + (c >>> 30);
    w[j++] = l & 1073741823;
  }
  return c;
}
function am3(i, x, w, j, c, n) {
  var xl = x & 16383, xh = x >> 14;
  while (--n >= 0) {
    var l = this[i] & 16383;
    var h = this[i++] >> 14;
    var m = xh * l + h * xl;
    l = xl * l + ((m & 16383) << 14) + w[j] + c;
    c = (l >> 28) + (m >> 14) + xh * h;
    w[j++] = l & 268435455;
  }
  return c;
}
if (typeof navigator == "undefined") {
  BigInteger.prototype.am = am3;
  dbits = 28;
} else if (j_lm && navigator && navigator.appName == "Microsoft Internet Explorer") {
  BigInteger.prototype.am = am2;
  dbits = 30;
} else if (j_lm && navigator && navigator.appName != "Netscape") {
  BigInteger.prototype.am = am1;
  dbits = 26;
} else {
  BigInteger.prototype.am = am3;
  dbits = 28;
}
BigInteger.prototype.DB = dbits;
BigInteger.prototype.DM = (1 << dbits) - 1;
BigInteger.prototype.DV = 1 << dbits;
var BI_FP = 52;
BigInteger.prototype.FV = Math.pow(2, BI_FP);
BigInteger.prototype.F1 = BI_FP - dbits;
BigInteger.prototype.F2 = 2 * dbits - BI_FP;
var BI_RM = "0123456789abcdefghijklmnopqrstuvwxyz";
var BI_RC = new Array();
var rr;
var vv;
rr = "0".charCodeAt(0);
for (vv = 0; vv <= 9; ++vv)
  BI_RC[rr++] = vv;
rr = "a".charCodeAt(0);
for (vv = 10; vv < 36; ++vv)
  BI_RC[rr++] = vv;
rr = "A".charCodeAt(0);
for (vv = 10; vv < 36; ++vv)
  BI_RC[rr++] = vv;
function int2char(n) {
  return BI_RM.charAt(n);
}
function intAt(s, i) {
  var c = BI_RC[s.charCodeAt(i)];
  return c == null ? -1 : c;
}
function bnpCopyTo(r) {
  for (var i = this.t - 1; i >= 0; --i)
    r[i] = this[i];
  r.t = this.t;
  r.s = this.s;
}
function bnpFromInt(x) {
  this.t = 1;
  this.s = x < 0 ? -1 : 0;
  if (x > 0)
    this[0] = x;
  else if (x < -1)
    this[0] = x + this.DV;
  else
    this.t = 0;
}
function nbv(i) {
  var r = nbi();
  r.fromInt(i);
  return r;
}
function bnpFromString(s, b) {
  var k;
  if (b == 16)
    k = 4;
  else if (b == 8)
    k = 3;
  else if (b == 256)
    k = 8;
  else if (b == 2)
    k = 1;
  else if (b == 32)
    k = 5;
  else if (b == 4)
    k = 2;
  else {
    this.fromRadix(s, b);
    return;
  }
  this.t = 0;
  this.s = 0;
  var i = s.length, mi = false, sh = 0;
  while (--i >= 0) {
    var x = k == 8 ? s[i] & 255 : intAt(s, i);
    if (x < 0) {
      if (s.charAt(i) == "-")
        mi = true;
      continue;
    }
    mi = false;
    if (sh == 0)
      this[this.t++] = x;
    else if (sh + k > this.DB) {
      this[this.t - 1] |= (x & (1 << this.DB - sh) - 1) << sh;
      this[this.t++] = x >> this.DB - sh;
    } else
      this[this.t - 1] |= x << sh;
    sh += k;
    if (sh >= this.DB)
      sh -= this.DB;
  }
  if (k == 8 && (s[0] & 128) != 0) {
    this.s = -1;
    if (sh > 0)
      this[this.t - 1] |= (1 << this.DB - sh) - 1 << sh;
  }
  this.clamp();
  if (mi)
    BigInteger.ZERO.subTo(this, this);
}
function bnpClamp() {
  var c = this.s & this.DM;
  while (this.t > 0 && this[this.t - 1] == c)
    --this.t;
}
function bnToString(b) {
  if (this.s < 0)
    return "-" + this.negate().toString(b);
  var k;
  if (b == 16)
    k = 4;
  else if (b == 8)
    k = 3;
  else if (b == 2)
    k = 1;
  else if (b == 32)
    k = 5;
  else if (b == 4)
    k = 2;
  else
    return this.toRadix(b);
  var km = (1 << k) - 1, d, m = false, r = "", i = this.t;
  var p = this.DB - i * this.DB % k;
  if (i-- > 0) {
    if (p < this.DB && (d = this[i] >> p) > 0) {
      m = true;
      r = int2char(d);
    }
    while (i >= 0) {
      if (p < k) {
        d = (this[i] & (1 << p) - 1) << k - p;
        d |= this[--i] >> (p += this.DB - k);
      } else {
        d = this[i] >> (p -= k) & km;
        if (p <= 0) {
          p += this.DB;
          --i;
        }
      }
      if (d > 0)
        m = true;
      if (m)
        r += int2char(d);
    }
  }
  return m ? r : "0";
}
function bnNegate() {
  var r = nbi();
  BigInteger.ZERO.subTo(this, r);
  return r;
}
function bnAbs() {
  return this.s < 0 ? this.negate() : this;
}
function bnCompareTo(a) {
  var r = this.s - a.s;
  if (r != 0)
    return r;
  var i = this.t;
  r = i - a.t;
  if (r != 0)
    return this.s < 0 ? -r : r;
  while (--i >= 0)
    if ((r = this[i] - a[i]) != 0)
      return r;
  return 0;
}
function nbits(x) {
  var r = 1, t;
  if ((t = x >>> 16) != 0) {
    x = t;
    r += 16;
  }
  if ((t = x >> 8) != 0) {
    x = t;
    r += 8;
  }
  if ((t = x >> 4) != 0) {
    x = t;
    r += 4;
  }
  if ((t = x >> 2) != 0) {
    x = t;
    r += 2;
  }
  if ((t = x >> 1) != 0) {
    x = t;
    r += 1;
  }
  return r;
}
function bnBitLength() {
  if (this.t <= 0)
    return 0;
  return this.DB * (this.t - 1) + nbits(this[this.t - 1] ^ this.s & this.DM);
}
function bnpDLShiftTo(n, r) {
  var i;
  for (i = this.t - 1; i >= 0; --i)
    r[i + n] = this[i];
  for (i = n - 1; i >= 0; --i)
    r[i] = 0;
  r.t = this.t + n;
  r.s = this.s;
}
function bnpDRShiftTo(n, r) {
  for (var i = n; i < this.t; ++i)
    r[i - n] = this[i];
  r.t = Math.max(this.t - n, 0);
  r.s = this.s;
}
function bnpLShiftTo(n, r) {
  var bs = n % this.DB;
  var cbs = this.DB - bs;
  var bm = (1 << cbs) - 1;
  var ds = Math.floor(n / this.DB), c = this.s << bs & this.DM, i;
  for (i = this.t - 1; i >= 0; --i) {
    r[i + ds + 1] = this[i] >> cbs | c;
    c = (this[i] & bm) << bs;
  }
  for (i = ds - 1; i >= 0; --i)
    r[i] = 0;
  r[ds] = c;
  r.t = this.t + ds + 1;
  r.s = this.s;
  r.clamp();
}
function bnpRShiftTo(n, r) {
  r.s = this.s;
  var ds = Math.floor(n / this.DB);
  if (ds >= this.t) {
    r.t = 0;
    return;
  }
  var bs = n % this.DB;
  var cbs = this.DB - bs;
  var bm = (1 << bs) - 1;
  r[0] = this[ds] >> bs;
  for (var i = ds + 1; i < this.t; ++i) {
    r[i - ds - 1] |= (this[i] & bm) << cbs;
    r[i - ds] = this[i] >> bs;
  }
  if (bs > 0)
    r[this.t - ds - 1] |= (this.s & bm) << cbs;
  r.t = this.t - ds;
  r.clamp();
}
function bnpSubTo(a, r) {
  var i = 0, c = 0, m = Math.min(a.t, this.t);
  while (i < m) {
    c += this[i] - a[i];
    r[i++] = c & this.DM;
    c >>= this.DB;
  }
  if (a.t < this.t) {
    c -= a.s;
    while (i < this.t) {
      c += this[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += this.s;
  } else {
    c += this.s;
    while (i < a.t) {
      c -= a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c -= a.s;
  }
  r.s = c < 0 ? -1 : 0;
  if (c < -1)
    r[i++] = this.DV + c;
  else if (c > 0)
    r[i++] = c;
  r.t = i;
  r.clamp();
}
function bnpMultiplyTo(a, r) {
  var x = this.abs(), y = a.abs();
  var i = x.t;
  r.t = i + y.t;
  while (--i >= 0)
    r[i] = 0;
  for (i = 0; i < y.t; ++i)
    r[i + x.t] = x.am(0, y[i], r, i, 0, x.t);
  r.s = 0;
  r.clamp();
  if (this.s != a.s)
    BigInteger.ZERO.subTo(r, r);
}
function bnpSquareTo(r) {
  var x = this.abs();
  var i = r.t = 2 * x.t;
  while (--i >= 0)
    r[i] = 0;
  for (i = 0; i < x.t - 1; ++i) {
    var c = x.am(i, x[i], r, 2 * i, 0, 1);
    if ((r[i + x.t] += x.am(i + 1, 2 * x[i], r, 2 * i + 1, c, x.t - i - 1)) >= x.DV) {
      r[i + x.t] -= x.DV;
      r[i + x.t + 1] = 1;
    }
  }
  if (r.t > 0)
    r[r.t - 1] += x.am(i, x[i], r, 2 * i, 0, 1);
  r.s = 0;
  r.clamp();
}
function bnpDivRemTo(m, q, r) {
  var pm = m.abs();
  if (pm.t <= 0)
    return;
  var pt = this.abs();
  if (pt.t < pm.t) {
    if (q != null)
      q.fromInt(0);
    if (r != null)
      this.copyTo(r);
    return;
  }
  if (r == null)
    r = nbi();
  var y = nbi(), ts = this.s, ms = m.s;
  var nsh = this.DB - nbits(pm[pm.t - 1]);
  if (nsh > 0) {
    pm.lShiftTo(nsh, y);
    pt.lShiftTo(nsh, r);
  } else {
    pm.copyTo(y);
    pt.copyTo(r);
  }
  var ys = y.t;
  var y0 = y[ys - 1];
  if (y0 == 0)
    return;
  var yt = y0 * (1 << this.F1) + (ys > 1 ? y[ys - 2] >> this.F2 : 0);
  var d1 = this.FV / yt, d2 = (1 << this.F1) / yt, e = 1 << this.F2;
  var i = r.t, j = i - ys, t = q == null ? nbi() : q;
  y.dlShiftTo(j, t);
  if (r.compareTo(t) >= 0) {
    r[r.t++] = 1;
    r.subTo(t, r);
  }
  BigInteger.ONE.dlShiftTo(ys, t);
  t.subTo(y, y);
  while (y.t < ys)
    y[y.t++] = 0;
  while (--j >= 0) {
    var qd = r[--i] == y0 ? this.DM : Math.floor(r[i] * d1 + (r[i - 1] + e) * d2);
    if ((r[i] += y.am(0, qd, r, j, 0, ys)) < qd) {
      y.dlShiftTo(j, t);
      r.subTo(t, r);
      while (r[i] < --qd)
        r.subTo(t, r);
    }
  }
  if (q != null) {
    r.drShiftTo(ys, q);
    if (ts != ms)
      BigInteger.ZERO.subTo(q, q);
  }
  r.t = ys;
  r.clamp();
  if (nsh > 0)
    r.rShiftTo(nsh, r);
  if (ts < 0)
    BigInteger.ZERO.subTo(r, r);
}
function bnMod(a) {
  var r = nbi();
  this.abs().divRemTo(a, null, r);
  if (this.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
    a.subTo(r, r);
  return r;
}
function Classic(m) {
  this.m = m;
}
function cConvert(x) {
  if (x.s < 0 || x.compareTo(this.m) >= 0)
    return x.mod(this.m);
  else
    return x;
}
function cRevert(x) {
  return x;
}
function cReduce(x) {
  x.divRemTo(this.m, null, x);
}
function cMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}
function cSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}
Classic.prototype.convert = cConvert;
Classic.prototype.revert = cRevert;
Classic.prototype.reduce = cReduce;
Classic.prototype.mulTo = cMulTo;
Classic.prototype.sqrTo = cSqrTo;
function bnpInvDigit() {
  if (this.t < 1)
    return 0;
  var x = this[0];
  if ((x & 1) == 0)
    return 0;
  var y = x & 3;
  y = y * (2 - (x & 15) * y) & 15;
  y = y * (2 - (x & 255) * y) & 255;
  y = y * (2 - ((x & 65535) * y & 65535)) & 65535;
  y = y * (2 - x * y % this.DV) % this.DV;
  return y > 0 ? this.DV - y : -y;
}
function Montgomery(m) {
  this.m = m;
  this.mp = m.invDigit();
  this.mpl = this.mp & 32767;
  this.mph = this.mp >> 15;
  this.um = (1 << m.DB - 15) - 1;
  this.mt2 = 2 * m.t;
}
function montConvert(x) {
  var r = nbi();
  x.abs().dlShiftTo(this.m.t, r);
  r.divRemTo(this.m, null, r);
  if (x.s < 0 && r.compareTo(BigInteger.ZERO) > 0)
    this.m.subTo(r, r);
  return r;
}
function montRevert(x) {
  var r = nbi();
  x.copyTo(r);
  this.reduce(r);
  return r;
}
function montReduce(x) {
  while (x.t <= this.mt2)
    x[x.t++] = 0;
  for (var i = 0; i < this.m.t; ++i) {
    var j = x[i] & 32767;
    var u0 = j * this.mpl + ((j * this.mph + (x[i] >> 15) * this.mpl & this.um) << 15) & x.DM;
    j = i + this.m.t;
    x[j] += this.m.am(0, u0, x, i, 0, this.m.t);
    while (x[j] >= x.DV) {
      x[j] -= x.DV;
      x[++j]++;
    }
  }
  x.clamp();
  x.drShiftTo(this.m.t, x);
  if (x.compareTo(this.m) >= 0)
    x.subTo(this.m, x);
}
function montSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}
function montMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}
Montgomery.prototype.convert = montConvert;
Montgomery.prototype.revert = montRevert;
Montgomery.prototype.reduce = montReduce;
Montgomery.prototype.mulTo = montMulTo;
Montgomery.prototype.sqrTo = montSqrTo;
function bnpIsEven() {
  return (this.t > 0 ? this[0] & 1 : this.s) == 0;
}
function bnpExp(e, z) {
  if (e > 4294967295 || e < 1)
    return BigInteger.ONE;
  var r = nbi(), r2 = nbi(), g = z.convert(this), i = nbits(e) - 1;
  g.copyTo(r);
  while (--i >= 0) {
    z.sqrTo(r, r2);
    if ((e & 1 << i) > 0)
      z.mulTo(r2, g, r);
    else {
      var t = r;
      r = r2;
      r2 = t;
    }
  }
  return z.revert(r);
}
function bnModPowInt(e, m) {
  var z;
  if (e < 256 || m.isEven())
    z = new Classic(m);
  else
    z = new Montgomery(m);
  return this.exp(e, z);
}
BigInteger.prototype.copyTo = bnpCopyTo;
BigInteger.prototype.fromInt = bnpFromInt;
BigInteger.prototype.fromString = bnpFromString;
BigInteger.prototype.clamp = bnpClamp;
BigInteger.prototype.dlShiftTo = bnpDLShiftTo;
BigInteger.prototype.drShiftTo = bnpDRShiftTo;
BigInteger.prototype.lShiftTo = bnpLShiftTo;
BigInteger.prototype.rShiftTo = bnpRShiftTo;
BigInteger.prototype.subTo = bnpSubTo;
BigInteger.prototype.multiplyTo = bnpMultiplyTo;
BigInteger.prototype.squareTo = bnpSquareTo;
BigInteger.prototype.divRemTo = bnpDivRemTo;
BigInteger.prototype.invDigit = bnpInvDigit;
BigInteger.prototype.isEven = bnpIsEven;
BigInteger.prototype.exp = bnpExp;
BigInteger.prototype.toString = bnToString;
BigInteger.prototype.negate = bnNegate;
BigInteger.prototype.abs = bnAbs;
BigInteger.prototype.compareTo = bnCompareTo;
BigInteger.prototype.bitLength = bnBitLength;
BigInteger.prototype.mod = bnMod;
BigInteger.prototype.modPowInt = bnModPowInt;
BigInteger.ZERO = nbv(0);
BigInteger.ONE = nbv(1);
function bnClone() {
  var r = nbi();
  this.copyTo(r);
  return r;
}
function bnIntValue() {
  if (this.s < 0) {
    if (this.t == 1)
      return this[0] - this.DV;
    else if (this.t == 0)
      return -1;
  } else if (this.t == 1)
    return this[0];
  else if (this.t == 0)
    return 0;
  return (this[1] & (1 << 32 - this.DB) - 1) << this.DB | this[0];
}
function bnByteValue() {
  return this.t == 0 ? this.s : this[0] << 24 >> 24;
}
function bnShortValue() {
  return this.t == 0 ? this.s : this[0] << 16 >> 16;
}
function bnpChunkSize(r) {
  return Math.floor(Math.LN2 * this.DB / Math.log(r));
}
function bnSigNum() {
  if (this.s < 0)
    return -1;
  else if (this.t <= 0 || this.t == 1 && this[0] <= 0)
    return 0;
  else
    return 1;
}
function bnpToRadix(b) {
  if (b == null)
    b = 10;
  if (this.signum() == 0 || b < 2 || b > 36)
    return "0";
  var cs = this.chunkSize(b);
  var a = Math.pow(b, cs);
  var d = nbv(a), y = nbi(), z = nbi(), r = "";
  this.divRemTo(d, y, z);
  while (y.signum() > 0) {
    r = (a + z.intValue()).toString(b).substr(1) + r;
    y.divRemTo(d, y, z);
  }
  return z.intValue().toString(b) + r;
}
function bnpFromRadix(s, b) {
  this.fromInt(0);
  if (b == null)
    b = 10;
  var cs = this.chunkSize(b);
  var d = Math.pow(b, cs), mi = false, j = 0, w = 0;
  for (var i = 0; i < s.length; ++i) {
    var x = intAt(s, i);
    if (x < 0) {
      if (s.charAt(i) == "-" && this.signum() == 0)
        mi = true;
      continue;
    }
    w = b * w + x;
    if (++j >= cs) {
      this.dMultiply(d);
      this.dAddOffset(w, 0);
      j = 0;
      w = 0;
    }
  }
  if (j > 0) {
    this.dMultiply(Math.pow(b, j));
    this.dAddOffset(w, 0);
  }
  if (mi)
    BigInteger.ZERO.subTo(this, this);
}
function bnpFromNumber(a, b, c) {
  if ("number" == typeof b) {
    if (a < 2)
      this.fromInt(1);
    else {
      this.fromNumber(a, c);
      if (!this.testBit(a - 1))
        this.bitwiseTo(BigInteger.ONE.shiftLeft(a - 1), op_or, this);
      if (this.isEven())
        this.dAddOffset(1, 0);
      while (!this.isProbablePrime(b)) {
        this.dAddOffset(2, 0);
        if (this.bitLength() > a)
          this.subTo(BigInteger.ONE.shiftLeft(a - 1), this);
      }
    }
  } else {
    var x = new Array(), t = a & 7;
    x.length = (a >> 3) + 1;
    b.nextBytes(x);
    if (t > 0)
      x[0] &= (1 << t) - 1;
    else
      x[0] = 0;
    this.fromString(x, 256);
  }
}
function bnToByteArray() {
  var i = this.t, r = new Array();
  r[0] = this.s;
  var p = this.DB - i * this.DB % 8, d, k = 0;
  if (i-- > 0) {
    if (p < this.DB && (d = this[i] >> p) != (this.s & this.DM) >> p)
      r[k++] = d | this.s << this.DB - p;
    while (i >= 0) {
      if (p < 8) {
        d = (this[i] & (1 << p) - 1) << 8 - p;
        d |= this[--i] >> (p += this.DB - 8);
      } else {
        d = this[i] >> (p -= 8) & 255;
        if (p <= 0) {
          p += this.DB;
          --i;
        }
      }
      if ((d & 128) != 0)
        d |= -256;
      if (k == 0 && (this.s & 128) != (d & 128))
        ++k;
      if (k > 0 || d != this.s)
        r[k++] = d;
    }
  }
  return r;
}
function bnEquals(a) {
  return this.compareTo(a) == 0;
}
function bnMin(a) {
  return this.compareTo(a) < 0 ? this : a;
}
function bnMax(a) {
  return this.compareTo(a) > 0 ? this : a;
}
function bnpBitwiseTo(a, op, r) {
  var i, f, m = Math.min(a.t, this.t);
  for (i = 0; i < m; ++i)
    r[i] = op(this[i], a[i]);
  if (a.t < this.t) {
    f = a.s & this.DM;
    for (i = m; i < this.t; ++i)
      r[i] = op(this[i], f);
    r.t = this.t;
  } else {
    f = this.s & this.DM;
    for (i = m; i < a.t; ++i)
      r[i] = op(f, a[i]);
    r.t = a.t;
  }
  r.s = op(this.s, a.s);
  r.clamp();
}
function op_and(x, y) {
  return x & y;
}
function bnAnd(a) {
  var r = nbi();
  this.bitwiseTo(a, op_and, r);
  return r;
}
function op_or(x, y) {
  return x | y;
}
function bnOr(a) {
  var r = nbi();
  this.bitwiseTo(a, op_or, r);
  return r;
}
function op_xor(x, y) {
  return x ^ y;
}
function bnXor(a) {
  var r = nbi();
  this.bitwiseTo(a, op_xor, r);
  return r;
}
function op_andnot(x, y) {
  return x & ~y;
}
function bnAndNot(a) {
  var r = nbi();
  this.bitwiseTo(a, op_andnot, r);
  return r;
}
function bnNot() {
  var r = nbi();
  for (var i = 0; i < this.t; ++i)
    r[i] = this.DM & ~this[i];
  r.t = this.t;
  r.s = ~this.s;
  return r;
}
function bnShiftLeft(n) {
  var r = nbi();
  if (n < 0)
    this.rShiftTo(-n, r);
  else
    this.lShiftTo(n, r);
  return r;
}
function bnShiftRight(n) {
  var r = nbi();
  if (n < 0)
    this.lShiftTo(-n, r);
  else
    this.rShiftTo(n, r);
  return r;
}
function lbit(x) {
  if (x == 0)
    return -1;
  var r = 0;
  if ((x & 65535) == 0) {
    x >>= 16;
    r += 16;
  }
  if ((x & 255) == 0) {
    x >>= 8;
    r += 8;
  }
  if ((x & 15) == 0) {
    x >>= 4;
    r += 4;
  }
  if ((x & 3) == 0) {
    x >>= 2;
    r += 2;
  }
  if ((x & 1) == 0)
    ++r;
  return r;
}
function bnGetLowestSetBit() {
  for (var i = 0; i < this.t; ++i)
    if (this[i] != 0)
      return i * this.DB + lbit(this[i]);
  if (this.s < 0)
    return this.t * this.DB;
  return -1;
}
function cbit(x) {
  var r = 0;
  while (x != 0) {
    x &= x - 1;
    ++r;
  }
  return r;
}
function bnBitCount() {
  var r = 0, x = this.s & this.DM;
  for (var i = 0; i < this.t; ++i)
    r += cbit(this[i] ^ x);
  return r;
}
function bnTestBit(n) {
  var j = Math.floor(n / this.DB);
  if (j >= this.t)
    return this.s != 0;
  return (this[j] & 1 << n % this.DB) != 0;
}
function bnpChangeBit(n, op) {
  var r = BigInteger.ONE.shiftLeft(n);
  this.bitwiseTo(r, op, r);
  return r;
}
function bnSetBit(n) {
  return this.changeBit(n, op_or);
}
function bnClearBit(n) {
  return this.changeBit(n, op_andnot);
}
function bnFlipBit(n) {
  return this.changeBit(n, op_xor);
}
function bnpAddTo(a, r) {
  var i = 0, c = 0, m = Math.min(a.t, this.t);
  while (i < m) {
    c += this[i] + a[i];
    r[i++] = c & this.DM;
    c >>= this.DB;
  }
  if (a.t < this.t) {
    c += a.s;
    while (i < this.t) {
      c += this[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += this.s;
  } else {
    c += this.s;
    while (i < a.t) {
      c += a[i];
      r[i++] = c & this.DM;
      c >>= this.DB;
    }
    c += a.s;
  }
  r.s = c < 0 ? -1 : 0;
  if (c > 0)
    r[i++] = c;
  else if (c < -1)
    r[i++] = this.DV + c;
  r.t = i;
  r.clamp();
}
function bnAdd(a) {
  var r = nbi();
  this.addTo(a, r);
  return r;
}
function bnSubtract(a) {
  var r = nbi();
  this.subTo(a, r);
  return r;
}
function bnMultiply(a) {
  var r = nbi();
  this.multiplyTo(a, r);
  return r;
}
function bnSquare() {
  var r = nbi();
  this.squareTo(r);
  return r;
}
function bnDivide(a) {
  var r = nbi();
  this.divRemTo(a, r, null);
  return r;
}
function bnRemainder(a) {
  var r = nbi();
  this.divRemTo(a, null, r);
  return r;
}
function bnDivideAndRemainder(a) {
  var q = nbi(), r = nbi();
  this.divRemTo(a, q, r);
  return new Array(q, r);
}
function bnpDMultiply(n) {
  this[this.t] = this.am(0, n - 1, this, 0, 0, this.t);
  ++this.t;
  this.clamp();
}
function bnpDAddOffset(n, w) {
  if (n == 0)
    return;
  while (this.t <= w)
    this[this.t++] = 0;
  this[w] += n;
  while (this[w] >= this.DV) {
    this[w] -= this.DV;
    if (++w >= this.t)
      this[this.t++] = 0;
    ++this[w];
  }
}
function NullExp() {
}
function nNop(x) {
  return x;
}
function nMulTo(x, y, r) {
  x.multiplyTo(y, r);
}
function nSqrTo(x, r) {
  x.squareTo(r);
}
NullExp.prototype.convert = nNop;
NullExp.prototype.revert = nNop;
NullExp.prototype.mulTo = nMulTo;
NullExp.prototype.sqrTo = nSqrTo;
function bnPow(e) {
  return this.exp(e, new NullExp());
}
function bnpMultiplyLowerTo(a, n, r) {
  var i = Math.min(this.t + a.t, n);
  r.s = 0;
  r.t = i;
  while (i > 0)
    r[--i] = 0;
  var j;
  for (j = r.t - this.t; i < j; ++i)
    r[i + this.t] = this.am(0, a[i], r, i, 0, this.t);
  for (j = Math.min(a.t, n); i < j; ++i)
    this.am(0, a[i], r, i, 0, n - i);
  r.clamp();
}
function bnpMultiplyUpperTo(a, n, r) {
  --n;
  var i = r.t = this.t + a.t - n;
  r.s = 0;
  while (--i >= 0)
    r[i] = 0;
  for (i = Math.max(n - this.t, 0); i < a.t; ++i)
    r[this.t + i - n] = this.am(n - i, a[i], r, 0, 0, this.t + i - n);
  r.clamp();
  r.drShiftTo(1, r);
}
function Barrett(m) {
  this.r2 = nbi();
  this.q3 = nbi();
  BigInteger.ONE.dlShiftTo(2 * m.t, this.r2);
  this.mu = this.r2.divide(m);
  this.m = m;
}
function barrettConvert(x) {
  if (x.s < 0 || x.t > 2 * this.m.t)
    return x.mod(this.m);
  else if (x.compareTo(this.m) < 0)
    return x;
  else {
    var r = nbi();
    x.copyTo(r);
    this.reduce(r);
    return r;
  }
}
function barrettRevert(x) {
  return x;
}
function barrettReduce(x) {
  x.drShiftTo(this.m.t - 1, this.r2);
  if (x.t > this.m.t + 1) {
    x.t = this.m.t + 1;
    x.clamp();
  }
  this.mu.multiplyUpperTo(this.r2, this.m.t + 1, this.q3);
  this.m.multiplyLowerTo(this.q3, this.m.t + 1, this.r2);
  while (x.compareTo(this.r2) < 0)
    x.dAddOffset(1, this.m.t + 1);
  x.subTo(this.r2, x);
  while (x.compareTo(this.m) >= 0)
    x.subTo(this.m, x);
}
function barrettSqrTo(x, r) {
  x.squareTo(r);
  this.reduce(r);
}
function barrettMulTo(x, y, r) {
  x.multiplyTo(y, r);
  this.reduce(r);
}
Barrett.prototype.convert = barrettConvert;
Barrett.prototype.revert = barrettRevert;
Barrett.prototype.reduce = barrettReduce;
Barrett.prototype.mulTo = barrettMulTo;
Barrett.prototype.sqrTo = barrettSqrTo;
function bnModPow(e, m) {
  var i = e.bitLength(), k, r = nbv(1), z;
  if (i <= 0)
    return r;
  else if (i < 18)
    k = 1;
  else if (i < 48)
    k = 3;
  else if (i < 144)
    k = 4;
  else if (i < 768)
    k = 5;
  else
    k = 6;
  if (i < 8)
    z = new Classic(m);
  else if (m.isEven())
    z = new Barrett(m);
  else
    z = new Montgomery(m);
  var g = new Array(), n = 3, k1 = k - 1, km = (1 << k) - 1;
  g[1] = z.convert(this);
  if (k > 1) {
    var g2 = nbi();
    z.sqrTo(g[1], g2);
    while (n <= km) {
      g[n] = nbi();
      z.mulTo(g2, g[n - 2], g[n]);
      n += 2;
    }
  }
  var j = e.t - 1, w, is1 = true, r2 = nbi(), t;
  i = nbits(e[j]) - 1;
  while (j >= 0) {
    if (i >= k1)
      w = e[j] >> i - k1 & km;
    else {
      w = (e[j] & (1 << i + 1) - 1) << k1 - i;
      if (j > 0)
        w |= e[j - 1] >> this.DB + i - k1;
    }
    n = k;
    while ((w & 1) == 0) {
      w >>= 1;
      --n;
    }
    if ((i -= n) < 0) {
      i += this.DB;
      --j;
    }
    if (is1) {
      g[w].copyTo(r);
      is1 = false;
    } else {
      while (n > 1) {
        z.sqrTo(r, r2);
        z.sqrTo(r2, r);
        n -= 2;
      }
      if (n > 0)
        z.sqrTo(r, r2);
      else {
        t = r;
        r = r2;
        r2 = t;
      }
      z.mulTo(r2, g[w], r);
    }
    while (j >= 0 && (e[j] & 1 << i) == 0) {
      z.sqrTo(r, r2);
      t = r;
      r = r2;
      r2 = t;
      if (--i < 0) {
        i = this.DB - 1;
        --j;
      }
    }
  }
  return z.revert(r);
}
function bnGCD(a) {
  var x = this.s < 0 ? this.negate() : this.clone();
  var y = a.s < 0 ? a.negate() : a.clone();
  if (x.compareTo(y) < 0) {
    var t = x;
    x = y;
    y = t;
  }
  var i = x.getLowestSetBit(), g = y.getLowestSetBit();
  if (g < 0)
    return x;
  if (i < g)
    g = i;
  if (g > 0) {
    x.rShiftTo(g, x);
    y.rShiftTo(g, y);
  }
  while (x.signum() > 0) {
    if ((i = x.getLowestSetBit()) > 0)
      x.rShiftTo(i, x);
    if ((i = y.getLowestSetBit()) > 0)
      y.rShiftTo(i, y);
    if (x.compareTo(y) >= 0) {
      x.subTo(y, x);
      x.rShiftTo(1, x);
    } else {
      y.subTo(x, y);
      y.rShiftTo(1, y);
    }
  }
  if (g > 0)
    y.lShiftTo(g, y);
  return y;
}
function bnpModInt(n) {
  if (n <= 0)
    return 0;
  var d = this.DV % n, r = this.s < 0 ? n - 1 : 0;
  if (this.t > 0)
    if (d == 0)
      r = this[0] % n;
    else
      for (var i = this.t - 1; i >= 0; --i)
        r = (d * r + this[i]) % n;
  return r;
}
function bnModInverse(m) {
  var ac = m.isEven();
  if (this.isEven() && ac || m.signum() == 0)
    return BigInteger.ZERO;
  var u = m.clone(), v = this.clone();
  var a = nbv(1), b = nbv(0), c = nbv(0), d = nbv(1);
  while (u.signum() != 0) {
    while (u.isEven()) {
      u.rShiftTo(1, u);
      if (ac) {
        if (!a.isEven() || !b.isEven()) {
          a.addTo(this, a);
          b.subTo(m, b);
        }
        a.rShiftTo(1, a);
      } else if (!b.isEven())
        b.subTo(m, b);
      b.rShiftTo(1, b);
    }
    while (v.isEven()) {
      v.rShiftTo(1, v);
      if (ac) {
        if (!c.isEven() || !d.isEven()) {
          c.addTo(this, c);
          d.subTo(m, d);
        }
        c.rShiftTo(1, c);
      } else if (!d.isEven())
        d.subTo(m, d);
      d.rShiftTo(1, d);
    }
    if (u.compareTo(v) >= 0) {
      u.subTo(v, u);
      if (ac)
        a.subTo(c, a);
      b.subTo(d, b);
    } else {
      v.subTo(u, v);
      if (ac)
        c.subTo(a, c);
      d.subTo(b, d);
    }
  }
  if (v.compareTo(BigInteger.ONE) != 0)
    return BigInteger.ZERO;
  if (d.compareTo(m) >= 0)
    return d.subtract(m);
  if (d.signum() < 0)
    d.addTo(m, d);
  else
    return d;
  if (d.signum() < 0)
    return d.add(m);
  else
    return d;
}
var lowprimes = [
  2,
  3,
  5,
  7,
  11,
  13,
  17,
  19,
  23,
  29,
  31,
  37,
  41,
  43,
  47,
  53,
  59,
  61,
  67,
  71,
  73,
  79,
  83,
  89,
  97,
  101,
  103,
  107,
  109,
  113,
  127,
  131,
  137,
  139,
  149,
  151,
  157,
  163,
  167,
  173,
  179,
  181,
  191,
  193,
  197,
  199,
  211,
  223,
  227,
  229,
  233,
  239,
  241,
  251,
  257,
  263,
  269,
  271,
  277,
  281,
  283,
  293,
  307,
  311,
  313,
  317,
  331,
  337,
  347,
  349,
  353,
  359,
  367,
  373,
  379,
  383,
  389,
  397,
  401,
  409,
  419,
  421,
  431,
  433,
  439,
  443,
  449,
  457,
  461,
  463,
  467,
  479,
  487,
  491,
  499,
  503,
  509,
  521,
  523,
  541,
  547,
  557,
  563,
  569,
  571,
  577,
  587,
  593,
  599,
  601,
  607,
  613,
  617,
  619,
  631,
  641,
  643,
  647,
  653,
  659,
  661,
  673,
  677,
  683,
  691,
  701,
  709,
  719,
  727,
  733,
  739,
  743,
  751,
  757,
  761,
  769,
  773,
  787,
  797,
  809,
  811,
  821,
  823,
  827,
  829,
  839,
  853,
  857,
  859,
  863,
  877,
  881,
  883,
  887,
  907,
  911,
  919,
  929,
  937,
  941,
  947,
  953,
  967,
  971,
  977,
  983,
  991,
  997
];
var lplim = (1 << 26) / lowprimes[lowprimes.length - 1];
function bnIsProbablePrime(t) {
  var i, x = this.abs();
  if (x.t == 1 && x[0] <= lowprimes[lowprimes.length - 1]) {
    for (i = 0; i < lowprimes.length; ++i)
      if (x[0] == lowprimes[i])
        return true;
    return false;
  }
  if (x.isEven())
    return false;
  i = 1;
  while (i < lowprimes.length) {
    var m = lowprimes[i], j = i + 1;
    while (j < lowprimes.length && m < lplim)
      m *= lowprimes[j++];
    m = x.modInt(m);
    while (i < j)
      if (m % lowprimes[i++] == 0)
        return false;
  }
  return x.millerRabin(t);
}
function bnpMillerRabin(t) {
  var n1 = this.subtract(BigInteger.ONE);
  var k = n1.getLowestSetBit();
  if (k <= 0)
    return false;
  var r = n1.shiftRight(k);
  t = t + 1 >> 1;
  if (t > lowprimes.length)
    t = lowprimes.length;
  var a = nbi();
  for (var i = 0; i < t; ++i) {
    a.fromInt(lowprimes[Math.floor(Math.random() * lowprimes.length)]);
    var y = a.modPow(r, this);
    if (y.compareTo(BigInteger.ONE) != 0 && y.compareTo(n1) != 0) {
      var j = 1;
      while (j++ < k && y.compareTo(n1) != 0) {
        y = y.modPowInt(2, this);
        if (y.compareTo(BigInteger.ONE) == 0)
          return false;
      }
      if (y.compareTo(n1) != 0)
        return false;
    }
  }
  return true;
}
BigInteger.prototype.chunkSize = bnpChunkSize;
BigInteger.prototype.toRadix = bnpToRadix;
BigInteger.prototype.fromRadix = bnpFromRadix;
BigInteger.prototype.fromNumber = bnpFromNumber;
BigInteger.prototype.bitwiseTo = bnpBitwiseTo;
BigInteger.prototype.changeBit = bnpChangeBit;
BigInteger.prototype.addTo = bnpAddTo;
BigInteger.prototype.dMultiply = bnpDMultiply;
BigInteger.prototype.dAddOffset = bnpDAddOffset;
BigInteger.prototype.multiplyLowerTo = bnpMultiplyLowerTo;
BigInteger.prototype.multiplyUpperTo = bnpMultiplyUpperTo;
BigInteger.prototype.modInt = bnpModInt;
BigInteger.prototype.millerRabin = bnpMillerRabin;
BigInteger.prototype.clone = bnClone;
BigInteger.prototype.intValue = bnIntValue;
BigInteger.prototype.byteValue = bnByteValue;
BigInteger.prototype.shortValue = bnShortValue;
BigInteger.prototype.signum = bnSigNum;
BigInteger.prototype.toByteArray = bnToByteArray;
BigInteger.prototype.equals = bnEquals;
BigInteger.prototype.min = bnMin;
BigInteger.prototype.max = bnMax;
BigInteger.prototype.and = bnAnd;
BigInteger.prototype.or = bnOr;
BigInteger.prototype.xor = bnXor;
BigInteger.prototype.andNot = bnAndNot;
BigInteger.prototype.not = bnNot;
BigInteger.prototype.shiftLeft = bnShiftLeft;
BigInteger.prototype.shiftRight = bnShiftRight;
BigInteger.prototype.getLowestSetBit = bnGetLowestSetBit;
BigInteger.prototype.bitCount = bnBitCount;
BigInteger.prototype.testBit = bnTestBit;
BigInteger.prototype.setBit = bnSetBit;
BigInteger.prototype.clearBit = bnClearBit;
BigInteger.prototype.flipBit = bnFlipBit;
BigInteger.prototype.add = bnAdd;
BigInteger.prototype.subtract = bnSubtract;
BigInteger.prototype.multiply = bnMultiply;
BigInteger.prototype.divide = bnDivide;
BigInteger.prototype.remainder = bnRemainder;
BigInteger.prototype.divideAndRemainder = bnDivideAndRemainder;
BigInteger.prototype.modPow = bnModPow;
BigInteger.prototype.modInverse = bnModInverse;
BigInteger.prototype.pow = bnPow;
BigInteger.prototype.gcd = bnGCD;
BigInteger.prototype.isProbablePrime = bnIsProbablePrime;
BigInteger.prototype.square = bnSquare;

// ../_tools_/src/Curve.js
var rng = new SecureRandom();
function ECFieldElementFp(q, x) {
  this.x = x;
  this.q = q;
}
function feFpEquals(other) {
  if (other == this)
    return true;
  return this.q.equals(other.q) && this.x.equals(other.x);
}
function feFpToBigInteger() {
  return this.x;
}
function feFpNegate() {
  return new ECFieldElementFp(this.q, this.x.negate().mod(this.q));
}
function feFpAdd(b) {
  return new ECFieldElementFp(this.q, this.x.add(b.toBigInteger()).mod(this.q));
}
function feFpSubtract(b) {
  return new ECFieldElementFp(this.q, this.x.subtract(b.toBigInteger()).mod(this.q));
}
function feFpMultiply(b) {
  return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger()).mod(this.q));
}
function feFpSquare() {
  return new ECFieldElementFp(this.q, this.x.square().mod(this.q));
}
function feFpDivide(b) {
  return new ECFieldElementFp(this.q, this.x.multiply(b.toBigInteger().modInverse(this.q)).mod(this.q));
}
ECFieldElementFp.prototype.equals = feFpEquals;
ECFieldElementFp.prototype.toBigInteger = feFpToBigInteger;
ECFieldElementFp.prototype.negate = feFpNegate;
ECFieldElementFp.prototype.add = feFpAdd;
ECFieldElementFp.prototype.subtract = feFpSubtract;
ECFieldElementFp.prototype.multiply = feFpMultiply;
ECFieldElementFp.prototype.square = feFpSquare;
ECFieldElementFp.prototype.divide = feFpDivide;
function ECPointFp(curve, x, y, z) {
  this.curve = curve;
  this.x = x;
  this.y = y;
  if (z == null) {
    this.z = BigInteger.ONE;
  } else {
    this.z = z;
  }
  this.zinv = null;
}
function pointFpGetX() {
  if (this.zinv == null) {
    this.zinv = this.z.modInverse(this.curve.q);
  }
  var r = this.x.toBigInteger().multiply(this.zinv);
  this.curve.reduce(r);
  return this.curve.fromBigInteger(r);
}
function pointFpGetY() {
  if (this.zinv == null) {
    this.zinv = this.z.modInverse(this.curve.q);
  }
  var r = this.y.toBigInteger().multiply(this.zinv);
  this.curve.reduce(r);
  return this.curve.fromBigInteger(r);
}
function pointFpEquals(other) {
  if (other == this)
    return true;
  if (this.isInfinity())
    return other.isInfinity();
  if (other.isInfinity())
    return this.isInfinity();
  var u, v;
  u = other.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(other.z)).mod(this.curve.q);
  if (!u.equals(BigInteger.ZERO))
    return false;
  v = other.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(other.z)).mod(this.curve.q);
  return v.equals(BigInteger.ZERO);
}
function pointFpIsInfinity() {
  if (this.x == null && this.y == null)
    return true;
  return this.z.equals(BigInteger.ZERO) && !this.y.toBigInteger().equals(BigInteger.ZERO);
}
function pointFpNegate() {
  return new ECPointFp(this.curve, this.x, this.y.negate(), this.z);
}
function pointFpAdd(b) {
  if (this.isInfinity())
    return b;
  if (b.isInfinity())
    return this;
  var u = b.y.toBigInteger().multiply(this.z).subtract(this.y.toBigInteger().multiply(b.z)).mod(this.curve.q);
  var v = b.x.toBigInteger().multiply(this.z).subtract(this.x.toBigInteger().multiply(b.z)).mod(this.curve.q);
  if (BigInteger.ZERO.equals(v)) {
    if (BigInteger.ZERO.equals(u)) {
      return this.twice();
    }
    return this.curve.getInfinity();
  }
  var THREE = new BigInteger("3");
  var x1 = this.x.toBigInteger();
  var y1 = this.y.toBigInteger();
  var x2 = b.x.toBigInteger();
  var y2 = b.y.toBigInteger();
  var v2 = v.square();
  var v3 = v2.multiply(v);
  var x1v2 = x1.multiply(v2);
  var zu2 = u.square().multiply(this.z);
  var x3 = zu2.subtract(x1v2.shiftLeft(1)).multiply(b.z).subtract(v3).multiply(v).mod(this.curve.q);
  var y3 = x1v2.multiply(THREE).multiply(u).subtract(y1.multiply(v3)).subtract(zu2.multiply(u)).multiply(b.z).add(u.multiply(v3)).mod(this.curve.q);
  var z3 = v3.multiply(this.z).multiply(b.z).mod(this.curve.q);
  return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}
function pointFpTwice() {
  if (this.isInfinity())
    return this;
  if (this.y.toBigInteger().signum() == 0)
    return this.curve.getInfinity();
  var THREE = new BigInteger("3");
  var x1 = this.x.toBigInteger();
  var y1 = this.y.toBigInteger();
  var y1z1 = y1.multiply(this.z);
  var y1sqz1 = y1z1.multiply(y1).mod(this.curve.q);
  var a = this.curve.a.toBigInteger();
  var w = x1.square().multiply(THREE);
  if (!BigInteger.ZERO.equals(a)) {
    w = w.add(this.z.square().multiply(a));
  }
  w = w.mod(this.curve.q);
  var x3 = w.square().subtract(x1.shiftLeft(3).multiply(y1sqz1)).shiftLeft(1).multiply(y1z1).mod(this.curve.q);
  var y3 = w.multiply(THREE).multiply(x1).subtract(y1sqz1.shiftLeft(1)).shiftLeft(2).multiply(y1sqz1).subtract(w.square().multiply(w)).mod(this.curve.q);
  var z3 = y1z1.square().multiply(y1z1).shiftLeft(3).mod(this.curve.q);
  return new ECPointFp(this.curve, this.curve.fromBigInteger(x3), this.curve.fromBigInteger(y3), z3);
}
function pointFpMultiply(k) {
  if (this.isInfinity())
    return this;
  if (k.signum() == 0)
    return this.curve.getInfinity();
  var e = k;
  var h = e.multiply(new BigInteger("3"));
  var neg = this.negate();
  var R2 = this;
  var i;
  for (i = h.bitLength() - 2; i > 0; --i) {
    R2 = R2.twice();
    var hBit = h.testBit(i);
    var eBit = e.testBit(i);
    if (hBit != eBit) {
      R2 = R2.add(hBit ? this : neg);
    }
  }
  return R2;
}
function pointFpMultiplyTwo(j, x, k) {
  var i;
  if (j.bitLength() > k.bitLength())
    i = j.bitLength() - 1;
  else
    i = k.bitLength() - 1;
  var R2 = this.curve.getInfinity();
  var both = this.add(x);
  while (i >= 0) {
    R2 = R2.twice();
    if (j.testBit(i)) {
      if (k.testBit(i)) {
        R2 = R2.add(both);
      } else {
        R2 = R2.add(this);
      }
    } else {
      if (k.testBit(i)) {
        R2 = R2.add(x);
      }
    }
    --i;
  }
  return R2;
}
ECPointFp.prototype.getX = pointFpGetX;
ECPointFp.prototype.getY = pointFpGetY;
ECPointFp.prototype.equals = pointFpEquals;
ECPointFp.prototype.isInfinity = pointFpIsInfinity;
ECPointFp.prototype.negate = pointFpNegate;
ECPointFp.prototype.add = pointFpAdd;
ECPointFp.prototype.twice = pointFpTwice;
ECPointFp.prototype.multiply = pointFpMultiply;
ECPointFp.prototype.multiplyTwo = pointFpMultiplyTwo;
function CurveFp(q, a, b) {
  this.q = q;
  this.a = this.fromBigInteger(a);
  this.b = this.fromBigInteger(b);
  this.infinity = new ECPointFp(this, null, null);
  this.reducer = new Barrett(this.q);
}
function curveFpGetQ() {
  return this.q;
}
function curveFpGetA() {
  return this.a;
}
function curveFpGetB() {
  return this.b;
}
function curveFpEquals(other) {
  if (other == this)
    return true;
  return this.q.equals(other.q) && this.a.equals(other.a) && this.b.equals(other.b);
}
function curveFpGetInfinity() {
  return this.infinity;
}
function curveFpFromBigInteger(x) {
  return new ECFieldElementFp(this.q, x);
}
function curveReduce(x) {
  this.reducer.reduce(x);
}
function curveFpDecodePointHex(s) {
  switch (parseInt(s.substr(0, 2), 16)) {
    case 0:
      return this.infinity;
    case 2:
    case 3:
      return null;
    case 4:
    case 6:
    case 7:
      var len = (s.length - 2) / 2;
      var xHex = s.substr(2, len);
      var yHex = s.substr(len + 2, len);
      return new ECPointFp(this, this.fromBigInteger(new BigInteger(xHex, 16)), this.fromBigInteger(new BigInteger(yHex, 16)));
    default:
      return null;
  }
}
function curveFpEncodePointHex(p) {
  if (p.isInfinity())
    return "00";
  var xHex = p.getX().toBigInteger().toString(16);
  var yHex = p.getY().toBigInteger().toString(16);
  var oLen = this.getQ().toString(16).length;
  if (oLen % 2 != 0)
    oLen++;
  while (xHex.length < oLen) {
    xHex = "0" + xHex;
  }
  while (yHex.length < oLen) {
    yHex = "0" + yHex;
  }
  return "04" + xHex + yHex;
}
CurveFp.prototype.getQ = curveFpGetQ;
CurveFp.prototype.getA = curveFpGetA;
CurveFp.prototype.getB = curveFpGetB;
CurveFp.prototype.equals = curveFpEquals;
CurveFp.prototype.getInfinity = curveFpGetInfinity;
CurveFp.prototype.fromBigInteger = curveFpFromBigInteger;
CurveFp.prototype.reduce = curveReduce;
CurveFp.prototype.decodePointHex = curveFpDecodePointHex;
CurveFp.prototype.encodePointHex = curveFpEncodePointHex;
function X9ECParameters(curve, g, n, h) {
  this.curve = curve;
  this.g = g;
  this.n = n;
  this.h = h;
}
function x9getCurve() {
  return this.curve;
}
function x9getG() {
  return this.g;
}
function x9getN() {
  return this.n;
}
function x9getH() {
  return this.h;
}
X9ECParameters.prototype.getCurve = x9getCurve;
X9ECParameters.prototype.getG = x9getG;
X9ECParameters.prototype.getN = x9getN;
X9ECParameters.prototype.getH = x9getH;
function fromHex(s) {
  return new BigInteger(s, 16);
}
function secp128r1() {
  var p = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFF");
  var a = fromHex("FFFFFFFDFFFFFFFFFFFFFFFFFFFFFFFC");
  var b = fromHex("E87579C11079F43DD824993C2CEE5ED3");
  var n = fromHex("FFFFFFFE0000000075A30D1B9038A115");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("04161FF7528B899B2D0C28607CA52C5B86CF5AC8395BAFEB13C02DA292DDED7A83");
  return new X9ECParameters(curve, G, n, h);
}
function secp160k1() {
  var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFAC73");
  var a = BigInteger.ZERO;
  var b = fromHex("7");
  var n = fromHex("0100000000000000000001B8FA16DFAB9ACA16B6B3");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("043B4C382CE37AA192A4019E763036F4F5DD4D7EBB938CF935318FDCED6BC28286531733C3F03C4FEE");
  return new X9ECParameters(curve, G, n, h);
}
function secp160r1() {
  var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFF");
  var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF7FFFFFFC");
  var b = fromHex("1C97BEFC54BD7A8B65ACF89F81D4D4ADC565FA45");
  var n = fromHex("0100000000000000000001F4C8F927AED3CA752257");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("044A96B5688EF573284664698968C38BB913CBFC8223A628553168947D59DCC912042351377AC5FB32");
  return new X9ECParameters(curve, G, n, h);
}
function secp192k1() {
  var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFEE37");
  var a = BigInteger.ZERO;
  var b = fromHex("3");
  var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFE26F2FC170F69466A74DEFD8D");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("04DB4FF10EC057E9AE26B07D0280B7F4341DA5D1B1EAE06C7D9B2F2F6D9C5628A7844163D015BE86344082AA88D95E2F9D");
  return new X9ECParameters(curve, G, n, h);
}
function secp192r1() {
  var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFF");
  var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFC");
  var b = fromHex("64210519E59C80E70FA7E9AB72243049FEB8DEE146B9B1");
  var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFF99DEF836146BC9B1B4D22831");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("04188DA80EB03090F67CBF20EB43A18800F4FF0AFD82FF101207192B95FFC8DA78631011ED6B24CDD573F977A11E794811");
  return new X9ECParameters(curve, G, n, h);
}
function secp224r1() {
  var p = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001");
  var a = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE");
  var b = fromHex("B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4");
  var n = fromHex("FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("04B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34");
  return new X9ECParameters(curve, G, n, h);
}
function secp256r1() {
  var p = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
  var a = fromHex("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC");
  var b = fromHex("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
  var n = fromHex("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
  var h = BigInteger.ONE;
  var curve = new CurveFp(p, a, b);
  var G = curve.decodePointHex("046B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C2964FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
  return new X9ECParameters(curve, G, n, h);
}
function getSEurveByName(name) {
  if (name == "secp128r1")
    return secp128r1();
  if (name == "secp160k1")
    return secp160k1();
  if (name == "secp160r1")
    return secp160r1();
  if (name == "secp192k1")
    return secp192k1();
  if (name == "secp192r1")
    return secp192r1();
  if (name == "secp224r1")
    return secp224r1();
  if (name == "secp256r1")
    return secp256r1();
  return null;
}
function Curve() {
}
function set_ec_params(name) {
  name = "secp" + name;
  var c = getSEurveByName(name);
  this.q = c.getCurve().getQ().toString();
  this.a = c.getCurve().getA().toBigInteger().toString();
  this.b = c.getCurve().getB().toBigInteger().toString();
  this.gx = c.getG().getX().toBigInteger().toString();
  this.gy = c.getG().getY().toBigInteger().toString();
  this.n = c.getN().toString();
}
function getCurve() {
  return new CurveFp(
    new BigInteger(this.q),
    new BigInteger(this.a),
    new BigInteger(this.b)
  );
}
function getG() {
  const curve = this.getCurve();
  return new ECPointFp(
    curve,
    curve.fromBigInteger(new BigInteger(this.gx)),
    curve.fromBigInteger(new BigInteger(this.gy))
  );
}
function pick_rand(_n) {
  var n = new BigInteger(_n);
  var n1 = n.subtract(BigInteger.ONE);
  var r = new BigInteger(n.bitLength(), rng);
  return r.mod(n1).add(BigInteger.ONE);
}
function do_alice_rand(ths) {
  var r = pick_rand(ths.n);
  ths.privateA = r.toString();
}
function do_alice_pub(ths) {
  var G = ths.getG();
  var a = new BigInteger(ths.privateA);
  var P = G.multiply(a);
  ths.publicAX = P.getX().toBigInteger().toString();
  ths.publicAY = P.getY().toBigInteger().toString();
}
function do_alice_key(ths) {
  var curve = ths.getCurve();
  var P = new ECPointFp(
    curve,
    curve.fromBigInteger(new BigInteger(ths.publicBX)),
    curve.fromBigInteger(new BigInteger(ths.publicBY))
  );
  var a = new BigInteger(ths.privateA);
  var S = P.multiply(a);
  ths.keyAX = S.getX().toBigInteger().toString();
  ths.keyAY = S.getY().toBigInteger().toString();
}
Curve.prototype.setAlgorithm = set_ec_params;
Curve.prototype.getCurve = getCurve;
Curve.prototype.getG = getG;
Curve.prototype.clean = function() {
  delete this.privateA;
  delete this.privateB;
  delete this.publicAX;
  delete this.publicAY;
  delete this.publicBX;
  delete this.publicBY;
  delete this.keyAX;
  delete this.keyAY;
  delete this.keyBX;
  delete this.keyBY;
};
Curve.prototype.init = function(algo = "256r1") {
  this.setAlgorithm(algo);
  do_alice_rand(this);
  do_alice_pub(this);
  this.private = this.privateA;
  this.public = {
    x: this.publicAX,
    y: this.publicAY
  };
};
Curve.prototype.x = function(x) {
  this.publicBX = x;
  if (typeof this.publicBY == "string") {
    do_alice_key(this);
    this.secret = {
      x: this.keyAX,
      y: this.keyAY
    };
    this.clean();
  }
};
Curve.prototype.y = function(y) {
  this.publicBY = y;
  if (typeof this.publicBX == "string") {
    do_alice_key(this);
    this.secret = {
      x: this.keyAX,
      y: this.keyAY
    };
    this.clean();
  }
};
Curve.prototype.msg = function(str) {
  this.message = str;
};
Curve.prototype.enc = function(power = 1) {
  return Encrypt(this.secret.x, this.message, power);
};
Curve.prototype.dec = function(power = 1) {
  return Decrypt(this.secret.x, this.message, power);
};
export {
  Curve,
  Decrypt,
  Encrypt
};
