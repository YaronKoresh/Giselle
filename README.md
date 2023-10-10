
# Giselle v2.0.0

### Giselle cipher, is a symetric key cipher, based on the XOR, base conversion, Scrypt & One Time Pad algorithm.

### Supports the Elliptic-curve Diffie–Hellman (ECDH) key agreement protocol.

### Supports the usage of emojis inside the passwords/messages (or any other high level characters...).

# How the algorithm encrypts messages?

1. Padding.

2. UTF-8 encoding.

3. Binary conversion.

4. Salt generation.

5. XOR (salt + message).

6. Loop of Key expansions & XOR (expansion using Scrypt).

7. Hex conversion.

7. Return ciphertext with salt (seperated with ":").

### The algorithm decrypts the ciphertext, using the same steps, flipped & in reversed order.

# An example *without* ECDH

```
// Import this package

import { Encrypt, Decrypt } from "secure-caesar"; // or: const { Encrypt, Decrypt } = await import("secure-caesar");

// Select a password
const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";

// Select a message to encrypt
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";

// Power level / Cipher strength (any positive integer, 1 or above)
const strength = 1;
// 1 is the default, it may take some time to encrypt/decrypt using strength above 1 !

// Encrypt
const ciphertext = Encrypt(password, message, strength);

// Decrypt
const plaintext = Decrypt(password, ciphertext, strength);

// "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
console.log(plaintext);
```

# An example *with* ECDH

```
// Import this package

import { Curve } from "secure-caesar"; // or: const { Curve } = await import("secure-caesar");

// First friend:
const curve = new Curve();
curve.init();

// Second friend:
const curve = new Curve();
curve.init();

// Now they need to publish their curve.public.x & curve.public.y .
// After that, each one of them need to insert the other friend's public X & Y...

curve.x(<publicX>);
curve.y(<publicY>);

// Now, let's talk! :)

// First friend:
curve.msg("I need help! SOS! I can't finish all that ice cream alone!!");
const iceCreamEmergencyCall = curve.enc();

// First friend send the encrypted message to the second friend.
// But without the ability to send the password, with their unsafe internet connection...
// How would the original message will be decrypted?
// Well... it could be decrypted easily!
// Their secrets are already the same :)
// If you do not believe, run: `console.log(curve.secret)` for both of the friends - the secret.x & secret.y should be equal.

// Second friend:
curve.msg( iceCreamEmergencyCall );
const decryptedSos = curve.dec();

console.log( decryptedSos );
// I need help! SOS! I can't finish all that ice cream alone!!

```

### Scrypt implementation from [scrypt-js](http://npmjs.com/package/scrypt-js).

# License

### This project is licensed under MIT open-source license.