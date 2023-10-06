
# Giselle v1.0.0

### Giselle cipher, is a symetric key cipher, based on the XOR binary operation & custom bases conversion.

### Supports the Elliptic-curve Diffie–Hellman (ECDH) key agreement protocol.

# How the algorithm encrypts messages?

1. Textually encodes the message, into binary, using @yaronkoresh/bases.

2. Calculates the amount of bits to use inside the encryption process.

3. Generates new binary salt, and XOR it with the binary message.

4. Numerically encodes the password, a few times, to expand it, using @yaronkoresh/bases.

5. Splits the password and the XOR results, into one digit chunks.

6. Adds each XOR bit to the expanded password digit, with the same index.

7. Encodes most of the data into Base62, then, returns the final results.

### The algorithm decrypts the ciphertext, using the same steps, flipped & in reversed order.

# An example *without* ECDH

```
// Import this package

import { Encrypt, Decrypt } from "secure-caesar"; // or: const { Encrypt, Decrypt } = await import("secure-caesar");

// Select a password
const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";

// Select a message to encrypt
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";

// Encrypt
const ciphertext = Encrypt(password, message);

// Decrypt
const plaintext = Decrypt(password, ciphertext);

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

# License

### This project is licensed under MIT open-source license.