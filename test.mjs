import { Curve, Encrypt, Decrypt } from "./index.mjs";

// => TEST 1 <=

// Select a password
const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";

// Select a message to encrypt
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";

// 1 or above is the amount of power usage needed by the encryption & decryption (the last parameter)
const powerUsage = 1;

// Encrypt
const ciphertext = Encrypt(password, message, powerUsage );
console.log(ciphertext);

// Decrypt
const plaintext = Decrypt(password, ciphertext, powerUsage );

// "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
console.log(
	plaintext === "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
);

// => TEST 2 <=

// First friend:
const curve1 = new Curve();
curve1.init();

// Second friend:
const curve2 = new Curve();
curve2.init();

// Now they need to publish their curve.public.x & curve.public.y .
// After that, each one of them need to insert the other friend's public X & Y...

curve1.x(curve2.public.x);
curve1.y(curve2.public.y);

curve2.x(curve1.public.x);
curve2.y(curve1.public.y);

// Now, let's talk! :)

// First friend:
curve1.msg("I need help! SOS! I can't finish all that ice cream alone!!");
const iceCreamEmergencyCall = curve1.enc();
console.log(iceCreamEmergencyCall);

// First friend send the encrypted message to the second friend.
// But without the ability to send the password, with their unsafe internet connection...
// How would the original message will be decrypted?
// Well... it could be decrypted easily!
// Their secrets are already the same :)
// If you do not believe, run: `console.log(curve.secret)` for both of the friends - the secret.x & secret.y should be equal.

// Second friend:
curve2.msg( iceCreamEmergencyCall );
const decryptedSos = curve2.dec();

// "I need help! SOS! I can't finish all that ice cream alone!!"
console.log(
	decryptedSos === "I need help! SOS! I can't finish all that ice cream alone!!"
);