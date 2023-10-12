import { Encrypt, Decrypt, Curve } from "./index.mjs";

const password = "gt785fy54dt897rgV#Yf3f98ktu9803xdj,9$#Y$#^TV%$GTB";
const message = "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)";
const strength = 1;

const ciphertext = Encrypt(password, message, strength);
console.log(ciphertext);

const plaintext = Decrypt(password, ciphertext, strength);
console.log(
	plaintext === "Hello there! my name is Yaroni Makaroni! You have a good taste in choosing npm libraries :)"
);

const curve = new Curve();
curve.init();

const curve2 = new Curve();
curve2.init();

curve2.x(curve.public.x);
curve2.y(curve.public.y);

curve2.msg("I need help! SOS! I can't finish all that ice cream alone!!");
const iceCreamEmergencyCall = curve2.enc();
console.log(iceCreamEmergencyCall);

curve.x(curve2.public.x);
curve.y(curve2.public.y);

curve.msg( iceCreamEmergencyCall );
const decryptedSos = curve.dec();
console.log(
	decryptedSos === "I need help! SOS! I can't finish all that ice cream alone!!"
);