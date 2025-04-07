# AES Decryption using JavaScript

This is part 2 in my 2 part series on AES encryption and decryption using JavaScript and the Crypto library that is included with modern browsers.

[Part 1, AES Encryption using JavaScript, can be read here.](https://blog.rm.dev/2025/04/05/AES-Encryption-using-JavaScript.html)

You can find the full source here:
[https://github.com/rmmoul/javascrt-aes-encryption](https://github.com/rmmoul/javascrt-aes-encryption)

I also have a working exmaple running on codpen here:
[https://codepen.io/Raymond-Moul/pen/mydoBoq](https://codepen.io/Raymond-Moul/pen/mydoBoq)

Much of the actual decryption process is nearly identical to the encryption process, aside from the first step where we cut up the message in its various parts. Many of the functions and methods used are explained in part 1 and skipped here to avoid redundancy. 

Here is the full decryption function that we’ll be working through and explaining:

```
async function decryptMessage(encryptedBase64, password) {
	// Convert the Base64 string back into a Uint8Array.
	const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

	// Extract the salt (first 16 bytes), IV (next 16 bytes), and ciphertext (remaining bytes).
	const salt = combined.slice(0, 16);
	const iv = combined.slice(16, 32);
	const ciphertext = combined.slice(32);

	// Encode the password as Uint8Array.
	const encoder = new TextEncoder();
	const passwordBytes = encoder.encode(password);

	// Import the password as key material.
	const keyMaterial = await crypto.subtle.importKey(
		'raw',
		passwordBytes,
		{ name: 'PBKDF2' },
		false,
		['deriveKey']
	);

	// Derive the same AES-CBC key using PBKDF2 (must use the same salt, iterations, and hash).
	const key = await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: 100000,
			hash: 'SHA-256'
		},
		keyMaterial,
		{ name: 'AES-CBC', length: 256 },
		false,
		['decrypt']
	);

	// Decrypt the ciphertext.
	const decryptedContent = await crypto.subtle.decrypt(
		{
			name: 'AES-CBC',
			iv: iv
		},
		key,
		ciphertext
	);

	// Convert the decrypted bytes back into a string.
	const decoder = new TextDecoder();
	return decoder.decode(decryptedContent);
}
```

## Retrieving the salt, IV, and encrypted message

The first thing the function does is to decode the message text from Base64 and move the data into a Unit8Array so that we can extract the salt, IV, and encrypted message text. 

```
// Convert the Base64 string back into a Uint8Array.
const combined = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

// Extract the salt (first 16 bytes), IV (next 16 bytes), and ciphertext (remaining bytes).
const salt = combined.slice(0, 16);
const iv = combined.slice(16, 32);
const ciphertext = combined.slice(32);

// Encode the password as Uint8Array.
const encoder = new TextEncoder();
const passwordBytes = encoder.encode(password);
```

Our salt and IV are both 16 bytes, so we use the slice method to extract the first 16 bytes of the integer array to get the salt and then next 16 bytes to get the IV, leaving the rest of the array which contains the encrypted message. 

We then take the password that was passed to the decryption function and convert it to an integer array using the TextEncoder interface. 

## Converting the password into a usable key

This process is nearly identical to the process in the encryption function and is [explained in part 1](https://blog.rm.dev/2025/04/05/AES-Encryption-using-JavaScript.html#create-the-encryption-key), aside from the keyUsages parameter set in the crypto.subtle.deriveKey method where we pass "decrypt" here. 

```
// Import the password as key material.
const keyMaterial = await crypto.subtle.importKey(
	'raw',
	passwordBytes,
	{ name: 'PBKDF2' },
	false,
	['deriveKey']
);

// Derive the same AES-CBC key using PBKDF2 (must use the same salt, iterations, and hash).
const key = await crypto.subtle.deriveKey(
	{
	name: 'PBKDF2',
	salt: salt,
	iterations: 100000,
	hash: 'SHA-256'
	},
	keyMaterial,
	{ name: 'AES-CBC', length: 256 },
	false,
	['decrypt']
);
```

## Decrypting the message

We can now decrypt the message using the [crypto.subtle.decrypt](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/decrypt) method.

```
// Decrypt the ciphertext.
const decryptedContent = await crypto.subtle.decrypt(
	{
		name: 'AES-CBC',
		iv: iv
	},
	key,
	ciphertext
);
```

Much like the encrypt method, the decrypt method takes 3 parameters:

```
decrypt(algorithm, key, data)
```

* algorithm
	- We're using the AES-CBC algorithm and will pass an AesCbcParams object with two values
		+ name
			* We specify AES-CBC here
		+ iv
			* We pass our 16 byte IV here
* key
	- We pass our derived CryptoKey object
* data
	- This is our integer array that contains the encrypted message text
	

## Converting the decrypted message back to text

```
// Convert the decrypted bytes back into a string.
const decoder = new TextDecoder();
return decoder.decode(decryptedContent);
```

This final step is the simple process of converting the message array back to text using the [TextDecoder decode()](https://developer.mozilla.org/en-US/docs/Web/API/TextDecoder/decode) method. The decrypted text is then returned by the function. 
