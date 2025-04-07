# AES Encryption using JavaScript

This is part 1 in a 2 part series on AES encryption and decryption using JavaScript and the Crypto library that is included with modern browsers. We'll work through the encryption and decryption functions and explain the various working parts.

[You can read part 2, about decryption, here.](https://blog.rm.dev/2025/04/07/AES-Decryption-using-JavaScript.html)

You can find the full source here:  
[https://github.com/rmmoul/javascrt-aes-encryption](https://github.com/rmmoul/javascrt-aes-encryption)

I also have a working exmaple running on codpen here:  
[https://codepen.io/Raymond-Moul/pen/mydoBoq](https://codepen.io/Raymond-Moul/pen/mydoBoq)


Here is the full encryption function that we'll be working through and explaining:

```
async function encryptMessage(message, password){
	// Convert strings to Uint8Arrays.
	const encoder = new TextEncoder();
	const passwordBytes = encoder.encode(password);
	const messageBytes = encoder.encode(message);

	// Generate a random salt for key derivation.
	const salt = crypto.getRandomValues(new Uint8Array(16));

	// Import the password as key material.
	const keyMaterial = await crypto.subtle.importKey(
		'raw',
		passwordBytes,
		{ name: 'PBKDF2' },
		false,
		['deriveKey']
	);

	// Derive an AES-CBC key using PBKDF2.
	const key = await crypto.subtle.deriveKey(
		{
			name: 'PBKDF2',
			salt: salt,
			iterations: 100000, // A higher count means better security but slower performance.
			hash: 'SHA-256'
		},
		keyMaterial,
		{ name: 'AES-CBC', length: 256 },
		false,
		['encrypt']
	);

	// Generate a random Initialization Vector.
	const iv = crypto.getRandomValues(new Uint8Array(16));

	// Encrypt the message.
	const encryptedContent = await crypto.subtle.encrypt(
		{
			name: 'AES-CBC',
			iv: iv
		},
		key,
		messageBytes
	);

	// Combine salt, IV, and ciphertext into a single Uint8Array.
	const saltLength = salt.byteLength;
	const ivLength = iv.byteLength;
	const ciphertext = new Uint8Array(encryptedContent);
	const combined = new Uint8Array(saltLength + ivLength + ciphertext.byteLength);

	combined.set(salt, 0);
	combined.set(iv, saltLength);
	combined.set(ciphertext, saltLength + ivLength);

	// Convert combined data to a Base64 string.
	const base64String = btoa(String.fromCharCode(...combined));
	return base64String;
}
	
```


## Encoding the message and password

The first thing that we do in the function is to convert the message and password into [Uint8Arrays](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array) so that the text is converted to integers in an array. These integer values will be the actual data that is used for the encryption, and later when the message is decrypted those integer numbers will be converted back into text. 

We do this with JavsScripts [TextEncoder](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder/encode) and the [encode() method](https://developer.mozilla.org/en-US/docs/Web/API/TextEncoder/encode)

```
// Convert strings to Uint8Arrays.
const encoder = new TextEncoder();
const passwordBytes = encoder.encode(password);
const messageBytes = encoder.encode(message);
		
```


## Create the encryption key

In the next section of the function we need to generate a [salt](https://en.wikipedia.org/wiki/Salt_(cryptography)), create a [CryptoKey object](https://developer.mozilla.org/en-US/docs/Web/API/CryptoKey) using our password, and then finally [derive the final encryption key](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey) using our salt and password. 

```
// Generate a random salt for key derivation.
const salt = crypto.getRandomValues(new Uint8Array(16));

// Import the password as key material.
const keyMaterial = await crypto.subtle.importKey(
	'raw',
	passwordBytes,
	{ name: 'PBKDF2' },
	false,
	['deriveKey']
);

// Derive an AES-CBC key using PBKDF2.
const key = await crypto.subtle.deriveKey(
	{
		name: 'PBKDF2',
		salt: salt,
		iterations: 100000, // A higher count means better security but slower performance.
		hash: 'SHA-256'
	},
	keyMaterial,
	{ name: 'AES-CBC', length: 256 },
	false,
	['encrypt']
);
```

The salt is generated using the [crypto.getRandomValues()](https://developer.mozilla.org/en-US/docs/Web/API/Crypto/getRandomValues) function to produce a "cryptographically strong" set of 16 numbers between 0 and 255. You can see an example of a generated salt by running the following in your browser's dev console:

``` 
alert(crypto.getRandomValues(new Uint8Array(16)));
```

You should see an alert popup with random values like this:  
126,11,104,66,56,207,70,142,171,219,91,89,158,80,250,159

The next step is to create the CryptoKey object using the [crypto.subtle.importKey](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey) method, which takes a number of parameters:

``` 
importKey(format, keyData, algorithm, extractable, keyUsages)
```

- format
	+ This is to specify the key format that will be returned, and we're requesting a [raw key format](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/importKey#raw) in our function
- keyData
	+ We're using the integer array that we generated from our password for the keyData
- algorithm
	+ The importKey method supports a number of algorithms, and we're using [PBKDF2](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/deriveKey#pbkdf2) which is designed to use low-entropy input like a person's password. 
- extractable
	+ This just specifies whether we want the key to be exportable and we do not need this so we're setting this value to false. 
- keyUsages
	+ We're going to use this CryptoKey object to derive the key that will be used to encrypt our message. This parameter can take multiple values in an array but we're only going to pass "deriveKey" since that is all we need to use it for.
	

The final step in this section of the function is to derive the key using the crypto.subtle.deriveKey method. This method takes several parameters and our selections are explained below. 

``` 
deriveKey(algorithm, baseKey, derivedKeyAlgorithm, extractable, keyUsages)
```

- algorithm
	+ We're using the PBKDF2 algorithm again here and we have an [array of parameters](https://developer.mozilla.org/en-US/docs/Web/API/Pbkdf2Params) to pass for this algorithm
		* name
			- PBKDF2
		* salt
			- We're using our generated salt
		* iterations
			- This sets the number of times the hash function will be executed. A higher number here will take more time (which is good) and we're setting 100,000 for our iterations 
		* hash
			- We're using the SHA-256 hashing method
- baseKey
	+ We're passing our keyMaterial CryptoKey object here
- derivedKeyAlgorithm
	+ We're using the AES CBC (Cipher Block Chaining) mode and need to pass an [array of parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesKeyGenParams) here
		* name
			- This is just the chosen algorithm name of AES-CBC
		* length
			- We're using the maximum length of 256
- extractable
	+ This just specifies whether we want the key to be exportable and we do not need this so we're setting this value to false.
- keyUsages
	+ This can take an array of specified usages but we're just using this key to encrypt so that's all we're setting
	

## Creating an IV and encrypting the message

Here we're creating an [IV (initialization vector)](https://en.wikipedia.org/wiki/Initialization_vector) using the same method we used to create our salt. We then use the IV, and our derived key to encrypt our message. 

```
// Generate a random Initialization Vector.
const iv = crypto.getRandomValues(new Uint8Array(16));

// Encrypt the message.
const encryptedContent = await crypto.subtle.encrypt(
	{
		name: 'AES-CBC',
		iv: iv
	},
	key,
	messageBytes
);
```

The encryption is done using the [crypto.subtle.encrypt](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt) method which takes a few parameters. 

```
encrypt(algorithm, key, data)
```

* algorithm
	- We're using the AES-CBC algorithm again here and need to pass [an array with two parameters](https://developer.mozilla.org/en-US/docs/Web/API/AesCbcParams) for this algorithm
		+ name
			* The algorithm name, AES-CBC
		+ iv
			* We pass the iv value we generated
* key
	- We pass our key which is the CyrptoKey object we derived previously
* data
	- This is the integer array that we created from our message text
	

## Combining our results and converting them to Base64 to share

The final steps combine the various pieces that will be needed to eventually decrypt our message and then return that as a Base64 string that can be easily shared via email or a plain text file. 

```
// Combine salt, IV, and ciphertext into a single Uint8Array.
const saltLength = salt.byteLength;
const ivLength = iv.byteLength;
const ciphertext = new Uint8Array(encryptedContent);
const combined = new Uint8Array(saltLength + ivLength + ciphertext.byteLength);

combined.set(salt, 0);
combined.set(iv, saltLength);
combined.set(ciphertext, saltLength + ivLength);

// Convert combined data to a Base64 string.
const base64String = btoa(String.fromCharCode(...combined));
return base64String;
```  

The first step here is to get the length of the salt and iv in bytes so that we can reserve enough space for them at the start of the integer array of the final combined data. 

We next convert the encrypted message into an integer array and make a final combined integer array that is sized based on the size of the salt, iv, and encrypted message. We do this because a Uint8Array has a fixed size so the combined array needs to be properly sized to fit each item. Then the iv, salt, and message (which are all integer arrays) get inserted into the final combined array using using the set() method and using the lengths of each item to specify the offset in the array to insert each value. 

Our final step is to convert the combined integer array into a Base64 string using the [btoa](https://developer.mozilla.org/en-US/docs/Web/API/Window/btoa) method, [String.fromCharCode](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String/fromCharCode), and using [spread syntax](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Spread_syntax) to allow the methods to iterate over the combined array. 

Our encryptMessage function then returns the Base64 text which can be shared and decrypted using the password that was used to encrypt it. 

[The decryption function is explained in part 2.](https://blog.rm.dev/2025/04/07/AES-Decryption-using-JavaScript.html)

