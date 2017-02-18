scrypt
======

The [scrypt](http://www.tarsnap.com/scrypt.html) key derivation function in Javascript.  Heavily based on ~~https://github.com/cheongwy/node-scrypt-js~~ (repository is gone, see [here](https://github.com/scintill/scrypt/tree/npm/node-scrypt-js) for my attempt to recover it from npm) but mine is meant to be more lightweight (one file), works in both browser and NodeJS, and can multi-thread in browsers.

Usage
======

Here's a simple example written for nodejs, using one of the test cases from [the `scrypt` paper](http://www.tarsnap.com/scrypt/scrypt.pdf):

```javascript
var module = require('./scrypt.js');
var Crypto_scrypt = module.Crypto_scrypt;
var Crypto = module.Crypto;

Crypto_scrypt("password", "NaCl", 1024, 8, 16, 64, function(result) {
	console.log(
		"scrypt of \"password\" with salt \"NaCl\" and "+
		"parameters 1024, 8, 16, 64 = "+
			Crypto.util.bytesToHex(result)
	);
});
```

Please also see `tests/tests.html` for browser tests, and/or `tests/tests.js` for the tests' entry point for both browser and nodejs (`typeof require` is used to check if it's nodejs).  (The module is structured/named a little weirdly; sorry, I didn't know the conventions very well when I made it.)

Note that the caller receives the result in a callback, since (in the browser at least) the hash is calculated asynchronously.
