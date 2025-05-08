/**
 * Cordova Plugin Crypto
 * 
 * This plugin is used to encrypt data using the X.509 Certificate in 1024-bit public key (PEM file).
 * 
 * @method encrypt Function to encrypt message, that will return a Promise.
 * @method decrypt Function to decrypt encodedMessage, that will return a Promise.
 */
interface PluginCrypt {

	/**
	 * Encrypts the given message using the provided public key.
	 * Resolves with the encrypted message, or rejects with an error.
	 *
	 * @param {string} message Message to encrypt
	 * @param {string} publicKey Public key. Should be a PEM file content, which is encoded in Base64. It's a X.509 Certificate in 1024-bit.
	 * 
	 * @example PluginCrypt.encrypt("Hello world!", "myPublicKeyString...")
	 * .then(v => console.log('encrypted:', v))
	 * .catch(e => console.error(e));
	 * 
	 * @returns {Promise<string>} A promise that resolves with the encrypted message
	 */
	encrypt: (message: string, publicKey: string) => Promise<string>;

	/**
	 * Decrypts the given encoded message using the given private key.
	 * Resolves with the decrypted message, rejects with any error.
	 *
	 * @param {string} encodedMessage Message to decrypt
	 * @param {string} privateKey Private key
	 * 
	 * @example PluginCrypt.decrypt("WHInp9LuXs1+3xxe4MT...", "myPrivateKeyString...")
	 * .then(v => console.log('encrypted:', v))
	 * .catch(e => console.error(e));
	 * 
	 * @returns {Promise<string>} A promise that resolves with the decrypted message
	 */
	decrypt: (encodedMessage: string, privateKey: string) => Promise<string>;

}

declare var PluginCrypt: PluginCrypt;