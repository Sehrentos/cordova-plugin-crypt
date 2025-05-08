/* global cordova:false */
/* globals window */
const exec = cordova.require('cordova/exec');

/**
 * Cordova Plugin Crypto - Client side plugin code
 * 
 * @type {PluginCrypt} see PluginCrypt.d.ts file for types
 */
const PluginCrypt = {
	encrypt: (message, publicKey) => new Promise((resolve, reject) => {
		if (typeof message !== "string") {
			return reject(Error("PluginCrypt.encrypt param 'message' is not String."));
		}
		if (typeof publicKey !== "string") {
			return reject(Error("PluginCrypt.encrypt param 'publicKey' is not String."));
		}
		exec(resolve, reject, 'PluginCrypt', 'encrypt', [
			message,
			publicKey,
		]);
	}),
	decrypt: (encodedMessage, privateKey) => new Promise((resolve, reject) => {
		if (typeof encodedMessage !== "string") {
			return reject(Error("PluginCrypt.decrypt param 'encodedMessage' is not String."));
		}
		if (typeof privateKey !== "string") {
			return reject(Error("PluginCrypt.decrypt param 'privateKey' is not String."));
		}
		exec(resolve, reject, 'PluginCrypt', 'decrypt', [
			encodedMessage,
			privateKey,
		]);
	})
};

module.exports = PluginCrypt;