# Cordova Plugin RSA Crypt

This cordova plugin was made to RSA encrypt or decrypt on Android with X.509 cert.

Note: `publickKey` must be `X.509` 1024-bit certificate, which is required by `X509EncodedKeySpec` this plugin uses.

## Install

Cordova command:
```sh
npx cordova plugin add .\<path-to>\cordova-plugin-crypt
```

## Uninstall

Cordova command:
```sh
npx cordova plugin rm cordova-plugin-crypt
```

## Example

The plugin is ready to use after the cordova `"deviceready"` event.

Encrypt method takes string message to encrypt and public key (X.509 1024-bit certificate / RSA/ECB/PKCS1Padding):
```js
const publicKey = "...your public key as base 64 here...";
PluginCrypt.encrypt("Some value to encrypt as RSA", publicKey)
  .then(encrypted => console.log('encrypted:', encrypted))
  .catch(e => console.error('encrypt failed:', e))
```

Decryption method takes encoded string message to encrypt and private key (PKCS#8 1024-bit certificate / RSA/ECB/PKCS1Padding):
```js
const privateKey = "...your private key as base 64 here...";
const encryptedMessage = "...some RSA encrypted message here...";
PluginCrypt.decrypt(encryptedMessage, privateKey)
  .then(decrypted => console.log('decrypted:', decrypted))
  .catch(e => console.error('decrypt fail:', e))
```
