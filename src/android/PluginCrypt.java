package org.apache.cordova.sehrentos;

import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaInterface;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.LOG;
import org.apache.cordova.PluginResult;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Base64;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.Cipher;

/**
 * This class exposes methods in Cordova that can be called from JavaScript.
 */
public class PluginCrypt extends CordovaPlugin {

	private static final String TAG = "PluginCrypt";
	private static final String ACTION_ENCRYPT = "encrypt";
	private static final String ACTION_DECRYPT = "decrypt";

	/**
	 * Executes the request and returns PluginResult.
	 *
	 * @param action          The action to execute.
	 * @param args            JSONArray of arguments for the plugin.
	 * @param callbackContext The callback context from which we were invoked.
	 */
	@Override
	public boolean execute(String action, final JSONArray args, final CallbackContext callbackContext)
			throws JSONException {
		LOG.d(TAG, "Executed action: " + action + " args: " + args.toString());
		/**
		 * Don't run any of these if the current activity is finishing
		 * in order to avoid android.view.WindowManager$BadTokenException
		 * crashing the app. Just return true here since false should only
		 * be returned in the event of an invalid action.
		 */
		if (cordova.getActivity().isFinishing()) {
			LOG.d(TAG, "Execute abort. Activity is closing or closed.");
			return true;
		}

		if (action.equals(ACTION_ENCRYPT)) {
			// backend thread, non blocking
			cordova.getThreadPool().execute(new Runnable() {
				// UI thread, non blocking
				// cordova.getActivity().runOnUiThread(new Runnable() {
				public void run() {
					try {
						LOG.d(TAG, "Encrypt start.");
						// check if activity is still running
						if (cordova.getActivity().isFinishing()) {
							LOG.d(TAG, "Encrypt abort. Activity is closing or closed.");
							return;
						}

						String message = args.getString(0);
						String publicKeyPEM = args.getString(1);

						LOG.d(TAG, "Parsing the public key from PEM format.");
						PublicKey publicKey = parsePublicKey(publicKeyPEM);

						LOG.d(TAG, "Encrypting the message using the public key.");
						String encryptedMessage = encryptMessage(message, publicKey);

						LOG.d(TAG, "Encrypt success.");
						callbackContext.success(encryptedMessage);
					} catch (Exception ex) {
						LOG.e(TAG, "Encryption failed: " + ex.toString());
						callbackContext.error("Encryption failed: " + ex.toString());
					}
				}
			});
			return true;
		}

		if (action.equals(ACTION_DECRYPT)) {
			// backend thread, non blocking
			cordova.getThreadPool().execute(new Runnable() {
				// UI thread, non blocking
				// cordova.getActivity().runOnUiThread(new Runnable() {
				public void run() {
					try {
						LOG.d(TAG, "Decrypt start.");

						// check if activity is still running
						if (cordova.getActivity().isFinishing()) {
							LOG.d(TAG, "Decrypt abort. Activity is closing or closed.");
							return;
						}

						String encryptedMessage = args.getString(0);
						String privateKeyPEM = args.getString(1);

						LOG.d(TAG, "Parsing the private key from PEM format.");
						PrivateKey privateKey = parsePrivateKey(privateKeyPEM);

						LOG.d(TAG, "Decrypting the message using the private key.");
						String decryptedMessage = decryptMessage(encryptedMessage, privateKey);

						LOG.d(TAG, "Decrypt success.");
						callbackContext.success(decryptedMessage);
					} catch (Exception ex) {
						LOG.e(TAG, "Decryption failed: " + ex.toString());
						callbackContext.error("Decryption failed: " + ex.toString());
					}
				}
			});
			return true;
		}

		// action not defined
		return false;
	}

	private PublicKey parsePublicKey(String publicKeyPEM) throws Exception {
		// remove PEM headers
		publicKeyPEM = publicKeyPEM.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");

		byte[] publicKeyBytes = Base64.getDecoder().decode(publicKeyPEM);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePublic(keySpec);
	}

	private PrivateKey parsePrivateKey(String privateKeyPEM) throws Exception {
		// remove PEM headers
		privateKeyPEM = privateKeyPEM.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----",
				"");

		byte[] privateKeyBytes = Base64.getDecoder().decode(privateKeyPEM);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		return keyFactory.generatePrivate(keySpec);
	}

	private String encryptMessage(String message, PublicKey publicKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] encryptedBytes = cipher.doFinal(message.getBytes("UTF-8"));
		return Base64.getEncoder().encodeToString(encryptedBytes);
	}

	private String decryptMessage(String encryptedMessage, PrivateKey privateKey) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] encryptedBytes = Base64.getDecoder().decode(encryptedMessage);
		byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
		return new String(decryptedBytes);
	}
}