package de.androidcrypto.talktoyourdesfirecard.nfcjlib;

import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Encryption and decryption using AES.
 * 
 * @author Daniel Andrade
 *
 * code taken from https://github.com/andrade/nfcjlib
 * LICENSE: https://github.com/andrade/nfcjlib/blob/master/LICENSE
 *
 * Note: the code was modified by AndroidCrypto for logging purposes
 */
public class AES {

	/**
	 * Encrypt using AES.
	 * 
	 * @param myIV	Initialization vector (16 bytes)
	 * @param myKey	Encryption key (16 bytes)
	 * @param myMsg	Message to encrypt
	 * @return		The cipher text, or null on error.
	 */

	private static final String TAG = AES.class.getName();

	public static byte[] encrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		Log.d(TAG, "encrypt with " + printData("myIV", myIV) + printData(" myKey", myKey) + printData(" myMsg", myMsg));
		byte[] cipherText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			SecretKey sks = new SecretKeySpec(myKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, sks, iv);
			cipherText = cipher.doFinal(myMsg);
		} catch (Exception e) {
			//TODO: multicatch only Java 1.7+
			e.printStackTrace();
			return null;
		}
		return cipherText;
	}

	/**
	 * Decrypt using AES.
	 * 
	 * @param myIV	Initialization vector
	 * @param myKey	Decryption key
	 * @param myMsg	Cipher text to decrypt
	 * @return		The plain text, or null on error.
	 */
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		Log.d(TAG, "decrypt with " + printData("myIV", myIV) + printData(" myKey", myKey) + printData(" myMsg", myMsg));
		byte[] plainText = null;
		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			SecretKey sks = new SecretKeySpec(myKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, sks, iv);
			plainText = cipher.doFinal(myMsg);
		} catch (Exception e) {
			//TODO: multicatch only Java 1.7+
			//e.printStackTrace();
			return null;
		}
		return plainText;
	}

	/**
	 * Decryption using AES.
	 * 
	 * @param myIV		the initialization vector
	 * @param myKey		the key
	 * @param myMsg		the message
	 * @param offset	the offset within the message, pointing at ciphertext
	 * @param length	the length of the ciphertext
	 * @return			the plaintext, or {@code null} on error
	 */
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg, int offset, int length) {
		Log.d(TAG, "decrypt with " + printData("myIV", myIV) + printData(" myKey", myKey) + printData(" myMsg", myMsg) + " offset: " + offset + " length: " + length);
		byte[] plainText = null;
		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			SecretKey sks = new SecretKeySpec(myKey, "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, sks, iv);
			plainText = cipher.doFinal(myMsg, offset, length);
		} catch (Exception e) {
			//TODO: multicatch only Java 1.7+
			//e.printStackTrace();
			return null;
		}
		return plainText;
	}
}