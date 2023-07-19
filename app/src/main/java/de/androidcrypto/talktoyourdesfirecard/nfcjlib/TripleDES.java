package de.androidcrypto.talktoyourdesfirecard.nfcjlib;

import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.util.Log;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

/**
 * @author Daniel Andrade
 *
 * code taken from https://github.com/andrade/nfcjlib
 * LICENSE: https://github.com/andrade/nfcjlib/blob/master/LICENSE
 *
 * Note: the code was modified by AndroidCrypto for logging purposes
 */
public class TripleDES {

	/**
	 * Encrypt using 3DES: DESede/CBC/NoPadding.
	 * 
	 * @param myIV	Initialization vector
	 * @param myKey	Secret key (24 Bytes)
	 * @param myMsg	Message to encrypt
	 * @return		The encrypted message, or <code>null</code> on error.
	 */

	private static final String TAG = TripleDES.class.getName();

	public static byte[] encrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		Log.d(TAG, "encrypt with " + printData("myIV", myIV) + printData(" myKey", myKey) + printData(" myMsg", myMsg));
		byte[] cipherText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			DESedeKeySpec desKey = new DESedeKeySpec(myKey);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
			SecretKey key = keyFactory.generateSecret(desKey);

			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			cipherText = cipher.doFinal(myMsg);
		} catch (Exception e) {
			//TODO: multicatch only Java 1.7+
			e.printStackTrace();
			return null;
		}

		return cipherText;
	}
	
	// ciphertext inside msg at offset and with length length
	public static byte[] decrypt(byte[] myKey, byte[] myMsg, int offset, int length) {
		Log.d(TAG, "decrypt with " + printData("myKey", myKey) + printData(" myMsg", myMsg) + " offset: " + offset + " length: " + length);
		return decrypt(new byte[8], myKey, myMsg, offset, length);
	}

	/**
	 * Decrypt using 3DES: DESede/CBC/NoPadding.
	 * 
	 * @param myIV	The initialization vector
	 * @param myKey	Secret key (24 Bytes)
	 * @param myMsg	Message to decrypt
	 * @return
	 */
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg) {
		Log.d(TAG, "decrypt with " + printData("myIV", myIV) + printData(" myKey", myKey) + printData(" myMsg", myMsg));
		return decrypt(myIV, myKey, myMsg, 0, myMsg.length);
	}
	
	public static byte[] decrypt(byte[] myIV, byte[] myKey, byte[] myMsg, int offset, int length) {
		Log.d(TAG, "decrypt with " + printData("myIV", myIV) + printData(" myKey", myKey) + printData(" myMsg", myMsg) + " offset: " + offset + " length: " + length);
		byte[] plainText = null;

		try {
			IvParameterSpec iv = new IvParameterSpec(myIV);
			DESedeKeySpec desKey = new DESedeKeySpec(myKey);
			SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("DESede");
			SecretKey key = keyFactory.generateSecret(desKey);

			Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
			//plainText = cipher.doFinal(myMsg);
			plainText = cipher.doFinal(myMsg, offset, length);
		} catch (Exception e) {
			//TODO: multicatch only Java 1.7+
			e.printStackTrace();
		}

		return plainText;
	}

}