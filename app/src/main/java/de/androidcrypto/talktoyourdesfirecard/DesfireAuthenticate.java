package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.nfc.tech.IsoDep;
import android.util.Log;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

public class DesfireAuthenticate {

    /**
     * @author Daniel Andrade
     *
     * code taken from https://github.com/andrade/nfcjlib
     * LICENSE: https://github.com/andrade/nfcjlib/blob/master/LICENSE
     *
     * Note: some minor modifications has been done by AndroidCrypto to run the code without the rest of the library
     */

    private static final String TAG = DesfireAuthenticate.class.getName();

    private IsoDep isoDep;

    // vars
    private boolean printToLog = true; // print data to log
    private int errorCode; // takes the result code
    private KeyType keyType;
    private Byte keyUsedForAuthentication;
    private byte[] initializationVector;
    private byte[] sessionKey;

    private String logData;

    public DesfireAuthenticate(IsoDep isoDep, boolean printToLog) {
        this.isoDep = isoDep;
        this.printToLog = printToLog;
    }

    public boolean authenticateWithNfcjlibDes(byte keyNo, byte[] key) {
        clearData();
        log("AUTHENTICATE", "**** start auth ****", false);
        log("authenticateWithNfcjlibDes", printData("key", key) + " keyNo: " + keyNo, true);
        //Log.d(TAG, "authenticateWithNfcjlibDes " + printData("key", key) + " keyNo: " + keyNo);
        try {
            log("AUTHENTICATE", "**** end auth ****", false);
            return authenticate(key, keyNo, KeyType.DES);
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            return false;
        }
    }

    public boolean authenticateWithNfcjlibTDes(byte keyNo, byte[] key) {
        clearData();
        log("AUTHENTICATE", "**** start auth ****", false);
        log("authenticateWithNfcjlibTDes", printData("key", key) + " keyNo: " + keyNo, true);
        //Log.d(TAG, "authenticateWithNfcjlibTDes " + printData("key", key) + " keyNo: " + keyNo);
        try {
            log("AUTHENTICATE", "**** end auth ****", false);
            return authenticate(key, keyNo, KeyType.TDES);
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            return false;
        }
    }

    public boolean authenticateWithNfcjlibTkTDes(byte keyNo, byte[] key) {
        clearData();
        log("AUTHENTICATE", "**** start auth ****", false);
        log("authenticateWithNfcjlibTkTDes", printData("key", key) + " keyNo: " + keyNo, true);
        //Log.d(TAG, "authenticateWithNfcjlibTkTDes " + printData("key", key) + " keyNo: " + keyNo);
        try {
            log("AUTHENTICATE", "**** end auth ****", false);
            return authenticate(key, keyNo, KeyType.TKTDES);
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            return false;
        }
    }

    public boolean authenticateWithNfcjlibAes(byte keyNo, byte[] key) {
        clearData();
        log("AUTHENTICATE", "**** start auth ****", false);
        log("authenticateWithNfcjlibAes", printData("key", key) + " keyNo: " + keyNo, true);
        //Log.d(TAG, "authenticateWithNfcjlibAes " + printData("key", key) + " keyNo: " + keyNo);
        try {
            log("AUTHENTICATE", "**** end auth ****", false);
            return authenticate(key, keyNo, KeyType.AES);
        } catch (IOException e) {
            Log.e(TAG, "IOException: " + e.getMessage());
            return false;
        }
    }

    private enum KeyType {
        DES,
        TDES,
        TKTDES,
        AES;
    }

    /**
     * DES/3DES mode of operation.
     */
    private enum DESMode {
        SEND_MODE,
        RECEIVE_MODE;
    }

    // constants
    private final byte AUTHENTICATE_DES_2K3DES = (byte) 0x0A;
    private final byte AUTHENTICATE_3K3DES = (byte) 0x1A;
    private final byte AUTHENTICATE_AES	= (byte) 0xAA;


    /**
     * Mutual authentication between PCD and PICC.
     *
     * @param key	the secret key (8 bytes for DES, 16 bytes for 3DES/AES and
     * 				24 bytes for 3K3DES)
     * @param keyNo	the key number
     * @param type	the cipher
     * @return		true for success
     * @throws IOException
     */
    private boolean authenticate(byte[] key, byte keyNo, KeyType type) throws IOException {
        log("authenticate", printData("key", key) + " keyNo: " + keyNo + " keyType: " + type.toString(), true);
        log("authenticate", "the authentication is done in several steps shown here in detail", false);
        //Log.d(TAG, "authenticate " + printData("key", key) + " keyNo: " + keyNo + " keyType: " + type.toString());
        log("authenticate", "step 01 validate that the key is valid", false);
        if (!validateKey(key, type)) {
            throw new IllegalArgumentException();
        }
        log("authenticate", "step 02 setKeyVersion to 00 for all non AES keys", false);
        if (type != KeyType.AES) {
            // remove version bits from Triple DES keys
            setKeyVersion(key, 0, key.length, (byte) 0x00);
        }
        log("authenticate", "step 02 key is now " + printData("key", key), false);
        log("authenticate", "step 03 set the initVector0 to 16 bytes (AES) or 8 bytes (DES)", false);
        final byte[] iv0 = type == KeyType.AES ? new byte[16] : new byte[8];
        byte[] apdu;
        byte[] responseAPDU;
        log("authenticate", "step 04 set the authCommand depending on keyType", false);
        // 1st message exchange
        apdu = new byte[7];
        apdu[0] = (byte) 0x90;

        switch (type) {
            case DES:
            case TDES:
                log("authenticate", "step 04 authCommand: AUTHENTICATE_DES_2K3DES (0x0A)", false);
                apdu[1] = AUTHENTICATE_DES_2K3DES;
                break;
            case TKTDES:
                log("authenticate", "step 04 authCommand: AUTHENTICATE_DES_3K3DES (0x1A)", false);
                apdu[1] = AUTHENTICATE_3K3DES;
                break;
            case AES:
                log("authenticate", "step 04 authCommand: AUTHENTICATE_AES (0xAA)", false);
                apdu[1] = AUTHENTICATE_AES;
                break;
            default:
                assert false : type;
        }
        apdu[4] = 0x01;
        apdu[5] = keyNo;
        //responseAPDU = transmit(apdu);
        log("authenticate", "step 05 send the APDU to the PICC and receive a response " + printData("apdu", apdu), false);
        responseAPDU = isoDep.transceive(apdu);
        log("authenticate", "step 05 responseAPDU" + printData("responseAPDU", responseAPDU), false);
        //this.code = getSW2(responseAPDU);
        errorCode = getSW2(responseAPDU);
        feedback(apdu, responseAPDU);
        if (getSW2(responseAPDU) != 0xAF)
            return false;

        //byte[] responseData = getData(responseAPDU);
        byte[] responseData = Arrays.copyOf(responseAPDU, responseAPDU.length - 2);
        log("authenticate", "step 05 responseData" + printData("responseData", responseData), false);
        // step 3
        log("authenticate", "step 06 decrypt the responseData to randB with iv0 " + printData("iv0", iv0), false);
        byte[] randB = recv(key, getData(responseAPDU), type, iv0);
        if (randB == null)
            return false;
        log("authenticate", "step 06 randB " + printData("randB", randB), false);
        byte[] randBr = rotateLeft(randB);
        log("authenticate", "step 07 rotate randB to the LEFT " + printData("randBr", randBr), false);
        byte[] randA = new byte[randB.length];

        //fillRandom(randA);
        randA = getRandomData(randA);
        log("authenticate", "step 08 generate randA " + printData("randA", randA), false);
        // step 3: encryption
        byte[] plaintext = new byte[randA.length + randBr.length];
        System.arraycopy(randA, 0, plaintext, 0, randA.length);
        System.arraycopy(randBr, 0, plaintext, randA.length, randBr.length);
        log("authenticate", "step 09 concatenate randA || randBr" + printData("plaintext", plaintext), false);
        byte[] iv1 = Arrays.copyOfRange(responseData,
                responseData.length - iv0.length, responseData.length);
        log("authenticate", "step 10 get iv1 from responseData " + printData("iv1", iv1), false);
        log("authenticate", "step 11 encrypt plaintext with key and iv1", false);
        byte[] ciphertext = send(key, plaintext, type, iv1);
        if (ciphertext == null)
            return false;
        log("authenticate", "step 11 " + printData("ciphertext", ciphertext), false);
        // 2nd message exchange
        apdu = new byte[5 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = (byte) 0xAF;
        apdu[4] = (byte) ciphertext.length;
        System.arraycopy(ciphertext, 0, apdu, 5, ciphertext.length);
        //responseAPDU = transmit(apdu);
        log("authenticate", "step 12 send the ciphertext to the PICC and receive a response " + printData("apdu", apdu), false);
        responseAPDU = isoDep.transceive(apdu);
        log("authenticate", "step 12 responseAPDU" + printData("responseAPDU", responseAPDU), false);
        //this.code = getSW2(responseAPDU);
        errorCode = getSW2(responseAPDU);
        feedback(apdu, responseAPDU);
        if (getSW2(responseAPDU) != 0x00)
            return false;

        // step 5
        byte[] iv2 = Arrays.copyOfRange(ciphertext,
                ciphertext.length - iv0.length, ciphertext.length);
        log("authenticate", "step 13 get iv2 from ciphertext " + printData("iv2", iv2), false);
        log("authenticate", "step 14 decrypt responseData to randAr with key and iv2 " + printData("responseData", getData(responseAPDU)), false);
        byte[] randAr = recv(key, getData(responseAPDU), type, iv2);
        log("authenticate", "step 14 " + printData("randAr", randAr), false);
        if (randAr == null)
            return false;
        byte[] randAr2 = rotateLeft(randA);
        log("authenticate", "step 15 rotate randAr to the LEFT " + printData("randAr2", randAr2), false);
        log("authenticate", "step 16 equality check " + printData("randAr", randAr) + " " + printData("randAr2", randAr2), false);
        for (int i = 0; i < randAr2.length; i++)
            if (randAr[i] != randAr2[i])
                return false;

        // step 6
        byte[] skey = generateSessionKey(randA, randB, type);
        log("authenticate", "step 17 generateSessionKey " + printData("skey", skey), false);
        //Log.d(TAG, "The random A is " + Dump.hex(randA));
        log("authenticate", "The random A is " + Utils.bytesToHexNpeUpperCase(randA), false);
        //Log.d(TAG, "The random A is " + Utils.bytesToHexNpeUpperCase(randA));
        //Log.d(TAG, "The random B is " + Dump.hex(randB));
        //Log.d(TAG, "The random B is " + Utils.bytesToHexNpeUpperCase(randB));
        log("authenticate", "The random B is " + Utils.bytesToHexNpeUpperCase(randB), false);
        //Log.d(TAG, "The skey     is " + Dump.hex(skey));
        log("authenticate", "The skey     is " + Utils.bytesToHexNpeUpperCase(skey), false);
        //Log.d(TAG, "The skey     is " + Utils.bytesToHexNpeUpperCase(skey));
        //this.ktype = type;
        this.keyType = type;
        //this.kno = keyNo;
        this.keyUsedForAuthentication = keyNo;
        log("authenticate", "The auth key is " + keyNo, false);
        //this.iv = iv0;
        this.initializationVector = iv0;
        log("authenticate", "The iv0      is" + printData("", iv0), false);
        //this.skey = skey;
        this.sessionKey = skey;
        log("authenticate", "sessionKey   is" + printData("", sessionKey), false);
        return true;
    }

    /**
     * Validates a key according with its type.
     *
     * @param key	the key
     * @param type	the type
     * @return		{@code true} if the key matches the type,
     * 				{@code false} otherwise
     */
    private boolean validateKey(byte[] key, KeyType type) {
        log("validateKey", printData("key", key) + " keyType: " + type.toString(), true);
        //Log.d(TAG, "validateKey " + printData("key", key) + " keyType: " + type.toString());
        if (type == KeyType.DES && (key.length != 8)
                || type == KeyType.TDES && (key.length != 16 || !isKey3DES(key))
                || type == KeyType.TKTDES && key.length != 24
                || type == KeyType.AES && key.length != 16) {
            Log.e(TAG, String.format("Key validation failed: length is %d and type is %s", key.length, type));
            return false;
        }
        return true;
    }

    /**
     * Checks whether a 16-byte key is a 3DES key.
     * <p>
     * Some 3DES keys may actually be DES keys because the LSBit of
     * each byte is used for key versioning by MDF. A 16-byte key is
     * also a DES key if the first half of the key is equal to the second.
     *
     * @param key	the 16-byte 3DES key to check
     * @return		<code>true</code> if the key is a 3DES key
     */
    private boolean isKey3DES(byte[] key) {
        log("isKey3DES", printData("key", key), true);
        //Log.d(TAG, "isKey3DES " + printData("key", key));
        if (key.length != 16)
            return false;
        byte[] tmpKey = Arrays.copyOfRange(key, 0, key.length);
        setKeyVersion(tmpKey, 0, tmpKey.length, (byte) 0x00);
        for (int i = 0; i < 8; i++)
            if (tmpKey[i] != tmpKey[i + 8])
                return true;
        return false;
    }

    /**
     * Returns a copy of the data bytes in the response body. If this APDU as
     * no body, this method returns a byte array with a length of zero.
     *
     * @return a copy of the data bytes in the response body or the empty
     *    byte array if this APDU has no body.
     */
    private byte[] getData(byte[] responseAPDU) {
        log("getData", printData("responseAPDU", responseAPDU), true);
        //Log.d(TAG, "getData " + printData("responseAPDU", responseAPDU));
        byte[] data = new byte[responseAPDU.length - 2];
        System.arraycopy(responseAPDU, 0, data, 0, data.length);
        return data;
    }

    /**
     * Returns the value of the status byte SW2 as a value between 0 and 255.
     *
     * @return the value of the status byte SW2 as a value between 0 and 255.
     */
    private int getSW2(byte[] responseAPDU) {
        log("getSW2", printData("responseAPDU", responseAPDU), true);
        //Log.d(TAG, "getSW2 " + printData("responseAPDU", responseAPDU));
        return responseAPDU[responseAPDU.length - 1] & 0xff;
    }

    private byte[] getRandomData(byte[] key) {
        log("getRandomData", printData("key", key), true);
        //Log.d(TAG, "getRandomData " + printData("var", var));
        int keyLength = key.length;
        return getRandomData(keyLength);
    }

    /**
     * generates a random 8 bytes long array
     *
     * @return 8 bytes long byte[]
     */
    private byte[] getRandomData(int length) {
        log("getRandomData", "length: " + length, true);
        //Log.d(TAG, "getRandomData " + " length: " + length);
        byte[] value = new byte[length];
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(value);
        return value;
    }

    // rotate the array one byte to the left
    private byte[] rotateLeft(byte[] data) {
        log("rotateLeft", printData("data", data), true);
        byte[] ret = new byte[data.length];
        System.arraycopy(data, 1, ret, 0, data.length - 1);
        ret[data.length - 1] = data[0];
        return ret;
    }

    /**
     * Generate the session key using the random A generated by the PICC and
     * the random B generated by the PCD.
     *
     * @param randA	the random number A
     * @param randB	the random number B
     * @param type	the type of key
     * @return		the session key
     */
    private byte[] generateSessionKey(byte[] randA, byte[] randB, KeyType type) {
        log("generateSessionKey", printData("randA", randA) + printData(" randB", randB) + " keyType: " + type.toString(), true);
        //Log.d(TAG, "generateSessionKey " + printData("randA", randA) + printData(" randB", randB) + " keyType: " + type.toString());
        byte[] skey = null;

        switch (type) {
            case DES:
                skey = new byte[8];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                break;
            case TDES:
                skey = new byte[16];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                System.arraycopy(randA, 4, skey, 8, 4);
                System.arraycopy(randB, 4, skey, 12, 4);
                break;
            case TKTDES:
                skey = new byte[24];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                System.arraycopy(randA, 6, skey, 8, 4);
                System.arraycopy(randB, 6, skey, 12, 4);
                System.arraycopy(randA, 12, skey, 16, 4);
                System.arraycopy(randB, 12, skey, 20, 4);
                break;
            case AES:
                skey = new byte[16];
                System.arraycopy(randA, 0, skey, 0, 4);
                System.arraycopy(randB, 0, skey, 4, 4);
                System.arraycopy(randA, 12, skey, 8, 4);
                System.arraycopy(randB, 12, skey, 12, 4);
                break;
            default:
                assert false : type;  // never reached
        }
        return skey;
    }

    // Receiving data that needs decryption.
    private byte[] recv(byte[] key, byte[] data, KeyType type, byte[] iv) {
        log("recv", printData("key", key) + printData(" data", data) + " keyType: " + type.toString() + printData(" iv", iv), true);
        //Log.d(TAG, "recv " + printData("key", key) + printData(" data", data) + " keyType: " + type.toString() + printData(" iv", iv));
        switch (type) {
            case DES:
                log("recv", "keyType case DES decryption with decrypt in DESMode.RECEIVE_MODE", false);
                return decrypt(key, data, DESMode.RECEIVE_MODE);
            case TDES:
                log("recv", "keyType case TDES decryption with decrypt in DESMode.RECEIVE_MODE", false);
                return decrypt(key, data, DESMode.RECEIVE_MODE);
            case TKTDES:
                log("recv", "keyType case TKTDES decryption with TripleDES.decrypt", false);
                return TripleDES.decrypt(iv == null ? new byte[8] : iv, key, data);
            case AES:
                log("recv", "keyType case AES decryption with AES.decrypt", false);
                return AES.decrypt(iv == null ? new byte[16] : iv, key, data);
            default:
                return null;
        }
    }

    // DES/3DES decryption: CBC send mode and CBC receive mode
    private byte[] decrypt(byte[] key, byte[] data, DESMode mode) {
        log("decrypt", printData("key", key) + printData(" data", data) + " DesMode: " + mode.toString(), true);
        log("decrypt", "this method is called from 'recv' in keyType cases DES or TDES", false);
        //Log.d(TAG, "decrypt " + printData("key", key) + printData(" data", data) + " DesMode: " + mode.toString());
        byte[] modifiedKey = new byte[24];
        System.arraycopy(key, 0, modifiedKey, 16, 8);
        System.arraycopy(key, 0, modifiedKey, 8, 8);
        System.arraycopy(key, 0, modifiedKey, 0, key.length);
        log("decrypt", "generate " + printData("modifiedKey", modifiedKey), false);

        /* MF3ICD40, which only supports DES/3DES, has two cryptographic
         * modes of operation (CBC): send mode and receive mode. In send mode,
         * data is first XORed with the IV and then decrypted. In receive
         * mode, data is first decrypted and then XORed with the IV. The PCD
         * always decrypts. The initial IV, reset in all operations, is all zeros
         * and the subsequent IVs are the last decrypted/plain block according with mode.
         *
         * MDF EV1 supports 3K3DES/AES and remains compatible with MF3ICD40.
         */
        byte[] ciphertext = new byte[data.length];
        byte[] cipheredBlock = new byte[8];

        switch (mode) {
            case SEND_MODE:
                log("decrypt", "mode case SEND_MODE", false);
                log("decrypt", "XOR w/ previous ciphered block --> decrypt", false);
                // XOR w/ previous ciphered block --> decrypt
                log("decrypt", "data before XORing " + printData("data", data) + printData(" cipheredBlock", cipheredBlock), false);
                for (int i = 0; i < data.length; i += 8) {
                    for (int j = 0; j < 8; j++) {
                        data[i + j] ^= cipheredBlock[j];
                    }
                    log("decrypt", "data after  XORing " + printData("data", data) + printData(" cipheredBlock", cipheredBlock), false);
                    log("decrypt", "calling TripleDES.decrypt with " + printData("modifiedKey", modifiedKey) + printData(" data", data) + " i: " + i + " length: " + 8, false);
                    cipheredBlock = TripleDES.decrypt(modifiedKey, data, i, 8);
                    log("decrypt", "TripleDES.decrypt " + printData("cipheredBlock", cipheredBlock), false);
                    System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
                    log("decrypt", printData(" ciphertext", ciphertext), false);
                }
                break;
            case RECEIVE_MODE:
                log("decrypt", "mode case RECEIVE_MODE", false);
                log("decrypt", "decrypt --> XOR w/ previous plaintext block", false);
                // decrypt --> XOR w/ previous plaintext block
                log("decrypt", "calling TripleDES.decrypt with " + printData("modifiedKey", modifiedKey) + printData(" data", data) + " offset: " + 0 + " length: " + 8, false);
                cipheredBlock = TripleDES.decrypt(modifiedKey, data, 0, 8);
                log("decrypt", "TripleDES.decrypt " + printData("cipheredBlock", cipheredBlock), false);
                // implicitly XORed w/ IV all zeros
                log("decrypt", "implicitly XORed w/ IV all zeros", false);
                System.arraycopy(cipheredBlock, 0, ciphertext, 0, 8);
                log("decrypt", printData(" ciphertext", ciphertext), false);
                log("decrypt", "data before XORing " + printData("ciphertext", ciphertext) + printData(" cipheredBlock", cipheredBlock), false);
                for (int i = 8; i < data.length; i += 8) {
                    log("decrypt", "calling TripleDES.decrypt with " + printData("modifiedKey", modifiedKey) + printData(" data", data) + " i: " + i + " length: " + 8, false);
                    cipheredBlock = TripleDES.decrypt(modifiedKey, data, i, 8);
                    log("decrypt", "TripleDES.decrypt " + printData("cipheredBlock", cipheredBlock), false);
                    log("decrypt", "now XORing cipheredBlock with data for bytes " + i + printData(" cipheredBlock", cipheredBlock) + printData(" data", data), false);
                    for (int j = 0; j < 8; j++) {
                        cipheredBlock[j] ^= data[i + j - 8];
                    }
                    log("decrypt", "cipheredBlock after XORing " + printData("cipheredBlock", cipheredBlock), false);
                    System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
                    log("decrypt", "ciphertext after copy for bytes " + i + printData(" ciphertext", ciphertext), false);
                }
                log("decrypt", "data after  XORing " + printData("ciphertext", ciphertext) + printData(" cipheredBlock", cipheredBlock), false);
                break;
            default:
                log("decrypt", "method received wrong mode, returning NULL", false);
                Log.e(TAG, "Wrong way (decrypt)");
                return null;
        }
        log("decrypt", "returning " + printData("ciphertext", ciphertext), false);
        return ciphertext;
    }

    // IV sent is the global one but it is better to be explicit about it: can be null for DES/3DES
    // if IV is null, then it is set to zeros
    // Sending data that needs encryption.
    private byte[] send(byte[] key, byte[] data, KeyType type, byte[] iv) {
        log("send", printData("key", key) + printData(" data", data) + " keyType: " + type.toString() + printData(" iv", iv), true);
        //Log.d(TAG, "send " + printData("key", key) + printData(" data", data) + " keyType: " + type.toString() + printData(" iv", iv));
        switch (type) {
            case DES:
                log("send", "keyType case DES decryption with decrypt in DESMode.SEND_MODE", false);
                return decrypt(key, data, DESMode.SEND_MODE);
            case TDES:
                log("send", "keyType case TDES decryption with decrypt in DESMode.SEND_MODE", false);
                return decrypt(key, data, DESMode.SEND_MODE);
            case TKTDES:
                log("send", "keyType case TKTDES encryption with TripleDES.encrypt", false);
                return TripleDES.encrypt(iv == null ? new byte[8] : iv, key, data);
            case AES:
                log("send", "keyType case AES encryption with AES.encrypt", false);
                return AES.encrypt(iv == null ? new byte[16] : iv, key, data);
            default:
                return null;
        }
    }

    // feedback/debug: a request-response round
    private void feedback(byte[] command, byte[] response) {
        log("feedback", printData("command", command) + printData(" response", response), true);
        //Log.d(TAG, "feedback " + printData("command", command) + printData(" response", response));
        //if(print) {
        /*
        if(Mprint) {
            Log.d(TAG, "---> " + getHexString(command, true) + " (" + command.length + ")");
        }
        //if(print) {
        if(Mprint) {
            Log.d(TAG, "<--- " + getHexString(response, true) + " (" + response.length + ")");
        }
        */
        log("feedback", " ---> " + getHexString(command, true) + " (" + command.length + ")", false);
        log("feedback", " <--- " + getHexString(response, true) + " (" + response.length + ")", false);
    }

    private String getHexString(byte[] data, boolean space) {
        log("getHexString", printData("data", data) + " space: " + space, true);
        //Log.d(TAG, "getHexString " + printData("a", a) + " space: " + space);
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xff));
            if(space) {
                sb.append(' ');
            }
        }
        return sb.toString().trim().toUpperCase();
    }

    /**
     * Note on all KEY data (important for DES/TDES keys only)
     * A DES key has a length 64 bits (= 8 bytes) but only 56 bits are used for encryption, the remaining 8 bits are were
     * used as parity bits and within DESFire as key version information.
     * If you are using the 'original' key you will run into authentication issues.
     * You should always strip of the parity bits by running the setKeyVersion command
     * e.g. setKeyVersion(AID_DesLog_Key2_New, 0, AID_DesLog_Key2_New.length, (byte) 0x00);
     * This will set the key version to '0x00' by setting all parity bits to '0x00'
     */

    /**
     * Set the version on a DES key. Each least significant bit of each byte of
     * the DES key, takes one bit of the version. Since the version is only
     * one byte, the information is repeated if dealing with 16/24-byte keys.
     *
     * @param a       1K/2K/3K 3DES
     * @param offset  start position of the key within a
     * @param length  key length
     * @param version the 1-byte version
     */
    // source: nfcjLib
    private void setKeyVersion(byte[] a, int offset, int length, byte version) {
        log("setKeyVersion", printData("a", a) + " offset: " + offset + " length: " + length + " version: " + version, true);
        //Log.d(TAG, "setKeyVersion " + printData("a", a) + " offset: " + offset + " length: " + length + " version: " + version);
        if (length == 8 || length == 16 || length == 24) {
            for (int i = offset + length - 1, j = 0; i >= offset; i--, j = (j + 1) % 8) {
                a[i] &= 0xFE;
                a[i] |= ((version >>> j) & 0x01);
            }
        }
    }

    /**
     * END authentication codes taken from DESFireEv1.java (NFCJLIB)
     */

    private void clearData() {
        logData = "";
        keyUsedForAuthentication = (byte) 0xff;
        errorCode = -1;
        sessionKey = null;
        initializationVector = null;
    }


    private void log(String methodName, String data, boolean isMethodHeader) {
        if (printToLog) {
            logData += "method: " + methodName + "\n" + data + "\n";
            Log.d(TAG, "method: " + methodName + ": " + data);
        }
    }

    public String getLogData() {
        return logData;
    }

    public int getErrorCode() {
        return errorCode;
    }

    public Byte getKeyUsedForAuthentication() {
        return keyUsedForAuthentication;
    }

    public String getKeyTypeString() {
        return keyType.toString();
    }

    public byte[] getInitializationVector() {
        return initializationVector;
    }

    public byte[] getSessionKey() {
        return sessionKey;
    }

}
