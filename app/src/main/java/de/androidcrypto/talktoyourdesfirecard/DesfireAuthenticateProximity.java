package de.androidcrypto.talktoyourdesfirecard;

import android.nfc.tech.IsoDep;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;


/**
 * This class is based on the work of
 */


public class DesfireAuthenticateProximity {

    private static final String TAG = DesfireAuthenticateProximity.class.getName();

    private IsoDep isoDep;
    private boolean printToLog = true; // print data to log
    private String logData;
    private byte[] sessionKey;
    private byte[] errorCode = new byte[2];


    // some constants
    private final byte AUTHENTICATE_DES_2K3DES_COMMAND = (byte) 0x0A;
    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    public DesfireAuthenticateProximity(IsoDep isoDep, boolean printToLog) {
        this.isoDep = isoDep;
        this.printToLog = printToLog;
    }


    public boolean authenticateD40(byte keyNo, byte[] key) {
        String methodName = "authenticateD40";
        log( methodName, printData("key", key) + " keyNo: " + keyNo, true);
        log(methodName, "step 01 get encrypted rndB from card", false);
        errorCode = new byte[2];
        // sanity checks
        if (keyNo < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (keyNo > 14) {
            Log.e(TAG, methodName + " keyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((key == null) || (key.length != 8)) {
            Log.e(TAG, "data length is not 8, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0,errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            apdu = wrapMessage(AUTHENTICATE_DES_2K3DES_COMMAND, new byte[]{keyNo});
            log(methodName, "get enc rndB " + printData("apdu", apdu), false);
            response = isoDep.transceive(apdu);
            log(methodName, "get enc rndB " + printData("response", response), false);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0xAF means more data need to get exchanged
        if (!checkResponseMoreData(responseBytes)) {
            log(methodName, "expected to get get 0xAF as error code but  found: " + printData("errorCode", responseBytes) + ", aborted", false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response
        byte[] encryptedRndB = getData(response);
        log(methodName, printData("encryptedRndB", encryptedRndB), false);

        // remove the keyVersion bits within a DES key
        log(methodName, "step 03 setKeyVersion to 00 for DES keys", false);
        setKeyVersion(key, 0, key.length, (byte) 0x00);
        log( methodName, printData("new DES key", key), false);

        log(methodName, "step 04 get the TDES key from DES key", false);
        byte[] tdesKey = getModifiedKey(key);
        log(methodName, printData("tdesKey", tdesKey), false);
        // start the decryption
        byte[] iv0 = new byte[8];
        log(methodName, "step 05 decrypt the encRndB TripeDES.decrypt with key " + printData("key", key) + printData("iv0", iv0), false);
        byte[] rndB = TripleDES.decrypt(iv0, tdesKey, encryptedRndB);
        log(methodName, printData("rndB", rndB), false);

        // authenticate 2nd part
        log(methodName, "step 06 generate a random rndA", false);
        byte[] rndA = new byte[8]; // this is a DES key
        rndA = getRandomData(rndA);
        log(methodName, printData("rndA", rndA), false);
        log(methodName, "step 07 rotate rndB LEFT", false);
        byte[] rndBLeftRotated = rotateLeft(rndB);
        log(methodName, printData("rndBLeftRotated", rndBLeftRotated), false);
        log(methodName, "step 08 concatenate rndA | rndBLeftRotated", false);
        byte[] rndArndBLeftRotated = concatenate(rndA, rndBLeftRotated);
        log(methodName, printData("rndArndBLeftRotated", rndArndBLeftRotated), false);

        /**
         * section copied from DesfireAuthenticate
         */
        byte[] iv1 = Arrays.copyOfRange(encryptedRndB,encryptedRndB.length - iv0.length, encryptedRndB.length);
        log("authenticate", "step xx get iv1 from responseData " + printData("iv1", iv1), false);
        log("decrypt", "mode case SEND_MODE", false);
        log("decrypt", "XOR w/ previous ciphered block --> decrypt", false);
        byte[] ciphertext = new byte[rndArndBLeftRotated.length];
        byte[] cipheredBlock = new byte[8];
        // XOR w/ previous ciphered block --> decrypt
        log("decrypt", "data before XORing " + printData("data", rndArndBLeftRotated) + printData(" cipheredBlock", cipheredBlock), false);
        for (int i = 0; i < rndArndBLeftRotated.length; i += 8) {
            for (int j = 0; j < 8; j++) {
                rndArndBLeftRotated[i + j] ^= cipheredBlock[j];
            }
            log("decrypt", "data after  XORing " + printData("data", rndArndBLeftRotated) + printData(" cipheredBlock", cipheredBlock), false);
            log("decrypt", "calling TripleDES.decrypt with " + printData("modifiedKey", tdesKey) + printData(" data", rndArndBLeftRotated) + " i: " + i + " length: " + 8, false);
            cipheredBlock = TripleDES.decrypt(tdesKey, rndArndBLeftRotated, i, 8);
            log("decrypt", "TripleDES.decrypt " + printData("cipheredBlock", cipheredBlock), false);
            System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
            log("decrypt", printData(" ciphertext", ciphertext), false);
        }
        byte[] encryptedRndArndBLeftRotated = ciphertext.clone();
        /**
         * section copied from DesfireAuthenticate END
         */

        /*
        log(methodName, "step 09 encrypt rndArndBLeftRotated", false);
        log(methodName, "TripleDES.encrypt with " + printData("tdesKey", tdesKey) + printData(" iv0", iv0), false);
        byte[] encryptedRndArndBLeftRotated = TripleDES.encrypt(iv0, tdesKey, rndArndBLeftRotated);

         */
        //log(methodName, "TripleDES.encrypt with " + printData("tdesKey", tdesKey) + printData(" iv1", iv1), false);
        //byte[] encryptedRndArndBLeftRotated = TripleDES.encrypt(iv1, tdesKey, rndArndBLeftRotated);

        log(methodName, printData("encryptedRndArndBLeftRotated", encryptedRndArndBLeftRotated), false);
        log(methodName, "step 10 send the encrypted data to the PICC", false);
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, encryptedRndArndBLeftRotated);
            log(methodName, "send encryptedRndArndBLeftRotated " + printData("apdu", apdu), false);
            response = isoDep.transceive(apdu);
            log(methodName, "send encryptedRndArndBLeftRotated " + printData("response", response), false);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0x00 means the exchange was OK
        if (!checkResponse(responseBytes)) {
            log(methodName, "expected to get get 0x00 as error code but  found: " + printData("errorCode", responseBytes) + ", aborted", false);
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response
        byte[] encryptedRndA = getData(response);
        log(methodName, printData("encryptedRndA0", encryptedRndA), false);
        log(methodName, "step 11 Get iv2 from encryptedRndArndBLeftRotated", false);
        byte[] iv2 = Arrays.copyOfRange(encryptedRndArndBLeftRotated,
                encryptedRndArndBLeftRotated.length - iv0.length, encryptedRndArndBLeftRotated.length);
        log(methodName, printData("iv0", iv0), false);
        byte[] decryptedRndALeftRotated = TripleDES.decrypt(iv0, tdesKey, encryptedRndA);
        log(methodName, printData("decryptedRndALeftRotated", decryptedRndALeftRotated), false);
        log(methodName, "step xx rotate decryptedRndALeftRotated to RIGHT", false);
        byte[] decryptedRndA = rotateRight(decryptedRndALeftRotated);
        // todo check that both keys are equals

        log(methodName, printData("rndA received ", rndA), false);
        log(methodName, printData("rndA          ", rndA), false);
        log(methodName, printData("rndB          ", rndB), false);
        sessionKey = getSessionKey(rndA, rndB);
        log(methodName, printData("sessionKey    ", sessionKey), false);
        return true;
    }


    /**
     * section for key handling and byte operations
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

    private byte[] getModifiedKey(byte[] key) {
        String methodName = "getModifiedKey";
        log(methodName, printData("key", key), true);
        if ((key == null) || (key.length != 8)) {
            log(methodName, "Error: key is NULL or key length is not of 8 bytes length, aborted", false);
            return null;
        }
        byte[] modifiedKey = new byte[24];
        System.arraycopy(key, 0, modifiedKey, 16, 8);
        System.arraycopy(key, 0, modifiedKey, 8, 8);
        System.arraycopy(key, 0, modifiedKey, 0, key.length);
        log(methodName, printData("modifiedKey", modifiedKey), false);
        return modifiedKey;
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

    // rotate the array one byte to the right
    private static byte[] rotateRight(byte[] data) {
        byte[] unrotated = new byte[data.length];
        for (int i = 1; i < data.length; i++) {
            unrotated[i] = data[i - 1];
        }
        unrotated[0] = data[data.length - 1];
        return unrotated;
    }

    private static byte[] concatenate(byte[] dataA, byte[] dataB) {
        byte[] concatenated = new byte[dataA.length + dataB.length];
        for (int i = 0; i < dataA.length; i++) {
            concatenated[i] = dataA[i];
        }

        for (int i = 0; i < dataB.length; i++) {
            concatenated[dataA.length + i] = dataB[i];
        }
        return concatenated;
    }

    private byte[] getSessionKey(byte[] rndA, byte[] rndB) {
        log("getSessionKey", printData("rndA", rndA) + printData(" rndB", rndB), true);
        byte[] sessKey = new byte[8];
        System.arraycopy(rndA, 0, sessKey, 0 ,4);
        System.arraycopy(rndB, 0, sessKey, 4 ,4);
        return sessKey;
    }

    /**
     * section for command and response handling
     */

    private byte[] wrapMessage(byte command, byte[] parameters) throws IOException {
        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write((byte) 0x90);
        stream.write(command);
        stream.write((byte) 0x00);
        stream.write((byte) 0x00);
        if (parameters != null) {
            stream.write((byte) parameters.length);
            stream.write(parameters);
        }
        stream.write((byte) 0x00);
        return stream.toByteArray();
    }

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_OK, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * checks if the response has an 0x'91AF' at the end means success
     * but there are more data frames available
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponseMoreData(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_MORE_DATA_AVAILABLE, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
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
        log("getData", printData("responseData", data), false);
        return data;
    }

    /**
     * section for service methods
     */

    private String printData(String dataName, byte[] data) {
        int dataLength;
        String dataString = "";
        if (data == null) {
            dataLength = 0;
            dataString = "IS NULL";
        } else {
            dataLength = data.length;
            dataString = bytesToHex(data);
        }
        StringBuilder sb = new StringBuilder();
        sb
                .append(dataName)
                .append(" length: ")
                .append(dataLength)
                .append(" data: ")
                .append(dataString);
        return sb.toString();
    }

    private static String bytesToHex(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString();
    }

    private String bytesToHexNpeUpperCase(byte[] bytes) {
        if (bytes == null) return "";
        StringBuffer result = new StringBuffer();
        for (byte b : bytes)
            result.append(Integer.toString((b & 0xff) + 0x100, 16).substring(1));
        return result.toString().toUpperCase();
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

    public byte[] getErrorCode() {
        return errorCode;
    }
    public byte[] getSessionKey() {
        return sessionKey;
    }
}
