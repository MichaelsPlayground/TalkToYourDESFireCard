package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.nfc.tech.IsoDep;
import android.text.TextUtils;
import android.util.Log;
import android.widget.TextView;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class is based on the work of
 */


public class DesfireAuthenticateLegacy {

    private static final String TAG = DesfireAuthenticateLegacy.class.getName();

    private IsoDep isoDep;
    private boolean printToLog = true; // print data to log
    private String logData = "";

    private byte[] selectedApplicationIdentifier;
    private boolean authenticateLegacyD40Success = false;
    private boolean authenticateLegacyAesSuccess = false;
    private byte keyNumberUsedForAuthentication = -1;
    private byte[] SessionKey;

    private byte[] errorCode = new byte[2];


    // some constants
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte AUTHENTICATE_DES_2K3DES_COMMAND = (byte) 0x0A;
    private final byte AUTHENTICATE_AES_COMMAND = (byte) 0xAA;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;
    private final byte CHANGE_KEY_COMMAND = (byte) 0xC4;

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};

    private final byte[] RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS = new byte[]{(byte) 0x91, (byte) 0xFD};
    private final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFE};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    private static final int MAXIMUM_FILE_SIZE = 32; // standard files could get larger but to avoid any framing this is hardcoded limit

    public DesfireAuthenticateLegacy(IsoDep isoDep, boolean printToLog) {
        this.isoDep = isoDep;
        this.printToLog = printToLog;
    }

    /**
     * section for application handling
     */

    /**
     * although the selectApplication does not require any authentication or encryption features this
     * method is placed here to ensure that selecting of an application invalidates any data used in
     * authentication (e.g. a session key)
     * @param applicationIdentifier : 3 bytes
     * @return true on SUCCESS
     */
    public boolean selectApplication(byte[] applicationIdentifier) {
        logData = "";
        final String methodName = "selectApplication";
        log(methodName, methodName);
        // sanity checks
        if (applicationIdentifier == null) {
            Log.e(TAG, methodName + " applicationIdentifier is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (applicationIdentifier.length != 3) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 3, found: " + applicationIdentifier.length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        log(methodName, printData("applicationIdentifier", applicationIdentifier));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(SELECT_APPLICATION_COMMAND, applicationIdentifier);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            selectedApplicationIdentifier = applicationIdentifier.clone();
            invalidateAllAuthentificationData();
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            selectedApplicationIdentifier = null;
            invalidateAllAuthentificationData();
            return false;
        }
    }


    /**
     * section for standard files handling (read & write) that needs encryption
     */

    public byte[] readFromAStandardFileEncipheredCommunicationDes(byte fileNumber, int fileSize) {
        logData = "";
        final String methodName = "readStandardFileEncipheredCommunicationDes";
        log(methodName, methodName);
        // sanity checks
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((fileSize < 0) || (fileSize > MAXIMUM_FILE_SIZE)) {
            Log.e(TAG, methodName + " fileSize has to be in range 0.." + MAXIMUM_FILE_SIZE + " but found " + fileSize + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((SessionKey == null) || (SessionKey.length != 8)) {
            Log.d(TAG, "missing successful authentication with authenticateD40, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log(methodName, "lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        // generate the parameter
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offset, 0, 3);
        baos.write(length, 0, 3);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");

            // now strip of the response bytes

            // now we return all data
            byte[] responseData = Arrays.copyOf(response, response.length - 2);
            // response length: 42 data: 19e32d7ac29b6737f016d94be2839da3e22db2d039cbe1dd90b67e5b29b98ca1c247812eed438a4e9100
            // responseData length: 40 data: 19e32d7ac29b6737f016d94be2839da3e22db2d039cbe1dd90b67e5b29b98ca1c247812eed438a4e
            // the  decryption will happen here
            //byte[] encryptedData = Arrays.copyOfRange(responseData, 0, 36);
            byte[] encryptedFullData = responseData.clone();
            // try to decrypt with SessionKey
            byte[] modDesKey = getTDesKeyFromDesKey(SessionKey); // get a TripleDES key (length 24 bytes) of a DES key (8 bytes)
            byte[] decryptedFullData = TripleDES.decrypt(new byte[8], modDesKey, encryptedFullData);
            log(methodName, printData("decryptedFullData", decryptedFullData));
            // decryptedFullData length: 40 data: 31323320736f6d65206461746100000000000000000000000000000000000000ccd0800000000000
            // decryptedFullData is decrypted file content (32 byte) || CRC16 (2 bytes) || padding with zero (6 bytes)
            byte[] decryptedData = Arrays.copyOfRange(decryptedFullData, 0, 32);
            byte[] crc16RecData = Arrays.copyOfRange(decryptedFullData, 32, 34);
            byte[] paddingData = Arrays.copyOfRange(decryptedFullData, 34, 40);
            log(methodName, printData("crc16RecData", crc16RecData));
            log(methodName, printData("paddingData", paddingData));

            // verify the CRC16
            log(methodName, "verify the CRC16 now");
            byte[] crc16CalData = calculateApduCRC16R(decryptedFullData, 32);
            log(methodName, printData("crc16CalData", crc16CalData));
            if (Arrays.equals(crc16RecData, crc16CalData)) {
                log(methodName, "CRC16 SUCCESS");
            } else {
                log(methodName, "CRC16 FAILURE");
            }
            return decryptedData;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }

    public boolean writeToAStandardFileEncipheredCommunicationDes(byte fileNumber, byte[] data) {

        // status WORKING

        final String methodName = "writeToAStandardFileEncipheredCommunicationDes";
        log(methodName, methodName);
        // sanity checks
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((data == null) || (data.length < 1) || (data.length > MAXIMUM_FILE_SIZE)) {
            Log.e(TAG, "data length not in range 1.." + MAXIMUM_FILE_SIZE + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((SessionKey == null) || (SessionKey.length != 8)) {
            Log.d(TAG, "missing successful authentication with authenticateD40, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log(methodName,"lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // first: build the wrapped APDU with unencrypted data
        // generate the parameter
        int numberOfBytes = data.length;
        //int numberOfBytes = paddedData.length;
        int offsetBytes = 0; // write from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(numberOfBytes); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offset, 0, 3);
        baos.write(length, 0, 3);
        baos.write(data, 0, numberOfBytes);
        //baos.write(paddedData, 0, numberOfBytes);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));

        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName,"transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // fullApdu = preprocess(fullApdu, 7, cs);  // 7 = 1+3+3 (fileNo+off+len)
        // sample from nfcjlib
        // fullApdu1 length: 45 data: 903d00002701000000200000310000000000000000000000000000000000000000000000000000000000000000
        // ciphertext length: 40 data: 89e277a19cec752a5e8d993d8886cbc3d3af2064149a1e7f5a6b166f98610b6ea5c36f3b7d0d6027
        // ret length: 53 data: 903d00002f0100000020000089e277a19cec752a5e8d993d8886cbc3d3af2064149a1e7f5a6b166f98610b6ea5c36f3b7d0d602700
        // fullApdu2 length: 53 data: 903d00002f0100000020000089e277a19cec752a5e8d993d8886cbc3d3af2064149a1e7f5a6b166f98610b6ea5c36f3b7d0d602700
        //
        // case ENCIPHERED: return preprocessEnciphered(apdu, offset);

        // second: run the encrypted process:
        // byte[] ciphertext = encryptApdu(apdu, offset, skey, iv, ktype);
        byte[] ciphertext = preprocessEnciphered(apdu, 7);
        Log.d(TAG, methodName + printData(" ciphertext", ciphertext));
        // fullApdu = preprocess(fullApdu, 7, cs);  // 7 = 1+3+3 (fileNo+off+len)
        // case ENCIPHERED: return preprocessEnciphered(apdu, offset);
        // this will add a CRC16 as well

        // send the encrypted data to the PICC

        byte[] response = new byte[0];
        try {
            response = isoDep.transceive(ciphertext);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName,"transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            return false;
        }
    }

    /**
     * prepares the apdu for encryption by lengthen the apdu by '5' to have extra space for CRC16,
     * the length field (index 4, starting at 0) is adapted by '+5'. The apdu is partially encrypted
     * (the data only)
     * @param apdu
     * @param offset
     * @return
     */

    // calculate CRC and append, encrypt, and update global IV
    private byte[] preprocessEnciphered(byte[] apdu, int offset) {
        final String logString = "preprocessEnciphered";
        log(logString, printData("apdu", apdu) + " offset: " + offset, true);

        log(logString, printData("SESSION_KEY_DES", SessionKey));
        byte[] ciphertext = encryptApdu(apdu, offset, SessionKey);
        log(logString, printData("ciphertext", ciphertext));

        // rebuild the apdu
        byte[] ret = new byte[5 + offset + ciphertext.length + 1];
        System.arraycopy(apdu, 0, ret, 0, 5 + offset);
        System.arraycopy(ciphertext, 0, ret, 5 + offset, ciphertext.length);
        ret[4] = (byte) (offset + ciphertext.length);
        log(logString, printData("ret", ret));
        return ret;
    }

    /**
     * encrypts the apdu with the SessionKey but the headers are left out, so that only the data get encrypted
     * @param apdu : complete ("wrapped") apdu including finalizing 0x00 value
     * @param offset : e.g. for writeStandardFile it is '7'
     * @param sessionKey 8 bytes long (DES) key
     * @return
     */
    /* Only data is encrypted. Headers are left out (e.g. keyNo for credit). */
    private byte[] encryptApdu(byte[] apdu, int offset, byte[] sessionKey) {
        final String logString = "encryptApdu";
        log(logString, printData("apdu", apdu) + " offset: " + offset, true);
        int blockSize = 8;
        int payloadLen = apdu.length - 6;
        // calculate the CRC16
        byte[] crc = calculateApduCRC16C(apdu, offset);
        int padding = 0;  // padding=0 if block length is adequate
        if ((payloadLen - offset + crc.length) % blockSize != 0)
            padding = blockSize - (payloadLen - offset + crc.length) % blockSize;
        int ciphertextLen = payloadLen - offset + crc.length + padding;
        byte[] plaintext = new byte[ciphertextLen];
        System.arraycopy(apdu, 5 + offset, plaintext, 0, payloadLen - offset);
        System.arraycopy(crc, 0, plaintext, payloadLen - offset, crc.length);
        //return send(sessionKey, plaintext, iv);
        return decrypt(sessionKey, plaintext);
    }

    /**
     * decrypt the data using the DES key in SEND mode (data is first XORed with the IV and then decrypted)
     * @param key input is a DES key (8 bytes) which is internally multiplied to a 24 bytes long TDES key
     * @param data
     * @return
     */

    // DES/3DES decryption: CBC send mode and CBC receive mode
    private byte[] decrypt(byte[] key, byte[] data) {
        final String logString = "decrypt";
        log(logString, printData("key", key) + printData(" data", data), true);
        byte[] modifiedKey = new byte[24];
        System.arraycopy(key, 0, modifiedKey, 16, 8);
        System.arraycopy(key, 0, modifiedKey, 8, 8);
        System.arraycopy(key, 0, modifiedKey, 0, key.length);

        /* MF3ICD40, which only supports DES/3DES, has two cryptographic
         * modes of operation (CBC): send mode and receive mode. In send mode,
         * data is first XORed with the IV and then decrypted. In receive
         * mode, data is first decrypted and then XORed with the IV. The PCD
         * always decrypts. The initial IV, reset in all operations, is all zeros
         * and the subsequent IVs are the last decrypted/plain block according with mode.
         *
         * MDF EV1 supports 3K3DES/AES and remains compatible with MF3ICD40.
         */

        // this SEND mode
        log(logString, "decrypt is using the SEND mode, means that data is first XORed with the IV and then decrypted");
        log(logString, "The IV remains 8* 0x00 all the time.");
        byte[] ciphertext = new byte[data.length];
        byte[] cipheredBlock = new byte[8];
        // XOR w/ previous ciphered block --> decrypt
        for (int i = 0; i < data.length; i += 8) {
            for (int j = 0; j < 8; j++) {
                data[i + j] ^= cipheredBlock[j];
            }
            cipheredBlock = TripleDES.decrypt(modifiedKey, data, i, 8);
            System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
        }
        return ciphertext;
    }

    /**
     * calculate the CRC16 value for a RECEIVED message to verify the accompanied CRC16
     * @param apdu
     * @param length
     * @return
     *
     * code taken from https://github.com/andrade/nfcjlib
     * LICENSE: https://github.com/andrade/nfcjlib/blob/master/LICENSE
     */
    private byte[] calculateApduCRC16R(byte[] apdu, int length) {
        final String logString = "calculateApduCRC16R";
        log(logString, printData("apdu", apdu) + " length: " + length, true);
        byte[] data = new byte[length];
        System.arraycopy(apdu, 0, data, 0, length);
        return CRC16.get(data);
    }

    /**
     * calculate the CRC16 value for a SEND message to accompany the CRC16 with the data send to the PICC
     * The CRC16 is calculated only over data, the offset is added by '5' to get the CRC16 value
     * If the apdu is of length 0 the CRC16 is calculated over a byte[0]
     * @param apdu
     * @param offset
     * @return
     *
     * code taken from https://github.com/andrade/nfcjlib
     * LICENSE: https://github.com/andrade/nfcjlib/blob/master/LICENSE
     */
    private byte[] calculateApduCRC16C(byte[] apdu, int offset) {
        final String logString = "calculateApduCRC16C";
        log(logString, printData("apdu", apdu) + " offset: " + offset, true);
        if (apdu.length == 5) {
            return CRC16.get(new byte[0]);
        } else {
            return CRC16.get(apdu, 5 + offset, apdu.length - 5 - offset - 1);
        }
    }

    public byte[] getFileSettings(byte fileNumber) {
        final String methodName = "getFileSettings";
        Log.d(TAG, methodName);
        // sanity checks
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(GET_FILE_SETTINGS_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }


    public boolean changeFileSettings(byte fileNumber) {
        // NOTE: don't forget to authenticate with CAR key
        final String methodName = "changeFileSettings";
        Log.d(TAG, methodName);
        if ((SessionKey == null) || (SessionKey.length != 8)) {
            log(methodName, "the SESSION KEY DES is null or not of length 8, did you forget to authenticate with a CAR key first ?");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }

        //byte selectedFileIdByte = Byte.parseByte(selectedFileId);
        Log.d(TAG, "changeTheFileSettings for selectedFileId " + fileNumber);
        Log.d(TAG, printData("DES session key", SessionKey));

        // CD | File No | Comms setting byte | Access rights (2 bytes) | File size (3 bytes)
        byte commSettingsByte = 0; // plain communication without any encryption

        // we are changing the keys for R and W from 0x34 to 0x22;
        byte accessRightsRwCar = (byte) 0x12; // Read&Write Access & ChangeAccessRights
        //byte accessRightsRW = (byte) 0x34; // Read Access & Write Access // read with key 3, write with key 4
        byte accessRightsRW = (byte) 0x22; // Read Access & Write Access // read with key 2, write with key 2
        // to calculate the crc16 over the setting bytes we need a 3 byte long array
        byte[] bytesForCrc = new byte[3];
        bytesForCrc[0] = commSettingsByte;
        bytesForCrc[1] = accessRightsRwCar;
        bytesForCrc[2] = accessRightsRW;
        Log.d(TAG, printData("bytesForCrc", bytesForCrc));
        byte[] crc16Value = CRC16.get(bytesForCrc);
        Log.d(TAG, printData("crc16Value", crc16Value));
        // create a 8 byte long array
        byte[] bytesForDecryption = new byte[8];
        System.arraycopy(bytesForCrc, 0, bytesForDecryption, 0, 3);
        System.arraycopy(crc16Value, 0, bytesForDecryption, 3, 2);
        Log.d(TAG, printData("bytesForDecryption", bytesForDecryption));
        // generate 24 bytes long triple des key
        byte[] tripleDES_SESSION_KEY = getTDesKeyFromDesKey(SessionKey);
        Log.d(TAG, printData("tripleDES Session Key", tripleDES_SESSION_KEY));
        byte[] IV_DES = new byte[8];
        Log.d(TAG, printData("IV_DES", IV_DES));
        byte[] decryptedData = TripleDES.decrypt(IV_DES, tripleDES_SESSION_KEY, bytesForDecryption);
        Log.d(TAG, printData("decryptedData", decryptedData));
        // the parameter for wrapping
        byte[] parameter = new byte[9];
        parameter[0] = fileNumber;
        System.arraycopy(decryptedData, 0, parameter, 1, 8);
        Log.d(TAG, printData("parameter", parameter));
        byte[] wrappedCommand;
        byte[] response;
        try {
            wrappedCommand = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, parameter);
            Log.d(TAG, printData("wrappedCommand", wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
            Log.d(TAG, printData("response", response));
            System.arraycopy(response, 0, errorCode, 0, 2);
            if (checkResponse(response)) {
                return true;
            } else {
                return false;
            }
        } catch (IOException e) {
            log(methodName, "IOException: " + e.getMessage());
            e.printStackTrace();
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
        }
        return false;
    }


    /**
     * section key handling (e.g. change keys) that needs encryption
     */

    public boolean changeDesKey(byte authenticationKeyNumber, byte changeKeyNumber,
                                 byte[] changeKeyNew, byte[] changeKeyOld, String changeKeyName) {
        final String methodName = "changeDesKey";
        log(methodName, methodName);
        // sanity checks
        if (authenticationKeyNumber < 0) {
            Log.e(TAG, methodName + " authenticationKeyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (authenticationKeyNumber > 14) {
            Log.e(TAG, methodName + " authenticationKeyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (changeKeyNumber < 0) {
            Log.e(TAG, methodName + " changeKeyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (changeKeyNumber > 14) {
            Log.e(TAG, methodName + " changeKeyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
         if ((changeKeyNew == null) || (changeKeyNew.length != 8)) {
            Log.e(TAG, methodName + " changeKeyNew is NULL or of wrong length, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((changeKeyOld == null) || (changeKeyOld.length != 8)) {
            Log.e(TAG, methodName + " changeKeyOld is NULL or of wrong length, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (TextUtils.isEmpty(changeKeyName)) {
            Log.e(TAG, methodName + " changeKeyName is empty, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log(methodName,methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((SessionKey == null) || (SessionKey.length != 8)) {
            log(methodName,methodName + " SESSION_KEY_DES is null or not of length 8 (missing auth ?), aborted");
            Log.e(TAG, methodName + " SESSION_KEY_DES is null or not of length 8 (missing auth ?), aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }

        // important: don't use the original keys for changes as the PICC is using
        // only 56 bit of the 64 bit long (8 bytes) DES key, the remaining 8 bits are used for the
        // key version. The following method call will set the keyVersion to 0 so the 'original' may get
        // altered.
        log(methodName, printData("new key before setKeyVersion", changeKeyNew));
        byte KEY_VERSION = 0;
        setKeyVersion(changeKeyOld, 0, changeKeyOld.length, KEY_VERSION);
        setKeyVersion(changeKeyNew, 0, changeKeyNew.length, KEY_VERSION);
        log(methodName,printData("new key after  setKeyVersion", changeKeyNew));

        byte[] plaintext = new byte[24]; // this is the final array
        int nklen = 16;
        System.arraycopy(changeKeyNew, 0, plaintext, 0, changeKeyNew.length);
        log(methodName,printData("plaintext", plaintext));
        // 8-byte DES keys accepted: internally have to be handled w/ 16 bytes
        System.arraycopy(changeKeyNew, 0, plaintext, 8, changeKeyNew.length);
        changeKeyNew = Arrays.copyOfRange(plaintext, 0, 16);

        log(methodName,printData("newKey TDES", changeKeyNew));

        // xor the new key with the old key if a key is changed different to authentication key
        if ((changeKeyNumber & 0x0F) != keyNumberUsedForAuthentication) {
            for (int i = 0; i < changeKeyNew.length; i++) {
                plaintext[i] ^= changeKeyOld[i % changeKeyOld.length];
            }
        }
        log(methodName,printData("plaintext", plaintext));

        byte[] crc;
        int addDesKeyVersionByte = (byte) 0x00;

        crc = CRC16.get(plaintext, 0, nklen + addDesKeyVersionByte);
        System.arraycopy(crc, 0, plaintext, nklen + addDesKeyVersionByte, 2);

        // this crc16 value is necessary only when the keyNumber used for authentication differs from key to change
        if ((changeKeyNumber & 0x0F) != keyNumberUsedForAuthentication) {
            crc = CRC16.get(changeKeyNew);
            System.arraycopy(crc, 0, plaintext, nklen + addDesKeyVersionByte + 2, 2);
        }
        log(methodName, printData("plaintext before encryption", plaintext));
        byte[] ciphertext = null;
        System.out.println(printData("SESSION_KEY_DES", SessionKey));
        ciphertext = decrypt(SessionKey, plaintext);
        Log.d(methodName, printData("ciphertext after encryption", ciphertext));

        byte[] apdu = new byte[5 + 1 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = CHANGE_KEY_COMMAND;
        apdu[4] = (byte) (1 + plaintext.length);
        apdu[5] = changeKeyNumber;
        System.arraycopy(ciphertext, 0, apdu, 6, ciphertext.length);
        Log.d(methodName, printData("apdu", apdu));

        byte[] changeKeyDesResponse = new byte[0];
        try {
            //response = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
            changeKeyDesResponse = isoDep.transceive(apdu);
            log(methodName, printData("changeKeyDesResponse", changeKeyDesResponse));
            System.arraycopy(returnStatusBytes(changeKeyDesResponse), 0, errorCode, 0, 2);
            //System.arraycopy(selectApplicationResponse, 0, response, 0, selectApplicationResponse.length);
            if (checkResponse(changeKeyDesResponse)) {
                return true;
            } else {
                return false;
            }
        } catch (Exception e) {
            //throw new RuntimeException(e);
            log(methodName, "changeKeyDes transceive failed: " + e.getMessage());
            byte[] responseManual = new byte[]{(byte) 0x91, (byte) 0xFF};
            System.arraycopy(responseManual, 0, e, 0, 2);
            return false;
        }
    }




    /**
     * section for authentication
     */

    /**
     * authenticateD40 uses the legacy authentication method with command 0x0A
     *
     * @param keyNo (00..14) but maximum is defined during application setup
     * @param key   (DES key with length of 8 bytes)
     * @return TRUE when authentication was successful
     *
     * Note: the code was adopted from the nfcjlib written by Daniel Andrade
     * source: https://github.com/andrade/nfcjlib
     */

    public boolean authenticateD40(byte keyNo, byte[] key) {
        // status WORKING
        invalidateAllAuthentificationData();
        logData = "";
        String methodName = "authenticateD40";
        log(methodName, printData("key", key) + " keyNo: " + keyNo, true);
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
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        log(methodName, "step 01 get encrypted rndB from card");
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            apdu = wrapMessage(AUTHENTICATE_DES_2K3DES_COMMAND, new byte[]{keyNo}); // 0x0A
            log(methodName, "- send auth apdu   " + printData("apdu    ", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "- receive response " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0xAF means more data need to get exchanged
        if (!checkResponseMoreData(responseBytes)) {
            log(methodName, "expected to get get 0xAF as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response
        log(methodName, "step 02 get the encrypted rndB from response data");
        
        byte[] encryptedRndB = getData(response);
        log(methodName, printData("- encryptedRndB", encryptedRndB));

        // remove the keyVersion bits within a DES key
        log(methodName, "step 03 setKeyVersion to 00 for DES keys");
        log(methodName, printData("- DES key provided      ", key));
        setKeyVersion(key, 0, key.length, (byte) 0x00);
        log(methodName, printData("- DES key w/keyVersion 0", key));

        log(methodName, "step 04 get a TDES key from the DES key");
        byte[] tdesKey = getTDesKeyFromDesKey(key);
        log(methodName, printData("- DES key  ", key));
        log(methodName, printData("- TDES key", tdesKey));

        // start the decryption
        byte[] iv0 = new byte[8];
        log(methodName, "step 06 decrypt the encRndB using TripeDES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        log(methodName, printData("- encrypted rndB", encryptedRndB));
        byte[] rndB = TripleDES.decrypt(iv0, tdesKey, encryptedRndB);
        log(methodName, printData("- decrypted rndB", rndB));

        log(methodName, "step 06 rotate the decrypted rndB by 1 position/byte to the left");
        log(methodName, printData("- rndB             ", rndB));
        byte[] rndBLeftRotated = rotateLeft(rndB);
        log(methodName, printData("- rndB left rotated", rndBLeftRotated));

        // authenticate 2nd part
        log(methodName, "step 07 generate a random rndA");
        byte[] rndA = new byte[8]; // this is a DES key
        rndA = getRandomData(rndA);
        log(methodName, printData("- rndA", rndA));

        log(methodName, "step 08 concatenate rndA || rndB left rotated");
        byte[] rndArndBLeftRotated = concatenate(rndA, rndBLeftRotated);
        log(methodName, printData("- rndA || rndB left rotated", rndArndBLeftRotated));

        log(methodName, "step 09 copy encryptedRndB to iv1 from position " +
                (encryptedRndB.length - iv0.length) + " to " + (encryptedRndB.length));
        byte[] iv1 = Arrays.copyOfRange(encryptedRndB, encryptedRndB.length - iv0.length, encryptedRndB.length);
        log(methodName, printData("iv1", iv1));

        log(methodName, "step 09 copy encryptedRndB to iv1 from position ");

        log(methodName, "step 10 encrypt rndA || rndB left rotated");
        log(methodName, "        Note: we are encrypting the data by DEcrypting the plaintext due to PICC characteristics");
        log(methodName, "using mode case SEND_MODE = XOR w/ previous ciphered block --> decrypt");
        log(methodName, "step 10 encryption magic starting ********************");
        byte[] manualDecryptionResult = tripleDesSendModeDecryption(tdesKey, rndArndBLeftRotated);
        byte[] ciphertext = new byte[rndArndBLeftRotated.length];
        byte[] cipheredBlock = new byte[8];
        // XOR w/ previous ciphered block --> decrypt
        log(methodName, "XOR w/ previous ciphered block --> decrypt");
        log(methodName, "data before XORing " + printData("data", rndArndBLeftRotated) + printData(" cipheredBlock", cipheredBlock));

        log(methodName, "running a 2 round loop to XOR rndArndBLeftRotated with the previous cipheredBlock and DEcrypt the block using TripleDES");
        log(methodName, "The outer loop is running for i=0 to <" + rndArndBLeftRotated.length + " in steps of 8");
        for (int i = 0; i < rndArndBLeftRotated.length; i += 8) {
            log(methodName, "outer loop i: " + i);
            log(methodName, "The inner loop is running for j=0 to <8"  + " in steps of 1");
            for (int j = 0; j < 8; j++) {
                rndArndBLeftRotated[i + j] ^= cipheredBlock[j];
            }
            cipheredBlock = TripleDES.decrypt(tdesKey, rndArndBLeftRotated, i, 8);
            log(methodName, "TripleDES.decrypt " + printData("cipheredBlock", cipheredBlock));
            log(methodName, " copying cipheredBlock to ciphertext from i = " + i + " length 8");
            System.arraycopy(cipheredBlock, 0, ciphertext, i, 8);
            log("decrypt", printData(" ciphertext", ciphertext));
        }
        byte[] encryptedRndArndBLeftRotated = ciphertext.clone();
        log(methodName, "step 10 encryption magic ending   ********************");

        // for test purposes I'm comparing the manualDecryptionResult with the encryptedRndArndBLeftRotated
        boolean manualDecryptionEquals = Arrays.equals(manualDecryptionResult, encryptedRndArndBLeftRotated);
        if (manualDecryptionEquals) {
            log(methodName, "manual decryption: SUCCESS");
            } else {
            log(methodName, "manual decryption: FAILURE");
        }

        log(methodName, printData("- encrypted rndA || rndB left rotated", encryptedRndArndBLeftRotated));
        log(methodName, "step 11 send the encrypted data to the PICC using the 0xAF command (more data)");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, encryptedRndArndBLeftRotated);
            log(methodName, "- send auth apdu   " + printData("apdu    ", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "- receive response " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0x00 means the exchange was OK
        if (!checkResponse(responseBytes)) {
            log(methodName, "expected to get get 0x00 as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response
        log(methodName, "step 12 the response data is the encrypted rndA from the PICC");
        log(methodName, "        Note: the received (encrypted) rndA is left rotated");
        byte[] encryptedRndA = getData(response);
        log(methodName, printData("- encrypted rndA left rotated", encryptedRndA));


        log(methodName, printData("encryptedRndA", encryptedRndA));
        log(methodName, "The iv is set to 8 * 0x00");
        log(methodName, printData("iv0", iv0));

        log(methodName, "step 13 decrypt the encrypted rndA left rotated using TripeDES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        log(methodName, printData("- encrypted left rotated rndA", encryptedRndB));
        byte[] decryptedRndALeftRotated = TripleDES.decrypt(iv0, tdesKey, encryptedRndA);
        log(methodName, printData("- decrypted left rotated rndA", decryptedRndALeftRotated));

        log(methodName, "step 14 rotate decrypted left rotated rndA to RIGHT");
        byte[] decryptedRndA = rotateRight(decryptedRndALeftRotated);
        log(methodName, printData("- decrypted rndA", decryptedRndA));

        log(methodName, "step 15 compare self generated rndA with rndA received from PICC");
        boolean rndAEqual = Arrays.equals(rndA, decryptedRndA);
        log(methodName, printData("- rndA generated", rndA));
        log(methodName, printData("- rndA received ", decryptedRndA));

        log(methodName, "- rndA generated and received are equals: " + rndAEqual);

        log(methodName, "step 16 generate the DES Session key from rndA and rndB");
        log(methodName, printData("- rndA          ", rndA));
        log(methodName, printData("- rndB          ", rndB));
        SessionKey = getSessionKeyDes(rndA, rndB);
        log(methodName, "- This are the first 4 bytes of rndA and rndB, the DES Session key is");
        log(methodName, "- rndA first 4 bytes || rndB first 4 bytes");
        byte[] rndAfirst4Bytes = Arrays.copyOf(rndA, 4);
        byte[] rndBfirst4Bytes = Arrays.copyOf(rndB, 4);
        log(methodName, "- rndA first 4 Bytes    " + bytesToHexNpeUpperCase(rndAfirst4Bytes));
        log(methodName, "- rndB first 4 Bytes            " + bytesToHexNpeUpperCase(rndBfirst4Bytes));
        log(methodName, "- SessionKey is 8 Bytes " + bytesToHexNpeUpperCase(SessionKey) + " (length: " + SessionKey.length + ")");

        log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            authenticateLegacyD40Success = true;
            keyNumberUsedForAuthentication = keyNo;
            log(methodName, "*********************");
            return true;
        } else {
            log(methodName, "****   FAILURE   ****");
            log(methodName, "*********************");
            return false;
        }
    }

    // this is just a manual method to test the SEND encryption magic

    /**
     * manually runs the TripleDES DEcryption using the SEND mode means:
     * XORing the ciphertext with previous ciphered block, than DEcrypt
     * The algorithm is Triple DES using the CBC mode
     * @param tdesKeyExt : a 24 bytes long TDES key
     * @param ciphertextExt : a 16 bytes long array with the ciphertext to decrypt
     * @return the decrypted plaintext (16 bytes)
     *
     * Note: this method is limited to ciphertext lengths of exact 16 bytes so it is NOT usable for
     * any longer data. This is due to the demonstration of the decryption
     */

    public byte[] tripleDesSendModeDecryption(byte[] tdesKeyExt, byte[] ciphertextExt) {
        String methodName = "tripleDesSendModeDecryption";
        log(methodName, "*** start of the manual decryption ***");
        // sanity checks
        if ((tdesKeyExt == null) || (tdesKeyExt.length != 24)) return null;
        if ((ciphertextExt == null) || (ciphertextExt.length != 16)) return null;

        // using cloned data to avoid any change on data outside this method
        byte[] tdesKey = tdesKeyExt.clone();
        byte[] ciphertext = ciphertextExt.clone();
        int ciphertextLength = ciphertext.length;
        byte[] plaintext = new byte[ciphertextLength]; // the result array after decryption
        log(methodName, "the ciphertext is " + ciphertextLength +
                " bytes long so we need to run " + (ciphertextLength / 8) +
                " rounds to decrypt (length / 8)");

        log(methodName, "******** manual decryption text start ********");
        log(methodName, "SEND mode means: XORing the ciphertext with previous ciphered block, than DEcrypt");
        log(methodName, printData("tdesKey", tdesKey));

        log(methodName, "1 starting with an empty 'cipheredBlock' of 8 bytes length = DES block length");
        byte[] cipheredBlock = new byte[8];
        log(methodName, printData("cipheredBlock   ", cipheredBlock));

        log(methodName, "2 split the ciphertext into blocks of 8 bytes");
        log(methodName, printData("ciphertext     ", ciphertext));
        byte[] ciphertextBlock1 = Arrays.copyOfRange(ciphertext, 0, 8);
        log(methodName, printData("ciphertextBlock1", ciphertextBlock1));
        byte[] ciphertextBlock2 = Arrays.copyOfRange(ciphertext, 8, 16);
        log(methodName, printData("ciphertextBlock2", ciphertextBlock2));

        log(methodName, "3 XORing ct1 with cipheredBlock");
        byte[] ct1Xored = xor(ciphertextBlock1, cipheredBlock);
        log(methodName, printData("ct1 Xored       ", ct1Xored));

        log(methodName, "4 decrypt ct1Xored using TripleDES.decrypt");
        byte[] ct1XoredDecrypted = de.androidcrypto.talktoyourdesfirecard.nfcjlib.TripleDES.decrypt(tdesKey, ct1Xored, 0, 8);
        log(methodName, printData("ct1Xored decrypt", ct1XoredDecrypted));

        log(methodName, "5 copy ct1XoredDecrypted to cipheredBlock");
        cipheredBlock = ct1XoredDecrypted.clone();
        log(methodName, printData("cipheredBlock   ", cipheredBlock));

        log(methodName, "6 XORing ct2 with cipheredBlock");
        byte[] ct2Xored = xor(ciphertextBlock2, cipheredBlock);
        log(methodName, printData("ct2Xored        ", ct2Xored));

        log(methodName, "7 decrypt ct2Xored using TripleDES.decrypt");
        byte[] ct2XoredDecrypted = de.androidcrypto.talktoyourdesfirecard.nfcjlib.TripleDES.decrypt(tdesKey, ct2Xored, 0, 8);
        log(methodName, printData("ct2 Xored decrypt", ct2XoredDecrypted));

        log(methodName, "8 Note: for more data this would be extended but we are ready now");

        log(methodName, "9 concatenate ct1XoredDecrypted and ct2XoredDecrypted to plaintext");
        plaintext = concatenate(ct1XoredDecrypted, ct2XoredDecrypted);
        log(methodName, printData("plaintext", plaintext));
        log(methodName, "******** manual decryption text end **********");
        return plaintext;
    }


    /**
     * authenticateAes uses the legacy authentication method with command 0xAA
     *
     * @param keyNo (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SESSION_KEY is NOT tested so far
     *
     * Note: the code was adopted from the nfcjlib written by Daniel Andrade
     * source: https://github.com/andrade/nfcjlib
     */

    public boolean authenticateAes(byte keyNo, byte[] key) {
        // status WORKING
        logData = "";
        invalidateAllAuthentificationData();
        String methodName = "authenticateAes";
        log(methodName, printData("key", key) + " keyNo: " + keyNo, true);
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
        if ((key == null) || (key.length != 16)) {
            Log.e(TAG, methodName + " data length is not 16, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        log(methodName, "step 01 get encrypted rndB from card");
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            apdu = wrapMessage(AUTHENTICATE_AES_COMMAND, new byte[]{keyNo});
            log(methodName, "get enc rndB " + printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "get enc rndB " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0xAF means more data need to get exchanged
        if (!checkResponseMoreData(responseBytes)) {
            log(methodName, "expected to get get 0xAF as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response
        byte[] rndB_enc = getData(response);
        log(methodName, printData("encryptedRndB", rndB_enc));

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        log(methodName, "step 02 initial iv0 is 16 zero bytes " + printData("iv0", iv0));
        log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        byte[] rndBSession = rndB.clone();
        log(methodName, printData("rndB", rndB));

        log(methodName, "step 04 rotate rndB to LEFT");
        byte[] rndB_leftRotated = rotateLeft(rndB);
        log(methodName, printData("rndB_leftRotated", rndB_leftRotated));

        // authenticate 2nd part
        log(methodName, "step 05 generate a random rndA");
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        log(methodName, printData("rndA", rndA));
        byte[] rndASession = rndA.clone();

        log(methodName, "step 06 concatenate rndA | rndB_leftRotated");
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated));

        // IV is now encrypted RndB received from the tag
        log(methodName, "step 07 iv1 is encryptedRndB received from the tag");
        byte[] iv1 = rndB_enc.clone();
        log(methodName, printData("iv1", iv1));

        // Encrypt RndAB_rot
        log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0x00 means the exchange was OK
        if (!checkResponse(responseBytes)) {
            log(methodName, "expected to get get 0x00 as error code but  found: " + printData("errorCode", responseBytes) + ", aborted");
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response
        log(methodName, "step 10 received encrypted rndA LEFT rotated from PICC");
        byte[] rndA_leftRotated_enc = getData(response);
        log(methodName, printData("rndA_leftRotated_enc", rndA_leftRotated_enc));

        //IV is now the last 16 bytes of RndAB_rot_enc
        log(methodName, "step 11 iv2 is now the last 16 bytes of rndArndB_leftRotated_enc: " + printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));
        int rndArndB_leftRotated_encLength = rndArndB_leftRotated_enc.length;
        byte[] iv2 = Arrays.copyOfRange(rndArndB_leftRotated_enc,
                rndArndB_leftRotated_encLength - 16, rndArndB_leftRotated_encLength);
        log(methodName, printData("iv2", iv2));

        // Decrypt encrypted RndA_rot
        log(methodName, "step 12 decrypt rndA_leftRotated_enc with iv2 and key");
        byte[] rndA_leftRotated = AES.decrypt(iv2, key, rndA_leftRotated_enc);
        log(methodName, printData("rndA_leftRotated", rndA_leftRotated));

        log(methodName, "step 13 rotate rndA_leftRotated to RIGHT");
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        log(methodName, printData("rndA_received", rndA_received));

        boolean rndAEqual = Arrays.equals(rndA, rndA_received);

        log(methodName, printData("rndA received ", rndA_received));
        log(methodName, printData("rndA          ", rndA));
        log(methodName, "rndA and rndA received are equal: " + rndAEqual);
        log(methodName, printData("rndB          ", rndB));
        SessionKey = getSessionKeyAes(rndA, rndB);
        log(methodName, printData("sessionKey    ", SessionKey));
        byte[] sessKey = getSessionKeyAes(rndASession, rndBSession);
        log(methodName, printData("sessKey       ", sessKey));
        log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            authenticateLegacyAesSuccess = true;
            keyNumberUsedForAuthentication = keyNo;
        } else {
            log(methodName, "****   FAILURE   ****");
        }
        log(methodName, "*********************");
        return rndAEqual;

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

    /**
     * generate a TDES key (24 bytes length) from a DES key (8 bytes) by multiplying the key
     * @param key : DES key (8 bytes long)
     * @return : TDES key (24 bytes long)
     */
    public byte[] getTDesKeyFromDesKey(byte[] key) {
        String methodName = "getTDesKeyFromDesKey";
        log(methodName, printData("key", key), true);
        if ((key == null) || (key.length != 8)) {
            log(methodName, "Error: key is NULL or key length is not of 8 bytes length, aborted");
            return null;
        }
        byte[] tdesKey = new byte[24];
        System.arraycopy(key, 0, tdesKey, 16, 8);
        System.arraycopy(key, 0, tdesKey, 8, 8);
        System.arraycopy(key, 0, tdesKey, 0, key.length);
        log(methodName, printData("TDES key", tdesKey));
        return tdesKey;
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

    private byte[] getSessionKeyDes(byte[] rndA, byte[] rndB) {
        log("getSessionKey", printData("rndA", rndA) + printData(" rndB", rndB), true);
        byte[] sessKey = new byte[8];
        System.arraycopy(rndA, 0, sessKey, 0, 4);
        System.arraycopy(rndB, 0, sessKey, 4, 4);
        return sessKey;
    }

    /**
     * Test values for getSesAuthEncKey and getSesAuthMacKey
     * byte[] rndA = Utils.hexStringToByteArray("B04D0787C93EE0CC8CACC8E86F16C6FE");
     * byte[] rndB = Utils.hexStringToByteArray("FA659AD0DCA738DD65DC7DC38612AD81");
     * byte[] key = Utils.hexStringToByteArray("00000000000000000000000000000000");
     * byte[] SesAuthENCKey_expected = Utils.hexStringToByteArray("63DC07286289A7A6C0334CA31C314A04");
     * byte[] SesAuthMACKey_expected = Utils.hexStringToByteArray("774F26743ECE6AF5033B6AE8522946F6");
     *
     * usage: byte[] SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
     * usage: byte[] SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
     */


    /**
     * calculate the SessionAuthEncryptionKey after a successful authenticateAesEv2First
     * It uses the AesMac class for CMAC
     * The code is tested with example values in Mifare DESFire Light Features and Hints AN12343.pdf
     * on pages 33..35
     *
     * @param rndA              is the random generated 16 bytes long key A from reader
     * @param rndB              is the random generated 16 bytes long key B from PICC
     * @param authenticationKey is the 16 bytes long AES key used for authentication
     * @return the 16 bytes long (AES) encryption key
     */

    public byte[] getSesAuthEncKey(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        String methodName = "getSesAuthEncKey";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey));
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted");
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted");
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted");
            return null;
        }
        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] labelEnc = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0xA55A
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(labelEnc, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("cmacInput", cmacInput));
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac));
        return cmac;
    }

    /**
     * calculate the SessionAuthMacKey after a successful authenticateAesEv2First
     * It uses the AesMac class for CMAC
     * The code is tested with example values in Mifare DESFire Light Features and Hints AN12343.pdf
     * on pages 33..35
     *
     * @param rndA              is the random generated 16 bytes long key A from reader
     * @param rndB              is the random generated 16 bytes long key B from PICC
     * @param authenticationKey is the 16 bytes long AES key used for authentication
     * @return the 16 bytes long MAC key
     */

    public byte[] getSesAuthMacKey(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        String methodName = "getSesAuthMacKey";
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey));
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted");
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted");
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted");
            return null;
        }
        // see Mifare DESFire Light Features and Hints AN12343.pdf page 35
        byte[] cmacInput = new byte[32];
        byte[] labelEnc = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080

        System.arraycopy(labelEnc, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(rndA, 0, cmacInput, 6, 2);

        byte[] rndA02to07 = new byte[6];
        byte[] rndB00to05 = new byte[6];
        rndA02to07 = Arrays.copyOfRange(rndA, 2, 8);
        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA));
        log(methodName, printData("rndB     ", rndB));
        log(methodName, printData("cmacInput", cmacInput));
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac));
        return cmac;
    }

    public byte[] calculateDiverseKey(byte[] masterKey, byte[] input) {
        AesCmac mac = null;
        try {
            mac = new AesCmac();
            SecretKey key = new SecretKeySpec(masterKey, "AES");
            mac.init(key);  //set master key
            mac.updateBlock(input); //given input
            //for (byte b : input) System.out.print(" " + b);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            Log.e(TAG, "Exception on calculateDiverseKey: " + e.getMessage());
            return null;
        }
        return mac.doFinal();
    }

    private byte[] getSessionKeyAes(byte[] rndA, byte[] rndB) {
        log("getSessionKeyAes", printData("rndA", rndA) + printData(" rndB", rndB), true);
        byte[] sessKey = new byte[16];
        System.arraycopy(rndA, 0, sessKey, 0, 4);
        System.arraycopy(rndB, 0, sessKey, 4, 4);
        System.arraycopy(rndA, 12, sessKey, 8, 4);
        System.arraycopy(rndB, 12, sessKey, 12, 4);
        return sessKey;
    }

    /**
     * Generate the session key using the random A generated by the PICC and
     * the random B generated by the PCD.
     *
     * @param randA the random number A
     * @param randB the random number B
     * @return the session key
     * Note: modified for AES keys only, code taken from Nfcjlib
     */
    private static byte[] generateSessionKeyNfcjlib(byte[] randA, byte[] randB) {
        byte[] skey = new byte[16];
        System.arraycopy(randA, 0, skey, 0, 4);
        System.arraycopy(randB, 0, skey, 4, 4);
        System.arraycopy(randA, 12, skey, 8, 4);
        System.arraycopy(randB, 12, skey, 12, 4);
        return skey;
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
     * byte array if this APDU has no body.
     */
    private byte[] getData(byte[] responseAPDU) {
        log("getData", printData("responseAPDU", responseAPDU), true);
        //Log.d(TAG, "getData " + printData("responseAPDU", responseAPDU));
        byte[] data = new byte[responseAPDU.length - 2];
        System.arraycopy(responseAPDU, 0, data, 0, data.length);
        log("getData", printData("responseData", data));
        return data;
    }

    /**
     * section for service methods
     */

    private void invalidateAllAuthentificationData() {
        authenticateLegacyD40Success = false;
        authenticateLegacyAesSuccess = false;
        keyNumberUsedForAuthentication = -1;
        SessionKey = null;
    }

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

    private void log(String methodName, String data) {
        log(methodName, data, false);
    }

    private void log(String methodName, String data, boolean isMethodHeader) {
        if (printToLog) {
            logData += "method: " + methodName + "\n" + data + "\n";
            Log.d(TAG, "method: " + methodName + ": " + data);
        }
    }

    private byte[] xor(byte[] dataA, byte[] dataB) {
        if ((dataA == null) || (dataB == null)) {
            Log.e(TAG, "xor - dataA or dataB is NULL, aborted");
            return null;
        }
        // sanity check - both arrays need to be of the same length
        int dataALength = dataA.length;
        int dataBLength = dataB.length;
        if (dataALength != dataBLength) {
            Log.e(TAG, "xor - dataA and dataB lengths are different, aborted (dataA: " + dataALength + " dataB: " + dataBLength + " bytes)");
            return null;
        }
        for (int i = 0; i < dataALength; i++) {
            dataA[i] ^= dataB[i];
        }
        return dataA;
    }

    public String getLogData() {
        return logData;
    }

    public byte[] getErrorCode() {
        return errorCode;
    }

    public boolean isAuthenticateLegacyD40Success() {
        return authenticateLegacyD40Success;
    }

    public boolean isAuthenticateLegacyAesSuccess() {
        return authenticateLegacyAesSuccess;
    }

    public int getKeyNumberUsedForAuthentication() {
        return keyNumberUsedForAuthentication;
    }

    public byte[] getSessionKey() {
        return SessionKey;
    }

}
