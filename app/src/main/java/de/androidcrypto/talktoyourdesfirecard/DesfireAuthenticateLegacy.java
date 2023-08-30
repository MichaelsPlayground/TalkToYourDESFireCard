package de.androidcrypto.talktoyourdesfirecard;

import android.nfc.tech.IsoDep;
import android.text.TextUtils;
import android.util.Log;

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

import de.androidcrypto.talktoyourdesfirecard.nfcjlib.AES;
import de.androidcrypto.talktoyourdesfirecard.nfcjlib.CRC16;
import de.androidcrypto.talktoyourdesfirecard.nfcjlib.TripleDES;

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
    private final byte FORMAT_PICC_COMMAND = (byte) 0xFC;

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};

    private final byte[] RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS = new byte[]{(byte) 0x91, (byte) 0xFD};
    private final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFE};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    public static final byte[] MASTER_APPLICATION_IDENTIFIER = new byte[3];
    public final byte[] MASTER_APPLICATION_KEY_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    public final byte MASTER_APPLICATION_KEY_NUMBER = (byte) 0x00;

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
            // sample 905a000003d0d1d200
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


    public byte[] getFileSettings(byte fileNumber) {
        final String methodName = "getFileSettings";
        Log.d(TAG, methodName);
        // sanity checks
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        //if (fileNumber > 14) {
        // changed for using Transaction MAC files
        if (fileNumber > 31) {
            //Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            Log.e(TAG, methodName + " fileNumber is > 31, aborted");
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
        System.out.println("*** 1");
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
        System.out.println("*** 2");
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
        System.out.println("*** 3");
        log(methodName,printData("newKey TDES", changeKeyNew));

        // xor the new key with the old key if a key is changed different to authentication key
        if ((changeKeyNumber & 0x0F) != keyNumberUsedForAuthentication) {
            for (int i = 0; i < changeKeyNew.length; i++) {
                plaintext[i] ^= changeKeyOld[i % changeKeyOld.length];
            }
        }
        log(methodName,printData("plaintext", plaintext));
        System.out.println("*** 4");
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
        System.out.println("*** 5");
        byte[] apdu = new byte[5 + 1 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = CHANGE_KEY_COMMAND;
        apdu[4] = (byte) (1 + plaintext.length);
        apdu[5] = changeKeyNumber;
        System.arraycopy(ciphertext, 0, apdu, 6, ciphertext.length);
        Log.d(methodName, printData("apdu", apdu));
        System.out.println("*** 6");
        byte[] changeKeyDesResponse = new byte[0];
        try {
            //response = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
            changeKeyDesResponse = isoDep.transceive(apdu);
            log(methodName, printData("changeKeyDesResponse", changeKeyDesResponse));
            System.arraycopy(returnStatusBytes(changeKeyDesResponse), 0, errorCode, 0, 2);
            //System.arraycopy(selectApplicationResponse, 0, response, 0, selectApplicationResponse.length);
            System.out.println("*** 7 " + printData("changeKeyDesResponse", changeKeyDesResponse));
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

    // status: NOT WORKING
    private boolean changeDesKeyToAes(byte authenticationKeyNumber, byte changeKeyNumber,
                                byte[] changeKeyNew, byte[] changeKeyOld, String changeKeyName) {
        final String methodName = "changeDesKeyToAes";
        System.out.println("*** 1");
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
        if ((changeKeyNew == null) || (changeKeyNew.length != 16)) {
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
        System.out.println("*** 2");
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
        System.out.println("*** 3");
        log(methodName,printData("newKey TDES", changeKeyNew));

        // xor the new key with the old key if a key is changed different to authentication key
        if ((changeKeyNumber & 0x0F) != keyNumberUsedForAuthentication) {
            for (int i = 0; i < changeKeyNew.length; i++) {
                plaintext[i] ^= changeKeyOld[i % changeKeyOld.length];
            }
        }
        log(methodName,printData("plaintext", plaintext));
        System.out.println("*** 4");
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
        System.out.println("*** 5");
        byte[] apdu = new byte[5 + 1 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = CHANGE_KEY_COMMAND;
        apdu[4] = (byte) (1 + plaintext.length);
        apdu[5] = changeKeyNumber;
        System.arraycopy(ciphertext, 0, apdu, 6, ciphertext.length);
        Log.d(methodName, printData("apdu", apdu));
        System.out.println("*** 6");
        byte[] changeKeyDesResponse = new byte[0];
        try {
            //response = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
            changeKeyDesResponse = isoDep.transceive(apdu);
            log(methodName, printData("changeKeyDesResponse", changeKeyDesResponse));
            System.arraycopy(returnStatusBytes(changeKeyDesResponse), 0, errorCode, 0, 2);
            //System.arraycopy(selectApplicationResponse, 0, response, 0, selectApplicationResponse.length);
            System.out.println("*** 7 " + printData("changeKeyDesResponse", changeKeyDesResponse));
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

    // status: NOT WORKING
    private boolean changeAesKeyToDes(byte authenticationKeyNumber, byte changeKeyNumber,
                                     byte[] changeKeyNew, byte[] changeKeyOld, String changeKeyName) {
        final String methodName = "changeAesKeyToDes";
        System.out.println("*** 1");
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
        System.out.println("*** 2");
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
        System.out.println("*** 3");
        log(methodName,printData("newKey TDES", changeKeyNew));

        // xor the new key with the old key if a key is changed different to authentication key
        if ((changeKeyNumber & 0x0F) != keyNumberUsedForAuthentication) {
            for (int i = 0; i < changeKeyNew.length; i++) {
                plaintext[i] ^= changeKeyOld[i % changeKeyOld.length];
            }
        }
        log(methodName,printData("plaintext", plaintext));
        System.out.println("*** 4");
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
        System.out.println("*** 5");
        byte[] apdu = new byte[5 + 1 + ciphertext.length + 1];
        apdu[0] = (byte) 0x90;
        apdu[1] = CHANGE_KEY_COMMAND;
        apdu[4] = (byte) (1 + plaintext.length);
        apdu[5] = changeKeyNumber;
        System.arraycopy(ciphertext, 0, apdu, 6, ciphertext.length);
        Log.d(methodName, printData("apdu", apdu));
        System.out.println("*** 6");
        byte[] changeKeyDesResponse = new byte[0];
        try {
            //response = isoDep.transceive(wrapMessage(selectApplicationCommand, applicationIdentifier));
            changeKeyDesResponse = isoDep.transceive(apdu);
            log(methodName, printData("changeKeyDesResponse", changeKeyDesResponse));
            System.arraycopy(returnStatusBytes(changeKeyDesResponse), 0, errorCode, 0, 2);
            //System.arraycopy(selectApplicationResponse, 0, response, 0, selectApplicationResponse.length);
            System.out.println("*** 7 " + printData("changeKeyDesResponse", changeKeyDesResponse));
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
     * section for general handling
     */

    public boolean formatPicc() {
        logData = "";
        final String methodName = "formatPicc";
        log(methodName, methodName);

        if ((isoDep == null) || (!isoDep.isConnected())) {
            log(methodName,"no or lost connection to the card, aborted");
            Log.e(TAG, methodName + " no or lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // the first step is to select the Master Application
        boolean success = selectApplication(MASTER_APPLICATION_IDENTIFIER);
        if (!success) {
            log(methodName,"selection of Master Application failed, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // the second step is to authentication with Master Application key
        log(methodName, "trying to authenticate with MASTER_APPLICATION_KEY_NUMBER 01 DES DEFAULT");
        success = authenticateD40(MASTER_APPLICATION_KEY_NUMBER, MASTER_APPLICATION_KEY_DES_DEFAULT);
        if (!success) {
            log(methodName,"authenticate failed, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // now we are formatting the card
        byte[] response = new byte[0];
        byte[] wrappedCommand;
        try {
            wrappedCommand = wrapMessage(FORMAT_PICC_COMMAND, null);
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
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
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
        log(methodName, "step 06 decrypt the encRndB using TripleDES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
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

        log(methodName, "step 13 decrypt the encrypted rndA left rotated using TripleDES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
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
     * XORing the ciphertext with previous ciphered block, then DEcrypt
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
        log(methodName, "SEND mode means: XORing the ciphertext with previous ciphered block, then DEcrypt");
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
