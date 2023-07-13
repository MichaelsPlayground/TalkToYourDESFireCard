package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.nfc.tech.IsoDep;
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


/**
 * this class is based on these two documents that are public available from NXP:
 * Mifare DESFire Light Features and Hints AN12343.pdf
 * MIFARE DESFire Light contactless application IC MF2DLHX0.pdf
 */

/**
 * The following tables shows which commands are implemented in this class so far.
 * Some commands depend of the file settings (e.g. read data from a Standard file can be done
 * using Plain, MACed or Enciphered communication
 *
 *                                                              communication types
 * active commands so far:                                   PLAIN  MACed  ENCIPHERED
 * AUTHENTICATE_AES_EV2_FIRST_COMMAND = (byte) 0x71;          n.a.   n.a.     WORK
 * AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND = (byte) 0x77;      n.a.   n.a.     WORK
 * GET_CARD_UID_COMMAND = (byte) 0x51;                        n.a.   n.a.     WORK
 *
 * CREATE_DATA_FILE_COMMAND = (byte) 0xxx;
 * READ_DATA_COMMAND = (byte) 0xxx;
 * WRITE_DATA_COMMAND = (byte) 0xxx;
 *
 * CREATE_VALUE_FILE_COMMAND = (byte) 0xxx;
 * READ_VALUE_FILE_COMMAND = (byte) 0xxx;
 * CREDIT_VALUE_FILE_COMMAND = (byte) 0xxx;
 * DEBIT_VALUE_FILE_COMMAND = (byte) 0xxx;
 *
 * CREATE_RECORD_FILE_COMMAND = (byte) 0xxx;
 * READ_RECORD_FILE_COMMAND = (byte) 0xxx;
 * WRITE_RECORD_FILE_COMMAND = (byte) 0xxx;
 *
 * DELETE_FILE_COMMAND = (byte) 0xxx;
 * GET_FILE_SETTINGS = (byte) 0xxx;
 * GET_FILE_KEY_SETTINGS = (byte) 0xxx;
 *
 * CHANGE_KEY_COMMAND = (byte) 0xxx;
 *
 * GET_FREE_MEMORY_ON_CARD_COMMAND = (byte) 0xxx;
 * FORMAT_PICC_COMMAND = (byte) 0xxx;
 *
 *
 */

public class DesfireAuthenticateEv2 {

    private static final String TAG = DesfireAuthenticateEv2.class.getName();

    private IsoDep isoDep;
    private boolean printToLog = true; // print data to log
    private String logData;
    private boolean authenticateEv2FirstSuccess = false;
    private boolean authenticateEv2NonFirstSuccess = false;
    private byte keyNumberUsedForAuthentication = -1;

    private byte[] SesAuthENCKey; // filled by authenticateAesEv2First
    private byte[] SesAuthMACKey; // filled by authenticateAesEv2First
    private int CmdCounter = 0; // filled / resetted by authenticateAesEv2First
    private byte[] TransactionIdentifier; // resetted by authenticateAesEv2First
    // note on TransactionIdentifier: LSB encoding
    private byte[] errorCode = new byte[2];


    // some constants
    private final byte AUTHENTICATE_AES_EV2_FIRST_COMMAND = (byte) 0x71;
    private final byte AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND = (byte) 0x77;
    private final byte GET_CARD_UID_COMMAND = (byte) 0x51;

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    public DesfireAuthenticateEv2(IsoDep isoDep, boolean printToLog) {
        this.isoDep = isoDep;
        this.printToLog = printToLog;
    }

    public byte[] getCardUidEv2() {
        String logData = "";
        String methodName = "getCardUidEv2";
        log(methodName, "started", true);
        // sanity checks
/*
        if (!authenticateEv2FirstSuccess) {
            if (!authenticateEv2NonFirstSuccess) {
                Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
                System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
                return null;
            }
        }

 */

        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }


        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }


        byte[] responseData = new byte[2];

        // parameter
        byte[] cmdCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(GET_CARD_UID_COMMAND);
        baos.write(cmdCounterLsb, 0, cmdCounterLsb.length);
        baos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] parameter = baos.toByteArray();
        log(methodName, "parameter for GET_CARD_UID_COMMAND", false);
        log(methodName, "command: " + Utils.byteToHex(GET_CARD_UID_COMMAND), false);
        log(methodName, Utils.printData("cmdCounterLsb", cmdCounterLsb), false);
        log(methodName, Utils.printData("TransactionIdentifier", TransactionIdentifier), false);
        log(methodName, Utils.printData("parameter", parameter), false);

        // generate the MAC
        //byte[] mac = g
        // MACKSesAuthMACKey(Ins || CmdCtr || TI)

        // testdata
        byte[] parameterTest = Utils.hexStringToByteArray("510000569D4B24");
        byte[] SesAuthMACKeyTest = Utils.hexStringToByteArray("FD9E26C9766F07C1D07106C0F8F3671F");
        byte[] macOverCommandExpected = Utils.hexStringToByteArray("ED5CB7A932EF8D7C2E91B42A1139F11B");

        //byte[] macOverCommand = calculateDiverseKey(SesAuthMACKey, parameter);
        byte[] macOverCommand = calculateDiverseKey(SesAuthMACKeyTest, parameterTest); // this is working
        //byte[] macOverCommand = calculateApduCMAC(parameterTest, SesAuthMACKeyTest, new byte[16]);
        log(methodName, Utils.printData("macOverData", macOverCommand), false);
        log(methodName, Utils.printData("macOvDatExp", macOverCommandExpected), false);

        // now truncate the MAC
        // sample MAC: ED5CB7A932EF8D7C2E91B42A1139F11B
        //               5C  A9  EF  7C  91  2A  39  1B
        // Truncated MAC = every 2nd uneven byte of the MAC =
        // Trunc  MAC: 5CA9EF7C912A391B



        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] encryptedData;
        try {
            apdu = wrapMessage(GET_CARD_UID_COMMAND, parameter);
            log(methodName, printData(" apdu", apdu), false);
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, responseData, 0, 2);
            return null ;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, responseData, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            encryptedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
                /*
                byte[] result = getCardUid(output, responseData);
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the data I'm receiving is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with any key ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + printData(" UID", result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                }
                */
        // correct result is 045e0832501490 (7 bytes)
        // encrypt result is length: 16 data: 359734583048c7ea0e6352f0478c6068
        // decrypt result is length: 16 data: 7a4f24afd255ab778cbc1b9fae1c6cad
        // correct result is                  045e0832501490 (7 bytes)
        //byte[] encryptionKeyAes = SESSION_KEY_AES;
        //log(methodName, printData("encryptionKey AES", encryptionKeyAes),false);

        //byte[] iv = IV.clone(); // an AES IV is 16 bytes long
        //log(methodName, printData("IV", iv),false);
        log(methodName, printData("apdu", apdu),false);
        //byte[] cmacIv = calculateApduCMAC(apdu, encryptionKeyAes, iv);
        //log(methodName, printData("cmacIv", cmacIv),false);
        log(methodName, printData("encrypted data", encryptedData),false);

        //byte[] decryptedData = AES.decrypt(cmacIv, encryptionKeyAes, encryptedData);
        //log(methodName, printData("decryptedData", decryptedData),false);
        // decryptedData is 7 bytes UID || 4 bytes CRC32 || 5 bytes RFU = 00's
        //byte[] cardUid = Arrays.copyOfRange(decryptedData, 0, 7);
        //byte[] crc32Received = Arrays.copyOfRange(decryptedData, 7, 11);
        //log(methodName, printData("cardUid", cardUid),false);
        //log(methodName, printData("crc32 received", crc32Received),false);

        // check crc32 over received DATA (only)
        int cardUidLength = 7;
        //byte[] crc32Calculated = calculateApduCRC32R(decryptedData, cardUidLength);
        //log(methodName, printData("crc32 calcultd", crc32Calculated),false);
        /*
        if (Arrays.equals(crc32Received, crc32Calculated)) {
            log(methodName, "CRC32 matches calculated CRC32", false);
            //writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " CRC32 DOES match calculated CRC32", COLOR_GREEN);
        } else {
            log(methodName, "CRC32 DOES NOT matches calculated CRC32",false);
            //writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " CRC16 DOES NOT matches calculated CRC16", COLOR_RED);
            return null;
        }

         */
        // set the new global IV
        //IV = encryptedData.clone();
        //log(methodName, "new global IV is" + printData("", IV));

        return null;
    }




    /**
     * authenticateAesEv2First uses the EV2First authentication method with command 0x71
     *
     * @param keyNo (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SesAuthENCKey and SesAuthMACKey is NOT tested so far
     * <p>
     * This method is using the AesCmac class for CMAC calculations
     */

    public boolean authenticateAesEv2First(byte keyNo, byte[] key) {

        /**
         * see MIFARE DESFire Light contactless application IC.pdf, pages 27 ff and 55ff
         *
         * Purpose: To start a new transaction
         * Capability Bytes: PCD and PICC capability bytes are exchanged (PDcap2, PCDcap2)
         * Transaction Identifier: A new transaction identifier is generated which remains valid for the full transaction
         * Command Counter: CmdCtr is reset to 0x0000
         * Session Keys: New session keys are generated
         */

        // see example in Mifare DESFire Light Features and Hints AN12343.pdf pages 33 ff
        // and MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 52 ff
        logData = "";
        invalidateAllData();
        String methodName = "authenticateAesEv2First";
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
        log(methodName, "step 01 get encrypted rndB from card", false);
        log(methodName, "This method is using the AUTHENTICATE_AES_EV2_FIRST_COMMAND so it will work with AES-based application only", false);
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            /**
             * note: the parameter needs to be a 2 byte long value, the first one is the key number and the second
             * one could any LEN capability ??
             * I'm setting the byte[] to keyNo | 0x00
             */
            byte[] parameter = new byte[2];
            parameter[0] = keyNo;
            parameter[1] = (byte) 0x00; // is already 0x00
            log(methodName, printData("parameter", parameter), false);
            apdu = wrapMessage(AUTHENTICATE_AES_EV2_FIRST_COMMAND, parameter);
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
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        byte[] rndB_enc = getData(response);
        log(methodName, printData("encryptedRndB", rndB_enc), false);

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        log(methodName, "step 02 iv0 is 16 zero bytes " + printData("iv0", iv0), false);
        log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0), false);
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        log(methodName, printData("rndB", rndB), false);

        log(methodName, "step 04 rotate rndB to LEFT", false);
        byte[] rndB_leftRotated = rotateLeft(rndB);
        log(methodName, printData("rndB_leftRotated", rndB_leftRotated), false);

        // authenticate 2nd part
        log(methodName, "step 05 generate a random rndA", false);
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        log(methodName, printData("rndA", rndA), false);

        log(methodName, "step 06 concatenate rndA | rndB_leftRotated", false);
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated), false);

        // IV is now encrypted RndB received from the tag
        log(methodName, "step 07 iv1 is 16 zero bytes", false);
        byte[] iv1 = new byte[16];
        log(methodName, printData("iv1", iv1), false);

        // Encrypt RndAB_rot
        log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1", false);
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc), false);

        // send encrypted data to PICC
        log(methodName, "step 09 send the encrypted data to the PICC", false);
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu), false);
            response = isoDep.transceive(apdu);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response), false);
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
        // now we know that we can work with the response, response is 32 bytes long
        // R-APDU (Part 2) E(Kx, TI || RndA' || PDcap2 || PCDcap2) || Response Code
        log(methodName, "step 10 received encrypted data from PICC", false);
        byte[] data_enc = getData(response);
        log(methodName, printData("data_enc", data_enc), false);

        //IV is now reset to zero bytes
        log(methodName, "step 11 iv2 is 16 zero bytes", false);
        byte[] iv2 = new byte[16];
        log(methodName, printData("iv2", iv2), false);

        // Decrypt encrypted data
        log(methodName, "step 12 decrypt data_enc with iv2 and key", false);
        byte[] data = AES.decrypt(iv2, key, data_enc);
        log(methodName, printData("data", data), false);
        // data is 32 bytes long, e.g. a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
        /**
         * structure of data
         * full example a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
         *
         * TI transaction information 04 bytes a1487b61
         * rndA LEFT rotated          16 bytes f69cef65a09742b481152325a7cb8fc6
         * PDcap2                     06 bytes 000000000000
         * PCDcap2                    06 bytes 000000000000
         */

        // split data
        byte[] ti = new byte[4]; // LSB notation
        byte[] rndA_leftRotated = new byte[16];
        byte[] pDcap2 = new byte[6];
        byte[] pCDcap2 = new byte[6];
        System.arraycopy(data, 0, ti, 0, 4);
        System.arraycopy(data, 4, rndA_leftRotated, 0, 16);
        System.arraycopy(data, 20, pDcap2, 0, 6);
        System.arraycopy(data, 26, pCDcap2, 0, 6);
        log(methodName, "step 13 full data needs to get split up in 4 values", false);
        log(methodName, printData("data", data), false);
        log(methodName, printData("ti", ti), false);
        log(methodName, printData("rndA_leftRotated", rndA_leftRotated), false);
        log(methodName, printData("pDcap2", pDcap2), false);
        log(methodName, printData("pCDcap2", pCDcap2), false);

        // PCD compares send and received RndA
        log(methodName, "step 14 rotate rndA_leftRotated to RIGHT", false);
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        log(methodName, printData("rndA_received ", rndA_received), false);
        boolean rndAEqual = Arrays.equals(rndA, rndA_received);
        //log(methodName, printData("rndA received ", rndA_received), false);
        log(methodName, printData("rndA          ", rndA), false);
        log(methodName, "rndA and rndA received are equal: " + rndAEqual, false);
        log(methodName, printData("rndB          ", rndB), false);

        log(methodName, "**** auth result ****", false);
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***", false);
            SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
            SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
            log(methodName, printData("SesAuthENCKey ", SesAuthENCKey), false);
            log(methodName, printData("SesAuthMACKey ", SesAuthMACKey), false);
            CmdCounter = 0;
            TransactionIdentifier = ti.clone();
            authenticateEv2FirstSuccess = true;
            keyNumberUsedForAuthentication = keyNo;
        } else {
            log(methodName, "****   FAILURE   ****", false);
            invalidateAllData();
        }
        log(methodName, "*********************", false);
        return rndAEqual;
    }

    /**
     * authenticateAesEv2NonFirst uses the EV2NonFirst authentication method with command 0x77
     *
     * @param keyNo (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SesAuthENCKey and SesAuthMACKey is NOT tested so far
     * <p>
     * This method is using the AesCmac class for CMAC calculations
     */

    public boolean authenticateAesEv2NonFirst(byte keyNo, byte[] key) {
        /**
         * see MIFARE DESFire Light contactless application IC.pdf, pages 27 ff and 55 ff
         * The authentication consists of two parts: AuthenticateEV2NonFirst - Part1 and
         * AuthenticateEV2NonFirst - Part2. Detailed command definition can be found in
         * Section 11.4.2. This command is rejected if there is no active authentication, except if the
         * targeted key is the OriginalityKey. For the rest, the behavior is exactly the same as for
         * AuthenticateEV2First, except for the following differences:
         * • No PCDcap2 and PDcap2 are exchanged and validated.
         * • Transaction Identifier TI is not reset and not exchanged.
         * • Command Counter CmdCtr is not reset.
         * After successful authentication, the PICC remains in EV2 authenticated state. On any
         * failure during the protocol, the PICC ends up in not authenticated state.
         *
         * Purpose: To start a new session within the ongoing transaction
         * Capability Bytes: No capability bytes are exchanged
         * Transaction Identifier: No new transaction identifier is generated (old one remains and is reused)
         * Command Counter: CmdCounter stays active and continues counting from the current value
         * Session Keys: New session keys are generated
         */

        logData = "";
        invalidateAllDataNonFirst();
        String methodName = "authenticateAesEv2NonFirst";
        log(methodName, printData("key", key) + " keyNo: " + keyNo, true);
        errorCode = new byte[2];
        // sanity checks
        if (!authenticateEv2FirstSuccess) {
            Log.e(TAG, methodName + " please run an authenticateEV2First before, aborted");
            log(methodName, "missing previous successfull authenticateEv2First, aborted", false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

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
        log(methodName, "step 01 get encrypted rndB from card", false);
        log(methodName, "This method is using the AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND so it will work with AES-based application only", false);
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            /**
             * note: the parameter needs to be a 1 byte long value, the first one is the key number
             * I'm setting the byte[] to keyNo
             */
            byte[] parameter = new byte[1];
            parameter[0] = keyNo;
            log(methodName, printData("parameter", parameter), false);
            apdu = wrapMessage(AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND, parameter);
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
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        byte[] rndB_enc = getData(response);
        log(methodName, printData("encryptedRndB", rndB_enc), false);

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        log(methodName, "step 02 iv0 is 16 zero bytes " + printData("iv0", iv0), false);
        log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0), false);
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        log(methodName, printData("rndB", rndB), false);

        log(methodName, "step 04 rotate rndB to LEFT", false);
        byte[] rndB_leftRotated = rotateLeft(rndB);
        log(methodName, printData("rndB_leftRotated", rndB_leftRotated), false);

        // authenticate 2nd part
        log(methodName, "step 05 generate a random rndA", false);
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        log(methodName, printData("rndA", rndA), false);

        log(methodName, "step 06 concatenate rndA | rndB_leftRotated", false);
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated), false);

        // IV is now encrypted RndB received from the tag
        log(methodName, "step 07 iv1 is 16 zero bytes", false);
        byte[] iv1 = new byte[16];
        log(methodName, printData("iv1", iv1), false);

        // Encrypt RndAB_rot
        log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1", false);
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc), false);

        // send encrypted data to PICC
        log(methodName, "step 09 send the encrypted data to the PICC", false);
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu), false);
            response = isoDep.transceive(apdu);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response), false);
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
        // now we know that we can work with the response, response is 16 bytes long
        // R-APDU (Part 2) E(Kx, RndA' || Response Code
        log(methodName, "step 10 received encrypted data from PICC", false);
        byte[] data_enc = getData(response);
        log(methodName, printData("data_enc", data_enc), false);

        //IV is now reset to zero bytes
        log(methodName, "step 11 iv2 is 16 zero bytes", false);
        byte[] iv2 = new byte[16];
        log(methodName, printData("iv2", iv2), false);

        // Decrypt encrypted data
        log(methodName, "step 12 decrypt data_enc with iv2 and key", false);
        byte[] data = AES.decrypt(iv2, key, data_enc);
        log(methodName, printData("data", data), false);
        // data is 32 bytes long, e.g. a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
        /**
         * structure of data
         * full example 55c4421b4db67d0777c2f9116bcd6b1a
         *
         * rndA LEFT rotated          16 bytes 55c4421b4db67d0777c2f9116bcd6b1a
         */

        // split data not necessary, data is rndA_leftRotated
        byte[] rndA_leftRotated = data.clone();
        log(methodName, "step 13 full data is rndA_leftRotated only", false);
        log(methodName, printData("rndA_leftRotated", rndA_leftRotated), false);

        // PCD compares send and received RndA
        log(methodName, "step 14 rotate rndA_leftRotated to RIGHT", false);
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        log(methodName, printData("rndA_received ", rndA_received), false);
        boolean rndAEqual = Arrays.equals(rndA, rndA_received);

        //log(methodName, printData("rndA received ", rndA_received), false);
        log(methodName, printData("rndA          ", rndA), false);
        log(methodName, "rndA and rndA received are equal: " + rndAEqual, false);
        log(methodName, printData("rndB          ", rndB), false);
        log(methodName, "**** auth result ****", false);
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***", false);
            SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
            SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
            log(methodName, printData("SesAuthENCKey ", SesAuthENCKey), false);
            log(methodName, printData("SesAuthMACKey ", SesAuthMACKey), false);
            //CmdCounter = 0; // is not resetted in EV2NonFirst
            //TransactionIdentifier = ti.clone(); // is not resetted in EV2NonFirst
            authenticateEv2NonFirstSuccess = true;
            keyNumberUsedForAuthentication = keyNo;
        } else {
            log(methodName, "****   FAILURE   ****", false);
            invalidateAllData();
        }
        log(methodName, "*********************", false);
        return rndAEqual;
    }

    /**
     * section for key handling and byte operations
     */


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

    // converts an int to a 2 byte long array inversed = LSB
    public static byte[] intTo2ByteArrayInversed(int value) {
        return new byte[] {
                (byte)value,
                (byte)(value >> 8)};
    }

    public boolean getSesAuthKeyTest() {
        /**
         * this will test the function using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf pages 33 - 35
         */

        byte[] rndA = Utils.hexStringToByteArray("B04D0787C93EE0CC8CACC8E86F16C6FE");
        byte[] rndB = Utils.hexStringToByteArray("FA659AD0DCA738DD65DC7DC38612AD81");
        byte[] authenticationKey = Utils.hexStringToByteArray("00000000000000000000000000000000");
        byte[] SesAuthENCKey_expected = Utils.hexStringToByteArray("63DC07286289A7A6C0334CA31C314A04");
        byte[] SesAuthMACKey_expected = Utils.hexStringToByteArray("774F26743ECE6AF5033B6AE8522946F6");
        byte[] SesAuthENCKey = getSesAuthEncKey(rndA, rndB, authenticationKey);
        byte[] SesAuthMACKey = getSesAuthMacKey(rndA, rndB, authenticationKey);
        if ((Arrays.equals(SesAuthENCKey_expected, SesAuthENCKey)) && (Arrays.equals(SesAuthMACKey_expected, SesAuthMACKey))) {
            Log.d(TAG, "getSesAuthKeyTest SUCCESS");
            return true;
        } else {
            Log.d(TAG, "getSesAuthKeyTest FAILURE");
            return false;
        }
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
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey), false);
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted", false);
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted", false);
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted", false);
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
        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndA02to07", rndA02to07), false);
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("rndB00to05", rndB00to05), false);
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored), false);
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("cmacInput", cmacInput), false);
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv), false);
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac), false);
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
        log(methodName, printData("rndA", rndA) + printData(" rndB", rndB) + printData(" authenticationKey", authenticationKey), false);
        // sanity checks
        if ((rndA == null) || (rndA.length != 16)) {
            log(methodName, "rndA is NULL or wrong length, aborted", false);
            return null;
        }
        if ((rndB == null) || (rndB.length != 16)) {
            log(methodName, "rndB is NULL or wrong length, aborted", false);
            return null;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 16)) {
            log(methodName, "authenticationKey is NULL or wrong length, aborted", false);
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
        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndA02to07", rndA02to07), false);
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("rndB00to05", rndB00to05), false);
        byte[] xored = xor(rndA02to07, rndB00to05);
        log(methodName, printData("xored     ", xored), false);
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        log(methodName, printData("rndA     ", rndA), false);
        log(methodName, printData("rndB     ", rndB), false);
        log(methodName, printData("cmacInput", cmacInput), false);
        byte[] iv = new byte[16];
        log(methodName, printData("iv       ", iv), false);
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        log(methodName, printData("cmacOut ", cmac), false);
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

    /**
     * copied from DESFireEV1.java class
     * necessary for calculation the new IV for decryption of getCardUid
     *
     * @param apdu
     * @param sessionKey
     * @param iv
     * @return
     */
    private byte[] calculateApduCMAC(byte[] apdu, byte[] sessionKey, byte[] iv) {
        Log.d(TAG, "calculateApduCMAC" + printData(" apdu", apdu) +
                printData(" sessionKey", sessionKey) + printData(" iv", iv));
        byte[] block;

        if (apdu.length == 5) {
            block = new byte[apdu.length - 4];
        } else {
            // trailing 00h exists
            block = new byte[apdu.length - 5];
            System.arraycopy(apdu, 5, block, 1, apdu.length - 6);
        }
        block[0] = apdu[1];
        Log.d(TAG, "calculateApduCMAC" + printData(" block", block));
        //byte[] newIv = desfireAuthenticateProximity.calculateDiverseKey(sessionKey, iv);
        //return newIv;
        byte[] cmacIv = CMAC.get(CMAC.Type.AES, sessionKey, block, iv);
        Log.d(TAG, "calculateApduCMAC" + printData(" cmacIv", cmacIv));
        return cmacIv;
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
        log("getData", printData("responseData", data), false);
        return data;
    }

    /**
     * section for service methods
     */

    private void invalidateAllData() {
        authenticateEv2FirstSuccess = false;
        authenticateEv2NonFirstSuccess = false;
        keyNumberUsedForAuthentication = -1;
        SesAuthENCKey = null; // filled by authenticateAesEv2First
        SesAuthMACKey = null; // filled by authenticateAesEv2First
        CmdCounter = 0; // filled / resetted by authenticateAesEv2First
        TransactionIdentifier = null; // resetted by authenticateAesEv2First
    }

    private void invalidateAllDataNonFirst() {
        // authenticateEv2FirstSuccess = false; skip out, is necessary for the NonFirst method
        authenticateEv2NonFirstSuccess = false;
        keyNumberUsedForAuthentication = -1;
        SesAuthENCKey = null; // filled by authenticateAesEv2First
        SesAuthMACKey = null; // filled by authenticateAesEv2First
        //CmdCounter = 0; // filled / resetted by authenticateAesEv2First
        //TransactionIdentifier = null; // resetted by authenticateAesEv2First
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


    public boolean isAuthenticateEv2FirstSuccess() {
        return authenticateEv2FirstSuccess;
    }

    public boolean isAuthenticateEv2NonFirstSuccess() {
        return authenticateEv2NonFirstSuccess;
    }

    public int getKeyNumberUsedForAuthentication() {
        return keyNumberUsedForAuthentication;
    }

    public byte[] getSesAuthENCKey() {
        return SesAuthENCKey;
    }

    public byte[] getSesAuthMACKey() {
        return SesAuthMACKey;
    }

    public int getCmdCounter() {
        return CmdCounter;
    }

    public byte[] getTransactionIdentifier() {
        return TransactionIdentifier;
    }

}
