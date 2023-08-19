package de.androidcrypto.talktoyourdesfirecard;


import android.nfc.tech.IsoDep;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

import de.androidcrypto.talktoyourdesfirecard.nfcjlib.TripleDES;

/**
 * This class is the light weight version of a larger library that connects to Mifare DESFire D40 tags ('legacy').
 * It contains all commands that are necessary to format a PICC (select Master Application and authenticateD40)
 * Note: This class is no longer maintained so use with extreme care.
 */

public class DesfireD40Light {

    private static final String TAG = DesfireD40Light.class.getName();

    private IsoDep isoDep;
    private String logData;
    private boolean printToLog = true; // print data to log
    private byte[] selectedApplicationIdentifier;

    private boolean authenticateLegacyD40Success = false;
    private byte keyNumberUsedForAuthentication = -1;
    private byte[] SessionKey;
    private byte[] errorCode = new byte[2];
    private String errorCodeReason = "";


    /**
     * some constants
     */
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte AUTHENTICATE_DES_2K3DES_COMMAND = (byte) 0x0A;
    private final byte FORMAT_PICC_COMMAND = (byte) 0xFC;

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFE};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    public static final byte[] MASTER_APPLICATION_IDENTIFIER = new byte[3];
    public final byte[] MASTER_APPLICATION_KEY_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    public final byte MASTER_APPLICATION_KEY_NUMBER = (byte) 0x00;

    public DesfireD40Light(IsoDep isoDep) {
        this.isoDep = isoDep;
        Log.i(TAG, "class is initialized");
    }

    /**
     * section for application handling
     */

    /**
     * Although the selectApplication does not require any authentication or encryption features this
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
        log(methodName, "trying to authenticate with MASTER_APPLICATION_KEY_NUMBER 00 DES DEFAULT");
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

    public byte getKeyNumberUsedForAuthentication() {
        return keyNumberUsedForAuthentication;
    }
}
