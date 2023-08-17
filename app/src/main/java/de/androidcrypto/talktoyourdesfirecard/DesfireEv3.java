package de.androidcrypto.talktoyourdesfirecard;


import static de.androidcrypto.talktoyourdesfirecard.DesfireAuthenticateEv2.intTo2ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.hexStringToByteArray;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.util.Log;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AccessControlException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import de.androidcrypto.talktoyourdesfirecard.nfcjlib.AES;

/**
 * This class is the full library that connects to Mifare DESFire EV1/EV2/EV3 tags for these commands:
 * - create (*1), select and delete (*2) an AES key based application
 * - authenticate with AES keys using 'authenticateEV2First' and 'authenticateEV2NonFirst'
 * - create and delete (*2) a Standard file with communication mode Plain or Full enciphered (but not MACed)
 * - write to and read from a Standard file in communication modes Plain and Full enciphered (but not MACed) (*3)
 *
 *
 * supported service methods:
 * - getVersion (version of the attached PICC)
 * - getFreeMemory of the PICC
 * - getFileId and getFileSettings of all file types within an application
 * - format the PICC
 * - getKeyVersion (version of an authentication key)
 * - changeApplicationKey (but not the MasterApplicationKey)
 * - changeApplicationSettings (but not for the  MasterApplication to avoid any damage of the tag)
 * - changeFileSettings
 *
 *
 * For DESFire EV3 only:
 * It contains all commands that are necessary to enable the Secret Unique NFC (SUN) feature that is
 * based on Secure Dynamic Messaging (SDM) that is available on DESFire EV3 tags only:
 * - createApplicationAesIso (adding an ISO application identifier and ISO Data File Name)
 * - createNdefContainerFile (having a dedicated fileNumber for NDEF usage)
 * - writeNdefContainer
 * - createStandardFileIso (adding an ISO fileNumber and ISO fileName with communication mode Plain only
 * - write a NDEF message containing an URL/Link record with communication mode Plain only
 *
 * (*1): using fixed application settings '0x0f' meaning Application master key authentication is necessary to change any key (default),
 *       the configuration is changeable if authenticated with the application master key (default setting)
 *       CreateFile / DeleteFile is permitted also without application master key authentication (default setting)
 *       GetFileIDs, GetFileSettings and GetKeySettings commands succeed independently of a preceding application master key authentication (default setting)
 *       Application master key is changeable (authentication with the current application master key necessary, default setting)
 *       You change this later using changeApplicationSettings
 *       The number of AES application keys is fixed to 5 to support the different access key rights that are set to (access rights can be changed later):
 *       key number 0 = Application Master Key
 *       key number 1 = Read & Write Access key
 *       key number 2 = Change Access rights key (CAR)
 *       key number 3 = Read Access key
 *       key number 4 = Write Access key
 * (*2): A deletion of an application or file does NOT release the (memory) space on the tag, that does happen on formatting the PICC only
 * (*3): by reading of the fileSettings the method automatically detects and selects the communication mode
 *
 * Not supported commands so far:
 * - working with Backup, Value, Linear Record, Cyclic Record and Transaction MAC files
 * - authentication using LRP ('authenticateLrpEV2First' and 'authenticateLrpEV2NonFirst')
 * - Communication mode MACed
 * - change MasterApplicationKey (not supported to avoid any damage of the tag)
 *
 */

public class DesfireEv3 {

    private static final String TAG = DesfireEv3.class.getName();


    private IsoDep isoDep;
    private String logData;
    private boolean authenticateEv2FirstSuccess = false;
    private boolean authenticateEv2NonFirstSuccess = false;
    private byte keyNumberUsedForAuthentication = -1;
    private byte[] SesAuthENCKey; // filled by authenticateAesEv2First
    private byte[] SesAuthMACKey; // filled by authenticateAesEv2First
    private int CmdCounter = 0; // filled / reset by authenticateAesEv2First
    private byte[] TransactionIdentifier; // reset by authenticateAesEv2First
    // note on TransactionIdentifier: LSB encoding
    private byte[] errorCode = new byte[2];
    private String errorCodeReason = "";

    /**
     * external constants for NDEF application and files
     */

    public static final byte[] NDEF_APPLICATION_IDENTIFIER = Utils.hexStringToByteArray("010000"); // this is the AID for NDEF application
    public static final byte[] NDEF_ISO_APPLICATION_IDENTIFIER = Utils.hexStringToByteArray("10E1"); // this is the ISO AID for NDEF application
    public static final byte[] NDEF_APPLICATION_DF_NAME = Utils.hexStringToByteArray("D2760000850101"); // this is the Data File name for NDEF application
    public static final byte NDEF_FILE_01_NUMBER = (byte) 0x01;
    public static final byte[] NDEF_FILE_01_ISO_NAME = Utils.hexStringToByteArray("03E1");
    //public static final byte[] NDEF_FILE_01_ACCESS_RIGHTS = Utils.hexStringToByteArray("EEEE"); // free access to all rights
    public static final byte[] NDEF_FILE_01_ACCESS_RIGHTS = Utils.hexStringToByteArray("E0EE"); // free access to all rights except CAR (key 0)
    public static final int NDEF_FILE_01_SIZE = 15;
    private final byte[] NDEF_FILE_01_CONTENT_CONTAINER = Utils.hexStringToByteArray("000F20003A00340406E10401000000"); // 256 byte
    public static final byte NDEF_FILE_02_NUMBER = (byte) 0x02;
    public static final byte[] NDEF_FILE_02_ISO_NAME = Utils.hexStringToByteArray("04E1");
    public static final byte[] NDEF_FILE_02_ACCESS_RIGHTS = Utils.hexStringToByteArray("00EE"); // free access for reading and writing, an authentication is needed for all other accesses
    public static final int NDEF_FILE_02_SIZE = 256;
    public static final int MAXIMUM_FILE_SIZE = 256; // this is fixed by me, could as long as about free memory of the tag


    /**
     * constants for commands
     */

    private final byte AUTHENTICATE_AES_EV2_FIRST_COMMAND = (byte) 0x71;
    private final byte AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND = (byte) 0x77;
    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte GET_VERSION_INFO_COMMAND = (byte) 0x60;
    private final byte CREATE_APPLICATION_COMMAND = (byte) 0xCA;
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte GET_FILE_IDS_COMMAND = (byte) 0x6F;
    private final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private final byte CHANGE_KEY_SECURE_COMMAND = (byte) 0xC4;
    private static final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;

    /**
     * class internal constants and limitations
     */
    boolean printToLog = true; // logging data in internal log string

    private final byte APPLICATION_MASTER_KEY_SETTINGS = (byte) 0x0F; // 'amks' all default values
    private final byte APPLICATION_CRYPTO_DES = 0x00; // add this to number of keys for DES
    //private final byte APPLICATION_CRYPTO_3KTDES = (byte) 0x40; // add this to number of keys for 3KTDES
    //private final byte APPLICATION_CRYPTO_AES = (byte) 0x80; // add this to number of keys for AES
    private final byte APPLICATION_CRYPTO_AES = (byte) 0xA0; // add this to number of keys for AES
    private final byte FILE_COMMUNICATION_SETTINGS_PLAIN = (byte) 0x00; // plain communication
    private final byte FILE_COMMUNICATION_SETTINGS_MACED = (byte) 0x01; // mac'ed communication
    private final byte FILE_COMMUNICATION_SETTINGS_FULL = (byte) 0x03; // full = enciphered communication
    private final int MAXIMUM_MESSAGE_LENGTH = 40;
    private static final byte MAXIMUM_NUMBER_OF_KEYS = 5; // the maximum of keys per application is 14
    private final int MAXIMUM_NUMBER_OF_FILES = 32; // as per datasheet DESFire EV3 this is valid for EV1, EV2 and EV3

    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_ISO_OK = new byte[]{(byte) 0x90, (byte) 0x00};
    private final byte[] RESPONSE_PERMISSION_DENIED_ERROR = new byte[]{(byte) 0x91, (byte) 0x9D};
    public static final byte[] RESPONSE_DUPLICATE_ERROR = new byte[]{(byte) 0x91, (byte) 0xDE};
    public static final byte[] RESPONSE_ISO_DUPLICATE_ERROR = new byte[]{(byte) 0x90, (byte) 0xDE};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFD};
    private static final byte[] RESPONSE_PARAMETER_ERROR = new byte[]{(byte) 0x91, (byte) 0xFE}; // failure because of wrong parameter
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure

    private final byte[] HEADER_ENC = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
    private final byte[] HEADER_MAC = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0x5AA5
    private final byte[] PADDING_FULL = hexStringToByteArray("80000000000000000000000000000000");

    /**
     * standard file
     */

    private byte[] selectedApplicationId; // filled by 'select application'
    private static byte[] APPLICATION_ALL_FILE_IDS; // filled by getAllFileIds and invalidated by selectApplication AND createFile
    private static FileSettings[] APPLICATION_ALL_FILE_SETTINGS; // filled by getAllFileSettings and invalidated by selectApplication AND createFile
    private FileSettings selectedFileSetting; // takes the fileSettings of the actual file
    private FileSettings[] fileSettingsArray = new FileSettings[MAXIMUM_NUMBER_OF_FILES]; // after an 'select application' the fileSettings of all files are read

    public enum CommunicationSettings {
        Plain, MACed, Full
    }


    public DesfireEv3(IsoDep isoDep) {
        this.isoDep = isoDep;
        Log.i(TAG, "class is initialized");
    }

    /**
     * section for application handling
     */

    /**
     * create a new application including ISO application identifier and ISO Data File Name using AES keys
     * This uses a fixed Application Master Key Settings value of 0x0F which is default value
     * @param applicationIdentifier   | length 3
     * @param applicationDfName       | length in range 1..16
     * @param numberOfApplicationKeys | range 1..14
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createApplicationAesIso(byte[] applicationIdentifier, byte[] isoApplicationIdentifier, byte[] applicationDfName, CommunicationSettings communicationSettings, int numberOfApplicationKeys) {
        String logData = "";
        final String methodName = "createApplicationAesIso";
        log(methodName, "started", true);
        log(methodName, printData("applicationIdentifier", applicationIdentifier));
        log(methodName, printData("isoApplicationIdentifier", isoApplicationIdentifier));
        log(methodName, printData("applicationDfName", applicationDfName));
        //log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "numberOfApplicationKeys: " + numberOfApplicationKeys);
        // sanity checks
        if (!checkApplicationIdentifier(applicationIdentifier)) return false; // logFile and errorCode are updated
        if ((isoApplicationIdentifier == null) || (isoApplicationIdentifier.length != 2)) {
            log(methodName, "isoApplicationIdentifier is NULL or not of length 2, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "isoApplicationIdentifier is NULL or not of length 2";
            return false;
        }
        if ((applicationDfName == null) || (applicationDfName.length < 1) || (applicationDfName.length > 16)) {
            log(methodName, "applicationDfName is NULL or not of length range 1..16, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "applicationDfName is NULL or not length range 1..16";
            return false;
        }
        if ((numberOfApplicationKeys < 1) || (numberOfApplicationKeys > 14)) {
            log(methodName, "numberOfApplicationKeys is not in range 1..14, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "numberOfApplicationKeys is not in range 1..14";
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // build the command string
        byte keyNumbers = (byte) numberOfApplicationKeys;
        // now adding the constant for key type, here fixed to AES = 0x80
        keyNumbers = (byte) (keyNumbers | APPLICATION_CRYPTO_AES);
        // "90CA00000E 010000 0F A5 10E1 D276000085010100"
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, applicationIdentifier.length);
        baos.write(APPLICATION_MASTER_KEY_SETTINGS); // application master key settings, fixed value
        baos.write(keyNumbers);
        baos.write(isoApplicationIdentifier, 0, isoApplicationIdentifier.length);
        baos.write(applicationDfName, 0, applicationDfName.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;

        try {
            apdu = wrapMessage(CREATE_APPLICATION_COMMAND, commandParameter);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            return false;
        }
    }

    /**
     * select an application by it's application identifier (AID)
     * @param applicationIdentifier | length 3
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean selectApplicationByAid(byte[] applicationIdentifier) {
        final String methodName = "selectApplication by AID";
        logData = "";
        log(methodName, "started", true);
        log(methodName, printData("applicationIdentifier", applicationIdentifier));
        errorCode = new byte[2];
        // sanity checks
        if (!checkApplicationIdentifier(applicationIdentifier)) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(SELECT_APPLICATION_COMMAND, applicationIdentifier);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            return false;
        }
    }

    /**
     * section for file handling
     */

    /**
     * create a Standard file in selected application using file Number and ISO fileId
     * @param fileNumber            | in range 0..31
     * @param isoFileId
     * @param communicationSettings | Plain, MACed or Full
     * @param accessRights          | Read & Write access key, CAR ke, Read key, Write key
     * @param fileSize              | maximum of 256 bytes
     * @param preEnableSdm          | set to true if you (later) want to enable SDM. If you don't set this on file creation it cannot get enabled later.
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createStandardFileIso(byte fileNumber, byte[] isoFileId, CommunicationSettings communicationSettings, byte[] accessRights, int fileSize, boolean preEnableSdm) {
        final String methodName = "createStandardFileIso";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("isoFileId", isoFileId));
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "fileSize: " + fileSize);
        log(methodName, "preEnableSdm: " + preEnableSdm);
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((isoFileId == null) || (isoFileId.length != 2)) {
            log(methodName, "isoFileId is NULL or not of length range 2, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "applicationDfName is NULL or not length range 1..16";
            return false;
        }
        if (!checkAccessRights(accessRights)) return false; // logFile and errorCode are updated
        if ((fileSize < 1) || (fileSize > MAXIMUM_FILE_SIZE)) {
            log(methodName, "fileSize is not in range 1..MAXIMUM_FILE_SIZE, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "fileSize is not in range 1..MAXIMUM_FILE_SIZE";
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.Plain) commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed) commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full) commSettings = FILE_COMMUNICATION_SETTINGS_FULL;
        // add 0x40 for pre-enabled SDM
        if (preEnableSdm) {
            commSettings = (byte) (commSettings | (byte) 0x40);
        }

        byte[] fileSizeByte = Utils.intTo3ByteArrayInversed(fileSize);
        // build the command string
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(isoFileId, 0, isoFileId.length);
        baos.write(commSettings);
        baos.write(accessRights, 0, accessRights.length);
        baos.write(fileSizeByte, 0, fileSizeByte.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;

        try {
            apdu = wrapMessage(CREATE_STANDARD_FILE_COMMAND, commandParameter);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            return false;
        }
    }

    /**
     * writes the NDEF container to a Standard file in the selected application. It uses the pre-defined
     * NDEF container that points to the NDEF Data file with fileNumber 02 and isoFileId 0x04E1
     * For writing it uses the 'writeToStandardFileRawPlain' method and as the data is less than
     * MAXIMUM_MESSAGE_LENGTH there is no need for chunking the data
     * @param fileNumber
     * @return
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean writeToStandardFileNdefContainerPlain(byte fileNumber) {
        String logData = "";
        final String methodName = "writeToStandardFileNdefContainerPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);

        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        return writeToStandardFileRawPlain(fileNumber, 0, NDEF_FILE_01_CONTENT_CONTAINER);
    }

    /**
     * writes an Url as NDEF Link record/message to a Standard File. If the complete NDEF message
     * exceeds the MAXIMUM_MESSAGE_LENGTH the data are written in chunks to avoid framing
     * The maximum NDEF message length is 256 bytes so the URL needs to be some characters smaller
     * as there is an overhead for NDEF handling.
     * THe URL should point to a webserver that can handle SUN/SDM messages
     * @param fileNumber    | in range 0..31
     * @param urlToWrite
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean writeToStandardFileUrlPlain(byte fileNumber, String urlToWrite) {
        String logData = "";
        final String methodName = "writeToStandardFileUrlPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "urlToWrite: " + urlToWrite);
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if (!Utils.isValidUrl(urlToWrite)) {
            log(methodName, "invalid urlToWrite, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "invalid urlToWrite";
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // adding NDEF wrapping
        NdefRecord ndefRecord = NdefRecord.createUri(urlToWrite);
        NdefMessage ndefMessage = new NdefMessage(ndefRecord);
        byte[] ndefMessageBytesHeadless = ndefMessage.toByteArray();
        // now we do have the NDEF message but it needs to get wrapped by '0x00 || (byte) (length of NdefMessage)
        byte[] data = new byte[ndefMessageBytesHeadless.length + 2];
        System.arraycopy(new byte[]{(byte) 0x00, (byte) (ndefMessageBytesHeadless.length)}, 0, data, 0, 2);
        System.arraycopy(ndefMessageBytesHeadless, 0, data, 2, ndefMessageBytesHeadless.length);
        if (data.length > MAXIMUM_FILE_SIZE) {
            log(methodName, "NDEF message exceeds MAXIMUM_FILE_SIZE, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "NDEF message exceeds MAXIMUM_FILE_SIZE";
            return false;
        }
        return writeToStandardFilePlain(fileNumber, data);
    }

    /**
     * This method will write the Template URL string to the NDEF-File 02. If the templateUrl
     * exceeds the maximum length for writing it will chunk the complete message into several parts
     *
     * @param templateUrl
     * @return true on success
     */
    /*
    public boolean writeToNdefFile2(String templateUrl) {

        // status:

        String logData = "";
        final String methodName = "writeToNdefFile2Iso";
        log(methodName, "started", true);
        log(methodName, "templateUrl: " + templateUrl);

        if (!Utils.isValidUrl(templateUrl)) {
            Log.d(TAG, "inValid templateURL, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            return false;
        }

        // adding NDEF wrapping
        NdefRecord ndefRecord = NdefRecord.createUri(templateUrl);
        NdefMessage ndefMessage = new NdefMessage(ndefRecord);
        byte[] ndefMessageBytesHeadless = ndefMessage.toByteArray();
        // now we do have the NDEF message but it needs to get wrapped by '0x00 || (byte) (length of NdefMessage)
        byte[] data = new byte[ndefMessageBytesHeadless.length + 2];
        System.arraycopy(new byte[]{(byte) 0x00, (byte) (ndefMessageBytesHeadless.length)}, 0, data, 0, 2);
        System.arraycopy(ndefMessageBytesHeadless, 0, data, 2, ndefMessageBytesHeadless.length);
        Log.d(TAG, printData("NDEF Message bytes", data));

        // depending on ndefMessageBytes length we need to send several write commands
        // this is due to avoid framing as the maximum command APDU length is limited to 66
        // bytes including all overhead and attached MAC
        int dataLength = data.length;

        int numberOfWrites = dataLength / MAXIMUM_MESSAGE_LENGTH;
        int numberOfWritesMod = Utils.mod(dataLength, MAXIMUM_MESSAGE_LENGTH);
        if (numberOfWritesMod > 0) numberOfWrites++; // one extra write for the remainder
        Log.d(TAG, "data length: " + dataLength + " numberOfWrites: " + numberOfWrites);
        boolean completeSuccess = true;
        int offset = 0;
        int numberOfDataToWrite = MAXIMUM_MESSAGE_LENGTH; // we are starting with a maximum length
        for (int i = 0; i < numberOfWrites; i++) {
            if (offset + numberOfDataToWrite > dataLength) {
                numberOfDataToWrite = dataLength - offset;
            }
            byte[] dataToWrite = Arrays.copyOfRange(data, offset, (offset + numberOfDataToWrite));
            boolean success = writeToStandardFileMax40Plain(NDEF_DATA_FILE_NUMBER, dataToWrite, offset);
            offset = offset + numberOfDataToWrite;
            if (!success) {
                completeSuccess = false;
                Log.e(TAG, methodName + " could not successfully write, aborted");
                log(methodName, "could not successfully write, aborted");
                System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
                return false;
            }
        }
        System.arraycopy(RESPONSE_OK, 0, errorCode, 0, 2);
        log(methodName, "SUCCESS");
        return true;
    }
*/

    /**
     * The method writes a byte array to a Standard file using CommunicationMode.Plain. If the data
     * length exceeds the MAXIMUM_MESSAGE_LENGTH the data will be written in chunks.
     * If the data length exceeds MAXIMUM_FILE_LENGTH the methods returns a FAILURE
     * @param fileNumber | in range 0..31 AND file is a Standard file
     * @param data
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */
    public boolean writeToStandardFilePlain(byte fileNumber, byte[] data) {
        String logData = "";
        final String methodName = "writeToStandardFilePlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("data", data));
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((data == null) || (data.length < 1) || (data.length > MAXIMUM_FILE_SIZE)) {
            log(methodName, "data length exceeds MAXIMUM_FILE_SIZE, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "data length exceeds MAXIMUM_FILE_SIZE";
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // The chunking is done to avoid framing as the maximum command APDU length is limited to 66
        // bytes including all overhead and attached MAC
        int dataLength = data.length;
        int numberOfWrites = dataLength / MAXIMUM_MESSAGE_LENGTH;
        int numberOfWritesMod = Utils.mod(dataLength, MAXIMUM_MESSAGE_LENGTH);
        if (numberOfWritesMod > 0) numberOfWrites++; // one extra write for the remainder
        Log.d(TAG, "data length: " + dataLength + " numberOfWrites: " + numberOfWrites);
        boolean completeSuccess = true;
        int offset = 0;
        int numberOfDataToWrite = MAXIMUM_MESSAGE_LENGTH; // we are starting with a maximum length
        for (int i = 0; i < numberOfWrites; i++) {
            if (offset + numberOfDataToWrite > dataLength) {
                numberOfDataToWrite = dataLength - offset;
            }
            byte[] dataToWrite = Arrays.copyOfRange(data, offset, (offset + numberOfDataToWrite));
            boolean success = writeToStandardFileRawPlain(fileNumber, offset, dataToWrite);
            offset = offset + numberOfDataToWrite;
            if (!success) {
                completeSuccess = false;
                Log.e(TAG, methodName + " could not successfully write, aborted");
                log(methodName, "could not successfully write, aborted");
                System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
                return false;
            }
        }
        System.arraycopy(RESPONSE_OK, 0, errorCode, 0, 2);
        log(methodName, "SUCCESS");
        return true;
    }

    /**
     * writes a byte array to a Standard file, beginning at offset position
     * This works for a Standard file with CommunicationMode.Plain only
     * Note: as the number of bytes is limited per transmission this method limits the amount
     * of data to a maximum of MAXIMUM_MESSAGE_LENGTH bytes
     * The method does not take care of the offset so 'offset + data.length <= file size' needs to obeyed
     * Do NOT CALL this method from outside this class but use one of the writeToStandardFile callers
     * as it uses the pre-read fileSettings
     * @param fileNumber | in range 0..31 AND file is a Standard file
     * @param data       | maximum of 40 bytes to avoid framing
     * @param offset     | offset in the file
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */
    private boolean writeToStandardFileRawPlain(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToStandardFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + Utils.printData(" data", data) + " offset: " + offset);

        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((data == null) || (data.length > 40)) {
            Log.e(TAG, methodName + " data is NULL or length is > 40, aborted");
            log(methodName, "data is NULL or length is > 40, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            return false;
        }
        if (offset < 0) {
            Log.e(TAG, methodName + " offset is < 0, aborted");
            log(methodName, "offset is < 0, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            return false;
        }
        // getFileSettings for file type and length information
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        int fileSize = fileSettings.getFileSizeInt();
        if (data.length > fileSize) {
            Log.e(TAG, methodName + " data length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            return false;
        }
        if (!Objects.equals(fileSettings.getFileTypeName(), FileSettings.STANDARD_FILE_TYPE)) {
            Log.e(TAG, methodName + " fileType is not a Standard file, aborted");
            log(methodName, "fileType is not a Standard file, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset);
        byte[] lengthOfDataBytes = Utils.intTo3ByteArrayInversed(data.length);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offsetBytes, 0, offsetBytes.length);
        baos.write(lengthOfDataBytes, 0, lengthOfDataBytes.length);
        baos.write(data, 0, data.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_COMMAND, commandParameter);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    /**
     * reads a Standard file in communication mode Plain from the beginning (offset = 0)
     * @param fileNumber
     * @param length
     * @return
     */
    public byte[] readStandardFilePlain(byte fileNumber, int length) {
        return readFromStandardFileRawPlain(fileNumber, 0, length);
    }


    /**
     * Read data from a Standard file, beginning at offset position and length of data.
     * As the amount of data that can be send from PICC to reader is limited the PCC will chunk the
     * data if exceeding this limit. The method automatically detects this behaviour and send the
     * necessary commands to get all data.
     * DO NOT CALL this method from outside this class but use one of the ReadFromStandardFile callers
     * as it uses the pre-read fileSettings
     * @param fileNumber | in range 0..31
     * @param offset     | offset in the file
     * @param length     | length of data > 1
     * @return the read data or NULL
     * Note: check errorCode and errorCodeReason in case of failure
     */

    private byte[] readFromStandardFileRawPlain(byte fileNumber, int offset, int length) {
        String logData = "";
        final String methodName = "readFromStandardFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null; // logFile and errorCode are updated
        if (offset < 0) {
            Log.e(TAG, methodName + " offset is < 0, aborted");
            log(methodName, "offset is < 0, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            return null;
        }
        // getFileSettings for file type and length information
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            return null;
        }
        if (!Objects.equals(fileSettings.getFileTypeName(), FileSettings.STANDARD_FILE_TYPE)) {
            Log.e(TAG, methodName + " fileType is not a Standard file, aborted");
            log(methodName, "fileType is not a Standard file, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            return null;
        }


        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        // generate the parameter
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offsetBytes, 0, offsetBytes.length);
        baos.write(lengthBytes, 0, lengthBytes.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] response;
        response = sendRequest(READ_STANDARD_FILE_COMMAND, commandParameter);
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (!checkResponse(response)) {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        errorCode = RESPONSE_OK.clone();
        errorCodeReason = "SUCCESS";
        return getData(response);
    }

    /**
     * section for files in general
     */

    /**
     * get the file numbers of all files within an application
     * Note: depending on the application master key settings this requires an preceding authentication
     * with the application master key
     *
     * @return an array of bytes with all available fileIds
     */
    public byte[] getAllFileIds() {
        final String methodName = "getAllFileIDs";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];
        // sanity checks
        if ((selectedApplicationId == null) || (selectedApplicationId.length != 3)) {
            Log.e(TAG, methodName + " select an application first, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(GET_FILE_IDS_COMMAND, null);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
        System.arraycopy(returnStatusBytes(response), 0, errorCode, 0, 2);
        byte[] responseData = Arrays.copyOfRange(response, 0, response.length - 2);
        if (checkResponse(response)) {
            Log.d(TAG, "response SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            APPLICATION_ALL_FILE_IDS = responseData.clone();
            return responseData;
        } else {
            Log.d(TAG, "response FAILURE");
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
    }

    /**
     * get the file numbers of all files within an application
     * Note: depending on the application master key settings this requires an preceding authentication
     * with the application master key
     *
     * @return an array of bytes with all available fileIds
     */
    public FileSettings[] getAllFileSettings() {
        final String methodName = "getAllFileSettings";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];
        // sanity checks
        if ((selectedApplicationId == null) || (selectedApplicationId.length != 3)) {
            Log.e(TAG, methodName + " select an application first, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if (APPLICATION_ALL_FILE_IDS == null) {
            Log.e(TAG, methodName + " select an application first, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if (APPLICATION_ALL_FILE_IDS.length == 0) {
            Log.e(TAG, methodName + " there are no files available, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        int numberOfFileIds = APPLICATION_ALL_FILE_IDS.length;
        APPLICATION_ALL_FILE_SETTINGS = new FileSettings[MAXIMUM_NUMBER_OF_FILES];
        for (int i = 0; i < numberOfFileIds; i++) {
            byte fileId = APPLICATION_ALL_FILE_IDS[i];
            byte[] fileSettingsByte = getFileSettings(fileId);
            if (fileSettingsByte != null) {
                FileSettings fileSettings = new FileSettings(fileId, fileSettingsByte);
                if (fileSettings != null) {
                    APPLICATION_ALL_FILE_SETTINGS[fileId] = fileSettings;
                }
            }
        }
        log(methodName, "ended");
        return APPLICATION_ALL_FILE_SETTINGS;
    }

    /**
     * get the file settings of a file within an application
     * Note: depending on the application master key settings this requires a preceding authentication
     * with the application master key
     *
     * @return an array of bytes with all available fileSettings
     * @fileNumber: the file number we need to read the settings from
     */

    public byte[] getFileSettings(byte fileNumber) {
        // this is using simple PLAIN communication without any encryption or MAC involved
        String logData = "";
        final String methodName = "getFileSettings";
        log(methodName, "started", true);
        // sanity checks
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        Log.d(TAG, methodName + " for fileNumber " + fileNumber);
        byte[] getFileSettingsParameters = new byte[1];
        getFileSettingsParameters[0] = fileNumber;
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(GET_FILE_SETTINGS_COMMAND, getFileSettingsParameters);
            log(methodName, printData("apdu", apdu));
            // method: getFileSettingsEv2: apdu length: 7 data: 90f50000010200
            // sample                                           90F50000010300
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
        System.arraycopy(returnStatusBytes(response), 0, errorCode, 0, 2);
        byte[] responseData = Arrays.copyOfRange(response, 0, response.length - 2);
        if (checkResponse(response)) {
            Log.d(TAG, "response SUCCESS");
            Log.d(TAG, "return for fileNumber " + fileNumber + " : " + printData("responseData", responseData));
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return responseData;
        } else {
            Log.d(TAG, "response FAILURE");
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
    }

    /**
     * changes the fileSettings of the file
     *
     * @param fileNumber            : in range 1..3
     * @param communicationSettings : Plain, MACed or Full
     * @param keyRW                 : keyNumber in range 0..4 or 14 ('E', free) or 15 ('F', never)
     * @param keyCar                : see keyRW
     * @param keyR                  : see keyRW
     * @param keyW                  : see keyRW
     * @param sdmEnable             : true = enables SDM and mirroring
     * @return : true on success
     * <p>
     * Note on SDM enabling: this will set some predefined, fixed values, that work with the sample NDEF string
     * https://choose.url.com/ntag424?e=00000000000000000000000000000000&c=0000000000000000
     * taken from NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 31
     * - communicationSettings: Plain
     * - enabling SDM and mirroring
     * - sdmOptions are '0xC1' (UID mirror: 1, SDMReadCtr: 1, SDMReadCtrLimit: 0, SDMENCFileData: 0, ASCII Encoding mode: 1
     * - SDMAccessRights are '0xF121':
     * 0xF: RFU
     * 0x1: FileAR.SDMCtrRet
     * 0x2: FileAR.SDMMetaRead
     * 0x1: FileAR.SDMFileRead
     * - Offsets:
     * ENCPICCDataOffset: 0x200000
     * SDMMACOffset:      0x430000
     * SDMMACInputOffset: 0x430000
     */

    public boolean changeFileSettingsNtag424Dna(byte fileNumber, DesfireAuthenticateEv2.CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable) {

        // this method can only enable Secure Dynamic Message but cannot set specific data like offsets
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // status: WORKING on enabling and disabling SDM feature

        String logData = "";
        final String methodName = "changeFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if (keyRW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is < 0, aborted";
            return false;
        }
        if ((keyRW > 4) & (keyRW != 14) & (keyRW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyCar < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is < 0, aborted";
            return false;
        }
        if ((keyCar > 4) & (keyCar != 14) & (keyCar != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyR < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is < 0, aborted";
            return false;
        }
        if ((keyR > 4) & (keyR != 14) & (keyR != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is < 0, aborted";
            return false;
        }
        if ((keyW > 4) & (keyW != 14) & (keyW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

        if (sdmEnable) {
            Log.d(TAG, "enabling Secure Dynamic Messaging feature on NTAG 424 DNA");
            if (fileNumber != 2) {
                errorCode = RESPONSE_PARAMETER_ERROR.clone();
                errorCodeReason = "sdmEnable works on fileNumber 2 only, aborted";
                return false;
            }
        }

/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // build the command data
        byte communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(DesfireAuthenticateEv2.CommunicationSettings.Plain.name()))
            communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(DesfireAuthenticateEv2.CommunicationSettings.MACed.name()))
            communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(DesfireAuthenticateEv2.CommunicationSettings.Encrypted.name()))
            communicationSettingsByte = (byte) 0x03;
        byte fileOption;
        if (sdmEnable) {
            fileOption = (byte) 0x40; // enable SDM and mirroring, Plain communication
        } else {
            fileOption = communicationSettingsByte;
        }
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)); // Read Access & Write Access
        byte sdmOptions = (byte) 0xC1; // UID mirror = 1, SDMReadCtr = 1, SDMReadCtrLimit = 0, SDMENCFileData = 0, ASCII Encoding mode = 1
        byte[] sdmAccessRights = hexStringToByteArray("F121");
        byte[] ENCPICCDataOffset = Utils.intTo3ByteArrayInversed(32); // 0x200000
        byte[] SDMMACOffset = Utils.intTo3ByteArrayInversed(67);      // 0x430000
        byte[] SDMMACInputOffset = Utils.intTo3ByteArrayInversed(67); // 0x430000
        ByteArrayOutputStream baosCommandData = new ByteArrayOutputStream();
        baosCommandData.write(fileOption);
        baosCommandData.write(accessRightsRwCar);
        baosCommandData.write(accessRightsRW);
        // following data are written on sdmEnable only
        if (sdmEnable) {
            baosCommandData.write(sdmOptions);
            baosCommandData.write(sdmAccessRights, 0, sdmAccessRights.length);
            baosCommandData.write(ENCPICCDataOffset, 0, ENCPICCDataOffset.length);
            baosCommandData.write(SDMMACOffset, 0, SDMMACOffset.length);
            baosCommandData.write(SDMMACInputOffset, 0, SDMMACInputOffset.length);
        }
        byte[] commandData = baosCommandData.toByteArray();
        log(methodName, printData("commandData", commandData));

        /*
from: NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf page 34
CmdData example: 4000E0C1F121200000430000430000
40 00E0 C1 F121 200000 430000 430000
40h = FileOption (SDM and
Mirroring enabled), CommMode: plain
00E0h = AccessRights (FileAR.ReadWrite: 0x0, FileAR.Change: 0x0, FileAR.Read: 0xE, FileAR.Write; 0x0)
C1h =
• UID mirror: 1
• SDMReadCtr: 1
• SDMReadCtrLimit: 0
• SDMENCFileData: 0
• ASCII Encoding mode: 1
F121h = SDMAccessRights (RFU: 0xF, FileAR.SDMCtrRet = 0x1, FileAR.SDMMetaRead: 0x2, FileAR.SDMFileRead: 0x1)
200000h = ENCPICCDataOffset
430000h = SDMMACOffset
430000h = SDMMACInputOffset
 */

        // eventually some padding is necessary with 0x80..00
        byte[] commandDataPadded = paddingWriteData(commandData);
        log(methodName, printData("commandDataPadded", commandDataPadded));

        // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // error in DESFire Light Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLength || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader = fileNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(fileNumber);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand);
/*
from NTAG424DNA sheet page 69:
PERMISSION_DENIED
- 9Dh PICC level (MF) is selected.
- access right Change of targeted file has access conditions set to Fh.
- Enabling Secure Dynamic Messaging (FileOption Bit 6 set to 1b) is only allowed for FileNo 02h.
 */
            // expected APDU 905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400 (31 bytes)
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return false;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean changeFileSettingsNtag424Dna(byte fileNumber, DesfireAuthenticateEv2.CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable, int encPiccDataOffset, int sdmMacOffset, int sdmMacInputOffset) {

        // this method can only enable Secure Dynamic Message but cannot set specific data like offsets
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // status: WORKING on enabling and disabling SDM feature with encrypted PICC data

        String logData = "";
        final String methodName = "changeFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if (keyRW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is < 0, aborted";
            return false;
        }
        if ((keyRW > 4) & (keyRW != 14) & (keyRW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyRW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyCar < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is < 0, aborted";
            return false;
        }
        if ((keyCar > 4) & (keyCar != 14) & (keyCar != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyCar is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyR < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is < 0, aborted";
            return false;
        }
        if ((keyR > 4) & (keyR != 14) & (keyR != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyR is > 4 but not 14 or 15, aborted";
            return false;
        }
        if (keyW < 0) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is < 0, aborted";
            return false;
        }
        if ((keyW > 4) & (keyW != 14) & (keyW != 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyW is > 4 but not 14 or 15, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA / DESFire EV3 tag ?), aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

        if (sdmEnable) {
            Log.d(TAG, "enabling Secure Dynamic Messaging feature on NTAG 424 DNA / DESFire EV3");
            if (fileNumber != 2) {
                errorCode = RESPONSE_PARAMETER_ERROR.clone();
                errorCodeReason = "sdmEnable works on fileNumber 2 only, aborted";
                return false;
            }
        }

        // todo validate offsets

/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // build the command data
        byte communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(DesfireAuthenticateEv2.CommunicationSettings.Plain.name()))
            communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(DesfireAuthenticateEv2.CommunicationSettings.MACed.name()))
            communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(DesfireAuthenticateEv2.CommunicationSettings.Encrypted.name()))
            communicationSettingsByte = (byte) 0x03;
        byte fileOption;
        if (sdmEnable) {
            fileOption = (byte) 0x40; // enable SDM and mirroring, Plain communication
        } else {
            fileOption = communicationSettingsByte;
        }
        byte accessRightsRwCar = (byte) ((keyRW << 4) | (keyCar & 0x0F)); // Read&Write Access & ChangeAccessRights
        byte accessRightsRW = (byte) ((keyR << 4) | (keyW & 0x0F)); // Read Access & Write Access
        byte sdmOptions = (byte) 0xC1; // UID mirror = 1, SDMReadCtr = 1, SDMReadCtrLimit = 0, SDMENCFileData = 0, ASCII Encoding mode = 1
        byte[] sdmAccessRights = hexStringToByteArray("F121");
        byte[] ENCPICCDataOffset = Utils.intTo3ByteArrayInversed(encPiccDataOffset); // e.g. 0x200000 for NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf example on pages 31 + 34
        byte[] SDMMACOffset = Utils.intTo3ByteArrayInversed(sdmMacOffset);      // e.g. 0x430000
        byte[] SDMMACInputOffset = Utils.intTo3ByteArrayInversed(sdmMacInputOffset); // e.g. 0x430000
        log(methodName, printData("ENCPICCDataOffset", ENCPICCDataOffset));
        log(methodName, printData("SDMMACOffset     ", SDMMACOffset));
        log(methodName, printData("SDMMACInputOffset", SDMMACInputOffset));
        /*
        values using server data: https://sdm.nfcdeveloper.com/tag
        ENCPICCDataOffset length: 3 data: 2a0000 (42d)
        SDMMACOffset      length: 3 data: 500000 (80d)
        SDMMACInputOffset length: 3 data: 500000 (80d)

         */
        ByteArrayOutputStream baosCommandData = new ByteArrayOutputStream();
        baosCommandData.write(fileOption);
        baosCommandData.write(accessRightsRwCar);
        baosCommandData.write(accessRightsRW);
        // following data are written on sdmEnable only
        if (sdmEnable) {
            baosCommandData.write(sdmOptions);
            baosCommandData.write(sdmAccessRights, 0, sdmAccessRights.length);
            baosCommandData.write(ENCPICCDataOffset, 0, ENCPICCDataOffset.length);
            baosCommandData.write(SDMMACOffset, 0, SDMMACOffset.length);
            baosCommandData.write(SDMMACInputOffset, 0, SDMMACInputOffset.length);
        }
        byte[] commandData = baosCommandData.toByteArray();
        log(methodName, printData("commandData", commandData));

        // this is the working command for encrypted PICC data
        //                                    4000e0c1 f121 2a0000500000500000
        //                                    4000e011 f1f1 2500002500002000004b0000
        // todo this is manually added by NdefForSdm value test 10 = encrypted PICC data and encrypted file data
        // status: working !
        //commandData = hexStringToByteArray("4000e0d1f1212a00004f00004f0000200000750000");
        //log(methodName, printData("commandData", commandData));

        // todo this is manually added by NdefForSdm value test 11 = NO encrypted PICC data but encrypted file data
        //commandData = hexStringToByteArray("4000e011f1f12500002500002000004b0000");

        // test 12 - encrypted PICC data, encrypted File data, sdm keys for all is 1, working
        //commandData = hexStringToByteArray("4000e0d1f1112a00004f00004f0000200000750000");
        // https://sdm.nfcdeveloper.com/tag?picc_data=1D963945833B280C8E0CE5D3F86127E0&enc=AFAE6C123CC478734FED103FD6851AA8&cmac=FCAC93426335D213


        log(methodName, printData("commandData", commandData));

        // eventually some padding is necessary with 0x80..00
        byte[] commandDataPadded = paddingWriteData(commandData);
        log(methodName, printData("commandDataPadded", commandDataPadded));

        byte[] encryptedData;
        // if commandDataPadded is longer than 16 bytes we need to encrypt in chunks
        if (commandDataPadded.length > 16) {
            Log.d(TAG, "The commandDataPadded length is > 16, encrypt in chunks");
            int numberOfDataBlocks = commandDataPadded.length / 16;
            log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
            List<byte[]> dataBlockList = Utils.divideArrayToList(commandDataPadded, 16);
            List<byte[]> dataBlockEncryptedList = new ArrayList<>();
            byte[] ivDataEncryption = ivForCmdData.clone(); // the "starting iv"
            for (int i = 0; i < numberOfDataBlocks; i++) {
                byte[] dataBlockEncrypted = AES.encrypt(ivDataEncryption, SesAuthENCKey, dataBlockList.get(i));
                dataBlockEncryptedList.add(dataBlockEncrypted);
                ivDataEncryption = dataBlockEncrypted.clone(); // new, subsequent iv for next encryption
            }
            for (int i = 0; i < numberOfDataBlocks; i++) {
                log(methodName, printData("dataBlock" + i + "Encrypted", dataBlockEncryptedList.get(i)));
            }
            // Encrypted Data (complete), concatenate all byte arrays
            ByteArrayOutputStream baosDataEncrypted = new ByteArrayOutputStream();
            for (int i = 0; i < numberOfDataBlocks; i++) {
                try {
                    baosDataEncrypted.write(dataBlockEncryptedList.get(i));
                } catch (IOException e) {
                    Log.e(TAG, "IOException on concatenating encrypted dataBlocks, aborted\n" +
                            e.getMessage());
                    return false;
                }
            }
            encryptedData = baosDataEncrypted.toByteArray();
        } else {
            Log.d(TAG, "The commandDataPadded length is = 16, encrypt in one run");
            // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
            encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        }
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // error in DESFire Light Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLength || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader = fileNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(fileNumber);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        // when enabling encrypted PICC data and encrypted File data
        // actual not work: 90 5f 0000 29 02 9192e1606bcf2b8a8ee09828b19a2df6a0c9919aedb5cffdb7c9783f9dd3f116 2e7d9cea75943571 00
        // tapLinx working:    5F         02 9F332C58ABA6992E87F89F09337990E315506EAF45E4A72E81C1DB30D728D7CE     E081D3EB02A213A3 (42 bytes)
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return false;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    // takes a full commandData from ActivateSdmActivity class
    // WARNING: be extreme careful with this method because there are NO validations on commandData
    public boolean changeFileSettingsNtag424Dna(byte fileNumber, byte[] commandData) {

        // this method can only enable Secure Dynamic Message but cannot set specific data like offsets
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // status: WORKING on enabling and disabling SDM feature with encrypted PICC data

        String logData = "";
        final String methodName = "changeFileSettings with commandData";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if ((commandData == null) || (commandData.length < 5)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "commandData is NULL or of insufficient length, aborted";
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA / DESFire EV3 tag ?), aborted";
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

/*
fileNumber: 01
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R  | W:   E0
accessRights RW:       0
accessRights CAR:      0
accessRights R:        14
accessRights W:        0
fileSize: 32
--------------
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: E0
accessRights R  | W:   EE
accessRights RW:       14
accessRights CAR:      0
accessRights R:        14
accessRights W:        14
fileSize: 256
--------------
fileNumber: 03
fileType: 0 (Standard)
communicationSettings: 03 (Encrypted)
accessRights RW | CAR: 30
accessRights R  | W:   23
accessRights RW:       3
accessRights CAR:      0
accessRights R:        2
accessRights W:        3
fileSize: 128
         */

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb", commandCounterLsb));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // take the the command data as parameter
        log(methodName, printData("commandData", commandData));

        // eventually some padding is necessary with 0x80..00
        byte[] commandDataPadded = paddingWriteData(commandData);
        log(methodName, printData("commandDataPadded", commandDataPadded));

        byte[] encryptedData;
        // if commandDataPadded is longer than 16 bytes we need to encrypt in chunks
        if (commandDataPadded.length > 16) {
            Log.d(TAG, "The commandDataPadded length is > 16, encrypt in chunks");
            int numberOfDataBlocks = commandDataPadded.length / 16;
            log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
            List<byte[]> dataBlockList = Utils.divideArrayToList(commandDataPadded, 16);
            List<byte[]> dataBlockEncryptedList = new ArrayList<>();
            byte[] ivDataEncryption = ivForCmdData.clone(); // the "starting iv"
            for (int i = 0; i < numberOfDataBlocks; i++) {
                byte[] dataBlockEncrypted = AES.encrypt(ivDataEncryption, SesAuthENCKey, dataBlockList.get(i));
                dataBlockEncryptedList.add(dataBlockEncrypted);
                ivDataEncryption = dataBlockEncrypted.clone(); // new, subsequent iv for next encryption
            }
            for (int i = 0; i < numberOfDataBlocks; i++) {
                log(methodName, printData("dataBlock" + i + "Encrypted", dataBlockEncryptedList.get(i)));
            }
            // Encrypted Data (complete), concatenate all byte arrays
            ByteArrayOutputStream baosDataEncrypted = new ByteArrayOutputStream();
            for (int i = 0; i < numberOfDataBlocks; i++) {
                try {
                    baosDataEncrypted.write(dataBlockEncryptedList.get(i));
                } catch (IOException e) {
                    Log.e(TAG, "IOException on concatenating encrypted dataBlocks, aborted\n" +
                            e.getMessage());
                    return false;
                }
            }
            encryptedData = baosDataEncrypted.toByteArray();
        } else {
            Log.d(TAG, "The commandDataPadded length is = 16, encrypt in one run");
            // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
            encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        }
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // error in DESFire Light Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLength || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader = fileNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(fileNumber);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        // when enabling encrypted PICC data and encrypted File data
        // actual not work: 90 5f 0000 29 02 9192e1606bcf2b8a8ee09828b19a2df6a0c9919aedb5cffdb7c9783f9dd3f116 2e7d9cea75943571 00
        // tapLinx working:    5F         02 9F332C58ABA6992E87F89F09337990E315506EAF45E4A72E81C1DB30D728D7CE     E081D3EB02A213A3 (42 bytes)
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: " + e.getMessage();
            return false;
        }
        if (!checkResponse(response)) {
            log(methodName, methodName + " FAILURE");
            byte[] responseBytes = returnStatusBytes(response);
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * verifies the responseMAC against the responseData using the SesAuthMACKey
     *
     * @param responseMAC
     * @param responseData (if data is encrypted use the encrypted data, not the decrypted data)
     *                     Note: in case of enciphered writings the data is null
     * @return true if MAC equals the calculated MAC
     */

    private boolean verifyResponseMac(byte[] responseMAC, byte[] responseData) {
        final String methodName = "verifyResponseMac";
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb, 0, commandCounterLsb.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        if (responseData != null) {
            responseMacBaos.write(responseData, 0, responseData.length);
        }
        byte[] macInput = responseMacBaos.toByteArray();
        log(methodName, printData("macInput", macInput));
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("responseMACTruncatedReceived  ", responseMAC));
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMAC)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    private byte[] truncateMAC(byte[] fullMAC) {
        final String methodName = "truncateMAC";
        log(methodName, printData("fullMAC", fullMAC), true);
        if ((fullMAC == null) || (fullMAC.length < 2)) {
            log(methodName, "fullMAC is NULL or of wrong length, aborted");
            return null;
        }
        int fullMACLength = fullMAC.length;
        byte[] truncatedMAC = new byte[fullMACLength / 2];
        int truncatedMACPos = 0;
        for (int i = 1; i < fullMACLength; i += 2) {
            truncatedMAC[truncatedMACPos] = fullMAC[i];
            truncatedMACPos++;
        }
        log(methodName, printData("truncatedMAC", truncatedMAC));
        return truncatedMAC;
    }

    /**
     * section for authentication
     */

    /**
     * authenticateAesEv2First uses the EV2First authentication method with command 0x71
     *
     * @param keyNumber (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SesAuthENCKey and SesAuthMACKey is NOT tested so far
     * <p>
     * This method is using the AesCmac class for CMAC calculations
     */

    public boolean authenticateAesEv2First(byte keyNumber, byte[] key) {

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
        boolean debug = false; // if true each single step is print out for debugging purposes
        logData = "";
        invalidateAllData();
        final String methodName = "authenticateAesEv2First";
        log(methodName, printData("key", key) + " keyNumber: " + keyNumber, true);
        errorCode = new byte[2];
        // sanity checks
        if (keyNumber < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (keyNumber > 14) {
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
        if (debug) log(methodName, "step 01 get encrypted rndB from card");
        log(methodName, "This method is using the AUTHENTICATE_AES_EV2_FIRST_COMMAND so it will work with AES-based application only");
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
            parameter[0] = keyNumber;
            parameter[1] = (byte) 0x00; // is already 0x00
            if (debug) log(methodName, printData("parameter", parameter));
            apdu = wrapMessage(AUTHENTICATE_AES_EV2_FIRST_COMMAND, parameter);
            if (debug) log(methodName, "get enc rndB " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug) log(methodName, "get enc rndB " + printData("response", response));
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
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        byte[] rndB_enc = getData(response);
        if (debug) log(methodName, printData("encryptedRndB", rndB_enc));

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        if (debug) log(methodName, "step 02 iv0 is 16 zero bytes " + printData("iv0", iv0));
        if (debug) log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        if (debug) log(methodName, printData("rndB", rndB));

        if (debug) log(methodName, "step 04 rotate rndB to LEFT");
        byte[] rndB_leftRotated = rotateLeft(rndB);
        if (debug) log(methodName, printData("rndB_leftRotated", rndB_leftRotated));

        // authenticate 2nd part
        if (debug) log(methodName, "step 05 generate a random rndA");
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        if (debug) log(methodName, printData("rndA", rndA));

        if (debug) log(methodName, "step 06 concatenate rndA | rndB_leftRotated");
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated));

        // IV is now encrypted RndB received from the tag
        if (debug) log(methodName, "step 07 iv1 is 16 zero bytes");
        byte[] iv1 = new byte[16];
        if (debug) log(methodName, printData("iv1", iv1));

        // Encrypt RndAB_rot
        if (debug) log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        if (debug) log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
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
            System.arraycopy(responseBytes, 0, errorCode, 0, 2);
            return false;
        }
        // now we know that we can work with the response, response is 32 bytes long
        // R-APDU (Part 2) E(Kx, TI || RndA' || PDcap2 || PCDcap2) || Response Code
        if (debug) log(methodName, "step 10 received encrypted data from PICC");
        byte[] data_enc = getData(response);
        if (debug) log(methodName, printData("data_enc", data_enc));

        //IV is now reset to zero bytes
        if (debug) log(methodName, "step 11 iv2 is 16 zero bytes");
        byte[] iv2 = new byte[16];
        if (debug) log(methodName, printData("iv2", iv2));

        // Decrypt encrypted data
        if (debug) log(methodName, "step 12 decrypt data_enc with iv2 and key");
        byte[] data = AES.decrypt(iv2, key, data_enc);
        if (debug) log(methodName, printData("data", data));
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
        if (debug) log(methodName, "step 13 full data needs to get split up in 4 values");
        if (debug) log(methodName, printData("data", data));
        if (debug) log(methodName, printData("ti", ti));
        if (debug) log(methodName, printData("rndA_leftRotated", rndA_leftRotated));
        if (debug) log(methodName, printData("pDcap2", pDcap2));
        if (debug) log(methodName, printData("pCDcap2", pCDcap2));

        // PCD compares send and received RndA
        if (debug) log(methodName, "step 14 rotate rndA_leftRotated to RIGHT");
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        if (debug) log(methodName, printData("rndA_received ", rndA_received));
        boolean rndAEqual = Arrays.equals(rndA, rndA_received);
        //log(methodName, printData("rndA received ", rndA_received));
        if (debug) log(methodName, printData("rndA          ", rndA));
        if (debug) log(methodName, "rndA and rndA received are equal: " + rndAEqual);
        if (debug) log(methodName, printData("rndB          ", rndB));

        if (debug) log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
            SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
            if (debug) log(methodName, printData("SesAuthENCKey ", SesAuthENCKey));
            if (debug) log(methodName, printData("SesAuthMACKey ", SesAuthMACKey));
            CmdCounter = 0;
            TransactionIdentifier = ti.clone();
            authenticateEv2FirstSuccess = true;
            keyNumberUsedForAuthentication = keyNumber;
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
        }
        if (debug) log(methodName, "*********************");
        return rndAEqual;
    }

    /**
     * authenticateAesEv2NonFirst uses the EV2NonFirst authentication method with command 0x77
     *
     * @param keyNumber (00..14) but maximum is defined during application setup
     * @param key   (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * Note: the authentication seems to work but the correctness of the SesAuthENCKey and SesAuthMACKey is NOT tested so far
     * <p>
     * This method is using the AesCmac class for CMAC calculations
     */

    public boolean authenticateAesEv2NonFirst(byte keyNumber, byte[] key) {
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

        boolean debug = false; // if true each single step is print out for debugging purposes
        logData = "";
        invalidateAllDataNonFirst();
        final String methodName = "authenticateAesEv2NonFirst";
        log(methodName, printData("key", key) + " keyNo: " + keyNumber, true);
        errorCode = new byte[2];
        // sanity checks
        if (!authenticateEv2FirstSuccess) {
            Log.e(TAG, methodName + " please run an authenticateEV2First before, aborted");
            log(methodName, "missing previous successfull authenticateEv2First, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }

        if (keyNumber < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (keyNumber > 14) {
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
        if (debug) log(methodName, "step 01 get encrypted rndB from card");
        if (debug) log(methodName, "This method is using the AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND so it will work with AES-based application only");
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            /**
             * note: the parameter needs to be a 1 byte long value, the first one is the key number
             * I'm setting the byte[] to keyNo
             */
            byte[] parameter = new byte[1];
            parameter[0] = keyNumber;
            if (debug) log(methodName, printData("parameter", parameter));
            apdu = wrapMessage(AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND, parameter);
            if (debug) log(methodName, "get enc rndB " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug) log(methodName, "get enc rndB " + printData("response", response));
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
            return false;
        }
        // now we know that we can work with the response, 16 bytes long
        // R-APDU (Part 1) (E(Kx, RndB)) || SW1 || SW2
        byte[] rndB_enc = getData(response);
        if (debug) log(methodName, printData("encryptedRndB", rndB_enc));

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        if (debug) log(methodName, "step 02 iv0 is 16 zero bytes " + printData("iv0", iv0));
        if (debug) log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        if (debug) log(methodName, printData("rndB", rndB));

        if (debug) log(methodName, "step 04 rotate rndB to LEFT");
        byte[] rndB_leftRotated = rotateLeft(rndB);
        if (debug) log(methodName, printData("rndB_leftRotated", rndB_leftRotated));

        // authenticate 2nd part
        if (debug) log(methodName, "step 05 generate a random rndA");
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        if (debug) log(methodName, printData("rndA", rndA));

        if (debug) log(methodName, "step 06 concatenate rndA | rndB_leftRotated");
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated));

        // IV is now encrypted RndB received from the tag
        if (debug) log(methodName, "step 07 iv1 is 16 zero bytes");
        byte[] iv1 = new byte[16];
        if (debug) log(methodName, printData("iv1", iv1));

        // Encrypt RndAB_rot
        if (debug) log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        if (debug) log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
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
        // now we know that we can work with the response, response is 16 bytes long
        // R-APDU (Part 2) E(Kx, RndA' || Response Code
        if (debug) log(methodName, "step 10 received encrypted data from PICC");
        byte[] data_enc = getData(response);
        if (debug) log(methodName, printData("data_enc", data_enc));

        //IV is now reset to zero bytes
        if (debug) log(methodName, "step 11 iv2 is 16 zero bytes");
        byte[] iv2 = new byte[16];
        if (debug) log(methodName, printData("iv2", iv2));

        // Decrypt encrypted data
        if (debug) log(methodName, "step 12 decrypt data_enc with iv2 and key");
        byte[] data = AES.decrypt(iv2, key, data_enc);
        if (debug) log(methodName, printData("data", data));
        // data is 32 bytes long, e.g. a1487b61f69cef65a09742b481152325a7cb8fc6000000000000000000000000
        /**
         * structure of data
         * full example 55c4421b4db67d0777c2f9116bcd6b1a
         *
         * rndA LEFT rotated          16 bytes 55c4421b4db67d0777c2f9116bcd6b1a
         */

        // split data not necessary, data is rndA_leftRotated
        byte[] rndA_leftRotated = data.clone();
        if (debug) log(methodName, "step 13 full data is rndA_leftRotated only");
        if (debug) log(methodName, printData("rndA_leftRotated", rndA_leftRotated));

        // PCD compares send and received RndA
        if (debug) log(methodName, "step 14 rotate rndA_leftRotated to RIGHT");
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        if (debug) log(methodName, printData("rndA_received ", rndA_received));
        boolean rndAEqual = Arrays.equals(rndA, rndA_received);

        //log(methodName, printData("rndA received ", rndA_received));
        if (debug) log(methodName, printData("rndA          ", rndA));
        if (debug) log(methodName, "rndA and rndA received are equal: " + rndAEqual);
        if (debug) log(methodName, printData("rndB          ", rndB));
        if (debug) log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            SesAuthENCKey = getSesAuthEncKey(rndA, rndB, key);
            SesAuthMACKey = getSesAuthMacKey(rndA, rndB, key);
            if (debug) log(methodName, printData("SesAuthENCKey ", SesAuthENCKey));
            if (debug) log(methodName, printData("SesAuthMACKey ", SesAuthMACKey));
            //CmdCounter = 0; // is not resetted in EV2NonFirst
            //TransactionIdentifier = ti.clone(); // is not resetted in EV2NonFirst
            authenticateEv2NonFirstSuccess = true;
            keyNumberUsedForAuthentication = keyNumber;
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
        }
        if (debug) log(methodName, "*********************");
        return rndAEqual;
    }

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

    private byte[] getSesAuthEncKey(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        boolean debug = false; // if true each single step is print out for debugging purposes
        final String methodName = "getSesAuthEncKey";
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
        if (debug) log(methodName, printData("rndA     ", rndA));
        if (debug) log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        if (debug) log(methodName, printData("rndB     ", rndB));
        if (debug) log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        if (debug) log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        if (debug) log(methodName, printData("rndA     ", rndA));
        if (debug) log(methodName, printData("rndB     ", rndB));
        if (debug) log(methodName, printData("cmacInput", cmacInput));
        byte[] iv = new byte[16];
        if (debug) log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        if (debug) log(methodName, printData("cmacOut ", cmac));
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

    private byte[] getSesAuthMacKey(byte[] rndA, byte[] rndB, byte[] authenticationKey) {
        // see
        // see MIFARE DESFire Light contactless application IC pdf, page 28
        boolean debug = false; // if true each single step is print out for debugging purposes
        final String methodName = "getSesAuthMacKey";
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
        if (debug) log(methodName, printData("rndA     ", rndA));
        if (debug) log(methodName, printData("rndA02to07", rndA02to07));
        rndB00to05 = Arrays.copyOfRange(rndB, 0, 6);
        if (debug) log(methodName, printData("rndB     ", rndB));
        if (debug) log(methodName, printData("rndB00to05", rndB00to05));
        byte[] xored = xor(rndA02to07, rndB00to05);
        if (debug) log(methodName, printData("xored     ", xored));
        System.arraycopy(xored, 0, cmacInput, 8, 6);
        System.arraycopy(rndB, 6, cmacInput, 14, 10);
        System.arraycopy(rndA, 8, cmacInput, 24, 8);

        if (debug) log(methodName, printData("rndA     ", rndA));
        if (debug) log(methodName, printData("rndB     ", rndB));
        if (debug) log(methodName, printData("cmacInput", cmacInput));
        byte[] iv = new byte[16];
        if (debug) log(methodName, printData("iv       ", iv));
        byte[] cmac = calculateDiverseKey(authenticationKey, cmacInput);
        if (debug) log(methodName, printData("cmacOut ", cmac));
        return cmac;
    }
    
    private byte[] getSesSDMFileReadENCKey(byte[] sdmFileReadKey, byte[] uid, byte[] sdmReadCounter) {
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 13 - 14
        // see NTAG 424 DNA NT4H2421Gx.pdf page 41
        boolean debug = false; // if true each single step is print out for debugging purposes
        final String methodName = "getSesSDMFileReadENCKey";
        log(methodName, printData("sdmFileReadKey", sdmFileReadKey) + printData(" uid", uid) + printData(" sdmReadCounter", sdmReadCounter), true);
        // sanity checks
        if ((sdmFileReadKey == null) || (sdmFileReadKey.length != 16)) {
            log(methodName, "sdmFileReadKey is NULL or wrong length, aborted");
            return null;
        }
        if ((uid == null) || (uid.length != 7)) {
            log(methodName, "uid is NULL or wrong length, aborted");
            return null;
        }
        if ((sdmReadCounter == null) || (sdmReadCounter.length != 3)) {
            log(methodName, "sdmReadCounter is NULL or wrong length, aborted");
            return null;
        }
        // CMAC calculation when CMACInputOffset = CMACOffset
        byte[] cmacInput = new byte[16];
        byte[] labelSdmEnc = new byte[]{(byte) (0xC3), (byte) (0x3C)}; // fixed to 0xC33C
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080
        System.arraycopy(labelSdmEnc, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(uid, 0, cmacInput, 6, 7);
        System.arraycopy(sdmReadCounter, 0, cmacInput, 13, 3);
        // todo this method is working only when UID and readCtr are present, if not the byte array is filled up with 00 to 16 bytes
        if (debug) log(methodName, printData("cmacInput", cmacInput));
        byte[] cmac = calculateDiverseKey(sdmFileReadKey, cmacInput);
        if (debug) log(methodName, printData("cmacOutput", cmac));
        return cmac;
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

    private byte[] xor(byte[] dataA, byte[] dataB) {
        log("xor", printData("dataA", dataA) + printData(" dataB", dataB), true);
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

    private byte[] calculateDiverseKey(byte[] masterKey, byte[] input) {
        Log.d(TAG, "calculateDiverseKey" + printData(" masterKey", masterKey) + printData(" input", input));
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
     * section for general tasks
     */

    /**
     * gets the technical data of the tapped tag
     * @return the VersionInfo
     */
    public VersionInfo getVersionInformation() {
        byte[] bytes = new byte[0];
        try {
            bytes = sendRequest(GET_VERSION_INFO_COMMAND);
            return new VersionInfo(bytes);
        } catch (Exception e) {
            log("getVersionInformation", "IOException: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
        }
        return null;
    }

    /**
     * checks that the tapped tag is of type DESFire EV3
     * As some commands do work on a DESFire EV3 tag only we need to check for that tag type
     * (e.g. enabling of the SUN/SDM feature)
     * @return true on success
     */
    public boolean checkForDESFireEv3() {
        VersionInfo versionInfo = getVersionInformation();
        if (versionInfo == null) return false;
        Log.d(TAG, versionInfo.dump());
        int hardwareType = versionInfo.getHardwareType(); // 1 = DESFire, 4 = NTAG family 4xx
        int hardwareVersion = versionInfo.getHardwareVersionMajor(); // 51 = DESFire EV3, 48 = NTAG 424 DNA
        return ((hardwareType == 1) && (hardwareVersion == 51));
    }

    /**
     * section for command and response handling
     */

    /**
     * The 'sendRequest' methods automatically detect an '0xAF' status meaning that more data is available,
     * e.g. when reading of a Standard file and the amount of data exceeds the maximum data length the data
     * is chunked by the PICC. The method will read as long as '0xAF' status bytes appear. When all data is
     * read the PICC sends a '0x00' meaning success and all data is provided.
     * @param command
     * @return the full received data including the code '0x9100'
     */

    public byte[] sendRequest(byte command) {
        return sendRequest(command, null);
    }

    private byte[] sendRequest(byte command, byte[] parameters) {
        try {
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            byte[] recvBuffer = sendData(wrapMessage(command, parameters));

            //writeToUiAppend(readResult, printData("sendRequest recvBuffer", recvBuffer));
            if (recvBuffer == null) {
                errorCode = RESPONSE_FAILURE.clone();
                return RESPONSE_FAILURE.clone();
            }
            if (recvBuffer.length < 2) {
                errorCode = RESPONSE_FAILURE.clone();
                return RESPONSE_FAILURE.clone();
            }
            while (true) {
                if (recvBuffer[recvBuffer.length - 2] != (byte) 0x91) {
                    errorCode = RESPONSE_FAILURE.clone();
                    return RESPONSE_FAILURE.clone();
                }
                output.write(recvBuffer, 0, recvBuffer.length - 2);
                byte status = recvBuffer[recvBuffer.length - 1];
                if (status == (byte) 0x00) {
                    break;
                } else if (status == (byte) 0xAF) {
                    recvBuffer = sendData(wrapMessage((byte) 0xAF, null));
                } else if (status == (byte) 0x9D) {
                    errorCode = RESPONSE_PERMISSION_DENIED_ERROR.clone();
                    errorCodeReason = "Permission denied";
                    return recvBuffer;
                } else if (status == (byte) 0xAE) {
                    errorCode = RESPONSE_AUTHENTICATION_ERROR.clone();
                    errorCodeReason = "Authentication error";
                    return recvBuffer;
                } else {
                    errorCode = RESPONSE_FAILURE.clone();
                    errorCodeReason = "Unknown status code: " + Integer.toHexString(status & 0xFF);
                    return recvBuffer;
                }
            }
            byte[] data = output.toByteArray();
            // adding return codes
            byte[] returnData = new byte[data.length + 2];
            System.arraycopy(data, 0, returnData, 0, data.length);
            System.arraycopy(RESPONSE_OK, 0, returnData, data.length, RESPONSE_OK.length);
            return returnData;
        } catch (IOException e) {
            Log.e(TAG, "transceive failed, IOException:\n" + e.getMessage());
            log("sendRequest", "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return RESPONSE_FAILURE.clone();
        }
    }

    private byte[] sendData(byte[] apdu) {
        String methodName = "sendData";
        if (isoDep == null) {
            Log.e(TAG, methodName + " isoDep is NULL");
            log(methodName, "isoDep is NULL, aborted");
            return null;
        }
        log(methodName, printData("send apdu -->", apdu));
        byte[] recvBuffer;
        try {
            recvBuffer = isoDep.transceive(apdu);
        } catch (TagLostException e) {
            errorCodeReason = "TagLostException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            errorCodeReason = "IOException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        }
        log(methodName, printData("received  <--", recvBuffer));
        return recvBuffer;
    }

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
     * Returns a copy of the data bytes in the response body. If this APDU as
     * no body, this method returns a byte array with a length of zero.
     *
     * @return a copy of the data bytes in the response body or the empty
     * byte array if this APDU has no body.
     */
    private byte[] getData(byte[] responseAPDU) {
        log("getData", printData("responseAPDU", responseAPDU), true);
        if ((responseAPDU == null) || (responseAPDU.length < 2)) {
            Log.e(TAG, "responseApdu is NULL or length is < 2, aborted");
            return null;
        }
        byte[] data = new byte[responseAPDU.length - 2];
        System.arraycopy(responseAPDU, 0, data, 0, data.length);
        log("getData", printData("responseData", data));
        return data;
    }

    /**
     * checks if the response has an 0x'9100' at the end means success
     * and the method returns the data without 0x'9100' at the end
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkResponse(byte[] data) {
        if (data == null) return false;
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

        private boolean checkResponseIso(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_ISO_OK, returnStatusBytes(data))) {
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
     * check some know method parameters
     */

    private boolean checkApplicationIdentifier(byte[] applicationIdentifier) {
        if ((applicationIdentifier == null) || (applicationIdentifier.length != 3)) {
            log("checkApplicationIdentifier", "applicationIdentifier is NULL or not of length 3, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "applicationIdentifier is NULL or not of length 3";
            return false;
        }
        return true;
    }

    private boolean checkFileNumber(byte fileNumber) {
        if ((fileNumber < 0) || (fileNumber > 31)) {
            log("checkFileNumber", "fileNumber is not in range 0..31, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "applicationIdentifier is NULL or not of length 3";
            return false;
        }
        return true;
    }

    // note: this does not check if in application creation all keys got created
    private boolean checkAccessRights(byte[] accessRights) {
        if ((accessRights == null) || (accessRights.length != 2)) {
            log("checkAccessRights", "accessRights are NULL or not of length 2, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "accessRights are NULL or not of length 2";
            return false;
        }
        return true;
    }

    private boolean checkIsoDep() {
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log("checkIsoDep", "lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            errorCodeReason = "lost connection to the card";
            return false;
        }
        return true;
    }

    /**
     * internal utility methods
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

    /**
     * add the padding bytes to data that is written to a Standard, Backup, Linear Record or Cyclic Record file
     * The encryption method does need a byte array of multiples of 16 bytes
     * If the unpaddedData is of (multiple) length of 16 the complete padding is added
     *
     * @param unpaddedData
     * @return the padded data
     */
    public byte[] paddingWriteData(byte[] unpaddedData) {
        // sanity checks
        if (unpaddedData == null) {
            Log.e(TAG, "paddingWriteData - unpaddedData is NULL, aborted");
            return null;
        }
        int unpaddedDataLength = unpaddedData.length;
        int paddingBytesLength = PADDING_FULL.length;
        byte[] fullPaddedData = new byte[unpaddedDataLength + paddingBytesLength];
        // concatenate unpaddedData and PADDING_FULL
        System.arraycopy(unpaddedData, 0, fullPaddedData, 0, unpaddedDataLength);
        System.arraycopy(PADDING_FULL, 0, fullPaddedData, unpaddedDataLength, paddingBytesLength);
        // this is maybe too long, trunc to multiple of 16 bytes
        int mult16 = fullPaddedData.length / 16;
        Log.d(TAG, "fullPaddedData.length: " + fullPaddedData.length);
        Log.d(TAG, "mult16               : " + mult16);
        return Arrays.copyOfRange(fullPaddedData, 0, (mult16 * 16));
    }

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


    /**
     * section for logging
     */

    private void log(String methodName, String data) {
        log(methodName, data, false);
    }

    private void log(String methodName, String data, boolean isMethodHeader) {
        if (printToLog) {
            logData += "method: " + methodName + "\n" + data + "\n";
            //logData += "\n" + methodName + ":\n" + data + "\n\n";
            Log.d(TAG, "method: " + methodName + ": " + data);
        }
    }

    /**
     * getter
     */

    public byte[] getErrorCode() {
        return errorCode;
    }

    public String getErrorCodeReason() {
        return errorCodeReason;
    }

    public String getLogData() {
        return logData;
    }
}
