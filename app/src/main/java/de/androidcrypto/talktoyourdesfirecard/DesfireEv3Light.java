package de.androidcrypto.talktoyourdesfirecard;


import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.util.Log;
import android.widget.TextView;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.AccessControlException;
import java.util.Arrays;

/**
 * This class is the light weight version of a larger library that connects to Mifare DESFire EV3 tags.
 * It contains all commands that are necessary to enable the Secret Unique NFC (SUN) feature that is
 * based on Secure Dynamic Messaging (SDM) that is available on DESFire EV3 tags.
 *
 */

public class DesfireEv3Light {


    private static final String TAG = DesfireEv3Light.class.getName();


    private IsoDep isoDep;
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
    private byte[] NDEF_FILE_01_CONTENT_CONTAINER = Utils.hexStringToByteArray("000F20003A00340406E10401000000"); // 256 byte
    public static final byte NDEF_FILE_02_NUMBER = (byte) 0x02;
    public static final byte[] NDEF_FILE_02_ISO_NAME = Utils.hexStringToByteArray("04E1");
    public static final byte[] NDEF_FILE_02_ACCESS_RIGHTS = Utils.hexStringToByteArray("00EE"); // free access for reading and writing, an authentication is needed for all other accesses
    public static final int NDEF_FILE_02_SIZE = 256;

    public static final int MAXIMUM_FILE_SIZE = 256; // this is fixed by me, could as long as about free memory of the tag
    public enum CommunicationSettings {
        Plain, MACed, Full
    }

    /**
     * constants for commands
     */
    private final byte GET_VERSION_INFO_COMMAND = (byte) 0x60;
    private final byte CREATE_APPLICATION_COMMAND = (byte) 0xCA;
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;

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

    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_ISO_OK = new byte[]{(byte) 0x90, (byte) 0x00};
    public static final byte[] RESPONSE_DUPLICATE_ERROR = new byte[]{(byte) 0x91, (byte) 0xDE};
    public static final byte[] RESPONSE_ISO_DUPLICATE_ERROR = new byte[]{(byte) 0x90, (byte) 0xDE};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private static final byte[] RESPONSE_PARAMETER_ERROR = new byte[]{(byte) 0x91, (byte) 0xFE}; // failure because of wrong parameter
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure

    /**
     * standard file
     */


    public DesfireEv3Light(IsoDep isoDep) {
        this.isoDep = isoDep;
        Log.i(TAG, "class is initialized");
    }

    /**
     * section for application handling
     */

    /**
     * create a new application including Data File Name using AES keys
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

/*
90 CA 00 00 0E 01 00 00 0F 21 10 E1 D2 76 00 00 85 01 01 00h
90 ca 00 00 0c 01 00 00 0f a5       d276000085010100

 */

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

        return writeToStandardFileRawPlain(fileNumber, NDEF_FILE_01_CONTENT_CONTAINER, 0);
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
     * The method writes a byte array to a Standard file using CommunicationMode.Plain. If the data
     * length exceeds the MAXIMUM_MESSAGE_LENGTH the data will be written in chunks.
     * If the data length exceeds MAXIMUM_FILE_LENGTH the methods returns a FAILURE
     * @param fileNumber | in range 0..31
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
            boolean success = writeToStandardFileRawPlain(fileNumber, dataToWrite, offset);
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
     * Do not call this method from outside this class but use one of the writeToStandardFile callers
     *
     * @param fileNumber | in range 0..31
     * @param data       | maximum of 40 bytes to avoid framing
     * @param offset     | offset in the file
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */
    private boolean writeToStandardFileRawPlain(byte fileNumber, byte[] data, int offset) {
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

    public byte[] readFromStandardFileRawPlain(byte fileNumber, int offset, int length) {
        String logData = "";
        final String methodName = "readFromStandardFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + "size: " + length);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null; // logFile and errorCode are updated
        if (offset < 0) {
            Log.e(TAG, methodName + " offset is < 0, aborted");
            log(methodName, "offset is < 0, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            return null;
        }
        if ((length <= 0) || (length > MAXIMUM_FILE_SIZE)) {
            Log.e(TAG, methodName + " length has to be in range 1.." + MAXIMUM_FILE_SIZE + " but found " + length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
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
        byte[] apdu;
        byte[] response;
        try {
            //pdu = wrapMessage(READ_STANDARD_FILE_COMMAND, commandParameter);
            response = sendRequest(READ_STANDARD_FILE_COMMAND, commandParameter);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        // as sendRequest strips off the statusByte there is no checkResponse here
        errorCode = RESPONSE_OK.clone();
        errorCodeReason = "SUCCESS";
        return getData(response);
    }


    /**
     * section for general tasks
     */

    public VersionInfo getVersionInformation() {
        byte[] bytes = new byte[0];
        try {
            bytes = sendRequest(GET_VERSION_INFO_COMMAND);
            return new VersionInfo(bytes);
        } catch (Exception e) {
            log("getVersionInformation", "IOException: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
        }
        return null;
    }

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

    public byte[] sendRequest(byte command) throws Exception {
        return sendRequest(command, null);
    }

    private byte[] sendRequest(byte command, byte[] parameters) throws IOException {
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        byte[] recvBuffer = sendData(wrapMessage(command, parameters));
        if (recvBuffer == null) {
            return null;
        }
        while (true) {
            if (recvBuffer[recvBuffer.length - 2] != (byte) 0x91) {
                throw new IOException("Invalid response");
            }
            output.write(recvBuffer, 0, recvBuffer.length - 2);
            byte status = recvBuffer[recvBuffer.length - 1];
            if (status == (byte) 0x00) {
                break;
            } else if (status == (byte) 0xAF) {
                recvBuffer = sendData(wrapMessage((byte) 0xAF, null));
            } else if (status == (byte) 0x9D) {
                throw new AccessControlException("Permission denied");
            } else if (status == (byte) 0xAE) {
                throw new AccessControlException("Authentication error");
            } else {
                throw new IOException("Unknown status code: " + Integer.toHexString(status & 0xFF));
            }
        }
        return output.toByteArray();
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
        log("getData", printData("responseData", data), false);
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
