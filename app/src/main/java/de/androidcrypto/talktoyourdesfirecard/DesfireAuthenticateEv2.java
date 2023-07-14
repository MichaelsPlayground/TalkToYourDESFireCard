package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.hexStringToByteArray;

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
 * <p>
 * communication types
 * active commands so far:                                   PLAIN  MACed  ENCIPHERED
 * AUTHENTICATE_AES_EV2_FIRST_COMMAND = (byte) 0x71;          n.a.   n.a.     WORK
 * AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND = (byte) 0x77;      n.a.   n.a.     WORK
 * GET_CARD_UID_COMMAND = (byte) 0x51;                        n.a.   n.a.     WORK
 * <p>
 * CREATE_DATA_FILE_COMMAND = (byte) 0xxx;
 * READ_DATA_COMMAND = (byte) 0xxx;
 * WRITE_DATA_COMMAND = (byte) 0xxx;
 * <p>
 * CREATE_VALUE_FILE_COMMAND = (byte) 0xxx;
 * READ_VALUE_FILE_COMMAND = (byte) 0xxx;
 * CREDIT_VALUE_FILE_COMMAND = (byte) 0xxx;
 * DEBIT_VALUE_FILE_COMMAND = (byte) 0xxx;
 * <p>
 * CREATE_RECORD_FILE_COMMAND = (byte) 0xxx;
 * READ_RECORD_FILE_COMMAND = (byte) 0xxx;
 * WRITE_RECORD_FILE_COMMAND = (byte) 0xxx;
 * <p>
 * DELETE_FILE_COMMAND = (byte) 0xxx;
 * GET_FILE_SETTINGS = (byte) 0xxx;
 * GET_FILE_KEY_SETTINGS = (byte) 0xxx;
 * <p>
 * CHANGE_KEY_COMMAND = (byte) 0xxx;
 * <p>
 * GET_FREE_MEMORY_ON_CARD_COMMAND = (byte) 0xxx;
 * FORMAT_PICC_COMMAND = (byte) 0xxx;
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
    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte READ_STANDARD_FILE_SECURE_COMMAND = (byte) 0xAD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte WRITE_STANDARD_FILE_SECURE_COMMAND = (byte) 0x8D;

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    private final byte[] HEADER_ENC = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
    private final byte[] HEADER_MAC = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0x5AA5

    private final byte FILE_COMMUNICATION_SETTINGS_PLAIN = (byte) 0x00; // plain communication
    private final byte FILE_COMMUNICATION_SETTINGS_ENCIPHERED = (byte) 0x03; // enciphered communication
    /**
     * for explanations on File Communication Settings see M075031_desfire.pdf page 15:
     * byte = 0: Plain communication
     * byte = 1: Plain communication secured by DES/3DES/AES MACing
     * byte = 3: Fully DES/3DES/AES enciphered communication
     */

    private final byte STANDARD_FILE_FREE_ACCESS_ID = (byte) 0x01; // file ID with free access
    private final byte STANDARD_FILE_KEY_SECURED_ACCESS_ID = (byte) 0x02; // file ID with key secured access
    // settings for key secured access depend on RadioButtons rbFileFreeAccess, rbFileKeySecuredAccess
    // key 0 is the  Application Master Key
    private final byte ACCESS_RIGHTS_RW_CAR_FREE = (byte) 0xEE; // Read&Write Access (free) & ChangeAccessRights (free)
    private final byte ACCESS_RIGHTS_R_W_FREE = (byte) 0xEE; // Read Access (free) & Write Access (free)
    private final byte ACCESS_RIGHTS_RW_CAR_SECURED = (byte) 0x12; // Read&Write Access (key 01) & ChangeAccessRights (key 02)
    private final byte ACCESS_RIGHTS_R_W_SECURED = (byte) 0x34; // Read Access (key 03) & Write Access (key 04)

    public DesfireAuthenticateEv2(IsoDep isoDep, boolean printToLog) {
        this.isoDep = isoDep;
        this.printToLog = printToLog;
    }

    public boolean createStandardFileEv2(byte fileNumber, int fileSize, boolean isStandardFile, boolean isEncrypted) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card
        String logData = "";
        String methodName = "createStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " fileSize: " + fileSize +
                " isStandardFile: " + isStandardFile + " isEncrypted: " + isEncrypted);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // todo other sanity checks on values

        byte[] fileSizeArray = Utils.intTo3ByteArrayInversed(fileSize); // lsb order
        byte[] paddingParameter = Utils.hexStringToByteArray("");
        // generate the parameter
        ByteArrayOutputStream baosParameter = new ByteArrayOutputStream();
        baosParameter.write(CREATE_STANDARD_FILE_COMMAND);
        baosParameter.write(fileNumber);
        baosParameter.write(FILE_COMMUNICATION_SETTINGS_ENCIPHERED); // todo this should not be fixed
        // the access rights depend on free access or not
        /*
        if (isFreeAccess) {
            baos.write(ACCESS_RIGHTS_RW_CAR_FREE);
            baos.write(ACCESS_RIGHTS_R_W_FREE);
        } else {
            baos.write(ACCESS_RIGHTS_RW_CAR_SECURED);
            baos.write(ACCESS_RIGHTS_R_W_SECURED);
        }*/
        baosParameter.write(ACCESS_RIGHTS_RW_CAR_SECURED);
        baosParameter.write(ACCESS_RIGHTS_R_W_SECURED);
        baosParameter.write(fileSizeArray, 0, 3);
        byte[] parameter = baosParameter.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));

        //
        // todo THIS IS NOT READY TO USE


        return false;
    }

    public boolean writeStandardFile(byte fileNumber, byte[] dataToWrite) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.WriteData in AES Secure Messaging using CommMode.Full
        // this is based on the write to a data file on a DESFire Light card

        String logData = "";
        String methodName = "writeStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // todo other sanity checks on values

        // todo read the file settings to get e.g. the fileSize and communication mode
        int FILE_SIZE_FIXED = 32;

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // MAC_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] header = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0xA55A
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(header, 0, header.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // data compl   22222222222222222222222222222222222222222222222222 (25 bytes)
        // data block 1 22222222222222222222222222222222 (16 bytes)
        // data block 2 22222222222222222280000000000000 (16 bytes, 9 data bytes and 15 padding bytes, beginning with 0x80)

        // create an empty array and copy the dataToWrite to clear the complete standard file
        // this is done to avoid the padding
        // todo work on this, this is rough coded
        byte[] fullDataToWrite = new byte[FILE_SIZE_FIXED];
        System.arraycopy(dataToWrite, 0, fullDataToWrite, 0, dataToWrite.length);

        // here we are splitting up the data into 2 data blocks
        byte[] dataBlock1 = Arrays.copyOfRange(fullDataToWrite, 0, 16);
        byte[] dataBlock2 = Arrays.copyOfRange(fullDataToWrite, 16, 32);
        log(methodName, printData("dataBlock1", dataBlock1));
        log(methodName, printData("dataBlock2", dataBlock2));

        // Encrypted Data Block 1 = E(KSesAuthENC, Data Input)
        byte[] dataBlock1Encrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, dataBlock1);
        byte[] iv2 = dataBlock1Encrypted.clone();
        log(methodName, printData("iv2", iv2));
        byte[] dataBlock2Encrypted = AES.encrypt(iv2, SesAuthENCKey, dataBlock2); // todo is this correct ? or startingIv ?

        //byte[] dataBlock2Encrypted = AES.encrypt(startingIv, SesAuthENCKey, dataBlock2); // todo is this correct ? or startingIv ?
        log(methodName, printData("startingIv", startingIv));
        log(methodName, printData("dataBlock1Encrypted", dataBlock1Encrypted));
        log(methodName, printData("dataBlock2Encrypted", dataBlock2Encrypted));

        // Encrypted Data (complete), concatenate 2 byte arrays
        byte[] encryptedData = concatenate(dataBlock1Encrypted, dataBlock2Encrypted);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        int fileSize = FILE_SIZE_FIXED;
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offset, 0, 3);
        baosCmdHeader.write(length, 0, 3);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(WRITE_STANDARD_FILE_SECURE_COMMAND); // 0xAD
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
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

        // todo this could be wrong parameter Data (FileNo || Offset || DataLenght || Data)
        // Data (CmdHeader || Encrypted Data || MAC) ??
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_SECURE_COMMAND, writeDataCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);

        // todo something missing ?
        return true;

    }


    public byte[] readStandardFile(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.ReadData in AES Secure Messaging using CommMode.Full
        // this is based on the read of a data file on a DESFire Light card

        // status WORKING

        String logData = "";
        String methodName = "readStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
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

        // todo other sanity checks on values

        // todo read the file settings to get e.g. the fileSize and communication mode

        int FILE_SIZE_FIXED = 32;
        // Generating the MAC for the Command APDU

        // CmdHeader (FileNo || Offset || DataLength)

        // generate the parameter

        // data in write example:
        // 22222222222222222222222222222222222222222222222222 (25)

        //int fileSize = 0; // fixed, read complete file
        int fileSize = FILE_SIZE_FIXED;
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offset, 0, 3);
        baosCmdHeader.write(length, 0, 3);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));
        // example: 00000000300000
        // MAC_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(READ_STANDARD_FILE_SECURE_COMMAND); // 0xAD
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));
        // example: AD0100CD73D8E500000000300000
        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));
        // example: 7CF94F122B3DB05F

        // Constructing the full ReadData Command APDU
        ByteArrayOutputStream baosReadDataCommand = new ByteArrayOutputStream();
        baosReadDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadDataCommand.toByteArray();
        log(methodName, printData("readDataCommand", readDataCommand));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] encryptedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_SECURE_COMMAND, readDataCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullEncryptedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        // response length: 58 data: 8b61541d54f73901c8498c71dd45bae80578c4b1581aad439a806f37517c86ad4df8970279bbb8874ef279149aaa264c3e5eceb0e37a87699100

        // the fullEncryptedData is 56 bytes long, the first 48 bytes are encryptedData and the last 8 bytes are the responseMAC
        int encryptedDataLength = fullEncryptedData.length - 8;
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includedes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] header = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(header, 0, header.length);
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData)); // should be the cardUID || 9 zero bytes
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, fileSize); // todo work on this
        log(methodName, printData("readData", readData));

        // verifying the received MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaos.write(encryptedData, 0, encryptedData.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput", macInput2));
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return readData;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
    }

    /*
    private byte[] readFromAStandardFilePlainCommunicationDes(TextView logTextView, byte fileNumber, int fileSize, byte[] methodResponse) {
        final String methodName = "createFilePlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if ((fileSize < 1) || (fileSize > MAXIMUM_FILE_SIZE)) {
            Log.e(TAG, methodName + " fileSize has to be in range 1.." + MAXIMUM_FILE_SIZE + " but found " + fileSize + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
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
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");

            // now strip of the response bytes
            // if the card responses more data than expected we truncate the data
            int expectedResponse = fileSize - offsetBytes;
            if (response.length == expectedResponse) {
                return response;
            } else if (response.length > expectedResponse) {
                // more data is provided - truncated
                return Arrays.copyOf(response, expectedResponse);
            } else {
                // less data is provided - we return as much as possible
                return response;
            }
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }
     */

    public byte[] getCardUidEv2() {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 15, 16, 17
        String logData = "";
        String methodName = "getCardUidEv2";
        log(methodName, "started", true);
        // sanity checks
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

        // parameter
        byte[] cmdCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(GET_CARD_UID_COMMAND);
        baos.write(cmdCounterLsb, 0, cmdCounterLsb.length);
        baos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] parameter = baos.toByteArray();
        log(methodName, "parameter for GET_CARD_UID_COMMAND");
        log(methodName, "command: " + Utils.byteToHex(GET_CARD_UID_COMMAND));
        log(methodName, printData("cmdCounterLsb", cmdCounterLsb));
        log(methodName, printData("TransactionIdentifier", TransactionIdentifier));
        log(methodName, printData("parameter", parameter));

        // generate the full MAC
        byte[] macOverCommand = calculateDiverseKey(SesAuthMACKey, parameter);
        log(methodName, printData("macOverCommand", macOverCommand));
        // now truncate the MAC
        byte[] macOverCommandTruncated = truncateMAC(macOverCommand);

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] encryptedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(GET_CARD_UID_COMMAND, macOverCommandTruncated);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullEncryptedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        // the fullEncryptedData is 24 bytes long, the first 16 bytes are encryptedData and the last 8 bytes are the responseMAC
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, 16);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, 16, 24);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] header = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(header, 0, header.length);
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb, 0, commandCounterLsb.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData)); // should be the cardUID || 9 zero bytes
        byte[] cardUid = Arrays.copyOfRange(decryptedData, 0, 7);
        log(methodName, printData("cardUid", cardUid));

        // verifying the received MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb, 0, commandCounterLsb.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaos.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = responseMacBaos.toByteArray();
        log(methodName, printData("macInput", macInput));
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return cardUid;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return null;
        }
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
        return new byte[]{
                (byte) value,
                (byte) (value >> 8)};
    }

    // convert a 2 byte long array to an int, the byte array is in inversed = LSB order
    private int byteArrayLength2InversedToInt(byte[] data) {
        return (data[1] & 0xff) << 8 | (data[0] & 0xff);
    }

    private byte[] truncateMAC(byte[] fullMAC) {
        String methodName = "truncateMAC";
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

    public boolean writeDataFullPart1Test() {
        /**
         * this will test several function using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf pages 55-57
         * to get a full apdu for part 1, preparing the data writing
         * test vectors are for Cmd.WriteData in AES Secure Messaging using CommMode.Full
         */

        byte[] SesAuthENCKeyTest = hexStringToByteArray("FFBCFE1F41840A09C9A88D0A4B10DF05");
        byte[] SesAuthMACKeyTest = hexStringToByteArray("37E7234B11BEBEFDE41A8F290090EF80");
        byte[] TI = hexStringToByteArray("CD73D8E5");
        int commandCounter = 0;
        byte[] startingIv = new byte[16];

        byte fileNumber = (byte) 0x00;

        byte[] data = hexStringToByteArray("22222222222222222222222222222222222222222222222222");
        byte[] dataBlock1 = hexStringToByteArray("22222222222222222222222222222222");
        byte[] dataBlock2 = hexStringToByteArray("22222222222222222280000000000000");
        int dataLength = 25;

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // MAC_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        Log.d(TAG,"CmdCounter: " + CmdCounter);
        Log.d(TAG, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] header = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0xA55A
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(header, 0, header.length);
        baosIvInput.write(TI, 0, TI.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        Log.d(TAG, printData("ivInput         ", ivInput));

        byte[] ivInput_expected = hexStringToByteArray("A55ACD73D8E500000000000000000000");
        Log.d(TAG, printData("ivInput_expected", ivInput_expected));
        if (!Arrays.equals(ivInput_expected, ivInput)) {
            Log.d(TAG, "ivInput Test FAILURE, aborted");
            return false;
        }

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        Log.d(TAG, printData("SesAuthENCKeyTest", SesAuthENCKeyTest));

        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKeyTest, ivInput);
        Log.d(TAG, printData("ivForCmdData         ", ivForCmdData));
        byte[] ivForCmdData_expected = hexStringToByteArray("871747AF36D72164A418BBFECCECD911");
        Log.d(TAG, printData("ivForCmdData_expected", ivForCmdData_expected));
        if (!Arrays.equals(ivForCmdData_expected, ivForCmdData)) {
            Log.d(TAG, "ivForCmdData Test FAILURE, aborted");
            return false;
        }

        // data compl   22222222222222222222222222222222222222222222222222 (25 bytes)
        // data block 1 22222222222222222222222222222222 (16 bytes)
        // data block 2 22222222222222222280000000000000 (16 bytes, 9 data bytes and 15 padding bytes, beginning with 0x80)

        // create an empty array and copy the dataToWrite to clear the complete standard file
        // this is done to avoid the padding

        Log.d(TAG, printData("dataBlock1", dataBlock1));
        Log.d(TAG, printData("dataBlock2", dataBlock2));

        // Encrypted Data Block 1 = E(KSesAuthENC, Data Input)
        byte[] dataBlock1Encrypted = AES.encrypt(ivForCmdData, SesAuthENCKeyTest, dataBlock1);
        Log.d(TAG, printData("dataBlock1Encrypted         ", dataBlock1Encrypted));
        byte[] dataBlock1Encrypted_expected = hexStringToByteArray("D7446FBC912580C0A65E738D28B609E4");
        Log.d(TAG, printData("dataBlock1Encrypted_expected", dataBlock1Encrypted_expected));
        if (!Arrays.equals(dataBlock1Encrypted_expected, dataBlock1Encrypted)) {
            Log.d(TAG, "dataBlock1Encrypted Test FAILURE, aborted");
            return false;
        }

        byte[] iv2 = dataBlock1Encrypted.clone();
        Log.d(TAG, printData("iv2", iv2));
        byte[] dataBlock2Encrypted = AES.encrypt(iv2, SesAuthENCKeyTest, dataBlock2); // todo is this correct ? or startingIv ?
        Log.d(TAG, printData("dataBlock2Encrypted         ", dataBlock2Encrypted));
        byte[] dataBlock2Encrypted_expected = hexStringToByteArray("3ADBB8FB2B4CA68744D1BBEBB37EBD32");
        Log.d(TAG, printData("dataBlock2Encrypted_expected", dataBlock2Encrypted_expected));
        if (!Arrays.equals(dataBlock2Encrypted_expected, dataBlock2Encrypted)) {
            Log.d(TAG, "dataBlock2Encrypted Test FAILURE, aborted");
            return false;
        }

        // Encrypted Data (complete), concatenate 2 byte arrays
        byte[] encryptedData = concatenate(dataBlock1Encrypted, dataBlock2Encrypted);
        Log.d(TAG, printData("encryptedData         ", encryptedData));
        byte[] encryptedData_expected = hexStringToByteArray("D7446FBC912580C0A65E738D28B609E43ADBB8FB2B4CA68744D1BBEBB37EBD32");
        Log.d(TAG, printData("encryptedData_expected", encryptedData_expected));
        if (!Arrays.equals(encryptedData_expected, encryptedData)) {
            Log.d(TAG, "encryptedData Test FAILURE, aborted");
            return false;
        }

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(dataLength); // LSB order
        Log.d(TAG, printData("length", length));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offset, 0, 3);
        baosCmdHeader.write(length, 0, 3);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        Log.d(TAG, printData("cmdHeader         ", cmdHeader));
        byte[] cmdHeader_expected = hexStringToByteArray("00000000190000");
        Log.d(TAG, printData("cmdHeader_expected", cmdHeader_expected));
        if (!Arrays.equals(cmdHeader_expected, cmdHeader)) {
            Log.d(TAG, "cmdHeader Test FAILURE, aborted");
            return false;
        }

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(WRITE_STANDARD_FILE_SECURE_COMMAND); // 0xAD
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TI, 0, TI.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        Log.d(TAG, printData("macInput", macInput));
        byte[] macInput_expected = hexStringToByteArray("8D0000CD73D8E500000000190000D7446FBC912580C0A65E738D28B609E43ADBB8FB2B4CA68744D1BBEBB37EBD32");
        Log.d(TAG, printData("macInput_expected", macInput_expected));
        if (!Arrays.equals(macInput_expected, macInput)) {
            Log.d(TAG, "macInput Test FAILURE, aborted");
            return false;
        }

        // generate the MAC (CMAC) with the SesAuthMACKey
        Log.d(TAG, printData("SesAuthMACKeyTest", SesAuthMACKeyTest));
        byte[] macFull = calculateDiverseKey(SesAuthMACKeyTest, macInput);
        Log.d(TAG, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        Log.d(TAG, printData("macTruncated", macTruncated));
        byte[] macTruncated_expected = hexStringToByteArray("700ADF7BB9F62A6C");
        Log.d(TAG, printData("macTruncated_expected", macTruncated_expected));
        if (!Arrays.equals(macTruncated_expected, macTruncated)) {
            Log.d(TAG, "macTruncated Test FAILURE, aborted");
            return false;
        }

        // todo this could be wrong parameter Data (FileNo || Offset || DataLenght || Data)
        // Data (CmdHeader || Encrypted Data || MAC) ??
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        Log.d(TAG, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_SECURE_COMMAND, writeDataCommand);
            Log.d(TAG, printData("apdu         ", apdu));
            byte[] apdu_expected = hexStringToByteArray("908D00002F00000000190000D7446FBC912580C0A65E738D28B609E43ADBB8FB2B4CA68744D1BBEBB37EBD32700ADF7BB9F62A6C00");
            Log.d(TAG, printData("apdu_expected", apdu_expected));
            if (!Arrays.equals(apdu_expected, apdu)) {
                Log.d(TAG, "apdu Test FAILURE, aborted");
                return false;
            }
            response = isoDep.transceive(apdu);
            Log.d(TAG, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, "transceive failed, IOException:\n" + e.getMessage());
            Log.d(TAG, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);


        return false;
    }


    public boolean readDataFullPart1Test() {
        /**
         * this will test several function using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf pages 57-58
         * to get a full apdu for part 1, prepairing the data retrieve
         * test vectors are for Cmd.ReadData in AES Secure Messaging using CommMode.Full
         */

        byte[] SesAuthENCKeyTest = hexStringToByteArray("FFBCFE1F41840A09C9A88D0A4B10DF05");
        byte[] SesAuthMACKeyTest = hexStringToByteArray("37E7234B11BEBEFDE41A8F290090EF80");
        byte[] TI = hexStringToByteArray("CD73D8E5");
        int commandCounter = 1;
        byte[] startingIv = new byte[16];

        byte fileNumber = (byte) 0x00;
        int fileSize = 48; // fixed, read complete file
        //int fileSize = 0; // fixed, read complete file
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offset, 0, 3);
        baosCmdHeader.write(length, 0, 3);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        Log.d(TAG, printData("cmdHeader", cmdHeader));
        byte[] cmdHeader_expected = Utils.hexStringToByteArray("00000000300000");
        if (!Arrays.equals(cmdHeader_expected, cmdHeader)) {
            Log.d(TAG, "cmdHeader Test FAILURE, aborted");
            return false;
        }

        // example:
        // MAC_Input
        byte[] commandCounterLsb = intTo2ByteArrayInversed(commandCounter);
        Log.d(TAG, printData("commandCounterLsb", commandCounterLsb));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(READ_STANDARD_FILE_SECURE_COMMAND); // 0xAD
        baosMacInput.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosMacInput.write(TI, 0, TI.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        byte[] macInput = baosMacInput.toByteArray();
        Log.d(TAG, printData("macInput         ", macInput));
        byte[] macInput_expected = Utils.hexStringToByteArray("AD0100CD73D8E500000000300000");
        Log.d(TAG, printData("macInput_expected", macInput_expected));
        if (!Arrays.equals(macInput_expected, macInput)) {
            Log.d(TAG, "macInput Test FAILURE, aborted");
            return false;
        }

        Log.d(TAG, printData("macInput", macInput));
        // example: AD0100CD73D8E500000000300000
        // generate the MAC (CMAC) with the SesAuthMACKey
        byte[] macFull = calculateDiverseKey(SesAuthMACKeyTest, macInput);
        Log.d(TAG, printData("macFull", macFull));

        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        Log.d(TAG, printData("macTruncated", macTruncated));
        byte[] macTruncated_expected = Utils.hexStringToByteArray("7CF94F122B3DB05F");
        if (!Arrays.equals(macTruncated_expected, macTruncated)) {
            Log.d(TAG, "macTruncated Test FAILURE, aborted");
            return false;
        }
        // example: 7CF94F122B3DB05F

        // Constructing the full ReadData Command APDU
        ByteArrayOutputStream baosReadDataCommand = new ByteArrayOutputStream();
        baosReadDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadDataCommand.toByteArray();
        Log.d(TAG, printData("readDataCommand", readDataCommand));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] encryptedData;
        byte[] responseMACTruncatedReceived;
        byte[] apdu_expected;
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_SECURE_COMMAND, readDataCommand);
            Log.d(TAG, printData("apdu", apdu));
            apdu_expected = Utils.hexStringToByteArray("90AD00000F000000003000007CF94F122B3DB05F00");
            if (!Arrays.equals(apdu_expected, apdu)) {
                Log.d(TAG, "apdu Test FAILURE, aborted");
                return false;
            }
            // example: 90AD00000F000000003000007CF94F122B3DB05F00 (21 bytes)
            // example: 90AD0000 0F 00 000000 300000 7CF94F122B3DB05F 00 (21 bytes)
            // my data: 90ad00000f020000002000007e23ca88e24b3e4100
            // my data: 90ad0000 0f 02 000000 200000 7e23ca88e24b3e41 00


        } catch (IOException e) {
            Log.e(TAG, "transceive failed, IOException:\n" + e.getMessage());
            Log.d(TAG, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (!Arrays.equals(apdu_expected, apdu)) {
            Log.d(TAG, "APDU FAILURE");
            return false;
        } else {
            Log.d(TAG, "APDU SUCCESS");
            return true;
        }

    }

    public boolean decryptDataTest() {
        /**
         * this will test several function using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf pages 15-17
         * to get a decrypted value.
         * test vectors are for getCardUid
         */
        byte[] SesAuthENCKeyTest = hexStringToByteArray("C1D7BD9F60034D8432F9AF3403D573D0");
        byte[] SesAuthMACKeyTest = hexStringToByteArray("FD9E26C9766F07C1D07106C0F8F3671F");
        byte[] TI = hexStringToByteArray("569D4B24");
        int commandCounter = 0;
        byte[] startingIv = new byte[16];
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] ivInputResponse_expected = hexStringToByteArray("5AA5569D4B2401000000000000000000");
        byte[] IV_Response_expected = hexStringToByteArray("5A42ECB2111A9267FA5F2682523229AC");
        byte[] DecryptedResponseData_expected = hexStringToByteArray("04DE5F1EACC040800000000000000000");
        // DecryptedResponseData is cardUID 7 bytes || padding (starting with 80) 9 bytes
        byte[] UID_expected = hexStringToByteArray("04DE5F1EACC040");
        byte[] EncryptedResponseData = hexStringToByteArray("CDFFBF6D34231DA2789DA9D3AB15D560");
        byte[] ResponseMACTruncated_expected = hexStringToByteArray("CE75E39EDBE94C2F");

        // build the IV_INPUT_RESPONSE
        // note: as this test starts after sending data to the card the commandCounter is increased by 1
        commandCounter += 1;
        byte[] header = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] commandCounterLsb = intTo2ByteArrayInversed(commandCounter);

        ByteArrayOutputStream baosIvInputResponse = new ByteArrayOutputStream();
        baosIvInputResponse.write(header, 0, header.length);
        baosIvInputResponse.write(TI, 0, TI.length);
        baosIvInputResponse.write(commandCounterLsb, 0, commandCounterLsb.length);
        baosIvInputResponse.write(padding, 0, padding.length);
        byte[] ivInputResponse = baosIvInputResponse.toByteArray();
        Log.d(TAG, printData("ivInputResponse         ", ivInputResponse));
        Log.d(TAG, printData("ivInputResponse_expected", ivInputResponse_expected));
        if (!Arrays.equals(ivInputResponse_expected, ivInputResponse)) {
            Log.d(TAG, "ivInputResponse Test FAILURE, aborted");
            return false;
        }

        // get the IV_Response by encrypting with SesAuthEncKey
        byte[] IV_Response = AES.encrypt(startingIv, SesAuthENCKeyTest, ivInputResponse);
        Log.d(TAG, printData("IV_Response         ", IV_Response));
        Log.d(TAG, printData("IV_Response_expected", IV_Response_expected));
        if (!Arrays.equals(IV_Response_expected, IV_Response)) {
            Log.d(TAG, "IV_Response Test FAILURE, aborted");
            return false;
        }

        // Decrypting the Response Data with the SesAuthENCKeyTest
        byte[] DecryptedResponseData = AES.decrypt(IV_Response, SesAuthENCKeyTest, EncryptedResponseData);
        Log.d(TAG, printData("DecryptedResponseData         ", DecryptedResponseData));
        Log.d(TAG, printData("DecryptedResponseData_expected", DecryptedResponseData_expected));
        if (!Arrays.equals(DecryptedResponseData_expected, DecryptedResponseData)) {
            Log.d(TAG, "DecryptedResponseData Test FAILURE, aborted");
            return false;
        }
        // get the 7 bytes of card UID and skip the last 9 bytes padding
        byte[] UID = Arrays.copyOfRange(DecryptedResponseData, 0, 7);
        Log.d(TAG, printData("UID         ", UID));
        Log.d(TAG, printData("UID_expected", UID_expected));
        if (!Arrays.equals(UID_expected, UID)) {
            Log.d(TAG, "UID Test FAILURE, aborted");
            return false;
        }

        // verify the responseMAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb, 0, commandCounterLsb.length);
        responseMacBaos.write(TI, 0, TI.length);
        responseMacBaos.write(EncryptedResponseData, 0, EncryptedResponseData.length);
        byte[] macInput = responseMacBaos.toByteArray();
        Log.d(TAG, printData("macInput", macInput));
        byte[] ResponseMACCalculated = calculateDiverseKey(SesAuthMACKeyTest, macInput);
        Log.d(TAG, printData("ResponseMACCalculated", ResponseMACCalculated));
        byte[] ResponseMACTruncatedCalculated = truncateMAC(ResponseMACCalculated);
        Log.d(TAG, printData("ResponseMACTruncatedCalculated", ResponseMACTruncatedCalculated));
        Log.d(TAG, printData("ResponseMACTruncatedReceived  ", ResponseMACTruncated_expected));
        if (!Arrays.equals(ResponseMACTruncated_expected, ResponseMACTruncatedCalculated)) {
            Log.d(TAG, "ResponseMACTruncated FAILURE");
            return false;
        } else {
            Log.d(TAG, "ResponseMACTruncated SUCCESS");
            return true;
        }
    }


    public boolean truncateMACTest() {
        /**
         * this will test the function 'truncateMAC' using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf page 16
         * to get a truncated MAC from a full mac
         */

        byte[] fullMAC = hexStringToByteArray("ED5CB7A932EF8D7C2E91B42A1139F11B");
        byte[] truncatedMAC_expected = hexStringToByteArray("5CA9EF7C912A391B");
        byte[] truncatedMAC = truncateMAC(fullMAC);
        if (Arrays.equals(truncatedMAC_expected, truncatedMAC)) {
            Log.d(TAG, "truncateMACTest SUCCESS");
            return true;
        } else {
            Log.d(TAG, "truncateMACTest FAILURE");
            return false;
        }
    }


    public boolean macOverCommandTest() {
        /**
         * this will test the function 'calculateDiverseKey' using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf page 16
         * to get a full mac for a MAC over the command
         */

        // testdata
        byte[] parameter = Utils.hexStringToByteArray("510000569D4B24");
        byte[] SesAuthMACKeyTest = Utils.hexStringToByteArray("FD9E26C9766F07C1D07106C0F8F3671F");
        byte[] macOverCommand_expected = Utils.hexStringToByteArray("ED5CB7A932EF8D7C2E91B42A1139F11B");
        byte[] macOverCommand = calculateDiverseKey(SesAuthMACKeyTest, parameter);
        if (Arrays.equals(macOverCommand_expected, macOverCommand)) {
            Log.d(TAG, "macOverCommandTest SUCCESS");
            return true;
        } else {
            Log.d(TAG, "macOverCommandTest FAILURE");
            return false;
        }
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
