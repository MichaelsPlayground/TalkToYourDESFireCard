package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.byteArrayLength4InversedToInt;
import static de.androidcrypto.talktoyourdesfirecard.Utils.byteToHex;
import static de.androidcrypto.talktoyourdesfirecard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourdesfirecard.Utils.intTo3ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.intTo4ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;
import static de.androidcrypto.talktoyourdesfirecard.Utils.removeAllNonAlphaNumeric;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.tech.IsoDep;
import android.util.Log;
import android.widget.TextView;

import androidx.annotation.NonNull;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
 * CREATE_STANDARD_FILE_COMMAND = (byte) 0xxx;
 * CREATE_BACKUP_FILE_COMMAND = (byte) 0xxx;
 * READ_DATA_COMMAND = (byte) 0xxx;
 * WRITE_DATA_COMMAND = (byte) 0xxx;
 * <p>
 * CREATE_VALUE_FILE_COMMAND = (byte) 0xxx;
 * READ_VALUE_FILE_COMMAND = (byte) 0xxx;
 * CREDIT_VALUE_FILE_COMMAND = (byte) 0xxx;
 * DEBIT_VALUE_FILE_COMMAND = (byte) 0xxx;
 * <p>
 * CREATE_LINEAR_RECORD_FILE_COMMAND = (byte) 0xxx;
 * CREATE_CYCLIC_RECORD_FILE_COMMAND = (byte) 0xxx;
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
    private final byte SELECT_APPLICATION_BY_AID_COMMAND = (byte) 0x5A;
    private final byte AUTHENTICATE_AES_EV2_FIRST_COMMAND = (byte) 0x71;
    private final byte AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND = (byte) 0x77;
    private final byte GET_CARD_UID_COMMAND = (byte) 0x51;

    private final byte GET_FILE_IDS_COMMAND = (byte) 0x6F;
    private final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private final byte SET_CONFIGURATION_SECURE_COMMAND = (byte) 0x5C;

    // standard file
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte READ_STANDARD_FILE_SECURE_COMMAND = (byte) 0xAD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte WRITE_STANDARD_FILE_SECURE_COMMAND = (byte) 0x8D;

    // value file
    private final byte GET_VALUE_COMMAND = (byte) 0x6C;
    private final byte CREDIT_VALUE_COMMAND = (byte) 0x0C;
    private final byte DEBIT_VALUE_COMMAND = (byte) 0xDC;

    // record file

    private static final byte READ_RECORD_FILE_SECURE_COMMAND = (byte) 0xAB;
    private static final byte WRITE_RECORD_FILE_SECURE_COMMAND = (byte) 0x8B;

    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte CREATE_BACKUP_FILE_COMMAND = (byte) 0xCB;
    private final byte CREATE_VALUE_FILE_COMMAND = (byte) 0xCC;
    private final byte CREATE_LINEAR_RECORD_FILE_COMMAND = (byte) 0xC1;
    private final byte CREATE_CYCLIC_RECORD_FILE_COMMAND = (byte) 0xC0;


    private static final byte COMMIT_TRANSACTION_SECURE_COMMAND = (byte) 0xC7;
    private static final byte COMMIT_READER_ID_SECURE_COMMAND = (byte) 0xC8;
    private final byte CREATE_TRANSACTION_MAC_FILE_COMMAND = (byte) 0xCE;
    private final byte DELETE_TRANSACTION_MAC_FILE_COMMAND = (byte) 0xDF;

    private final byte CHANGE_KEY_SECURE_COMMAND = (byte) 0xC4;
    private static final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;


    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure
    private final byte[] RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS = new byte[]{(byte) 0x91, (byte) 0xFD};
    private final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFE};

    private final byte[] HEADER_ENC = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
    private final byte[] HEADER_MAC = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0x5AA5

    private final byte FILE_COMMUNICATION_SETTINGS_PLAIN = (byte) 0x00; // plain communication
    private final byte FILE_COMMUNICATION_SETTINGS_MACED = (byte) 0x01; // mac'ed communication
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

    // key settings for Transaction MAC file
    private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0x10; // Read&Write Access (key 01) & ChangeAccessRights (key 00)
    private final byte ACCESS_RIGHTS_R_W_TMAC = (byte) 0x1F; // Read Access (key 01) & Write Access (no access)

    private final byte[] IV_LABEL_ENC = new byte[]{(byte) 0xA5, (byte) 0x5A}; // use as header for AES encryption
    private final byte[] IV_LABEL_DEC = new byte[]{(byte) 0x5A, (byte) 0xA5}; // use as header for AES decryption

    // predefined file numbers
    public final byte STANDARD_FILE_PLAIN_NUMBER = (byte) 0x00;
    public final byte STANDARD_FILE_MACED_NUMBER = (byte) 0x01;
    public final byte STANDARD_FILE_ENCRYPTED_NUMBER = (byte) 0x02;
    // backup 03, 04, 05
    public final byte BACKUP_FILE_PLAIN_NUMBER = (byte) 0x03;
    public final byte BACKUP_FILE_MACED_NUMBER = (byte) 0x04;
    public final byte BACKUP_FILE_ENCRYPTED_NUMBER = (byte) 0x05;
    // value files 06, 07, 08
    public final byte VALUE_FILE_PLAIN_NUMBER = (byte) 0x06; // 06
    public final byte VALUE_FILE_MACED_NUMBER = (byte) 0x07; // 07
    public final byte VALUE_FILE_ENCRYPTED_NUMBER = (byte) 0x08; // 08
    // linear record 09, 10, 11
    public final byte LINEAR_RECORD_FILE_PLAIN_NUMBER = (byte) 0x09; // 09
    public final byte LINEAR_RECORD_FILE_MACED_NUMBER = (byte) 0x0A; // 10
    public final byte LINEAR_RECORD_FILE_ENCRYPTED_NUMBER = (byte) 0x0B; // 11
    // cyclic record 12, 13, 14
    public final byte CYCLIC_RECORD_FILE_PLAIN_NUMBER = (byte) 0x0C; // 12
    public final byte CYCLIC_RECORD_FILE_MACED_NUMBER = (byte) 0x0D; // 13
    public final byte CYCLIC_RECORD_FILE_ENCRYPTED_NUMBER = (byte) 0x0E; // 14

    private static final byte MAXIMUM_NUMBER_OF_KEYS = 5; // the maximum of keys per application is 14
    private final int MAXIMUM_NUMBER_OF_FILES = 32; // as per datasheet DESFire EV3 this is valid for EV1, EV2 and EV3


    private final byte[] PADDING_FULL = hexStringToByteArray("80000000000000000000000000000000");
    private final byte[] PADDING_FULL_DES = hexStringToByteArray("8000000000000000");

    private byte[] selectedApplicationId; // filled by 'select application'
    private static byte[] APPLICATION_ALL_FILE_IDS; // filled by getAllFileIds and invalidated by selectApplication AND createFile
    private static FileSettings[] APPLICATION_ALL_FILE_SETTINGS; // filled by getAllFileSettings and invalidated by selectApplication AND createFile
    private FileSettings selectedFileSetting; // takes the fileSettings of the actual file
    private FileSettings[] fileSettingsArray = new FileSettings[MAXIMUM_NUMBER_OF_FILES]; // after an 'select application' the fileSettings of all files are read
    // this value get invalidated after creation of a new file in this application and you need to reselect the application


    public enum CommunicationSettings {
        Plain, MACed, Encrypted
    }

    public enum DesfireFileType {
        Standard, Backup, Value, LinearRecord, CyclicRecord
    }


    public DesfireAuthenticateEv2(IsoDep isoDep, boolean printToLog) {
        this.isoDep = isoDep;
        this.printToLog = printToLog;
    }

    // getFileSettings, command 0xF5, pages 24-27


    public boolean createStandardFileEv2(byte fileNumber, int fileSize, boolean isStandardFile, boolean isEncrypted) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card
        String logData = "";
        final String methodName = "createStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " fileSize: " + fileSize +
                " isStandardFile: " + isStandardFile + " isEncrypted: " + isEncrypted);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // todo other sanity checks on values

        APPLICATION_ALL_FILE_IDS = null;
        APPLICATION_ALL_FILE_SETTINGS = null;

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

    /**
     * section for Standard Files
     */

    public boolean writeStandardFileEv2(byte fileNumber, byte[] dataToWrite) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.WriteData in AES Secure Messaging using CommMode.Full
        // this is based on the write to a data file on a DESFire Light card

        // status WORKING - with prepared data blocks only:
        // todo add padding
        // if data length is a multiple of AES block length (16 bytes) we need to add a complete
        // block of padding data, beginning with 0x80 00 00...

        /**
         * Mifare DESFire Light Features and Hints AN12343.pdf page 30
         * 7.1.2 Encryption and Decryption
         * Encryption and decryption are done using the underlying block cipher (in this case
         * the AES block cipher) according to the CBC mode of the NIST Special Publication
         * 800-38A, see [6]. Padding is done according to Padding Method 2 (0x80 followed by zero
         * bytes) of ISO/IEC 9797-1. Note that if the original data is already a multiple of 16 bytes,
         * another additional padding block (16 bytes) is added. The only exception is during the
         * authentication itself, where no padding is applied at all.
         */

        String logData = "";
        final String methodName = "writeStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // todo other sanity checks on values

        /*
        // read the file settings to get e.g. the fileSize and communication mode
        boolean sfsSuccess = getSelectedFileSettings(fileNumber);
        if (!sfsSuccess) {
            log(methodName, "Could not retrieve the fileSettings for fileNumber " + fileNumber + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        } else {
            log(methodName, selectedFileSetting.dump());
        }
        */
        //int selectedFileSize = selectedFileSetting.getFileSizeInt();
        int selectedFileSize = 32;

        // what does happen when dataToWrite is longer than selectedFileSize ?
        // Answer: I'm trimming the data to selectedFileSize
        byte[] dataToWriteCorrectLength;
        if (dataToWrite.length > selectedFileSize) {
            log(methodName, "trimming dataToWrite to length of selected fileNumber: " + selectedFileSize);
            dataToWriteCorrectLength = Arrays.copyOfRange(dataToWrite, 0, selectedFileSize);
        } else {
            dataToWriteCorrectLength = dataToWrite.clone();
        }

        // next step is to pad the data according to padding rules in desfire EV2/3 for AES Secure Messaging fullMode
        byte[] dataPadded = paddingWriteData(dataToWriteCorrectLength);
        log(methodName, printData("data unpad", dataToWriteCorrectLength));
        log(methodName, printData("data pad  ", dataPadded));

        int numberOfDataBlocks = dataPadded.length / 16;
        log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
        List<byte[]> dataBlockList = Utils.divideArrayToList(dataPadded, 16);

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
        //byte[] fullDataToWrite = new byte[FILE_SIZE_FIXED];
        //System.arraycopy(dataToWrite, 0, fullDataToWrite, 0, dataToWrite.length);

        // here we are splitting up the data into 2 data blocks
        //byte[] dataBlock1 = Arrays.copyOfRange(fullDataToWrite, 0, 16);
        //byte[] dataBlock2 = Arrays.copyOfRange(fullDataToWrite, 16, 32);

        //log(methodName, printData("dataBlock1", dataBlock1));
        //log(methodName, printData("dataBlock2", dataBlock2));

        List<byte[]> dataBlockEncryptedList = new ArrayList<>();
        byte[] ivDataEncryption = ivForCmdData.clone(); // the "starting iv"

        for (int i = 0; i < numberOfDataBlocks; i++) {
            byte[] dataBlockEncrypted = AES.encrypt(ivDataEncryption, SesAuthENCKey, dataBlockList.get(i));
            dataBlockEncryptedList.add(dataBlockEncrypted);
            ivDataEncryption = dataBlockEncrypted.clone(); // new, subsequent iv for next encryption
        }
/*
        // Encrypted Data Block 1 = E(KSesAuthENC, Data Input)
        byte[] dataBlock1Encrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, dataBlock1);
        byte[] iv2 = dataBlock1Encrypted.clone();
        log(methodName, printData("iv2", iv2));
        byte[] dataBlock2Encrypted = AES.encrypt(iv2, SesAuthENCKey, dataBlock2); // todo is this correct ? or startingIv ?
*/
        //byte[] dataBlock2Encrypted = AES.encrypt(startingIv, SesAuthENCKey, dataBlock2); // todo is this correct ? or startingIv ?
//        log(methodName, printData("startingIv", startingIv));
        for (int i = 0; i < numberOfDataBlocks; i++) {
            log(methodName, printData("dataBlock" + i + "Encrypted", dataBlockEncryptedList.get(i)));
        }
        //log(methodName, printData("dataBlock1Encrypted", dataBlock1Encrypted));
        //log(methodName, printData("dataBlock2Encrypted", dataBlock2Encrypted));

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
        byte[] encryptedData = baosDataEncrypted.toByteArray();
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        int fileSize = selectedFileSize;
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        log(methodName, printData("length", length));
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

        // error in Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLenght || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public boolean writeStandardFileOrgEv2(byte fileNumber, byte[] dataToWrite) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.WriteData in AES Secure Messaging using CommMode.Full
        // this is based on the write to a data file on a DESFire Light card

        // status WORKING - with prepared data blocks only:
        // todo add padding
        // if data length is a multiple of AES block length (16 bytes) we need to add a complete
        // block of padding data, beginning with 0x80 00 00...


        /**
         * Mifare DESFire Light Features and Hints AN12343.pdf page 30
         * 7.1.2 Encryption and Decryption
         * Encryption and decryption are done using the underlying block cipher (in this case
         * the AES block cipher) according to the CBC mode of the NIST Special Publication
         * 800-38A, see [6]. Padding is done according to Padding Method 2 (0x80 followed by zero
         * bytes) of ISO/IEC 9797-1. Note that if the original data is already a multiple of 16 bytes,
         * another additional padding block (16 bytes) is added. The only exception is during the
         * authentication itself, where no padding is applied at all.
         */

        String logData = "";
        final String methodName = "writeStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // todo other sanity checks on values

        // todo read the file settings to get e.g. the fileSize and communication mode
        int FILE_SIZE_FIXED = 25;
        byte[] dataBlock1 = hexStringToByteArray("34222222222222222222222222222222");
        byte[] dataBlock2 = hexStringToByteArray("22222222222222222280000000000000");
        //int dataLength = 25;

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
        //byte[] fullDataToWrite = new byte[FILE_SIZE_FIXED];
        //System.arraycopy(dataToWrite, 0, fullDataToWrite, 0, dataToWrite.length);

        // here we are splitting up the data into 2 data blocks
        //byte[] dataBlock1 = Arrays.copyOfRange(fullDataToWrite, 0, 16);
        //byte[] dataBlock2 = Arrays.copyOfRange(fullDataToWrite, 16, 32);

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
        log(methodName, printData("length", length));
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

        // error in Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLenght || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public byte[] readStandardFileEv2(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.ReadData in AES Secure Messaging using CommMode.Full
        // this is based on the read of a data file on a DESFire Light card

        // status WORKING

        String logData = "";
        final String methodName = "readStandardFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        // todo other sanity checks on values

        // check that is a Standard or Backup file
        if (APPLICATION_ALL_FILE_SETTINGS == null) {
            Log.e(TAG, methodName + " missing getFileSettings, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS, 0, errorCode, 0, 2);
            return null;
        }
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings == null) {
            Log.e(TAG, methodName + " missing getFileSettings, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS, 0, errorCode, 0, 2);
            return null;
        }

        if ((fileSettings.getFileTypeName().equals(FileSettings.STANDARD_FILE_TYPE)) ||
                (fileSettings.getFileTypeName().equals(FileSettings.BACKUP_FILE_TYPE))) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        // read the file settings to get e.g. the fileSize and communication mode
        //int FILE_SIZE = 32;
        int FILE_SIZE = fileSettings.getFileSizeInt();
        log(methodName, "read the file with a length of " + FILE_SIZE + " bytes");

        // found a strange behaviour on the getFileSettings
        /**
         * found a strange behaviour on the getFileSettings: after a (successful) authentication the first
         * getFileSettings command returns an 0x7e = 'length error', so in case of an error I'm trying to
         * get the file settings a second time
         */

        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(FILE_SIZE); // LSB order
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
        log(methodName, printData("decryptedData", decryptedData));
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, FILE_SIZE);
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

    /**
     * section for backup files
     */

    public boolean writeBackupFileEv2(byte fileNumber, byte[] dataToWrite) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.WriteData in AES Secure Messaging using CommMode.Full
        // this is based on the write to a data file on a DESFire Light card

        // this code is advanced to run the commit command after the write command

        // status WORKING - with prepared data blocks only:
        // todo add padding
        // if data length is a multiple of AES block length (16 bytes) we need to add a complete
        // block of padding data, beginning with 0x80 00 00...

        /**
         * Mifare DESFire Light Features and Hints AN12343.pdf page 30
         * 7.1.2 Encryption and Decryption
         * Encryption and decryption are done using the underlying block cipher (in this case
         * the AES block cipher) according to the CBC mode of the NIST Special Publication
         * 800-38A, see [6]. Padding is done according to Padding Method 2 (0x80 followed by zero
         * bytes) of ISO/IEC 9797-1. Note that if the original data is already a multiple of 16 bytes,
         * another additional padding block (16 bytes) is added. The only exception is during the
         * authentication itself, where no padding is applied at all.
         */

        String logData = "";
        final String methodName = "writeBackupFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // todo other sanity checks on values

        /*
        // read the file settings to get e.g. the fileSize and communication mode
        boolean sfsSuccess = getSelectedFileSettings(fileNumber);
        if (!sfsSuccess) {
            log(methodName, "Could not retrieve the fileSettings for fileNumber " + fileNumber + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        } else {
            log(methodName, selectedFileSetting.dump());
        }
        */
        //int selectedFileSize = selectedFileSetting.getFileSizeInt();
        int selectedFileSize = 32;

        // what does happen when dataToWrite is longer than selectedFileSize ?
        // Answer: I'm trimming the data to selectedFileSize
        byte[] dataToWriteCorrectLength;
        if (dataToWrite.length > selectedFileSize) {
            log(methodName, "trimming dataToWrite to length of selected fileNumber: " + selectedFileSize);
            dataToWriteCorrectLength = Arrays.copyOfRange(dataToWrite, 0, selectedFileSize);
        } else {
            dataToWriteCorrectLength = dataToWrite.clone();
        }

        // next step is to pad the data according to padding rules in desfire EV2/3 for AES Secure Messaging fullMode
        byte[] dataPadded = paddingWriteData(dataToWriteCorrectLength);
        log(methodName, printData("data unpad", dataToWriteCorrectLength));
        log(methodName, printData("data pad  ", dataPadded));

        int numberOfDataBlocks = dataPadded.length / 16;
        log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
        List<byte[]> dataBlockList = Utils.divideArrayToList(dataPadded, 16);

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
        byte[] encryptedData = baosDataEncrypted.toByteArray();
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        int fileSize = selectedFileSize;
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(fileSize); // LSB order
        log(methodName, printData("length", length));
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

        // error in Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLenght || Data) is NOT correct, as well not the Data Message
        // correct is the following concatenation:

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public byte[] readDataFileEv2(byte fileNumber) {
        // this can be used to read Standard and Backup files
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 55 - 58
        // Cmd.ReadData in AES Secure Messaging using CommMode.Full
        // this is based on the read of a data file on a DESFire Light card

        // status WORKING

        String logData = "";
        final String methodName = "readDataFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        // todo other sanity checks on values

        // check that is a Standard or Backup file
        if (APPLICATION_ALL_FILE_SETTINGS == null) {
            Log.e(TAG, methodName + " missing getFileSettings, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS, 0, errorCode, 0, 2);
            return null;
        }
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings == null) {
            Log.e(TAG, methodName + " missing getFileSettings, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS, 0, errorCode, 0, 2);
            return null;
        }

        if ((fileSettings.getFileTypeName().equals(FileSettings.STANDARD_FILE_TYPE)) ||
                (fileSettings.getFileTypeName().equals(FileSettings.BACKUP_FILE_TYPE))) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        // read the file settings to get e.g. the fileSize and communication mode
        //int FILE_SIZE = 32;
        int FILE_SIZE = fileSettings.getFileSizeInt();
        log(methodName, "read the file with a length of " + FILE_SIZE + " bytes");

        // found a strange behaviour on the getFileSettings
        /**
         * found a strange behaviour on the getFileSettings: after a (successful) authentication the first
         * getFileSettings command returns an 0x7e = 'length error', so in case of an error I'm trying to
         * get the file settings a second time
         */

        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(FILE_SIZE); // LSB order
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
        log(methodName, printData("decryptedData", decryptedData));
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, FILE_SIZE);
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

    /**
     * section for Value files
     */

    public int getValueFileEv2(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 67 - 70
        // Cmd.GetValue in AES Secure Messaging using CommMode.Full
        // this is based on the get value on a value file on a DESFire Light card
        String logData = "";
        final String methodName = "getValueFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);

        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return -1;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return -1;
        }

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader ( = File number) )
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(GET_VALUE_COMMAND); // 0x6C
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Data (CmdHeader = File number || MAC)
        ByteArrayOutputStream baosGetValueCommand = new ByteArrayOutputStream();
        baosGetValueCommand.write(fileNumber);
        baosGetValueCommand.write(macTruncated, 0, macTruncated.length);
        byte[] getValueCommand = baosGetValueCommand.toByteArray();
        log(methodName, printData("getValueCommand", getValueCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        byte[] fullEncryptedData;
        byte[] encryptedData;
        try {
            apdu = wrapMessage(GET_VALUE_COMMAND, getValueCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return -1;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullEncryptedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return -1;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // the fullEncryptedData is xx bytes long, the first xx bytes are encryptedData and the last 8 bytes are the responseMAC
        int encryptedDataLength = fullEncryptedData.length - 8;
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includedes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        //byte[] header = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
        byte[] padding = hexStringToByteArray("0000000000000000"); // fixed 8 bytes
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length);
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData)); // should be the cardUID || 9 zero bytes
        // 00000000800000000000000000000000 should be like value (4 bytes LSB) || 12 padding bytes (0x80..00)
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, 4);
        log(methodName, printData("readData", readData));

        // verifying the received Response MAC
        // MAC_Input (RC || CmdCounter || TI || Encrypted Response Data)
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaos.write(encryptedData, 0, encryptedData.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return byteArrayLength4InversedToInt(decryptedData);
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return -1;
        }
    }

    public boolean creditValueFileEv2(byte fileNumber, int changeValue) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 70 - 71
        // Cmd.CreditValue in AES Secure Messaging using CommMode.Full
        // this is based on the credit a value on a value file on a DESFire Light card
        // Note: this document does not mention to submit a COMMIT command !
        String logData = "";
        final String methodName = "creditValueFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " changeValue: " + changeValue);

        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (changeValue < 1) {
            Log.e(TAG, methodName + " minimum changeValue is 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // encrypting the  command data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
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

        // Data (Value || Padding)
        // 71000000800000000000000000000000 ( 4 bytes LSB value || 12 bytes padding, starting with 0x80 00)
        byte[] value = intTo4ByteArrayInversed(changeValue);
        log(methodName, printData("value", value));
        byte[] padding2 = hexStringToByteArray("800000000000000000000000"); // 12 bytes
        log(methodName, printData("padding2", padding2));
        byte[] data = concatenate(value, padding2);
        log(methodName, printData("data", data));

        // Encrypt Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader = FileNo

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CREDIT_VALUE_COMMAND); // 0x0C
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
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

        // error in Feature and Hints page 70 point 23
        // wrong: Data (CmdHeader || MAC) and Data Messaging
        // correct: see below
        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosCreditValueCommand = new ByteArrayOutputStream();
        baosCreditValueCommand.write(fileNumber);
        baosCreditValueCommand.write(encryptedData, 0, encryptedData.length);
        baosCreditValueCommand.write(macTruncated, 0, macTruncated.length);
        byte[] creditValueCommand = baosCreditValueCommand.toByteArray();
        log(methodName, printData("creditValueCommand", creditValueCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CREDIT_VALUE_COMMAND, creditValueCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public boolean debitValueFileEv2(byte fileNumber, int changeValue) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 72 - 73
        // Cmd.DebitValue in AES Secure Messaging using CommMode.Full
        // this is based on the debit a value on a value file on a DESFire Light card
        // Note: this document does not mention to submit a COMMIT command !
        String logData = "";
        final String methodName = "debitValueFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " changeValue: " + changeValue);

        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if (changeValue < 1) {
            Log.e(TAG, methodName + " minimum changeValue is 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // encrypting the  command data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
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

        // Data (Value || Padding)
        // 71000000800000000000000000000000 ( 4 bytes LSB value || 12 bytes padding, starting with 0x80 00)
        byte[] value = intTo4ByteArrayInversed(changeValue);
        log(methodName, printData("value", value));
        byte[] padding2 = hexStringToByteArray("800000000000000000000000"); // 12 bytes
        log(methodName, printData("padding2", padding2));
        byte[] data = concatenate(value, padding2);
        log(methodName, printData("data", data));

        // Encrypt Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader = FileNo

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(DEBIT_VALUE_COMMAND); // 0xDC
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
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

        // error in Feature and Hints page 70 point 23
        // wrong: Data (CmdHeader || MAC) and Data Messaging
        // correct: see below
        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosDebitValueCommand = new ByteArrayOutputStream();
        baosDebitValueCommand.write(fileNumber);
        baosDebitValueCommand.write(encryptedData, 0, encryptedData.length);
        baosDebitValueCommand.write(macTruncated, 0, macTruncated.length);
        byte[] debitValueCommand = baosDebitValueCommand.toByteArray();
        log(methodName, printData("debitValueCommand", debitValueCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(DEBIT_VALUE_COMMAND, debitValueCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    /**
     * section for Record files
     */

    public boolean writeRecordFileEv2(byte fileNumber, byte[] dataToWrite) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
        // Cmd.WriteRecord in AES Secure Messaging using CommMode.Full
        // this is based on the write to a data file on a DESFire Light card

        // status
        // todo add padding
        // if data length is a multiple of AES block length (16 bytes) we need to add a complete
        // block of padding data, beginning with 0x80 00 00...

        /**
         * Mifare DESFire Light Features and Hints AN12343.pdf page 30
         * 7.1.2 Encryption and Decryption
         * Encryption and decryption are done using the underlying block cipher (in this case
         * the AES block cipher) according to the CBC mode of the NIST Special Publication
         * 800-38A, see [6]. Padding is done according to Padding Method 2 (0x80 followed by zero
         * bytes) of ISO/IEC 9797-1. Note that if the original data is already a multiple of 16 bytes,
         * another additional padding block (16 bytes) is added. The only exception is during the
         * authentication itself, where no padding is applied at all.
         */

        String logData = "";
        final String methodName = "writeRecordFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", dataToWrite));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // todo other sanity checks on values

        // todo read the file settings to get e.g. the recordSize and communication mode
        // NOTE we need to receive PRE PADDED DATA, not the full 32 data bytes for a record
        // in the MainActivity we padded the data (length 30 bytes) with 0x80 0x00
        int DATA_SIZE_FIXED = 30;


        //int dataLength = 25;

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // IV_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
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

        // create an empty array and copy the dataToWrite to clear the complete standard file
        // this is done to avoid the padding
        // todo work on this, this is rough coded
        //byte[] fullDataToWrite = new byte[FILE_SIZE_FIXED];
        //System.arraycopy(dataToWrite, 0, fullDataToWrite, 0, dataToWrite.length);

        // here we are splitting up the data into 2 data blocks
        byte[] dataBlock1 = Arrays.copyOfRange(dataToWrite, 0, 16);
        byte[] dataBlock2 = Arrays.copyOfRange(dataToWrite, 16, 32);
        log(methodName, printData("dataToWrite", dataToWrite));
        log(methodName, printData("dataBlock1 ", dataBlock1));
        log(methodName, printData("dataBlock2 ", dataBlock2));

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
        int dataSizeInt = DATA_SIZE_FIXED;
        int offsetBytes = 0; // read from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] dataSize = Utils.intTo3ByteArrayInversed(dataSizeInt); // LSB order
        log(methodName, printData("dataSize", dataSize));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offset, 0, offset.length);
        baosCmdHeader.write(dataSize, 0, dataSize.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(WRITE_RECORD_FILE_SECURE_COMMAND); // 0x8B
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

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteRecordCommand = new ByteArrayOutputStream();
        baosWriteRecordCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteRecordCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteRecordCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeRecordCommand = baosWriteRecordCommand.toByteArray();
        log(methodName, printData("writeRecordCommand", writeRecordCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_RECORD_FILE_SECURE_COMMAND, writeRecordCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public byte[] readRecordFileEv2(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 65 - 67
        // Cmd.ReadRecords in AES Secure Messaging using CommMode.Full
        // this is based on the read of a record file on a DESFire Light card

        // status WORKING but does not remove any padding from the data
        // todo read file settings to get recordSize, actualRecords etc

        // at the moment it is using a pre created Cyclic Record File with 5 records and
        // 5 application keys (AES) in full enciphered communication mode
        // reason: no examples for creating a record file in Features and Hints

        String logData = "";
        final String methodName = "readRecordFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return null;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }

        // todo other sanity checks on values

        // todo read the file settings to get e.g. the recordSize, actual records and communication mode

        int FILE_SIZE_FIXED = 32;
        // Generating the MAC for the Command APDU

        // CmdHeader (FileNo || RecordNo || RecordCount)
        // setting recordNo and recordCount to 0 to read all records
        int recordNoInt = 0;
        int recordCountInt = 0;
        byte[] recordNo = Utils.intTo3ByteArrayInversed(recordNoInt); // LSB order
        byte[] recordCount = Utils.intTo3ByteArrayInversed(recordCountInt); // LSB order

        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(recordNo, 0, recordNo.length);
        baosCmdHeader.write(recordCount, 0, recordCount.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader )
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(READ_RECORD_FILE_SECURE_COMMAND); // 0xAB
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full ReadRecords Command APDU
        // todo is this correct, NO encryption ??
        // Data (CmdHeader || MAC)

        // Constructing the full ReadData Command APDU
        ByteArrayOutputStream baosReadRecordCommand = new ByteArrayOutputStream();
        baosReadRecordCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadRecordCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadRecordCommand.toByteArray();
        log(methodName, printData("readRecordCommand", readDataCommand));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullEncryptedData;
        byte[] encryptedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(READ_RECORD_FILE_SECURE_COMMAND, readDataCommand);
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
        byte[] readData = decryptedData.clone();
        //byte[] readData = Arrays.copyOfRange(decryptedData, 0, fileSize); // todo work on this
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

    /**
     * section for commit
     */

    public boolean commitTransactionEv2() {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
        // Cmd.Commit in AES Secure Messaging using CommMode.MAC
        // this is based on the write of a record file on a DESFire Light card
        // additionally see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 106 - 107
        // Note: this is working ONLY when a Transaction MAC file is NOT present in the application
        //       If a TMAC file is present use the commitTMACTransactionEv2 method !

        // status WORKING

        String logData = "";
        final String methodName = "commitTransactionEv2";
        log(methodName, "started", true);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // here we are using just the commit command without preceding commitReaderId command
        // Constructing the full CommitTransaction Command APDU
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte[] startingIv = new byte[16];

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(COMMIT_TRANSACTION_SECURE_COMMAND); // 0xC7
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(COMMIT_TRANSACTION_OPTION);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the commitTransactionData
        ByteArrayOutputStream baosCommitTransactionCommand = new ByteArrayOutputStream();
        baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION);
        baosCommitTransactionCommand.write(macTruncated, 0, macTruncated.length);
        byte[] commitTransactionCommand = baosCommitTransactionCommand.toByteArray();
        log(methodName, printData("commitTransactionCommand", commitTransactionCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_SECURE_COMMAND, commitTransactionCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullResponseData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        // the full response depends on an enabled TransactionMAC file option:
        // TransactionMAC counter || TransactionMAC value || response MAC
        // if not enabled just the response MAC is returned

        // this does NOT work when a TransactionMAC file is present:
        // commitTransactionEv2 error code: 9D Permission denied error

        log(methodName, printData("fullResponseData", fullResponseData));
        byte[] responseMACTruncatedReceived = new byte[8];
        byte[] responseTmcv = new byte[0];
        int fullResponseDataLength = fullResponseData.length;
        if (fullResponseDataLength > 8) {
            log(methodName, "the fullResponseData has a length of " + fullResponseDataLength + " bytes, so the TMC and TMV are included");
            responseTmcv = Arrays.copyOfRange(fullResponseData, 0, (fullResponseDataLength - 8));
            responseMACTruncatedReceived = Arrays.copyOfRange(fullResponseData, (fullResponseDataLength - 8), fullResponseDataLength);
            log(methodName, printData("responseTmcv", responseTmcv));
        } else {
            responseMACTruncatedReceived = fullResponseData.clone();
        }

        // verifying the received MAC
        // MAC_Input (RC || CmdCounter || TI || Response Data)
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaos.write(responseTmcv, 0, responseTmcv.length);
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
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public boolean commitTMACTransactionEv2() {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
        // Cmd.Commit in AES Secure Messaging using CommMode.MAC
        // this is based on the write of a record file on a DESFire Light card
        // additionally see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 106 - 107

        // status WORKING

        String logData = "";
        final String methodName = "commitTMACTransactionEv2";
        log(methodName, "started", true);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // here we are using just the commit command with preceding commitReaderId command

        // Constructing the full CommitReaderID Command APDU
        // we do need a ReaderId
        byte[] READER_ID = hexStringToByteArray("28BF1982BE086FBC60A22DAEB66613EE"); // 16 bytes
        byte[] iv0Reader = new byte[16];
        log(methodName, printData("READER_ID", READER_ID));
        log(methodName, printData("iv0Reader", iv0Reader));

        // MAC_Input (Ins || CmdCounter || TI || Data (= Reader ID) )
        byte[] commandCounterLsb1Reader = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1Reader));
        ByteArrayOutputStream baosMacInputReader = new ByteArrayOutputStream();
        baosMacInputReader.write(COMMIT_READER_ID_SECURE_COMMAND); // 0xC8
        baosMacInputReader.write(commandCounterLsb1Reader, 0, commandCounterLsb1Reader.length);
        baosMacInputReader.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInputReader.write(READER_ID, 0, READER_ID.length);
        byte[] macInputReader = baosMacInputReader.toByteArray();
        log(methodName, printData("macInputReader", macInputReader));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFullReader = calculateDiverseKey(SesAuthMACKey, macInputReader);
        log(methodName, printData("macFullReader", macFullReader));
        // now truncate the MAC
        byte[] macTruncatedReader = truncateMAC(macFullReader);
        log(methodName, printData("macTruncatedReader", macTruncatedReader));

        // construction of the commitTransactionData Data (Encrypted Data || MAC)
        ByteArrayOutputStream baosCommitTransactionReaderCommand = new ByteArrayOutputStream();
        baosCommitTransactionReaderCommand.write(READER_ID, 0, READER_ID.length); // todo check if the READ_ID is UNENCRYPTED send ??
        baosCommitTransactionReaderCommand.write(macTruncatedReader, 0, macTruncatedReader.length);
        byte[] commitTransactionReaderCommand = baosCommitTransactionReaderCommand.toByteArray();
        log(methodName, printData("commitTransactionReaderCommand", commitTransactionReaderCommand));


        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] encryptedResponseData;
        try {
            apdu = wrapMessage(COMMIT_READER_ID_SECURE_COMMAND, commitTransactionReaderCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            encryptedResponseData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        // Encrypted Response Data EKSesAuthENC(Response Data)
        // sample: A1963F1BB9FC916A8B15B2DC58002531 (16 bytes)
        // decrypt the data
        int encryptedDataLength = encryptedResponseData.length - 8;
        log(methodName, "The encryptedResponseData is of length " + encryptedResponseData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        byte [] encryptedData = Arrays.copyOfRange(encryptedResponseData, 0, encryptedDataLength);
        byte[] responseMACTruncatedReceivedReader = Arrays.copyOfRange(encryptedResponseData, encryptedDataLength, encryptedResponseData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        // IV_Input_Response = 0x5A || 0xA5 || TI || CmdCtr || 0x0000000000000000 (8 bytes padding)
        byte[] commandCounterLsb2Reader = intTo2ByteArrayInversed(CmdCounter);
        byte[] paddingReader = hexStringToByteArray("0000000000000000");
        byte[] startingIvReader = new byte[16];
        ByteArrayOutputStream decryptBaosReader = new ByteArrayOutputStream();
        decryptBaosReader.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length); // (byte) 0x5A, (byte) 0xA5
        decryptBaosReader.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaosReader.write(commandCounterLsb2Reader, 0, commandCounterLsb2Reader.length);
        decryptBaosReader.write(paddingReader, 0, paddingReader.length);
        byte[] ivInputResponseReader = decryptBaosReader.toByteArray();
        log(methodName, printData("ivInputResponseReader", ivInputResponseReader));
        byte[] ivResponseReader = AES.encrypt(startingIvReader, SesAuthENCKey, ivInputResponseReader);
        log(methodName, printData("ivResponseReader", ivResponseReader));
        byte[] decryptedData = AES.decrypt(ivResponseReader, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData));
        log(methodName, "decryptedData is TMRI (TransactionMAC Reader ID");
        // Decrypted Response Data = (TMRI) : BDD40ED9F434F9DDCBF5821299CD2119 (16 bytes)

        // verifying the received MAC
        // MAC_Input (RC || CmdCounter || TI || Encrypted Response Data)
        byte[] commandCounterLsb3Reader = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream responseMacBaosReader = new ByteArrayOutputStream();
        responseMacBaosReader.write((byte) 0x00); // response code 00 means success
        responseMacBaosReader.write(commandCounterLsb3Reader, 0, commandCounterLsb3Reader.length);
        responseMacBaosReader.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaosReader.write(encryptedData, 0, encryptedData.length);
        byte[] macInput2Reader = responseMacBaosReader.toByteArray();
        log(methodName, printData("macInput2Reader", macInput2Reader));
        byte[] responseMACCalculatedReader = calculateDiverseKey(SesAuthMACKey, macInput2Reader);
        log(methodName, printData("responseMACTruncatedReceivedReader  ", responseMACTruncatedReceivedReader));
        log(methodName, printData("responseMACCalculatedReader", responseMACCalculatedReader));
        byte[] responseMACTruncatedCalculatedReader = truncateMAC(responseMACCalculatedReader);
        log(methodName, printData("responseMACTruncatedCalculatedReader", responseMACTruncatedCalculatedReader));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculatedReader, responseMACTruncatedReceivedReader)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            //return true; proceed when true
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }

        // now the regular COMMIT TRANSACTION is running

        // Constructing the full CommitTransaction Command APDU
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x01; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte[] startingIv = new byte[16];

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(COMMIT_TRANSACTION_SECURE_COMMAND); // 0xC7
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(COMMIT_TRANSACTION_OPTION);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the commitTransactionData
        ByteArrayOutputStream baosCommitTransactionCommand = new ByteArrayOutputStream();
        baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION);
        baosCommitTransactionCommand.write(macTruncated, 0, macTruncated.length);
        byte[] commitTransactionCommand = baosCommitTransactionCommand.toByteArray();
        log(methodName, printData("commitTransactionCommand", commitTransactionCommand));

        response = new byte[0];
        apdu = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_SECURE_COMMAND, commitTransactionCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullResponseData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        // the full response depends on an enabled TransactionMAC file option:
        // TransactionMAC counter || TransactionMAC value || response MAC
        // if not enabled just the response MAC is returned

        // this does NOT work when a TransactionMAC file is present:
        // commitTransactionEv2 error code: 9D Permission denied error

        log(methodName, printData("fullResponseData", fullResponseData));
        byte[] responseMACTruncatedReceived = new byte[8];
        byte[] responseTmcv = new byte[0];
        int fullResponseDataLength = fullResponseData.length;
        if (fullResponseDataLength > 8) {
            log(methodName, "the fullResponseData has a length of " + fullResponseDataLength + " bytes, so the TMC and TMV are included");
            // should be TMC || TMV || MAC now
            // sample: TMC (TMAC Counter) : 04000000 (4 bytes, counter in LSB encoding)
            // sample: TMV (TMAC Value)   : 94A3205E41588BA9 (8 bytes)
            responseTmcv = Arrays.copyOfRange(fullResponseData, 0, (fullResponseDataLength - 8));
            responseMACTruncatedReceived = Arrays.copyOfRange(fullResponseData, (fullResponseDataLength - 8), fullResponseDataLength);
            log(methodName, printData("responseTmcv", responseTmcv));
            // split up the data to TMC and TMV
            byte[] tmcByte = Arrays.copyOfRange(responseTmcv, 0, 4);
            byte[] tmvByte = Arrays.copyOfRange(responseTmcv, 4, 8);
            int tmcInt = byteArrayLength4InversedToInt(tmcByte);
            log(methodName, printData("tmcByte", tmcByte));
            log(methodName, "tmcInt: " + tmcInt);
            log(methodName, printData("tmvByte", tmvByte));

        } else {
            responseMACTruncatedReceived = fullResponseData.clone();
        }

        // verifying the received MAC
        // MAC_Input (RC || CmdCounter || TI || Response Data)
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        responseMacBaos.write(responseTmcv, 0, responseTmcv.length);
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
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }


    /**
     * section for transaction MAC files
     */

    public boolean createTransactionMacFileEv2(byte fileNumber, byte[] key) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card

        // for access rights see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
        // the TMAC can be read like a Standard file with size 12 bytes
        // Note that TMC and TMV can also be read out encrypted, if preferred. In this case, the
        // TransactionMAC file should be configured for CommMode.Full. One can then use ReadData to
        // retrieve this information, instead of requesting it within the response of CommitTransaction.
        // see pages 40-48 (General overview as well)

        String logData = "";
        final String methodName = "createTransactionMacFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + printData(" TransactionMacKey", key));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // todo is there any restriction on TMAC file numbers ?
        if ((key == null) || (key.length != 16)) {
            Log.e(TAG, methodName + " key length is not 16, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        byte TMACKeyOption = (byte) 0x02; // AES
        byte TMACKeyVersion = (byte) 0x00;

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        log(methodName, printData("TransactionIdentifier", TransactionIdentifier));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
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

        // Data (New TMAC Key)
        // taken from method header

        // Encrypted Data = E(KSesAuthENC, Data)
        byte[] keyEncrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, key);
        log(methodName, printData("keyEncrypted", keyEncrypted));
        byte[] iv2 = keyEncrypted.clone();
        log(methodName, printData("iv2", iv2));

        // Data (TMACKeyVersion || Padding)
        // don't forget to pad with 0x80..00
        byte[] keyVersionPadded = new byte[16];
        keyVersionPadded[0] = TMACKeyVersion;
        // padding with full padding
        System.arraycopy(PADDING_FULL, 0, keyVersionPadded, 1, (PADDING_FULL.length - 1));
        log(methodName, printData("keyVersionPadded", keyVersionPadded));

        // Encrypted Data = E(KSesAuthENC, Data)
        byte[] keyVersionPaddedEncrypted = AES.encrypt(iv2, SesAuthENCKey, keyVersionPadded);
        log(methodName, printData("keyVersionPaddedEncrypted", keyVersionPaddedEncrypted));

        // Encrypted Data (both blocks)
        byte[] encryptedData = concatenate(keyEncrypted, keyVersionPaddedEncrypted);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        startingIv = new byte[16];

        // this part is missing in the Feature & Hints document on page 84
        // CmdHeader (FileNo || CommunicationSettings || RW_CAR keys || R_W keys || TMACKeyOption)
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(FILE_COMMUNICATION_SETTINGS_PLAIN);
        baosCmdHeader.write(ACCESS_RIGHTS_RW_CAR_TMAC);
        baosCmdHeader.write(ACCESS_RIGHTS_R_W_TMAC);
        baosCmdHeader.write(TMACKeyOption);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted Data))
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CREATE_TRANSACTION_MAC_FILE_COMMAND); // 0xCE
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

        // Data (CmdHeader || MAC)
        // error in Features and Hints, page 84, point 30:
        // Data (CmdHeader || MAC) is NOT correct
        // correct is the following concatenation:

        // second error in point 32: Data Message shown is PLAIN data, not AES Secure Messaging data

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] createTransactionMacFileCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("createTransactionMacFileCommand", createTransactionMacFileCommand));
        
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CREATE_TRANSACTION_MAC_FILE_COMMAND, createTransactionMacFileCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // in Features and Hints is a 'short cutted' version what is done here

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public boolean deleteTransactionMacFileEv2(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 81 - 83
        // this is based on the creation of a TransactionMac file on a DESFire Light card
        // Cmd.DeleteTransactionMACFile
        String logData = "";
        final String methodName = "deleteTransactionMacFileEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        // todo is there any restriction on TMAC file numbers ?
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // Generating the MAC for the Command APDU
        // missing in Features and Hints
        // CmdHeader, here just the fileNumber

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = fileNumber)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(DELETE_TRANSACTION_MAC_FILE_COMMAND); // 0xDF
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(fileNumber);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Data (CmdHeader = fileNumber || MAC)
        ByteArrayOutputStream baosDeleteTransactionMacFileCommand = new ByteArrayOutputStream();
        baosDeleteTransactionMacFileCommand.write(fileNumber);
        baosDeleteTransactionMacFileCommand.write(macTruncated, 0, macTruncated.length);
        byte[] deleteTransactionMacFileCommand = baosDeleteTransactionMacFileCommand.toByteArray();
        log(methodName, printData("deleteTransactionMacFileCommand", deleteTransactionMacFileCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(DELETE_TRANSACTION_MAC_FILE_COMMAND, deleteTransactionMacFileCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // in Features and Hints is a 'short cutted' version what is done here

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
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
        final String methodName = "getCardUidEv2";
        log(methodName, "started", true);
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
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



    public boolean changeApplicationKeyEv2(byte keyNumber, byte[] keyNew, byte[] keyOld) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 76 - 80
        // this is based on the key change of an application key on a DESFire Light card
        // Cmd.ChangeKey Case 1: Key number to be changed ≠ Key number for currently authenticated session.

        // todo implement case 2
        // Case 2: Key number to be changed == Key number for currently authenticated session.

        String logData = "";
        final String methodName = "changeApplicationKeyEv2";
        log(methodName, "started", true);
        log(methodName, "keyNumber: " + keyNumber);
        log(methodName, printData("keyNew", keyNew));
        log(methodName, printData("keyOld", keyOld));
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((keyNumber < 0) || (keyNumber > MAXIMUM_NUMBER_OF_KEYS)) {
            Log.e(TAG, methodName + " keyNumber is not in range 0.." + MAXIMUM_NUMBER_OF_KEYS + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((keyNew == null) || (keyNew.length != 16)) {
            Log.e(TAG, methodName + " keyNew is NULL or not of length 16, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((keyOld == null) || (keyOld.length != 16)) {
            Log.e(TAG, methodName + " keyOld is NULL or not of length 16, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        final byte KEY_VERSION = (byte) 0x00; // fixed

        // Encrypting the Command Data

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
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

        // Data (New KeyValue || New KeyVersion || CRC32 of New KeyValue || Padding)
        // 0123456789012345678901234567890100A0A608688000000000000000000000
        // 01234567890123456789012345678901 00 A0A60868 8000000000000000000000
        // keyNew 16 byte              keyVers crc32 4  padding 11 bytes

        // error: this is missing in Feature & Hints
        // see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 71
        // 'if key 1 to 4 are to be changed (NewKey XOR OldKey) || KeyVer || CRC32NK'
        // if the keyNumber of the key to change is not the keyNumber that authenticated
        // we need to xor the new key with the old key, the CRC32 is run over the real new key (not the  XORed one)
        byte[] keyNewXor = keyNew.clone();
        for (int i = 0; i < keyOld.length; i++) {
            keyNewXor[i] ^= keyOld[i % keyOld.length];
        }
        log(methodName, printData("keyNewXor", keyNewXor));
        byte[] crc32 = CRC32.get(keyNew);
        log(methodName, printData("crc32 of keyNew", crc32));
        byte[] padding = hexStringToByteArray("8000000000000000000000");
        ByteArrayOutputStream baosData = new ByteArrayOutputStream();
        baosData.write(keyNewXor, 0, keyNewXor.length);
        baosData.write(KEY_VERSION);
        baosData.write(crc32, 0, crc32.length);
        baosData.write(padding, 0, padding.length);
        byte[] data = baosData.toByteArray();
        log(methodName, printData("data", data));

        // Encrypt the Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = keyNumber || Encrypted CmdData )
        // C40000BC354CD50180D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        // C4 0000 BC354CD5 01 80D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_KEY_SECURE_COMMAND); // 0xC4
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(keyNumber);
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

        // Data (CmdHeader = keyNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosChangeKeyCommand = new ByteArrayOutputStream();
        baosChangeKeyCommand.write(keyNumber);
        baosChangeKeyCommand.write(encryptedData, 0, encryptedData.length);
        baosChangeKeyCommand.write(macTruncated, 0, macTruncated.length);
        byte[] changeKeyCommand = baosChangeKeyCommand.toByteArray();
        log(methodName, printData("changeKeyCommand", changeKeyCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CHANGE_KEY_SECURE_COMMAND, changeKeyCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }

    public boolean setConfigurationValueFileLimit(byte fileNumber) {
        // see example in Mifare DESFire Light Features and Hints AN12343.pdf pages 12 ff
        // and MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 61 ff
        // for value file see page 64
        // error 7E = length error is thrown when length of command data != expected length
        // error 9D = PERMISSION_DENIED
        //            .. Option 09h: file configuration not allowed anymore as already done once or targeted file is not a Value file

        // status: NOT WORKING (throwing AE error ?)

        logData = "";
        final String methodName = "setConfigurationValueFileLimit";
        log(methodName, "fileNumber: " + fileNumber, true);

/*
The SetConfiguration command can be used to configure card or application-related attributes.
In example Table 5, the SetConfiguration command is used, to modify the parameters of the pre-installed value file inside the MIFARE DESFire Light application.
The modification which is executed, is setting the upper limit of the value file to 1000 (0x03E8) and setting the option "Free GetValue" to disabled, meaning an authentication is forced for retrieving the value.
Table 5.
Executing Cmd.SetConfiguration in CommMode.Full and Option 0x09 for updating the Value file
 */
        // sanity checks
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        byte optionOfSetConfiguration = (byte) 0x09; // (modify the Value File configuration)

        // using a fixed fileNumber for Value file enciphered = 0x08
        // upper limit is 0xE8030000 = 1000
        // lower limit is (unchanged) 0
        // value is 0
        // last 01 means: Free GetValue not allowed, LimitedCredit enabled

        // Data (FileNo || Lower Limit || Upper Limit || Value || ValueOption)
        byte[] data = hexStringToByteArray("0800000000E80300000000000001"); // 12 bytes, first 08 is fileNumber
        log(methodName, printData("data", data));

        // Encrypting the Command Data

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
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

        // fixed data
        // padding is 2 bytes
        byte[] dataPadded = hexStringToByteArray("0800000000E803000000000000018000"); // 16 bytes, first 08 is fileNumber
        log(methodName, printData("dataPadded", dataPadded));

        // Encrypted Data Block 1 = E(KSesAuthENC, Data Input)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, dataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        // CmdHeader = optionOfSetConfiguration
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(SET_CONFIGURATION_SECURE_COMMAND); // 0x5C
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(optionOfSetConfiguration);
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

        // Data (CmdHeader || Encrypted Data || MAC)
        // CmdHeader = optionOfSetConfiguration
        ByteArrayOutputStream baosSetConfigurationCommand = new ByteArrayOutputStream();
        baosSetConfigurationCommand.write(optionOfSetConfiguration);
        baosSetConfigurationCommand.write(encryptedData, 0, encryptedData.length);
        baosSetConfigurationCommand.write(macTruncated, 0, macTruncated.length);
        byte[] setConfigurationCommand = baosSetConfigurationCommand.toByteArray();
        log(methodName, printData("setConfigurationCommand", setConfigurationCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(SET_CONFIGURATION_SECURE_COMMAND, setConfigurationCommand);
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
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
        final String methodName = "authenticateAesEv2First";
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
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
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
     * create a file with file number 'fileNumber' of 'fileType' with 'communicationSettings'
     * Note: the new file will get default settings (see below) for an easy setup of file to
     * run a demonstration
     *
     * @param fileNumber
     * @param fileType
     * @param communicationSettings
     * @return true on SUCCESS
     */

    public boolean createAFile(byte fileNumber, DesfireFileType fileType, CommunicationSettings communicationSettings) {
        /**
         * here are the default values that are used during file creation:
         *
         * File number:   allowed file numbers are in range of 00 .. 14
         *
         * File types
         * Standard file: file size 32 bytes
         * Backup file:   file size 32 bytes
         * Value file:    minimum value limit 0
         *                minimum value limit 10000
         *                initial value 0
         *                limited credit operation DISABLED
         * Linear record file: record size 32 bytes
         *                     maximum records 5
         * Cyclic record file: record size 32 bytes
         *                     maximum records 6 (as one is needed for spare/cycling purpose)
         *
         * CommunicationSettings
         * Plain:      the communication is in Plain *1)
         * MACed:      the communication for reading and writing of data is secured by a (AES-based) CMAC
         * Enciphered: the communication for reading and writing of data is AES-128 encrypted and
         *             additionally secured by a (AES-based) CMAC
         *
         * *1) Note when the file access is authenticated using AES Secure Messaging (initiated by using
         *     the AuthenticateEV2First or AuthenticateEV2NonFirst the communication is secured by a MAC
         *
         * Access conditions:
         * The file has 5 keys in use:
         * Right for            key number
         * Read & Write access    1
         * Change access keys     2
         * Read access            3
         * Write access           4
         * Application Master key 0
         *
         * The creation of a file will invalidate the cached fileIDs and fileSettings and you need to
         * select the application again to get data
         *
         */

        // invalidate cached data
        APPLICATION_ALL_FILE_IDS = null;
        APPLICATION_ALL_FILE_SETTINGS = null;

        byte commSettings;
        if (communicationSettings == CommunicationSettings.Plain) {
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
            Log.d(TAG, "the communicationSettings are PLAIN");
        } else if (communicationSettings == CommunicationSettings.MACed) {
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
            Log.d(TAG, "the communicationSettings are MACed");
        } else if (communicationSettings == CommunicationSettings.Encrypted) {
            commSettings = FILE_COMMUNICATION_SETTINGS_ENCIPHERED;
            Log.d(TAG, "the communicationSettings are ENCIPHERED");
        } else {
            // should never happen
            Log.d(TAG, "wrong communicationSettings, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        final int SIZE = 32; // standard & backup fileSize, record files recordSize
        byte[] fileSizeByte = intTo3ByteArrayInversed(SIZE);

        // this is rough code for predefined files
        ByteArrayOutputStream parameter = new ByteArrayOutputStream();
        byte[] createFileParameter = new byte[0];
        byte createFileCommand = -1;

        if ((fileType == DesfireFileType.Standard) || (fileType == DesfireFileType.Backup)) {
            Log.d(TAG, "create a Standard or Backup file with default parameter");
            // build the parameter
            parameter.write(fileNumber);
            parameter.write(commSettings);
            parameter.write(ACCESS_RIGHTS_RW_CAR_SECURED);
            parameter.write(ACCESS_RIGHTS_R_W_SECURED);
            parameter.write(fileSizeByte, 0, fileSizeByte.length);
            createFileParameter = parameter.toByteArray();
            if (fileType == DesfireFileType.Standard) {
                createFileCommand = CREATE_STANDARD_FILE_COMMAND;
            } else {
                createFileCommand = CREATE_BACKUP_FILE_COMMAND;
            }
        }

        if (fileType == DesfireFileType.Value) {
            Log.d(TAG, "create a Value file with default parameter");
            // some default values
            int lowerLimitInt = 0;
            int upperLimitInt = 10000;
            int initialValueInt = 0;
            byte[] lowerLimit = Utils.intTo4ByteArrayInversed(lowerLimitInt);
            byte[] upperLimit = Utils.intTo4ByteArrayInversed(upperLimitInt);
            byte[] initialValue = Utils.intTo4ByteArrayInversed(initialValueInt);
            byte limitedCreditOperationEnabledByte = (byte) 0x00; // 00 means not enabled feature
            // build the parameter
            parameter.write(fileNumber);
            parameter.write(commSettings);
            parameter.write(ACCESS_RIGHTS_RW_CAR_SECURED);
            parameter.write(ACCESS_RIGHTS_R_W_SECURED);
            parameter.write(lowerLimit, 0, lowerLimit.length);
            parameter.write(upperLimit, 0, upperLimit.length);
            parameter.write(initialValue, 0, initialValue.length);
            parameter.write(limitedCreditOperationEnabledByte);
            createFileParameter = parameter.toByteArray();
            createFileCommand = CREATE_VALUE_FILE_COMMAND;
        }

        if ((fileType == DesfireFileType.LinearRecord) || (fileType == DesfireFileType.CyclicRecord)) {
            Log.d(TAG, "create a Linear or Cyclic Record file with default parameter");
            int numberOfRecords;
            if (fileType == DesfireFileType.LinearRecord) {
                createFileCommand = CREATE_LINEAR_RECORD_FILE_COMMAND;
                numberOfRecords = 5;
            } else {
                createFileCommand = CREATE_CYCLIC_RECORD_FILE_COMMAND;
                numberOfRecords = 6; // the cycling mechanism requires an additional record that is not shown on reading
            }
            byte[] maximumNumberOfRecords = intTo3ByteArrayInversed(numberOfRecords);
            // build the parameter
            parameter.write(fileNumber);
            parameter.write(commSettings);
            parameter.write(ACCESS_RIGHTS_RW_CAR_SECURED);
            parameter.write(ACCESS_RIGHTS_R_W_SECURED);
            parameter.write(fileSizeByte, 0, fileSizeByte.length);
            parameter.write(maximumNumberOfRecords, 0, maximumNumberOfRecords.length);
            createFileParameter = parameter.toByteArray();
        }

        Log.d(TAG, "createFileCommand: " + byteToHex(createFileCommand) + printData(" parameter", createFileParameter));
        byte[] response;
        try {
            byte[] apdu = wrapMessage(createFileCommand, createFileParameter);
            Log.d(TAG, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, "IOException " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        // we are expecting that the status code is 0x00 means the exchange was OK
        if (checkResponse(responseBytes)) {
            Log.d(TAG, "file creation SUCCESS");
            return true;
        } else {
            Log.d(TAG, "file creation FAILURE");
            return false;
        }
    }

    private boolean createFileSetPlain() {
        // creates 5 files with communication settings PLAIN

        return true;
    }

    public boolean createFileSetEncrypted() {
        // creates 5 files with communication settings ENCRYPTED
        Log.d(TAG, "createFileSetEncrypted");
        boolean createStandardFile = createAFile(STANDARD_FILE_ENCRYPTED_NUMBER, DesfireFileType.Standard, CommunicationSettings.Encrypted);
        boolean createBackupFile = createAFile(BACKUP_FILE_ENCRYPTED_NUMBER, DesfireFileType.Backup, CommunicationSettings.Encrypted);
        boolean createValueFile = createAFile(VALUE_FILE_ENCRYPTED_NUMBER, DesfireFileType.Value, CommunicationSettings.Encrypted);
        boolean createLinearRecordFile = createAFile(LINEAR_RECORD_FILE_ENCRYPTED_NUMBER, DesfireFileType.LinearRecord, CommunicationSettings.Encrypted);
        boolean createCyclicRecordFile = createAFile(CYCLIC_RECORD_FILE_ENCRYPTED_NUMBER, DesfireFileType.CyclicRecord, CommunicationSettings.Encrypted);
        Log.d(TAG, "createStandardFile result: " + createStandardFile);
        Log.d(TAG, "createBackupFile result: " + createBackupFile);
        Log.d(TAG, "createValueFile result: " + createValueFile);
        Log.d(TAG, "createLinearRecordFile result: " + createLinearRecordFile);
        Log.d(TAG, "createCyclicRecordFile result: " + createCyclicRecordFile);
        return true; // returns true independent of results
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
        final String methodName = "authenticateAesEv2NonFirst";
        log(methodName, printData("key", key) + " keyNo: " + keyNo, true);
        errorCode = new byte[2];
        // sanity checks
        if (!authenticateEv2FirstSuccess) {
            Log.e(TAG, methodName + " please run an authenticateEV2First before, aborted");
            log(methodName, "missing previous successfull authenticateEv2First, aborted", false);
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
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
            log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
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
     * section for application handling
     */

    // this is using PLAIN communication and does not require any authentication but as we read the fileSettings
    // of all files within the application we need to do it in this class
    public boolean selectApplicationByAidEv2(byte[] applicationIdentifier) {
        final String methodName = "selectApplication by AID EV2";
        logData = "";
        log(methodName, printData("applicationIdentifier", applicationIdentifier), true);
        errorCode = new byte[2];
        // sanity checks
        if ((applicationIdentifier == null) || (applicationIdentifier.length != 3)) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 16 or NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(SELECT_APPLICATION_BY_AID_COMMAND, applicationIdentifier);
            log(methodName,printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            log(methodName, "SUCCESS");
            selectedApplicationId = applicationIdentifier.clone();
            APPLICATION_ALL_FILE_IDS = null;
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            log(methodName, "FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes) +
                    " error code: " + EV3.getErrorCode(responseBytes));
            selectedApplicationId = null;
            APPLICATION_ALL_FILE_IDS = null;
            return false;
        }
    }

    /**
     * section for files in general
     */

    /**
     * get the file numbers of all files within an application
     * Note: depending on the application master key settings this requires an preceding authentication
     *       with the application master key
     * @return an array of bytes with all available fileIds
     */
    public byte[] getAllFileIdsEv2() {
        final String methodName = "getAllFileIDs EV2";
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
     *       with the application master key
     * @return an array of bytes with all available fileIds
     */
    public FileSettings[] getAllFileSettingsEv2() {
        final String methodName = "getAllFileSettings EV2";
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
            byte[] fileSettingsByte = getFileSettingsEv2(fileId);
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
     * Note: depending on the application master key settings this requires an preceding authentication
     *       with the application master key
     * @fileNumber: the file number we need to read the settings from
     * @return an array of bytes with all available fileIds
     */

    public byte[] getFileSettingsEv2(byte fileNumber) {
        // this is using simple PLAIN communication without any encryption or MAC involved
        String logData = "";
        final String methodName = "getFileSettingsEv2";
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
        Log.d(TAG,  methodName + " for fileNumber " + fileNumber);
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

    public boolean changeFileSettingsEv2(byte fileNumber) {

        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35 for SDM example
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 65 - 69 for fields and errors
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 69 - 70 for getFileSettings with responses incl. SDM
        // see NTAG 424 DNA NT4H2421Gx.pdf pages 71 - 72 for getFileCounters
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 23 - 25 for general workflow with FULL communication

        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 34 - 35
        // Change NDEF file settings using Cmd.ChangeFileSettings using CommMode.Full
        // this is based on the changeFileSettings on a NTAG 424 DNA tag

        // status WORKING (getFileSettings is returning more data)
        // 00 40 00 E0 00 01 00 C1 F1 21 20 00 00 43 00 00 43 00 00 (19 bytes)
        //    FileOpt

        String logData = "";
        final String methodName = "changeFileSettingsEv2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if (fileNumber < 0) {
            Log.d(TAG, "fileNumber < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // MAC_Input
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(HEADER_MAC, 0, HEADER_MAC.length);
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

        // build the cmdData, is a bit complex due to a lot of options - here it is shortened
        //byte[] commandData = hexStringToByteArray("4000E0C1F121200000430000430000");
        byte[] commandData = hexStringToByteArray("40EEEEC1F121200000320000450000"); // this is the data of the working TapLinx command

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

        // this is from https://community.nxp.com/t5/NFC/NTAG-424-DNA-Change-NDEF-File-Settings-problem/td-p/1328599
        // 40 00 E0 D1 F1 21 1F 00 00 44 00 00 44 00 00 40 00 00 8A 00 00 80 00 00 00 00 00 00 00 00 00 00
        // 4000E0D1F1211F00004400004400004000008A00008000000000000000000000

        // our fix commandData from example has 15 bytes so we do need 16 bytes
        byte[] commandDataPadded = hexStringToByteArray("4000E0C1F12120000043000043000080");
        //byte[] commandDataPadded = hexStringToByteArray("40EEEEC1F12120000043000043000080");
        //byte[] commandDataPadded = hexStringToByteArray("4000E0D1F1211F00004400004400004000008A00008000000000000000000000");

        // this is the command from working TapLinx example
        //byte[] commandDataPadded = hexStringToByteArray("40EEEEC1F12120000032000045000080");

        log(methodName, printData("commandDataPadded", commandDataPadded));

        // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_FILE_SETTINGS_COMMAND); // 0x5F
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
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

        // error in Features and Hints, page 57, point 28:
        // Data (FileNo || Offset || DataLenght || Data) is NOT correct, as well not the Data Message
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
            apdu = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, writeDataCommand); //0261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A04 25d = 19b
            // comApdu       905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400
            // my apdu       905f00001902d7bff30bb6d212e512ddf49942a754f7003b5d104371344200

            // when I append sample data this change
            // gives error   9D Permission denied error
/*
from NTAG424DNA sheet page 69:
PERMISSION_DENIED
- 9Dh PICC level (MF) is selected.
- access right Change of targeted file has access conditions set to Fh.
- Enabling Secure Dynamic Messaging (FileOption Bit 6 set to 1b) is only allowed for FileNo 02h.
 */
            // expected APDU 905F0000190261B6D97903566E84C3AE5274467E89EAD799B7C1A0EF7A0400 (31 bytes)
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
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // verifying the received Response MAC
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write((byte) 0x00); // response code 00 means success
        responseMacBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        responseMacBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        byte[] macInput2 = responseMacBaos.toByteArray();
        log(methodName, printData("macInput2", macInput2));
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        byte[] responseMACCalculated = calculateDiverseKey(SesAuthMACKey, macInput2);
        log(methodName, printData("responseMACCalculated", responseMACCalculated));
        byte[] responseMACTruncatedCalculated = truncateMAC(responseMACCalculated);
        log(methodName, printData("responseMACTruncatedCalculated", responseMACTruncatedCalculated));
        log(methodName, printData("responseMACTruncatedReceived  ", responseMACTruncatedReceived));
        // compare the responseMAC's
        if (Arrays.equals(responseMACTruncatedCalculated, responseMACTruncatedReceived)) {
            Log.d(TAG, "responseMAC SUCCESS");
            System.arraycopy(RESPONSE_OK, 0, errorCode, 0, RESPONSE_OK.length);
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            return false;
        }
    }



    private boolean getSelectedFileSettings(byte fileNumber) {
        Log.d(TAG, "getSelectedFileSettings for fileNumber " + fileNumber);
        // no sanity checks are done !
        byte[] fileSettingsReceived = getFileSettingsEv2(fileNumber);
        if (fileSettingsReceived != null) {
            selectedFileSetting = new FileSettings(fileNumber, fileSettingsReceived);
            Log.d(TAG, "getSelectedFileSettings SUCCESS");
            return true;
        } else {
            selectedFileSetting = null;
            Log.d(TAG, "getSelectedFileSettings FAILURE");
            return false;
        }
    }

    /**
     * section for NDEF handling
     */

    public boolean createNdefApplicationIsoDes(TextView logTextView) {
        // note: all data is hardcoded !

        if (logTextView == null) return false;

        // MIFARE DESFire CreateApplication using the default AID 000001h (see section 6.4.1 for the definition of the allowed AID values),
        // key settings equal to 0Fh, NumOfKeys equal to 01h, File-ID equal to 10E1h, DF-name equal to D2760000850101
        // Command: 90 CA 00 00 0E 01 00 00 0F 21 10 E1 D2 76 00 00 85 01 01 00h

        // todo change this is rough code from MIFARE DESFire as Type 4 Tag AN11004.pdf

        String logData = "";
        final String methodName = "createApplicationIsoDes";
        log(methodName, "started", true);

        byte createApplicationCommand = (byte) 0xCA;
        byte[] commandSequence = Utils.hexStringToByteArray("90CA00000E0100000F2110E1D276000085010100"); // this is the command for 0e0e
        // byte[] commandSequence = Utils.hexStringToByteArray("90CA00000E0100000F2110E1D276000085010100"); this is the command in the pdf
        byte[] response;
        try {
            Log.d(TAG, printData("commandSequence", commandSequence));
            response = isoDep.transceive(commandSequence);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG, "error on running the createApplicationIsoDes command " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean createNdefApplicationIsoAes(TextView logTextView) {
        // note: all data is hardcoded !

        if (logTextView == null) return false;

        // MIFARE DESFire CreateApplication using the default AID 000001h (see section 6.4.1 for the definition of the allowed AID values),
        // key settings equal to 0Fh, NumOfKeys equal to 01h, File-ID equal to 10E1h, DF-name equal to D2760000850101
        // Command: 90 CA 00 00 0E 01 00 00 0F 21 10 E1 D2 76 00 00 85 01 01 00h

        // todo change this is rough code from MIFARE DESFire as Type 4 Tag AN11004.pdf

        String logData = "";
        final String methodName = "createApplicationIsoAes";
        log(methodName, "started", true);

        byte createApplicationCommand = (byte) 0xCA;
        byte[] commandSequence = Utils.hexStringToByteArray("90CA00000E0100000FA510E1D276000085010100"); // this is the command taken from TapLinx
        //byte[] commandSequence = Utils.hexStringToByteArray ("90CA00000E0100000F2110E1D276000085010100"); // this is the command for 0e0e
        // byte[] commandSequence = Utils.hexStringToByteArray("90CA00000E0100000F2110E1D276000085010100"); this is the command in the pdf
        byte[] response;
        try {
            Log.d(TAG, printData("commandSequence", commandSequence));
            response = isoDep.transceive(commandSequence);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG, "error on running the createApplicationIsoAes command " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean selectNdefApplicationIso(TextView logTextView) {
        String logData = "";
        final String methodName = "createApplicationIsoDes";
        log(methodName, "started", true);

        // todo change this is rough programming
        //byte[] commandSequence = Utils.hexStringToByteArray("905A00000301000000");
        byte[] commandSequence = Utils.hexStringToByteArray("905A00000301000000"); // taken from TapLinx
        //byte selectApplicationCommand = (byte) 0x5A;
        byte[] response;
        try {
            Log.d(TAG, printData("commandSequence", commandSequence));
            response = isoDep.transceive(commandSequence);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG,  methodName +  " ERROR " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean createNdefContainerFileIso(TextView logTextView) {

        // this code is taken from MIFARE DESFire as Type 4 Tag AN11004.pdf
        // this is raw code with fixed data, todo CHANGE
        /*
        step 4
        MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
        ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh,
        FileSize bigger equal to 00000Fh
        Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h
        NOTE: There is an error in the command, the Access Rights do have a wrong value

        step 6
        MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID),
        ISO FileID equal to E104h, ComSet equal to 00h, AccessRights equal to EEE0h,
        FileSize equal to 000800h (2048 Bytes)
        Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
         */

        String logData = "";
        final String methodName = "createNdefContainerFileIso";
        log(methodName, "started", true);

        byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090103E100EEEE0F000000");
        byte createApplicationCommand = (byte) 0xCD;
        byte[] response;
        try {
            Log.d(TAG, printData("commandSequence", commandSequence));
            response = isoDep.transceive(commandSequence);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG,  methodName +  " ERROR " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean writeToNdefContainerFileIso(TextView logTextView) {

        String logData = "";
        final String methodName = "writeToNdefContainerFileIso";
        log(methodName, "started", true);

        byte[] NDEF_CONTAINER = Utils.hexStringToByteArray("000F20003A00340406E10401000000"); // 256 byte
        byte FILE_ID_01 = (byte) 0x01;
        // build the apdu
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = Utils.intTo3ByteArrayInversed(NDEF_CONTAINER.length);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(FILE_ID_01); // fileNumber
        baos.write(offset, 0, offset.length);
        baos.write(lengthOfData, 0, lengthOfData.length);
        baos.write(NDEF_CONTAINER, 0, NDEF_CONTAINER.length);
        byte[] commandParameter = baos.toByteArray();
        byte writeStandardFileCommand = (byte) 0x3D;
        byte[] wrappedCommand;
        byte[] response;
        try {
            Log.d(TAG, printData("commandParameter", commandParameter));
            wrappedCommand = wrapMessage(writeStandardFileCommand, commandParameter);
            Log.d(TAG, printData("wrappedCommand", wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG,  methodName +  " ERROR " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean createNdefFile2Iso(TextView logTextView) {

        // this code is taken from MIFARE DESFire as Type 4 Tag AN11004.pdf
        // this is raw code with fixed data, todo CHANGE
        /*
        step 4
        MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
        ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh,
        FileSize bigger equal to 00000Fh
        Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h
        NOTE: There is an error in the command, the Access Rights do have a wrong value

        step 6
        MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID),
        ISO FileID equal to E104h, ComSet equal to 00h, AccessRights equal to EEE0h,
        FileSize equal to 000800h (2048 Bytes)
        Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
         */

        String logData = "";
        final String methodName = "createNdefFile2Iso";
        log(methodName, "started", true);

        //byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090204E140E0EE00010000"); // 256 byte // ERROR 9d error
        //byte[] commandSequence = Utils.hexStringToByteArray("90CD0000120204E14000E0C1F12120000043000043000000"); // error 7e command length error
        byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090204E100EEEE00010000");
        byte[] commandSequenceSdm1 = Utils.hexStringToByteArray("90CD0204E100EEE0000100BF25B5B1446EFC2E00"); // error 7e
        byte[] commandSequenceSdm2 = Utils.hexStringToByteArray("90CD0204E140EEE0000100E922B3C4DFBEF1E600");// error 7e
        byte[] response;
        byte[] wrappedCommand;
        try {
            /*
            Log.d(TAG, printData("commandParameter", commandParameter));
            wrappedCommand = wrapMessage(createNdefFile2Command, commandParameter);
            Log.d(TAG, printData("wrappedCommand", wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
             */
            Log.d(TAG, printData("commandSequence", commandSequence));
            response = isoDep.transceive(commandSequence);
            //Log.d(TAG, printData("commandSequenceSdm1", commandSequenceSdm1));
            //response = isoDep.transceive(commandSequenceSdm1);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG,  methodName +  " ERROR " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean createNdefFile2IsoFrozen(TextView logTextView) {

        // this code is taken from MIFARE DESFire as Type 4 Tag AN11004.pdf
        // this is raw code with fixed data, todo CHANGE
        /*
        step 4
        MIFARE DESFire CreateStdDataFile with FileNo equal to 01h (CC File DESFire FID),
        ISO FileID equal to E103h, ComSet equal to 00h, AccessRights equal to EEEEh,
        FileSize bigger equal to 00000Fh
        Command: 90 CD 00 00 09 01 03 E1 00 00 E0 0F 00 00 00h
        NOTE: There is an error in the command, the Access Rights do have a wrong value

        step 6
        MIFARE DESFire CreateStdDataFile with FileNo equal to 02h (NDEF File DESFire FID),
        ISO FileID equal to E104h, ComSet equal to 00h, AccessRights equal to EEE0h,
        FileSize equal to 000800h (2048 Bytes)
        Command: 90 CD 00 00 09 02 04 E1 00 E0 EE 00 08 00 00h
         */

        String logData = "";
        final String methodName = "createNdefFile2Iso";
        log(methodName, "started", true);

        /**
         * FROZEN as this is working code !!
         */

        //byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090204E140E0EE00010000"); // 256 byte // ERROR 9d error
        //byte[] commandSequence = Utils.hexStringToByteArray("90CD0000120204E14000E0C1F12120000043000043000000"); // error 7e command length error
        byte[] commandSequence = Utils.hexStringToByteArray("90CD0000090204E100EEEE00010000");
        //byte[] commandSequenceSdm1 = Utils.hexStringToByteArray("90CD0204E100EEE0000100BF25B5B1446EFC2E00"); // error 7e
        byte[] commandSequenceSdm2 = Utils.hexStringToByteArray("90CD0204E140EEE0000100E922B3C4DFBEF1E600");// error 7e
        byte[] response;
        try {
            Log.d(TAG, printData("commandSequence", commandSequence));
            response = isoDep.transceive(commandSequence);
            //Log.d(TAG, printData("commandSequenceSdm1", commandSequenceSdm1));
            //response = isoDep.transceive(commandSequenceSdm1);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG,  methodName +  " ERROR " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    public boolean writeToNdefFile2Iso(TextView logTextView) {

        String logData = "";
        final String methodName = "writeToNdefFile2Iso";
        log(methodName, "started", true);

        String ndefSampleBackendUrl = "https://sdm.nfcdeveloper.com/tag?picc_data=00000000000000000000000000000000&cmac=0000000000000000";
        NdefRecord ndefRecord = NdefRecord.createUri(ndefSampleBackendUrl);
        NdefMessage ndefMessage = new NdefMessage(ndefRecord);
        byte[] ndefMessageBytesHeadless = ndefMessage.toByteArray();
        // now we do have the NDEF message but  it needs to get wrapped by '0x00 || (byte) (length of NdefMessage)
        byte[] ndefMessageBytes = new byte[ndefMessageBytesHeadless.length + 2];
        System.arraycopy(new byte[]{(byte) 0x00, (byte) (ndefMessageBytesHeadless.length)}, 0, ndefMessageBytes, 0, 2);
        System.arraycopy(ndefMessageBytesHeadless, 0, ndefMessageBytes, 2, ndefMessageBytesHeadless.length);
        Log.d(TAG, printData("NDEF Message bytes", ndefMessageBytes));

        byte FILE_ID_02 = (byte) 0x02;
        // build the apdu
        byte[] offset = new byte[]{(byte) 0x00, (byte) 0xf00, (byte) 0x00}; // write at the beginning, fixed
        byte[] lengthOfData = Utils.intTo3ByteArrayInversed(ndefMessageBytes.length);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(FILE_ID_02); // fileNumber
        baos.write(offset, 0, offset.length);
        baos.write(lengthOfData, 0, lengthOfData.length);
        baos.write(ndefMessageBytes, 0, ndefMessageBytes.length);
        byte[] commandParameter = baos.toByteArray();
        byte writeStandardFileCommand = (byte) 0x3D;

        // this  are sample data with a timestamp
        commandParameter = hexStringToByteArray("02000000200000323032332e30372e32372031323a35333a353220313233343536373839303132");
        // commandParameter length: 39 data: 02000000200000323032332e30372e32372031323a35333a353220313233343536373839303132
        // wrappedCommand   length: 45 data: 903d00002702000000200000323032332e30372e32372031323a35333a35322031323334353637383930313200

        byte[] wrappedCommand;
        byte[] response;
        try {
            Log.d(TAG, printData("commandParameter", commandParameter));
            wrappedCommand = wrapMessage(writeStandardFileCommand, commandParameter);
            Log.d(TAG, printData("wrappedCommand", wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
            Log.d(TAG, printData("response", response));
        } catch (Exception e) {
            Log.e(TAG,  methodName +  " ERROR " + e.getMessage());
            return false;
        }
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE");
            return false;
        }
    }

    /**
     * section for NDEF data decryption
     */

    public byte[] decryptNdefDataEv2(byte[] iv, byte[] key, byte[] ciphertext) {
        String logData = "";
        final String methodName = "decryptNdefDataEv2";
        log(methodName, "started", true);
        // some sanity checks on input
        if ((iv == null) || (key == null) || (ciphertext == null)) {
            Log.d(TAG, methodName + " input data is null, aborted");
            return null;
        }
        if ((iv.length != 16) || (key.length != 16)) {
            Log.d(TAG, methodName + " iv or key length is not 16, aborted");
            return null;
        }
        byte[] plaintext;
        try {
            plaintext = AES.decrypt(iv, key, ciphertext);
        } catch (Exception e) {
            Log.d(TAG, methodName + " decryption throws exception:\n" + e.getMessage());
            return null;
        }
        Log.d(TAG, methodName + printData(" plaintext", plaintext));
        return plaintext;
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

    public byte[] truncateMAC(byte[] fullMAC) {
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
     * add the padding bytes to data that is written to a Standard, Backup, Linear Record or Cyclic Record file
     * The encryption method does need a byte array of multiples of 16 bytes
     * If the unpaddedData is of (multiple) length of 16 the complete padding is added
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

    public byte[] paddingWriteDataDes(byte[] unpaddedData) {
        // sanity checks
        if (unpaddedData == null) {
            Log.e(TAG, "paddingWriteData - unpaddedData is NULL, aborted");
            return null;
        }
        int unpaddedDataLength = unpaddedData.length;
        int paddingBytesLength = PADDING_FULL_DES.length;
        byte[] fullPaddedData = new byte[unpaddedDataLength + paddingBytesLength];
        // concatenate unpaddedData and PADDING_FULL
        System.arraycopy(unpaddedData, 0, fullPaddedData, 0, unpaddedDataLength);
        System.arraycopy(PADDING_FULL_DES, 0, fullPaddedData, unpaddedDataLength, paddingBytesLength);
        // this is maybe too long, trunc to multiple of 8 bytes
        int mult8 = fullPaddedData.length / 8;
        Log.d(TAG, "fullPaddedData.length: " + fullPaddedData.length);
        Log.d(TAG, "mult8c               : " + mult8);
        return Arrays.copyOfRange(fullPaddedData, 0, (mult8 * 8));
    }

    public boolean createTransactionMacFileFullPart1Test() {
        /**
         * this will test several function using test vectors from
         * Mifare DESFire Light Features and Hints AN12343.pdf pages 83-85
         * to get a full apdu for part 1, preparing the data writing
         * test vectors are for Cmd.CreateTransactionMACFile
         */

        final String methodName = "createTransactionMacFileFullPart1Test";
        log(methodName, "started", true);

        byte[] SesAuthENCKeyTest = hexStringToByteArray("CFD5F757E422144FE831842694AF69AF");
        byte[] SesAuthMACKeyTest = hexStringToByteArray("390F25170E00278C62B718F3025FCA59");
        byte[] TI = hexStringToByteArray("B350F7C9");
        int commandCounter = 1;
        byte[] startingIv = new byte[16];
        byte fileNumber = (byte) 0x0F;
        byte[] TMAC_KeyTest = hexStringToByteArray("F7D23E0C44AFADE542BFDF2DC5C6AE02");


        byte TMACKeyOption = (byte) 0x02; // AES
        byte TMACKeyVersion = (byte) 0x00;

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(commandCounter);
        log(methodName, "CmdCounter: " + commandCounterLsb1);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        log(methodName, printData("TransactionIdentifier", TI));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
        baosIvInput.write(TI, 0, TI.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();
        log(methodName, printData("ivInput", ivInput));

        byte[] ivInput_expected = hexStringToByteArray("A55AB350F7C901000000000000000000");
        Log.d(TAG, printData("ivInput_expected", ivInput_expected));
        if (!Arrays.equals(ivInput_expected, ivInput)) {
            Log.d(TAG, "ivInput Test FAILURE, aborted");
            return false;
        }

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKeyTest));
        startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKeyTest, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        byte[] ivForCmdData_expected = hexStringToByteArray("303DC814A2C7366D298C50DC8F90BB36");
        Log.d(TAG, printData("ivForCmdData_expected", ivForCmdData_expected));
        if (!Arrays.equals(ivForCmdData_expected, ivForCmdData)) {
            Log.d(TAG, "ivForCmdData Test FAILURE, aborted");
            return false;
        }

        // Data (New TMAC Key)
        // taken from method header

        // Encrypted Data = E(KSesAuthENC, Data)
        byte[] keyEncrypted = AES.encrypt(ivForCmdData, SesAuthENCKeyTest, TMAC_KeyTest);
        log(methodName, printData("keyEncrypted", keyEncrypted));

        byte[] keyEncrypted_expected = hexStringToByteArray("E64CF1262C6B798B95C950FD7353EA87");
        Log.d(TAG, printData("keyEncrypted_expected", keyEncrypted_expected));
        if (!Arrays.equals(keyEncrypted_expected, keyEncrypted)) {
            Log.d(TAG, "keyEncrypted Test FAILURE, aborted");
            return false;
        }

        byte[] iv2 = keyEncrypted.clone();
        log(methodName, printData("iv2", iv2));

        // Data (TMACKeyVersion || Padding)
        // don't forget to pad with 0x80..00
        byte[] keyVersionPadded = new byte[16];
        keyVersionPadded[0] = TMACKeyVersion;
        // padding with full padding
        System.arraycopy(PADDING_FULL, 0, keyVersionPadded, 1, (PADDING_FULL.length - 1));
        log(methodName, printData("keyVersionPadded", keyVersionPadded));

        byte[] keyVersionPadded_expected = hexStringToByteArray("00800000000000000000000000000000");
        Log.d(TAG, printData("keyVersionPadded_expected", keyVersionPadded_expected));
        if (!Arrays.equals(keyVersionPadded_expected, keyVersionPadded)) {
            Log.d(TAG, "keyVersionPadded Test FAILURE, aborted");
            return false;
        }

        // Encrypted Data = E(KSesAuthENC, Data)
        byte[] keyVersionPaddedEncrypted = AES.encrypt(iv2, SesAuthENCKeyTest, keyVersionPadded);
        log(methodName, printData("keyVersionPaddedEncrypted", keyVersionPaddedEncrypted));

        byte[] keyVersionPaddedEncrypted_expected = hexStringToByteArray("64B1F4F4C69C4068F513715C486E18B3");
        Log.d(TAG, printData("keyVersionPaddedEncrypted_expected", keyVersionPaddedEncrypted_expected));
        if (!Arrays.equals(keyVersionPaddedEncrypted_expected, keyVersionPaddedEncrypted)) {
            Log.d(TAG, "keyVersionPaddedEncrypted Test FAILURE, aborted");
            return false;
        }

        // Encrypted Data (both blocks)
        byte[] encryptedData = concatenate(keyEncrypted, keyVersionPaddedEncrypted);
        log(methodName, printData("encryptedData", encryptedData));

        byte[] encryptedData_expected = hexStringToByteArray("E64CF1262C6B798B95C950FD7353EA8764B1F4F4C69C4068F513715C486E18B3");
        Log.d(TAG, printData("encryptedData_expected", encryptedData_expected));
        if (!Arrays.equals(encryptedData_expected, encryptedData)) {
            Log.d(TAG, "encryptedData Test FAILURE, aborted");
            return false;
        }

        // Generating the MAC for the Command APDU
        startingIv = new byte[16];

        // this part is missing in the Feature & Hints document on page 84
        // CmdHeader (FileNo || CommunicationSettings || RW_CAR keys || R_W keys || TMACKeyOption)
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(FILE_COMMUNICATION_SETTINGS_PLAIN);
        baosCmdHeader.write(ACCESS_RIGHTS_RW_CAR_TMAC);
        baosCmdHeader.write(ACCESS_RIGHTS_R_W_TMAC);
        baosCmdHeader.write(TMACKeyOption);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted Data))
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CREATE_TRANSACTION_MAC_FILE_COMMAND); // 0xCE
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TI, 0, TI.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));

        byte[] macInput_expected = hexStringToByteArray("CE0100B350F7C90F00101F02E64CF1262C6B798B95C950FD7353EA8764B1F4F4C69C4068F513715C486E18B3");
        Log.d(TAG, printData("macInput_expected", macInput_expected));
        if (!Arrays.equals(macInput_expected, macInput)) {
            Log.d(TAG, "macInput Test FAILURE, aborted");
            return false;
        }

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKeyTest));
        byte[] macFull = calculateDiverseKey(SesAuthMACKeyTest, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        byte[] macTruncated_expected = hexStringToByteArray("B3BE705D3E1FB8DC");
        Log.d(TAG, printData("macTruncated_expected", macTruncated_expected));
        if (!Arrays.equals(macTruncated_expected, macTruncated)) {
            Log.d(TAG, "macTruncated Test FAILURE, aborted");
            return false;
        }

        // Data (CmdHeader || MAC)
        // error in Features and Hints, page 84, point 30:
        // Data (CmdHeader || MAC) is NOT correct
        // correct is the following concatenation:

        // Data (CmdHeader || Encrypted Data || MAC)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(encryptedData, 0, encryptedData.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] createTransactionMacFileCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("createTransactionMacFileCommand", createTransactionMacFileCommand));

        byte[] createTransactionMacFileCommand_expected = hexStringToByteArray("0F00101F02E64CF1262C6B798B95C950FD7353EA8764B1F4F4C69C4068F513715C486E18B3B3BE705D3E1FB8DC");
        Log.d(TAG, printData("createTransactionMacFileCommand_expected", createTransactionMacFileCommand_expected));
        if (!Arrays.equals(createTransactionMacFileCommand_expected, createTransactionMacFileCommand)) {
            Log.d(TAG, "createTransactionMacFileCommand Test FAILURE, aborted");
            return false;
        }

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(CREATE_TRANSACTION_MAC_FILE_COMMAND, createTransactionMacFileCommand);
            log(methodName, printData("apdu", apdu));
            //response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));

            // cannot test the APDU, wrong data in document

            return true;

        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
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
            //response = isoDep.transceive(apdu);
            //Log.d(TAG, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, "transceive failed, IOException:\n" + e.getMessage());
            Log.d(TAG, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }
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
        final String methodName = "getSesAuthEncKey";
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
        final String methodName = "getSesAuthMacKey";
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


    public byte[] getSesSDMFileReadMACKey(byte[] sdmFileReadKey, byte[] uid, byte[] sdmReadCounter) {
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 15 - 18
        final String methodName = "getSesSDMFileReadMACKey";
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
        byte[] labelSdmMac = new byte[]{(byte) (0x3C), (byte) (0xC3)}; // fixed to 0x3CC3
        byte[] counter = new byte[]{(byte) (0x00), (byte) (0x01)}; // fixed to 0x0001
        byte[] length = new byte[]{(byte) (0x00), (byte) (0x80)}; // fixed to 0x0080
        System.arraycopy(labelSdmMac, 0, cmacInput, 0, 2);
        System.arraycopy(counter, 0, cmacInput, 2, 2);
        System.arraycopy(length, 0, cmacInput, 4, 2);
        System.arraycopy(uid, 0, cmacInput, 6, 7);
        System.arraycopy(sdmReadCounter, 0, cmacInput, 13, 3);
        // todo this method is working only when UID and readCtr are present, if not the byte array is filled up with 00 to 16 bytes
        log(methodName, printData("cmacInput", cmacInput));
        byte[] cmac = calculateDiverseKey(sdmFileReadKey, cmacInput);
        log(methodName, printData("cmacOutput", cmac));
        return cmac;
    }

    public byte[] getSdmMac(byte[] sesSDMFileReadMACKey) {
        // see NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 15 - 18
        final String methodName = "getSdmMac";
        log(methodName, printData("sesSDMFileReadMACKey", sesSDMFileReadMACKey), true);
        // sanity checks
        if ((sesSDMFileReadMACKey == null) || (sesSDMFileReadMACKey.length != 16)) {
            log(methodName, "sesSDMFileReadMACKey is NULL or wrong length, aborted");
            return null;
        }
        return calculateDiverseKey(sesSDMFileReadMACKey, new byte[0]);
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
            //logData += "method: " + methodName + "\n" + data + "\n";
            logData += "\n" + methodName + ":\n" + data + "\n\n";
            Log.d(TAG, "method: " + methodName + ": " + data);
        }
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
