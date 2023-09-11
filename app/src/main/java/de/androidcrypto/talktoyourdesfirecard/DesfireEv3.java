package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.byteArrayLength4InversedToInt;
import static de.androidcrypto.talktoyourdesfirecard.Utils.hexStringToByteArray;
import static de.androidcrypto.talktoyourdesfirecard.Utils.intFrom4ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.intTo2ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.intTo3ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.intTo4ByteArrayInversed;
import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
import android.nfc.TagLostException;
import android.nfc.tech.IsoDep;
import android.util.Log;

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

import de.androidcrypto.talktoyourdesfirecard.nfcjlib.AES;
import de.androidcrypto.talktoyourdesfirecard.nfcjlib.CRC32;


/**
 * This class is the full library that connects to Mifare DESFire EV1/EV2/EV3 tags for these commands:
 * - create (*1), select and delete (*2) an AES key based application
 * - authenticate with AES keys using 'authenticateEV2First' and 'authenticateEV2NonFirst'
 * - create and delete (*2) a Data file (Standard or Backup file) with communication mode Plain, MACed or Full enciphered
 * - write to and read from a Data file in communication modes Plain, MACed and Full enciphered (*3)
 * - create and delete (*2) a Value file with communication mode Plain, MACed or Full enciphered
 * - read, credit or debit a value in a Value file in communication modes Plain, MACed and Full enciphered (*3)
 * - create and delete (*2) a Record file (Linear or Cyclic Record file) with communication mode Plain, MACed or Full enciphered
 * - write to and read from a Record file in communication modes Plain, MACed and Full enciphered (*3)
 * <p>
 * supported service methods:
 * - getVersion (version of the attached PICC)
 * - getFreeMemory of the PICC
 * - getFileId and getFileSettings of all file types within an application
 * - format the PICC
 * - getKeyVersion (version of an authentication key)
 * - changeApplicationKey (but not the MasterApplicationKey)
 * - changeApplicationSettings (but not for the  MasterApplication to avoid any damage of the tag)
 * - changeFileSettings
 * <p>
 * <p>
 * For DESFire EV3 only:
 * It contains all commands that are necessary to enable the Secret Unique NFC (SUN) feature that is
 * based on Secure Dynamic Messaging (SDM) that is available on DESFire EV3 tags only:
 * - createApplicationAesIso (adding an ISO application identifier and ISO Data File Name)
 * - createNdefContainerFile (having a dedicated fileNumber for NDEF usage)
 * - writeNdefContainer
 * - createStandardFileIso (adding an ISO fileNumber and ISO fileName with communication mode Plain only
 * - write a NDEF message containing an URL/Link record with communication mode Plain only
 * <p>
 * General behaviour of the class:
 * - this class is using (application) access key based reading and writing methods. Although it is allowed
 * to use the value '0xE' (decimal 14) meaning 'free access without key' all read and write methods will
 * always check for a preceding authentication with a Read&Write, Read and/or Write access key. So if you
 * change the access key rights to '0xE' you cannot read or write from/to a file anymore with this class
 * <p>
 * (*1): using fixed application settings '0x0f' meaning Application master key authentication is necessary to change any key (default),
 * the configuration is changeable if authenticated with the application master key (default setting)
 * CreateFile / DeleteFile is permitted also without application master key authentication (default setting)
 * GetFileIDs, GetFileSettings and GetKeySettings commands succeed independently of a preceding application master key authentication (default setting)
 * Application master key is changeable (authentication with the current application master key necessary, default setting)
 * You change this later using changeApplicationSettings
 * The number of AES application keys is fixed to 5 to support the different access key rights that are set to (access rights can be changed later):
 * key number 0 = Application Master Key
 * key number 1 = Read & Write Access key
 * key number 2 = Change Access rights key (CAR)
 * key number 3 = Read Access key
 * key number 4 = Write Access key
 * (*2): A deletion of an application or file does NOT release the (memory) space on the tag, that does happen on formatting the PICC only
 * (*3): by reading of the fileSettings the method automatically detects and selects the communication mode
 * <p>
 * Not supported commands so far:
 * - working with Transaction MAC files
 * - authentication using LRP ('authenticateLrpEV2First' and 'authenticateLrpEV2NonFirst')
 * - change MasterApplicationKey (not supported to avoid any damage of the tag)
 */

// todo do not run some tasks after authentication (e.g. deleteFile won't run as the PICC is in authenticated state)

public class DesfireEv3 {

    private static final String TAG = DesfireEv3.class.getName();


    private final IsoDep isoDep;
    private String logData;
    private boolean authenticateEv2FirstSuccess = false;
    private boolean authenticateEv2NonFirstSuccess = false;
    private byte keyNumberUsedForAuthentication = -1;
    private byte[] SesAuthENCKey; // filled by authenticateAesEv2First
    private byte[] SesAuthMACKey; // filled by authenticateAesEv2First
    private int CmdCounter = 0; // filled / reset by authenticateAesEv2First
    private byte[] TransactionIdentifier; // reset by authenticateAesEv2First
    // note on TransactionIdentifier: LSB encoding

    // AES legacy authentication, not for encryption
    private boolean authenticateAesLegacySuccess = false;
    private byte keyNumberUsedForLegacyAuthentication = -1;
    private byte[] errorCode = new byte[2];
    private String errorCodeReason = "";

    /**
     * external constants for NDEF application and files
     */

    public enum DesfireFileType {
        Standard, Backup, Value, LinearRecord, CyclicRecord
    }

    public static final byte STANDARD_FILE_TYPE = (byte) 0x00;
    public static final byte BACKUP_FILE_TYPE = (byte) 0x01;
    public static final byte VALUE_FILE_TYPE = (byte) 0x02;
    public static final byte LINEAR_RECORD_FILE_TYPE = (byte) 0x03;
    public static final byte CYCLIC_RECORD_FILE_TYPE = (byte) 0x04;
    public static final byte TRANSACTION_MAC_FILE_TYPE = (byte) 0x05;

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
    private final byte AUTHENTICATE_AES_COMMAND = (byte) 0xAA;
    private final byte MORE_DATA_COMMAND = (byte) 0xAF;
    private final byte GET_VERSION_INFO_COMMAND = (byte) 0x60;
    private final byte GET_KEY_SETTINGS_COMMAND = (byte) 0x45;
    private final byte CREATE_APPLICATION_COMMAND = (byte) 0xCA;
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte SELECT_APPLICATION_ISO_COMMAND = (byte) 0xA4;
    private final byte DELETE_APPLICATION_COMMAND = (byte) 0xDA;
    private final byte GET_APPLICATION_IDS_COMMAND = (byte) 0x6A;
    private final byte GET_APPLICATION_DF_NAMES_COMMAND = (byte) 0x6D;
    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte WRITE_STANDARD_FILE_SECURE_COMMAND = (byte) 0x8D;
    private final byte READ_STANDARD_FILE_SECURE_COMMAND = (byte) 0xAD;
    private final byte CREATE_BACKUP_FILE_COMMAND = (byte) 0xCB;
    private final byte WRITE_DATA_FILE_COMMAND = (byte) 0x3D;
    private final byte READ_DATA_FILE_COMMAND = (byte) 0xBD;
    private final byte WRITE_DATA_FILE_SECURE_COMMAND = (byte) 0x8D;
    private final byte READ_DATA_FILE_SECURE_COMMAND = (byte) 0xAD;
    private final byte CREATE_VALUE_FILE_COMMAND = (byte) 0xCC;
    private final byte GET_VALUE_COMMAND = (byte) 0x6C;
    private final byte CREDIT_VALUE_FILE_COMMAND = (byte) 0x0C;
    private final byte DEBIT_VALUE_FILE_COMMAND = (byte) 0xDC;

    private final byte CREATE_LINEAR_RECORD_FILE_COMMAND = (byte) 0xC1;
    private final byte CREATE_CYCLIC_RECORD_FILE_COMMAND = (byte) 0xC0;
    private static final byte READ_RECORD_FILE_COMMAND = (byte) 0xBB;
    private static final byte READ_RECORD_FILE_SECURE_COMMAND = (byte) 0xAB;
    private static final byte WRITE_RECORD_FILE_SECURE_COMMAND = (byte) 0x8B;
    private static final byte CLEAR_RECORD_FILE_COMMAND = (byte) 0xEB;
    private final byte COMMIT_TRANSACTION_COMMAND = (byte) 0xC7;
    private final byte ABORT_TRANSACTION_COMMAND = (byte) 0xA7;
    private final byte SET_CONFIGURATION_SECURE_COMMAND = (byte) 0x5C;
    private final byte COMMIT_READER_ID_SECURE_COMMAND = (byte) 0xC8;
    private final byte READ_SIGNATURE_COMMAND = (byte) 0x3C;

    // section for Transaction MAC files
    private final byte CREATE_TRANSACTION_MAC_FILE_COMMAND = (byte) 0xCE;
    private final byte DELETE_TRANSACTION_MAC_FILE_COMMAND = (byte) 0xDF;
    public static final byte TRANSACTION_MAC_FILE_NUMBER = (byte) 0x1F; // 31
    // key settings for Transaction MAC file
    //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0x10; // Read&Write Access (key 01) & ChangeAccessRights (key 00)
    private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0xF0; // CommitReaderID disabled & ChangeAccessRights (key 00)
    /**
     * Note on Access Right 'RW' - see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
     * AppCommitReaderIDKey: Note that this access right has a specific meaning in the context of a TransactionMAC file
     * as if defines the availability and configuration for the CommitReaderID command:
     * 0h..4h: CommitReaderID enabled, requiring authentication with the specified application key index
     * Eh    : CommitReaderID enabled with free access
     * Fh    : CommitReaderID disabled
     */
    private final byte ACCESS_RIGHTS_R_W_TMAC = (byte) 0x1F; // Read Access (key 01) & Write Access (no access)

    private final byte GET_CARD_UID_COMMAND = (byte) 0x51;
    private final byte FORMAT_PICC_COMMAND = (byte) 0xFC;
    private final byte DELETE_FILE_COMMAND = (byte) 0xDF;
    private final byte GET_FILE_IDS_COMMAND = (byte) 0x6F;
    private final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private final byte CHANGE_KEY_SECURE_COMMAND = (byte) 0xC4;
    private static final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;

    /**
     * class internal constants and limitations
     */
    boolean printToLog = true; // logging data in internal log string
    public static final byte[] MASTER_APPLICATION_IDENTIFIER = Utils.hexStringToByteArray("000000"); // AID '00 00 00'
    private final byte APPLICATION_MASTER_KEY_SETTINGS = (byte) 0x0F; // 'amks' all default values
    private final byte APPLICATION_CRYPTO_DES = 0x00; // add this to number of keys for DES
    //private final byte APPLICATION_CRYPTO_3KTDES = (byte) 0x40; // add this to number of keys for 3KTDES
    //private final byte APPLICATION_CRYPTO_AES = (byte) 0x80; // add this to number of keys for AES
    private final byte APPLICATION_CRYPTO_AES = (byte) 0xA0; // add this to number of keys for AES
    private final byte FILE_COMMUNICATION_SETTINGS_PLAIN = (byte) 0x00; // plain communication
    private final byte FILE_COMMUNICATION_SETTINGS_MACED = (byte) 0x01; // mac'ed communication
    private final byte FILE_COMMUNICATION_SETTINGS_FULL = (byte) 0x03; // full = enciphered communication
    public static final byte[] ACCESS_RIGHTS_DEFAULT = hexStringToByteArray("1234"); // R&W access 1, CAR 2, R 3, W 4
    private final byte[] IV_LABEL_ENC = new byte[]{(byte) 0xA5, (byte) 0x5A}; // use as header for AES encryption
    private final byte[] IV_LABEL_DEC = new byte[]{(byte) 0x5A, (byte) 0xA5}; // use as header for AES decryption
    //private final int MAXIMUM_MESSAGE_LENGTH = 32;//
    private final int MAXIMUM_WRITE_MESSAGE_LENGTH = 40;
    private final int MAXIMUM_READ_MESSAGE_LENGTH = 40;
    private static final byte MAXIMUM_NUMBER_OF_KEYS = 5; // the maximum of keys per application is 14
    private final int MAXIMUM_NUMBER_OF_FILES = 32; // as per datasheet DESFire EV3 this is valid for EV1, EV2 and EV3
    private static final int MAXIMUM_VALUES = 2147483647;
    private static final byte[] TRANSACTION_MAC_READER_ID_DEFAULT = Utils.hexStringToByteArray("28BF1982BE086FBC60A22DAEB66613EE"); // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65

    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_UNAUTHENTICATED_OK = new byte[]{(byte) 0x91, (byte) 0x90};
    private final byte[] RESPONSE_ISO_OK = new byte[]{(byte) 0x90, (byte) 0x00};
    public static final byte[] RESPONSE_LENGTH_ERROR = new byte[]{(byte) 0x91, (byte) 0x7E};
    private final byte[] RESPONSE_PERMISSION_DENIED_ERROR = new byte[]{(byte) 0x91, (byte) 0x9D};
    public static final byte[] RESPONSE_DUPLICATE_ERROR = new byte[]{(byte) 0x91, (byte) 0xDE};
    public static final byte[] RESPONSE_ISO_DUPLICATE_ERROR = new byte[]{(byte) 0x90, (byte) 0xDE};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS = new byte[]{(byte) 0x91, (byte) 0xFB};
    private final byte[] RESPONSE_FAILURE_MISSING_AUTHENTICATION = new byte[]{(byte) 0x91, (byte) 0xFD};
    private static final byte[] RESPONSE_PARAMETER_ERROR = new byte[]{(byte) 0x91, (byte) 0xFC}; // failure because of wrong parameter
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF}; // general, undefined failure

    private final byte[] HEADER_ENC = new byte[]{(byte) (0x5A), (byte) (0xA5)}; // fixed to 0x5AA5
    private final byte[] HEADER_MAC = new byte[]{(byte) (0xA5), (byte) (0x5A)}; // fixed to 0x5AA5
    private final byte[] PADDING_FULL = hexStringToByteArray("80000000000000000000000000000000");

    /**
     * application
     */

    private byte[] selectedApplicationId; // filled by 'select application'

    /**
     * files
     */

    private static byte[] APPLICATION_ALL_FILE_IDS; // filled by getAllFileIds and invalidated by selectApplication AND createFile
    private List<byte[]> isoFileIdsList = new ArrayList<>(); // filled by getApplicationsIsoData and invalidated by onTagDiscovered
    private List<byte[]> isoDfNamesList = new ArrayList<>(); // filled by getApplicationsIsoData and invalidated by onTagDiscovered
    private static FileSettings[] APPLICATION_ALL_FILE_SETTINGS; // filled by getAllFileSettings and invalidated by selectApplication AND createFile
    private FileSettings selectedFileSetting; // takes the fileSettings of the actual file
    private FileSettings[] fileSettingsArray = new FileSettings[MAXIMUM_NUMBER_OF_FILES]; // after an 'select application' the fileSettings of all files are read
    private boolean isApplicationSelected = false; // used by SetupLightEnvironment, filled by selectApplicationByDfName
    private boolean isTransactionMacFilePresent = false; // true when a Transaction MAC file is present in an application
    private FileSettings transactionMacFileSettings; // not null when a transactionMacFile is present
    private boolean isTransactionMacCommitReaderId = false;
    private byte[] transactionMacFileReturnedTmcv; // if requested on commitTransaction the TMAC counter and Value are returned (only if TMAC file is present)
    private byte[] transactionMacReaderId; // necessary for Commit ReadId, filled on initialization with TRANSACTION_MAC_READER_ID_DEFAULT

    DesfireAuthenticateLegacy desfireD40;

    public enum CommunicationSettings {
        Plain, MACed, Full
    }


    public DesfireEv3(IsoDep isoDep) {
        this.isoDep = isoDep;
        Log.i(TAG, "class is initialized");
        transactionMacReaderId = TRANSACTION_MAC_READER_ID_DEFAULT.clone();
        isoFileIdsList = new ArrayList<>(); // filled by getApplicationsIsoData and invalidated by onTagDiscovered
        isoDfNamesList = new ArrayList<>(); // filled by getApplicationsIsoData and invalidated by onTagDiscovered
    }

    /**
     * just for testing
     */

    public void test() {
        String methodName = "test";
        // testing the decryption of Decrypted Response Data = (TMRI)
        // see Mifare DESFire Light Features and Hints AN12343.pdf page 64
        byte[] SesAuthEncKeyTest = Utils.hexStringToByteArray("78240CC5596B751D90023827B0B7E73D");
        byte[] TiTest = Utils.hexStringToByteArray("2D0611EC");
        byte[] commandCounterLsbTest = intTo2ByteArrayInversed(2);
        byte[] EncryptedResponseDataTest = Utils.hexStringToByteArray("A1963F1BB9FC916A8B15B2DC58002531");
        byte[] DecryptedResponseExpTest = Utils.hexStringToByteArray("BDD40ED9F434F9DDCBF5821299CD2119");
        byte[] DecryptedResponseTest;

        byte[] paddingReader = hexStringToByteArray("0000000000000000");
        byte[] startingIvReader = new byte[16];
        ByteArrayOutputStream decryptBaosReader = new ByteArrayOutputStream();
        decryptBaosReader.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length); // (byte) 0x5A, (byte) 0xA5
        decryptBaosReader.write(TiTest, 0, TiTest.length);
        decryptBaosReader.write(commandCounterLsbTest, 0, commandCounterLsbTest.length);
        decryptBaosReader.write(paddingReader, 0, paddingReader.length);
        byte[] ivInputResponseReader = decryptBaosReader.toByteArray();
        log(methodName, printData("ivInputResponseReader", ivInputResponseReader));
        byte[] ivResponseReader = AES.encrypt(startingIvReader, SesAuthEncKeyTest, ivInputResponseReader);
        log(methodName, printData("ivResponseReader", ivResponseReader));
        DecryptedResponseTest = AES.decrypt(ivResponseReader, SesAuthEncKeyTest, EncryptedResponseDataTest);
        log(methodName, printData("DecryptedResponse   Test", DecryptedResponseTest));
        log(methodName, printData("DecryptedResponseExpTest", DecryptedResponseExpTest));
        log(methodName, "decryptedData is previous TMRI (latest TransactionMAC Reader ID");
    }


    /**
     * For CommitReaderId method we do need a ReaderId as value. If we do not set an individual ReaderId
     * the DEFAULT ReaderId is used. This  method overwrites the DEFAULT with the individual ReaderId.
     *
     * @param transactionMacReaderId
     * @return true on success
     */

    public boolean setTransactionMacReaderId(byte[] transactionMacReaderId) {
        String methodName = "setTransactionMacReaderId";
        log(methodName, "started");
        log(methodName, printData("transactionMacReaderId", transactionMacReaderId));
        if ((transactionMacReaderId == null) || (transactionMacReaderId.length != 16)) {
            log(methodName, "transactionMacReaderId is NULL or not of length 16, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "transactionMacReaderId is NULL or not of length 16";
            return false;
        }
        this.transactionMacReaderId = transactionMacReaderId;
        return true;
    }

    /**
     * section for application handling
     */

    /**
     * create a new application using 5 AES keys
     * This uses a fixed Application Master Key Settings value of 0x0F which is default value
     *
     * @param applicationIdentifier   | length 3
     * @param numberOfApplicationKeys | range 1..14
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createApplicationAes(byte[] applicationIdentifier, int numberOfApplicationKeys) {
        String logData = "";
        final String methodName = "createApplicationAesIso";
        log(methodName, "started", true);
        log(methodName, printData("applicationIdentifier", applicationIdentifier));
        //log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "numberOfApplicationKeys: " + numberOfApplicationKeys);
        // sanity checks
        if (!checkApplicationIdentifier(applicationIdentifier))
            return false; // logFile and errorCode are updated
        if (Arrays.equals(applicationIdentifier, MASTER_APPLICATION_IDENTIFIER)) {
            log(methodName, "application identifier is 000000, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "application identifier is 000000";
            return false;
        }
        if ((numberOfApplicationKeys < 1) || (numberOfApplicationKeys > 14)) {
            log(methodName, "numberOfApplicationKeys is not in range 1..14, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "numberOfApplicationKeys is not in range 1..14";
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // build the command string
        byte keyNumbers = (byte) numberOfApplicationKeys;
        // now adding the constant for key type, here fixed to AES = 0x80
        //keyNumbers = (byte) (keyNumbers | APPLICATION_CRYPTO_AES);
        keyNumbers = (byte) (keyNumbers | (byte) 0x80);
        // "90CA00000E 010000 0F A5 10E1 D276000085010100"
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, applicationIdentifier.length);
        baos.write(APPLICATION_MASTER_KEY_SETTINGS); // application master key settings, fixed value
        baos.write(keyNumbers);
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
     * section for application handling
     */

    /**
     * create a new application using 5 AES keys
     * This uses a given Application Master Key Settings value (default could be 0x0F)
     * WARNING: be very careful on this value as it might freeze the application
     * This method does not run on the Master Application Identifier
     *
     * @param applicationIdentifier        | length 3 but NOT '000000'
     * @param numberOfApplicationKeys      | range 1..14
     * @param applicationMasterKeySettings | e.g. 0F
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createApplicationAes(byte[] applicationIdentifier, int numberOfApplicationKeys, byte applicationMasterKeySettings) {
        String logData = "";
        final String methodName = "createApplicationAesIso";
        log(methodName, "started", true);
        log(methodName, printData("applicationIdentifier", applicationIdentifier));
        //log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "numberOfApplicationKeys: " + numberOfApplicationKeys);
        // sanity checks
        if (!checkApplicationIdentifier(applicationIdentifier))
            return false; // logFile and errorCode are updated
        if (Arrays.equals(applicationIdentifier, MASTER_APPLICATION_IDENTIFIER)) {
            log(methodName, "application identifier is 000000, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "application identifier is 000000";
            return false;
        }
        if ((numberOfApplicationKeys < 1) || (numberOfApplicationKeys > 14)) {
            log(methodName, "numberOfApplicationKeys is not in range 1..14, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "numberOfApplicationKeys is not in range 1..14";
            return false;
        }
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // build the command string
        byte keyNumbers = (byte) numberOfApplicationKeys;
        // now adding the constant for key type, here fixed to AES = 0x80
        //keyNumbers = (byte) (keyNumbers | APPLICATION_CRYPTO_AES);
        keyNumbers = (byte) (keyNumbers | (byte) 0x80);
        // "90CA00000E 010000 0F A5 10E1 D276000085010100"
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, applicationIdentifier.length);
        baos.write(applicationMasterKeySettings);
        baos.write(keyNumbers);
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
     * create a new application including ISO application identifier and ISO Data File Name using AES keys
     * This uses a fixed Application Master Key Settings value of 0x0F which is default value
     *
     * @param applicationIdentifier   | length 3
     * @param applicationDfName       | length in range 1..16
     * @param numberOfApplicationKeys | range 1..14
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createApplicationAesIso(byte[] applicationIdentifier, byte[] isoApplicationIdentifier, byte[] applicationDfName, int numberOfApplicationKeys) {
        String logData = "";
        final String methodName = "createApplicationAesIso";
        log(methodName, "started", true);
        log(methodName, printData("applicationIdentifier", applicationIdentifier));
        log(methodName, printData("isoApplicationIdentifier", isoApplicationIdentifier));
        log(methodName, printData("applicationDfName", applicationDfName));
        //log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "numberOfApplicationKeys: " + numberOfApplicationKeys);
        // sanity checks
        if (!checkApplicationIdentifier(applicationIdentifier))
            return false; // logFile and errorCode are updated
        if ((isoApplicationIdentifier == null) || (isoApplicationIdentifier.length != 2)) {
            log(methodName, "isoApplicationIdentifier is NULL or not of length 2, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "isoApplicationIdentifier is NULL or not of length 2";
            return false;
        }
        if ((applicationDfName == null) || (applicationDfName.length < 1) || (applicationDfName.length > 16)) {
            log(methodName, "applicationDfName is NULL or not of length range 1..16, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "applicationDfName is NULL or not length range 1..16";
            return false;
        }
        if ((numberOfApplicationKeys < 1) || (numberOfApplicationKeys > 14)) {
            log(methodName, "numberOfApplicationKeys is not in range 1..14, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
     *
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
        if (!checkApplicationIdentifier(applicationIdentifier))
            return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(SELECT_APPLICATION_COMMAND, applicationIdentifier);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            invalidateAllData();
            invalidateAllNonAuthenticationData();
            selectedApplicationId = applicationIdentifier.clone();
            APPLICATION_ALL_FILE_IDS = getAllFileIds();
            APPLICATION_ALL_FILE_SETTINGS = getAllFileSettings();
            errorCode = RESPONSE_OK.clone();
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            return false;
        }
    }

    /**
     * selects an application on the discovered tag by application name (ISO command)
     *
     * @param dfApplicationName
     * @return Note: The DESFire Light has ONE pre defined application with name "D2760000850101"
     * see //NTAG 424 DNA and NTAG 424 DNA TagTamper features and hints AN12196.pdf pages 25-26
     */

    public boolean selectApplicationIsoByDfName(byte[] dfApplicationName) {
        String logData = "";
        final String methodName = "selectApplicationByIsoByDfName";
        log(methodName, "started", true);
        log(methodName, printData("dfApplicationName", dfApplicationName));

        if (isoDep == null) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "isoDep is NULL (maybe it is not a NTAG424DNA tag ?), aborted";
            return false;
        }
        if (dfApplicationName == null) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "dfApplicationName is NULL, aborted";
            return false;
        }
        // build command
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write((byte) 0x00);
        baos.write(SELECT_APPLICATION_ISO_COMMAND);
        baos.write((byte) 0x04); // select by DF name
        baos.write((byte) 0x0C); // return no FCI data
        //baos.write((byte) 0x00); // return the content of FCI = file id 1F
        baos.write(dfApplicationName.length);
        baos.write(dfApplicationName, 0, dfApplicationName.length);
        baos.write((byte) 0x00); // le
        byte[] apdu = baos.toByteArray();
        byte[] response = sendData(apdu);
        if (checkResponseIso(response)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            isApplicationSelected = true;
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * deletes the selected application without any further confirmation
     * Note: this command requires a preceding authentication with Application Master key
     *
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean deleteSelectedApplication() {
        final String methodName = "deleteSelectedApplication";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];
        // sanity checks
        if (!checkApplicationIdentifier(selectedApplicationId))
            return false; // logFile and errorCode are updated
        if (!checkAuthentication()) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(DELETE_APPLICATION_COMMAND, selectedApplicationId);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

    public List<byte[]> getApplicationIdsList() {
        final String methodName = "getApplicationIdsList";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];

        // sanity checks
        if (!checkIsMasterApplication()) return null; // select Master Application first
        if (!checkIsoDep()) return null;

        // get application ids
        List<byte[]> applicationIdList = new ArrayList<>();
        byte[] response;
        response = sendRequest(GET_APPLICATION_IDS_COMMAND);
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (!checkResponse(response)) {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        errorCode = RESPONSE_OK.clone();
        errorCodeReason = "SUCCESS";
        byte[] applicationListBytes = getData(response);
        applicationIdList = divideArray(applicationListBytes, 3);
        return applicationIdList;
    }

    public byte[] getApplicationDfNames() {
        final String methodName = "getApplicationDfNames";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];

        // sanity checks
        if (!checkIsMasterApplication()) return null; // select Master Application first
        if (!checkIsoDep()) return null;

        // get application ids
        byte[] response;
        response = sendRequest(GET_APPLICATION_DF_NAMES_COMMAND);
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (!checkResponse(response)) {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        errorCode = RESPONSE_OK.clone();
        errorCodeReason = "SUCCESS";
        byte[] applicationListBytes = getData(response);
        return applicationListBytes;
    }

    /**
     * tries to get the ISO File IDs and ISO DF Names from the application on the tag
     * On success retrieve the data by using the getters 'getIsoDfNamesList()' and
     * 'getIsoFileIdsList()', they return a List<byte[]>'
     *
     * @return true on success
     */

    public boolean getApplicationsIsoData() {
        byte[] dfNames = getApplicationDfNames();
        if ((dfNames == null) || (dfNames.length < 6)) {
            Log.e(TAG, "no DF names found, aborted");
            return false;
        }
        Log.d(TAG, printData("dfNames", dfNames));
        List<byte[]> appIdsList = getApplicationIdsList();
        if (appIdsList.size() < 1) {
            Log.e(TAG, "no applications found, aborted");
            return false;
        }

        // get iso file ids and df names by parsing through list
        int dfNamesLength = dfNames.length;
        isoFileIdsList = new ArrayList<>();
        isoDfNamesList = new ArrayList<>();
        int posAppId = -1;
        int posAppIdLast = -1;
        for (int i = 0; i < appIdsList.size(); i++) {
            byte[] appId = appIdsList.get(i);
            Log.d(TAG, "i: " + i + printData(" appId", appId));
            posAppId = indexOf(dfNames, appId);
            if (posAppId <= posAppIdLast) {
                // this  happens if the appId is part of a former element
                Log.e(TAG, "couldn't find the starting position, aborted");
                return false;
            }
            if (posAppId > -1) {
                Log.d(TAG, "found posAppId: " + posAppId);
            } else {
                Log.e(TAG, "appId not found in dfNames, aborted");
                return false;
            }
            if (posAppId > 0) {
                // skip the first id found
                // get the data from the first element up to element - 1
                Log.d(TAG, "get element data posAppIdLast: " + posAppIdLast + " posAppId: " + posAppId);
                byte[] elementData = Arrays.copyOfRange(dfNames, posAppIdLast, posAppId);
                Log.d(TAG, printData("elementData", elementData));
                byte[] appIdTemp = Arrays.copyOfRange(elementData, 0, 3);
                byte[] isoFileId = Arrays.copyOfRange(elementData, 3, 5);
                byte[] dfName = Arrays.copyOfRange(elementData, 5, elementData.length);
                isoFileIdsList.add(isoFileId);
                isoDfNamesList.add(dfName);
                Log.d(TAG, printData("appId", appIdTemp) + printData(" isoFileId", isoFileId) + printData(" dfName", dfName));
            }
            posAppIdLast = posAppId;
            if (i == (appIdsList.size() - 1)) {
                // grabbing the last element
                Log.d(TAG, "grabbing the last element");
                byte[] elementData = Arrays.copyOfRange(dfNames, posAppIdLast, dfNamesLength);
                Log.d(TAG, printData("elementData", elementData));
                byte[] appIdTemp = Arrays.copyOfRange(elementData, 0, 3);
                byte[] isoFileId = Arrays.copyOfRange(elementData, 3, 5);
                byte[] dfName = Arrays.copyOfRange(elementData, 5, elementData.length);
                isoFileIdsList.add(isoFileId);
                isoDfNamesList.add(dfName);
                Log.d(TAG, printData("appId", appIdTemp) + printData(" isoFileId", isoFileId) + printData(" dfName", dfName));
            }
        }
        Log.d(TAG, "isoFileIdsList size: " + isoFileIdsList.size());
        Log.d(TAG, "isoDfNamesList size: " + isoDfNamesList.size());
        for (int i = 0; i < isoFileIdsList.size(); i++) {
            Log.d(TAG, "i: " + i + printData(" isoFileId", isoFileIdsList.get(i)));
            Log.d(TAG, "i: " + i + printData(" isoDfName", isoDfNamesList.get(i)));
        }
        if ((isoFileIdsList.size() > 0) && (isoDfNamesList.size() > 1)) {
            Log.d(TAG, "applicationIsoData is available, use getter");
            return true;
        } else {
            Log.d(TAG, "applicationIsoData is NOT available");
            return false;
        }
    }


    /**
     * section for data file handling
     */


    /**
     * create a Standard file in selected application using file Number
     *
     * @param fileNumber            | in range 0..31
     * @param communicationSettings | Plain, MACed or Full Note: Please do not use MACed as there are no methods in this class to handle that communication type
     * @param accessRights          | Read & Write access key, CAR ke, Read key, Write key
     * @param fileSize              | maximum of 256 bytes
     * @param preEnableSdm          | set to true if you (later) want to enable SDM. If you don't set this on file creation it cannot get enabled later
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createAStandardFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, int fileSize, boolean preEnableSdm) {
        return createADataFile(fileNumber, communicationSettings, accessRights, true, fileSize, preEnableSdm);
    }

    /**
     * create a Backup file in selected application using file Number
     *
     * @param fileNumber            | in range 0..31
     * @param communicationSettings | Plain, MACed or Full Note: Please do not use MACed as there are no methods in this class to handle that communication type
     * @param accessRights          | Read & Write access key, CAR ke, Read key, Write key
     * @param fileSize              | maximum of 256 bytes
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createABackupFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, int fileSize) {
        return createADataFile(fileNumber, communicationSettings, accessRights, false, fileSize, false);
    }

    /**
     * create a Standard file in selected application using file Number and ISO fileId
     *
     * @param fileNumber            | in range 0..31
     * @param isoFileId
     * @param communicationSettings | Plain, MACed or Full
     * @param accessRights          | Read & Write access key, CAR ke, Read key, Write key
     * @param fileSize              | maximum of 256 bytes
     * @param preEnableSdm          | set to true if you (later) want to enable SDM. If you don't set this on file creation it cannot get enabled later.
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createAStandardFileIso(byte fileNumber, byte[] isoFileId, CommunicationSettings communicationSettings, byte[] accessRights, int fileSize, boolean preEnableSdm) {
        final String methodName = "createAStandardFileIso";
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
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
     * create a Data file in selected application using file Number, this should be called from createStandardFile or createBackupFile
     *
     * @param fileNumber            | in range 0..31
     * @param communicationSettings | Plain, MACed or Full
     * @param accessRights          | Read & Write access key, CAR ke, Read key, Write key
     * @param isStandardFile        | true when creating a Standard file, false will create a Backup file
     * @param fileSize              | maximum of 256 bytes
     * @param preEnableSdm          | set to true if you (later) want to enable SDM. If you don't set this on file creation it cannot
     *                              | get enabled later. Valid only on Standard files !
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    private boolean createADataFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, boolean isStandardFile, int fileSize, boolean preEnableSdm) {
        final String methodName = "createADataFile";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "isStandardFile: " + isStandardFile);
        log(methodName, "fileSize: " + fileSize);
        log(methodName, "preEnableSdm: " + preEnableSdm);
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if (!checkAccessRights(accessRights)) return false; // logFile and errorCode are updated
        if (!checkFileSize0(fileSize)) return false; // logFile and errorCode are updated
        /*
        if ((fileSize < 1) || (fileSize > MAXIMUM_FILE_SIZE)) {
            log(methodName, "fileSize is not in range 1..MAXIMUM_FILE_SIZE, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "fileSize is not in range 1..MAXIMUM_FILE_SIZE";
            return false;
        }
         */
        if (!isStandardFile)
            preEnableSdm = false; // SDM feature is available in Standard files only
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;
        // add 0x40 for pre-enabled SDM
        if (preEnableSdm) {
            commSettings = (byte) (commSettings | (byte) 0x40);
        }

        byte[] fileSizeByte = Utils.intTo3ByteArrayInversed(fileSize);
        // build the command string
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(commSettings);
        baos.write(accessRights, 0, accessRights.length);
        baos.write(fileSizeByte, 0, fileSizeByte.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            if (isStandardFile) {
                apdu = wrapMessage(CREATE_STANDARD_FILE_COMMAND, commandParameter);
            } else {
                apdu = wrapMessage(CREATE_BACKUP_FILE_COMMAND, commandParameter);
            }
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            errorCodeReason = "FAILURE";
            return false;
        }
    }

    public boolean createAValueFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, int minimumValue, int maximumValue, int initialValue, boolean limitedCreditOperation) {
        final String methodName = "createAValueFile";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "minimumValue: " + minimumValue);
        log(methodName, "maximumValue: " + maximumValue);
        log(methodName, "initialValue: " + initialValue);
        log(methodName, "limitedCreditOperation: " + limitedCreditOperation);
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkAccessRights(accessRights)) return false;
        if ((minimumValue < 0) || (minimumValue > MAXIMUM_VALUES)) {
            log(methodName, "minimumValue is not in range 0.." + MAXIMUM_VALUES + ", aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "minimumValue is not in range 0.." + MAXIMUM_VALUES;
            return false;
        }
        if ((maximumValue < 0) || (maximumValue > MAXIMUM_VALUES)) {
            log(methodName, "maximumValue is not in range 0.." + MAXIMUM_VALUES + ", aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "maximumValue is not in range 0.." + MAXIMUM_VALUES;
            return false;
        }
        if ((initialValue < 0) || (initialValue > MAXIMUM_VALUES)) {
            log(methodName, "initialValue is not in range 0.." + MAXIMUM_VALUES + ", aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "initialValue is not in range 0.." + MAXIMUM_VALUES;
            return false;
        }
        if (minimumValue >= maximumValue) {
            log(methodName, "minimumValue is not < maximumValue, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "minimumValue is not < maximumValue";
            return false;
        }
        if (!checkIsoDep()) return false;

        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        byte[] minimumValueByte = Utils.intTo4ByteArrayInversed(minimumValue);
        byte[] maximumValueByte = Utils.intTo4ByteArrayInversed(maximumValue);
        byte[] initialValueByte = Utils.intTo4ByteArrayInversed(initialValue);
        byte limitedCreditOperationEnabledByte;
        if (limitedCreditOperation) {
            limitedCreditOperationEnabledByte = (byte) 0x01; // 01 means enabled feature
        } else {
            limitedCreditOperationEnabledByte = (byte) 0x00; // 00 means disabled feature
        }

        // build the command string
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(commSettings);
        baos.write(accessRights, 0, accessRights.length);
        baos.write(minimumValueByte, 0, minimumValueByte.length);
        baos.write(maximumValueByte, 0, maximumValueByte.length);
        baos.write(initialValueByte, 0, initialValueByte.length);
        baos.write(limitedCreditOperationEnabledByte);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(CREATE_VALUE_FILE_COMMAND, commandParameter);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            errorCodeReason = "FAILURE";
            return false;
        }
    }

    public boolean createALinearRecordFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, int recordSize, int maximumNumberOfRecords) {
        final String methodName = "createALinearRecordFile";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "recordSize: " + recordSize);
        log(methodName, "maximumNumberOfRecords: " + maximumNumberOfRecords);
        return createARecordFile(fileNumber, communicationSettings, accessRights, recordSize, maximumNumberOfRecords, true);
    }

    public boolean createACyclicRecordFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, int recordSize, int maximumNumberOfRecords) {
        final String methodName = "createACyclicRecordFile";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "recordSize: " + recordSize);
        log(methodName, "maximumNumberOfRecords: " + maximumNumberOfRecords);
        return createARecordFile(fileNumber, communicationSettings, accessRights, recordSize, maximumNumberOfRecords, false);
    }

    private boolean createARecordFile(byte fileNumber, CommunicationSettings communicationSettings, byte[] accessRights, int recordSize, int maximumNumberOfRecords, boolean isLinearRecordFile) {
        final String methodName = "createARecordFile";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "recordSize: " + recordSize);
        log(methodName, "maximumNumberOfRecords: " + maximumNumberOfRecords);
        log(methodName, "isLinearRecordFile: " + isLinearRecordFile);

        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkAccessRights(accessRights)) return false;
        if (recordSize < 1) {
            log(methodName, "recordSize is < 1, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "recordSize is < 1";
            return false;
        }
        if (maximumNumberOfRecords < 1) {
            log(methodName, "maximumNumberOfRecords is < 1, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "maximumNumberOfRecords is < 1";
            return false;
        }
        if (!checkIsoDep()) return false;
        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        // build the command string
        byte[] recordSizeBytes = intTo3ByteArrayInversed(recordSize);
        byte[] maximumNumberOfRecordsBytes = intTo3ByteArrayInversed(maximumNumberOfRecords);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(commSettings);
        baos.write(accessRights, 0, accessRights.length);
        baos.write(recordSizeBytes, 0, recordSizeBytes.length);
        baos.write(maximumNumberOfRecordsBytes, 0, maximumNumberOfRecordsBytes.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            if (isLinearRecordFile) {
                apdu = wrapMessage(CREATE_LINEAR_RECORD_FILE_COMMAND, commandParameter);
            } else {
                apdu = wrapMessage(CREATE_CYCLIC_RECORD_FILE_COMMAND, commandParameter);
            }
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            errorCodeReason = "FAILURE";
            return false;
        }
    }

    public boolean createACyclicRecordFileIso(byte fileNumber, byte[] isoFileId, CommunicationSettings communicationSettings, byte[] accessRights, int recordSize, int maximumNumberOfRecords) {
        final String methodName = "createACyclicRecordFileIso";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("isoFileId", isoFileId));
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "recordSize: " + recordSize);
        log(methodName, "maximumNumberOfRecords: " + maximumNumberOfRecords);
        return createARecordFileIso(fileNumber, isoFileId, communicationSettings, accessRights, recordSize, maximumNumberOfRecords, false);
    }

    private boolean createARecordFileIso(byte fileNumber, byte[] isoFileId, CommunicationSettings communicationSettings, byte[] accessRights, int recordSize, int maximumNumberOfRecords, boolean isLinearRecordFile) {
        final String methodName = "createARecordFileIso";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("isoFileId", isoFileId));
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("accessRights", accessRights));
        log(methodName, "recordSize: " + recordSize);
        log(methodName, "maximumNumberOfRecords: " + maximumNumberOfRecords);
        log(methodName, "isLinearRecordFile: " + isLinearRecordFile);

        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkAccessRights(accessRights)) return false;
        if (recordSize < 1) {
            log(methodName, "recordSize is < 1, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "recordSize is < 1";
            return false;
        }
        if (maximumNumberOfRecords < 1) {
            log(methodName, "maximumNumberOfRecords is < 1, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "maximumNumberOfRecords is < 1";
            return false;
        }
        if (!checkIsoDep()) return false;
        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        // build the command string
        byte[] recordSizeBytes = intTo3ByteArrayInversed(recordSize);
        byte[] maximumNumberOfRecordsBytes = intTo3ByteArrayInversed(maximumNumberOfRecords);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(isoFileId, 0, isoFileId.length);
        baos.write(commSettings);
        baos.write(accessRights, 0, accessRights.length);
        baos.write(recordSizeBytes, 0, recordSizeBytes.length);
        baos.write(maximumNumberOfRecordsBytes, 0, maximumNumberOfRecordsBytes.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            if (isLinearRecordFile) {
                apdu = wrapMessage(CREATE_LINEAR_RECORD_FILE_COMMAND, commandParameter);
            } else {
                apdu = wrapMessage(CREATE_CYCLIC_RECORD_FILE_COMMAND, commandParameter);
            }
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            log(methodName, "SUCCESS");
            return true;
        } else {
            log(methodName, "FAILURE with " + printData("errorCode", errorCode));
            errorCodeReason = "FAILURE";
            return false;
        }

/*
final String methodName = "createAStandardFileIso";
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
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
 */
    }


    /**
     * create a Transaction MAC file in selected application using file Number
     * This is using CommunicationMode.Full for security reasons (see below)
     * Note: the created TransactionMAC file gets a DISABLED Commit ReaderId option
     * Note: the file can be read as a Standard file with a file length of 12 bytes
     *
     * From datasheet  MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 84
     * As the TransactionMACKey, AppTransactionMACKey is updated at this command, it shall be
     * executed only in a secure environment.
     *
     * @param fileNumber            | in range 0..31
     * @param communicationSettings | Plain mode only
     * @param communicationSettings | deprecated: Plain, MACed or Full
     * @param tmacAccessRights      | Read & Write access key, CAR ke, Read key, Write key
     *                              | Note: there are special meaning in the context of a
     *                              | e.g. '0xF01F'
     * @param transactionMacKey     | a 16 bytes long AES key for encryption of Transaction MAC data
     *                              | Note: the key version of this key is fixed to '0x00'
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */


    /**
     * Create a Transaction MAC file in selected application using file Number
     * The execution is done using CommunicationMode.Full for security reasons (see below)
     * Note: the created Transaction MAC file has CommunicationMode.Plain
     * Note: the created Transaction MAC file gets a DISABLED Commit ReaderId option
     * Note: the file can be read as a Standard file with a file length of 12 bytes
     * <p>
     * From datasheet  MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 84
     * As the TransactionMACKey, AppTransactionMACKey is updated at this command, it shall be
     * executed only in a secure environment.
     *
     * @param fileNumber                  | in range 0..31
     * @param communicationSettings       | Plain mode only
     * @param changeAccessRightsKeyNumber | this is the number of the Change Access Key
     * @param readAccessKeyNumber         | this is the number of the Read Access Key
     * @param transactionMacKey           | a 16 bytes long AES key for encryption of Transaction MAC data
     *                                    | Note: the key version of this key is fixed to '0x00'
     * @return | true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createATransactionMacFileFull(byte fileNumber, CommunicationSettings communicationSettings, int changeAccessRightsKeyNumber, int readAccessKeyNumber, byte[] transactionMacKey) {
        final String methodName = "createATransactionMacFileFull (disabled Commit ReaderId option)";
        log(methodName, "started", true);
        return createATransactionMacFileFull(fileNumber, communicationSettings, 15, changeAccessRightsKeyNumber, readAccessKeyNumber, false, transactionMacKey);
    }

    /**
     * Create a Transaction MAC file in selected application using file Number
     * The execution is done using CommunicationMode.Full for security reasons (see below)
     * Note: the created Transaction MAC file has CommunicationMode.Plain -> changed to all Comm.Modes
     * Note: the file can be read as a Standard file with a file length of 12 bytes
     * <p>
     * From datasheet  MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 84
     * As the TransactionMACKey, AppTransactionMACKey is updated at this command, it shall be
     * executed only in a secure environment.
     *
     * @param fileNumber                  | in range 0..31
     * @param communicationSettings       | Plain mode only
     * @param commitReaderIdAuthKeyNumber | the number of the key that authenticates the Commit ReadId command (e.g. 1)
     * @param changeAccessRightsKeyNumber | the number of the Change Access Key (e.g. 2)
     * @param readAccessKeyNumber         | the number of the Read Access Key (e.g. 3)
     * @param enableCommitReaderId        | true for enabling the  Commit ReaderId feature
     * @param transactionMacKey           | a 16 bytes long AES key for encryption of Transaction MAC data
     *                                    | Note: the key version of this key is fixed to '0x00'
     * @return | true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean createATransactionMacFileFull(byte fileNumber, CommunicationSettings communicationSettings, int commitReaderIdAuthKeyNumber, int changeAccessRightsKeyNumber, int readAccessKeyNumber, boolean enableCommitReaderId, byte[] transactionMacKey) {
        //public boolean createTransactionMacFileEv2(byte fileNumber, byte[] transactionMacAccessRights, byte[] key) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card

        // for access rights see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
        // the TMAC can be read like a Standard file with size 12 bytes
        // Note that TMC and TMV can also be read out encrypted, if preferred. In this case, the
        // TransactionMAC file should be configured for CommMode.Full. One can then use ReadData to
        // retrieve this information, instead of requesting it within the response of CommitTransaction.
        // see pages 40-48 (General overview as well)

        // key settings for Transaction MAC file
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0x10; // Read&Write Access (key 01) & ChangeAccessRights (key 00)
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0xF0; // CommitReaderID disabled & ChangeAccessRights (key 00)
        /**
         * Note on Access Right 'RW' - see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
         * AppCommitReaderIDKey: Note that this access right has a specific meaning in the context of a TransactionMAC file
         * as if defines the availability and configuration for the CommitReaderID command:
         * 0h..4h: CommitReaderID enabled, requiring authentication with the specified application key index
         * Eh    : CommitReaderID enabled with free access
         * Fh    : CommitReaderID disabled
         */
        //private final byte ACCESS_RIGHTS_R_W_TMAC = (byte) 0x1F; // Read Access (key 01) & Write Access (no access)

        final String methodName = "createATransactionMacFileFull";
        //logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "commitReaderIdAuthKeyNumber: " + commitReaderIdAuthKeyNumber);
        log(methodName, "changeAccessRightsKeyNumber: " + changeAccessRightsKeyNumber);
        log(methodName, "readAccessKeyNumber: " + readAccessKeyNumber);
        log(methodName, "enableCommitReaderId: " + enableCommitReaderId);
        log(methodName, printData("transactionMacKey", transactionMacKey));
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkKey(transactionMacKey)) return false;
        if (!checkKeyNumber(commitReaderIdAuthKeyNumber)) return false;
        if (!checkKeyNumber(changeAccessRightsKeyNumber)) return false;
        if (!checkKeyNumber(readAccessKeyNumber)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are building the tmacAccessRights depending on requests
        // if enableCommitReaderId == true the commitReaderIdAuthKeyNumber needs to be in range 00..14
        if ((enableCommitReaderId) && (commitReaderIdAuthKeyNumber > 14)) {
            log(methodName, "enableCommitReaderId is true but commitReaderIdAuthKeyNumber is not in range 0..14, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "enableCommitReaderId is true but commitReaderIdAuthKeyNumber is not in range 0..14";
            return false;
        }
        if ((!enableCommitReaderId) && (commitReaderIdAuthKeyNumber < 15)) {
            log(methodName, "enableCommitReaderId is false but commitReaderIdAuthKeyNumber is not 15, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "enableCommitReaderId is false but commitReaderIdAuthKeyNumber is not 15";
            return false;
        }
        byte accessRightsRwCar = (byte) ((commitReaderIdAuthKeyNumber << 4) | (changeAccessRightsKeyNumber & 0x0F)); // Read & Write Access key = CommitReaderId key || Change Access Rights key
        byte accessRightsRW = (byte) ((readAccessKeyNumber << 4) | (15 & 0x0F));// Read Access key || Write Access = 15 = never (fixed)
        byte[] tmacAccessRights = new byte[2];
        tmacAccessRights[0] = accessRightsRwCar;
        tmacAccessRights[1] = accessRightsRW;

        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.MACed) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        ;
        if (communicationSettings == CommunicationSettings.Full) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        //if (communicationSettings == CommunicationSettings.MACed) commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        //if (communicationSettings == CommunicationSettings.Full) commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        byte TMACKeyOption = (byte) 0x02; // AES
        byte TMACKeyVersion = (byte) 0x00; // fixed

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
        byte[] keyEncrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, transactionMacKey);
        log(methodName, printData("keyEncrypted", keyEncrypted));
        byte[] iv2 = keyEncrypted.clone();
        log(methodName, printData("iv2", iv2));

        // Data (TMACKeyVersion || Padding)
        // taken from method header and don't forget to pad with 0x80..00
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
        baosCmdHeader.write(tmacAccessRights, 0, tmacAccessRights.length);
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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean createATransactionMacFileFullNewLight(byte fileNumber, CommunicationSettings communicationSettings, int commitReaderIdAuthKeyNumber, int changeAccessRightsKeyNumber, int readAccessKeyNumber, boolean enableCommitReaderId, byte[] transactionMacKey) {
        //public boolean createTransactionMacFileEv2(byte fileNumber, byte[] transactionMacAccessRights, byte[] key) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card

        // for access rights see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
        // the TMAC can be read like a Standard file with size 12 bytes
        // Note that TMC and TMV can also be read out encrypted, if preferred. In this case, the
        // TransactionMAC file should be configured for CommMode.Full. One can then use ReadData to
        // retrieve this information, instead of requesting it within the response of CommitTransaction.
        // see pages 40-48 (General overview as well)

        // key settings for Transaction MAC file
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0x10; // Read&Write Access (key 01) & ChangeAccessRights (key 00)
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0xF0; // CommitReaderID disabled & ChangeAccessRights (key 00)
        /**
         * Note on Access Right 'RW' - see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
         * AppCommitReaderIDKey: Note that this access right has a specific meaning in the context of a TransactionMAC file
         * as if defines the availability and configuration for the CommitReaderID command:
         * 0h..4h: CommitReaderID enabled, requiring authentication with the specified application key index
         * Eh    : CommitReaderID enabled with free access
         * Fh    : CommitReaderID disabled
         */
        //private final byte ACCESS_RIGHTS_R_W_TMAC = (byte) 0x1F; // Read Access (key 01) & Write Access (no access)

        final String methodName = "createATransactionMacFileFull";
        //logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "commitReaderIdAuthKeyNumber: " + commitReaderIdAuthKeyNumber);
        log(methodName, "changeAccessRightsKeyNumber: " + changeAccessRightsKeyNumber);
        log(methodName, "readAccessKeyNumber: " + readAccessKeyNumber);
        log(methodName, "enableCommitReaderId: " + enableCommitReaderId);
        log(methodName, printData("transactionMacKey", transactionMacKey));
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkKey(transactionMacKey)) return false;
        if (!checkKeyNumber(commitReaderIdAuthKeyNumber)) return false;
        if (!checkKeyNumber(changeAccessRightsKeyNumber)) return false;
        if (!checkKeyNumber(readAccessKeyNumber)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are building the tmacAccessRights depending on requests
        // if enableCommitReaderId == true the commitReaderIdAuthKeyNumber needs to be in range 00..14
        if ((enableCommitReaderId) && (commitReaderIdAuthKeyNumber > 14)) {
            log(methodName, "enableCommitReaderId is true but commitReaderIdAuthKeyNumber is not in range 0..14, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "enableCommitReaderId is true but commitReaderIdAuthKeyNumber is not in range 0..14";
            return false;
        }
        if ((!enableCommitReaderId) && (commitReaderIdAuthKeyNumber < 15)) {
            log(methodName, "enableCommitReaderId is false but commitReaderIdAuthKeyNumber is not 15, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "enableCommitReaderId is false but commitReaderIdAuthKeyNumber is not 15";
            return false;
        }
        byte accessRightsRwCar = (byte) ((commitReaderIdAuthKeyNumber << 4) | (changeAccessRightsKeyNumber & 0x0F)); // Read & Write Access key = CommitReaderId key || Change Access Rights key
        byte accessRightsRW = (byte) ((readAccessKeyNumber << 4) | (15 & 0x0F));// Read Access key || Write Access = 15 = never (fixed)
        byte[] tmacAccessRights = new byte[2];
        tmacAccessRights[0] = accessRightsRwCar;
        tmacAccessRights[1] = accessRightsRW;

        byte commSettings = (byte) 0;
        /*
        if (communicationSettings == CommunicationSettings.MACed) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        if (communicationSettings == CommunicationSettings.Full) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
         */
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        if (communicationSettings == CommunicationSettings.MACed)
            commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        if (communicationSettings == CommunicationSettings.Full)
            commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        byte TMACKeyOption = (byte) 0x02; // AES
        byte TMACKeyVersion = (byte) 0x00; // fixed

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
        byte[] keyEncrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, transactionMacKey);
        log(methodName, printData("keyEncrypted", keyEncrypted));
        byte[] iv2 = keyEncrypted.clone();
        log(methodName, printData("iv2", iv2));

        // Data (TMACKeyVersion || Padding)
        // taken from method header and don't forget to pad with 0x80..00
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
        //baosCmdHeader.write(FILE_COMMUNICATION_SETTINGS_PLAIN);
        baosCmdHeader.write(commSettings);
        baosCmdHeader.write(tmacAccessRights, 0, tmacAccessRights.length);
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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean createATransactionMacFileFull(byte fileNumber, CommunicationSettings communicationSettings, byte[] tmacAccessRights, byte[] transactionMacKey) {
        //public boolean createTransactionMacFileEv2(byte fileNumber, byte[] transactionMacAccessRights, byte[] key) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card

        // for access rights see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
        // the TMAC can be read like a Standard file with size 12 bytes
        // Note that TMC and TMV can also be read out encrypted, if preferred. In this case, the
        // TransactionMAC file should be configured for CommMode.Full. One can then use ReadData to
        // retrieve this information, instead of requesting it within the response of CommitTransaction.
        // see pages 40-48 (General overview as well)

        // key settings for Transaction MAC file
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0x10; // Read&Write Access (key 01) & ChangeAccessRights (key 00)
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0xF0; // CommitReaderID disabled & ChangeAccessRights (key 00)
        /**
         * Note on Access Right 'RW' - see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
         * AppCommitReaderIDKey: Note that this access right has a specific meaning in the context of a TransactionMAC file
         * as if defines the availability and configuration for the CommitReaderID command:
         * 0h..4h: CommitReaderID enabled, requiring authentication with the specified application key index
         * Eh    : CommitReaderID enabled with free access
         * Fh    : CommitReaderID disabled
         */
        //private final byte ACCESS_RIGHTS_R_W_TMAC = (byte) 0x1F; // Read Access (key 01) & Write Access (no access)

        final String methodName = "createATransactionMacFileFull";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, printData("tmacAccessRights", tmacAccessRights));
        log(methodName, printData("transactionMacKey", transactionMacKey));
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkKey(transactionMacKey)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // modifying the tmacAccessRights - disabling Commit ReaderId option
        byte[] tmacAccessRightsModified = modifyTmacAccessRights(tmacAccessRights);
        if (tmacAccessRightsModified == null) {
            log(methodName, "tmacAccessRights are invalid, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }

        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.MACed) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        ;
        if (communicationSettings == CommunicationSettings.Full) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        //if (communicationSettings == CommunicationSettings.MACed) commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        //if (communicationSettings == CommunicationSettings.Full) commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        byte TMACKeyOption = (byte) 0x02; // AES
        byte TMACKeyVersion = (byte) 0x00; // fixed

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
        byte[] keyEncrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, transactionMacKey);
        log(methodName, printData("keyEncrypted", keyEncrypted));
        byte[] iv2 = keyEncrypted.clone();
        log(methodName, printData("iv2", iv2));

        // Data (TMACKeyVersion || Padding)
        // taken from method header and don't forget to pad with 0x80..00
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
        baosCmdHeader.write(tmacAccessRightsModified, 0, tmacAccessRightsModified.length);
        baosCmdHeader.write(TMACKeyOption);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted Data))
        byte[] macInput = getMacInput(CREATE_TRANSACTION_MAC_FILE_COMMAND, cmdHeader, encryptedData);

        /*
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CREATE_TRANSACTION_MAC_FILE_COMMAND); // 0xCE
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();
        */
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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }

    }

    public boolean createATransactionMacFileExtendedFull(byte fileNumber, CommunicationSettings communicationSettings, int commitReaderIdAuthKeyNumber, int changeAccessRightsKeyNumber, int readAccessKeyNumber, boolean enableCommitReaderId, byte[] transactionMacKey) {
        //public boolean createTransactionMacFileEv2(byte fileNumber, byte[] transactionMacAccessRights, byte[] key) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 83 - 85
        // this is based on the creation of a TransactionMac file on a DESFire Light card

        // for access rights see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
        // the TMAC can be read like a Standard file with size 12 bytes
        // Note that TMC and TMV can also be read out encrypted, if preferred. In this case, the
        // TransactionMAC file should be configured for CommMode.Full. One can then use ReadData to
        // retrieve this information, instead of requesting it within the response of CommitTransaction.
        // see pages 40-48 (General overview as well)

        // key settings for Transaction MAC file
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0x10; // Read&Write Access (key 01) & ChangeAccessRights (key 00)
        //private final byte ACCESS_RIGHTS_RW_CAR_TMAC = (byte) 0xF0; // CommitReaderID disabled & ChangeAccessRights (key 00)
        /**
         * Note on Access Right 'RW' - see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 14
         * AppCommitReaderIDKey: Note that this access right has a specific meaning in the context of a TransactionMAC file
         * as if defines the availability and configuration for the CommitReaderID command:
         * 0h..4h: CommitReaderID enabled, requiring authentication with the specified application key index
         * Eh    : CommitReaderID enabled with free access
         * Fh    : CommitReaderID disabled
         */
        //private final byte ACCESS_RIGHTS_R_W_TMAC = (byte) 0x1F; // Read Access (key 01) & Write Access (no access)

        final String methodName = "createATransactionMacFileExtendedFull";
        logData = "";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "communicationSettings: " + communicationSettings.toString());
        log(methodName, "commitReaderIdAuthKeyNumber: " + commitReaderIdAuthKeyNumber);
        log(methodName, "changeAccessRightsKeyNumber: " + changeAccessRightsKeyNumber);
        log(methodName, "readAccessKeyNumber: " + readAccessKeyNumber);
        log(methodName, "enableCommitReaderId" + enableCommitReaderId);
        log(methodName, printData("transactionMacKey", transactionMacKey));
        errorCode = new byte[2];
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkKey(transactionMacKey)) return false;
        if (!checkKeyNumber(commitReaderIdAuthKeyNumber)) return false;
        if (!checkKeyNumber(changeAccessRightsKeyNumber)) return false;
        if (!checkKeyNumber(readAccessKeyNumber)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are building the tmacAccessRights depending on requests
        // if enableCommitReaderId == true the commitReaderIdAuthKeyNumber needs to be in range 00..14
        if ((enableCommitReaderId) && (commitReaderIdAuthKeyNumber > 14)) {
            log(methodName, "enableCommitReaderId is true but commitReaderIdAuthKeyNumber is not in range 0..14, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "enableCommitReaderId is true but commitReaderIdAuthKeyNumber is not in range 0..14";
            return false;
        }
        if ((!enableCommitReaderId) && (commitReaderIdAuthKeyNumber < 15)) {
            log(methodName, "enableCommitReaderId is false but commitReaderIdAuthKeyNumber is not 15, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "enableCommitReaderId is false but commitReaderIdAuthKeyNumber is not 15";
            return false;
        }
        byte accessRightsRwCar = (byte) ((commitReaderIdAuthKeyNumber << 4) | (changeAccessRightsKeyNumber & 0x0F)); // Read & Write Access key = CommitReaderId key || Change Access Rights key
        byte accessRightsRW = (byte) ((readAccessKeyNumber << 4) | (15 & 0x0F));// Read Access key || Write Access = 15 = never (fixed)
        byte[] tmacAccessRights = new byte[2];
        tmacAccessRights[0] = accessRightsRwCar;
        tmacAccessRights[1] = accessRightsRW;

        /*
        // modifying the tmacAccessRights - disabling Commit ReaderId option
        byte[] tmacAccessRightsModified = modifyTmacAccessRights(tmacAccessRights);
        if (tmacAccessRightsModified == null) {
            log(methodName, "tmacAccessRights are invalid, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
         */

        byte commSettings = (byte) 0;
        if (communicationSettings == CommunicationSettings.MACed) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        ;
        if (communicationSettings == CommunicationSettings.Full) {
            log(methodName, "CommunicationSettings.Plain allowed only, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCodeReason = "tmacAccessRights are invalid";
            return false;
        }
        if (communicationSettings == CommunicationSettings.Plain)
            commSettings = FILE_COMMUNICATION_SETTINGS_PLAIN;
        //if (communicationSettings == CommunicationSettings.MACed) commSettings = FILE_COMMUNICATION_SETTINGS_MACED;
        //if (communicationSettings == CommunicationSettings.Full) commSettings = FILE_COMMUNICATION_SETTINGS_FULL;

        byte TMACKeyOption = (byte) 0x02; // AES
        byte TMACKeyVersion = (byte) 0x00; // fixed

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
        byte[] keyEncrypted = AES.encrypt(ivForCmdData, SesAuthENCKey, transactionMacKey);
        log(methodName, printData("keyEncrypted", keyEncrypted));
        byte[] iv2 = keyEncrypted.clone();
        log(methodName, printData("iv2", iv2));

        // Data (TMACKeyVersion || Padding)
        // taken from method header and don't forget to pad with 0x80..00
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
        baosCmdHeader.write(tmacAccessRights, 0, tmacAccessRights.length);
        baosCmdHeader.write(TMACKeyOption);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted Data))
        byte[] macInput = getMacInput(CREATE_TRANSACTION_MAC_FILE_COMMAND, cmdHeader, encryptedData);
/*
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CREATE_TRANSACTION_MAC_FILE_COMMAND); // 0xCE
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(cmdHeader, 0, cmdHeader.length);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();

 */
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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean createTransactionMacFileEv2(byte fileNumber, byte[] transactionMacAccessRights, byte[] key) {
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
        byte TMACKeyVersion = (byte) 0x00; // fixed

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
        // taken from method header and don't forget to pad with 0x80..00
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
        baosCmdHeader.write(transactionMacAccessRights, 0, transactionMacAccessRights.length);
        //baosCmdHeader.write(ACCESS_RIGHTS_RW_CAR_TMAC);
        //baosCmdHeader.write(ACCESS_RIGHTS_R_W_TMAC);
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        // verify the MAC
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }

        /*
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

         */
    }

    /**
     * section for file handling
     */


    /**
     * writes the NDEF container to a Standard file in the selected application. It uses the pre-defined
     * NDEF container that points to the NDEF Data file with fileNumber 02 and isoFileId 0x04E1
     * For writing it uses the 'writeToStandardFileRawPlain' method and as the data is less than
     * MAXIMUM_MESSAGE_LENGTH there is no need for chunking the data
     *
     * @param fileNumber
     * @return Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean writeToStandardFileNdefContainerPlain(byte fileNumber) {
        String logData = "";
        final String methodName = "writeToStandardFileNdefContainerPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);

        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        return writeToADataFileRawPlain(fileNumber, 0, NDEF_FILE_01_CONTENT_CONTAINER);
    }

    /**
     * writes an Url as NDEF Link record/message to a Standard File. If the complete NDEF message
     * exceeds the MAXIMUM_MESSAGE_LENGTH the data are written in chunks to avoid framing
     * The maximum NDEF message length is 256 bytes so the URL needs to be some characters smaller
     * as there is an overhead for NDEF handling.
     * THe URL should point to a webserver that can handle SUN/SDM messages
     *
     * @param fileNumber | in range 0..31
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
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
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "NDEF message exceeds MAXIMUM_FILE_SIZE";
            return false;
        }
        return writeToADataFileRawPlain(fileNumber, 0, data);
    }


    /**
     * writeToADataFile(byte fileNumber, byte[] data) - this is just a helper for
     * writeToADataFile(byte fileNumber, int offset, byte[] data)
     *
     * @param fileNumber
     * @param data
     * @return
     */

    public boolean writeToADataFile(byte fileNumber, byte[] data) {
        String logData = "";
        final String methodName = "writeToADataFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("data", data));
        return writeToADataFile(fileNumber, 0, data);
    }

    /**
     * The method writes a byte array to a Data file that can be a Standard or Backup file.
     * The communication mode is read out from 'getFileSettings command'.
     * If the comm mode is 'Plain' it runs the Plain path,
     * if the comm mode is 'MACed' it runs the Mac path,
     * if the comm mode is 'Full' it runs the Full.
     * The data is written to the  beginning of the file (offset = 0)
     * If the data length exceeds the MAXIMUM_WRITE_MESSAGE_LENGTH the data will be written in chunks.
     * If the data length exceeds MAXIMUM_FILE_LENGTH the methods returns a FAILURE
     *
     * @param fileNumber | in range 0..31 AND file is a Standard or Backup file
     * @param offset     | position to write the data, starting with 0
     * @param data
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean writeToADataFile(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToADataFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offset: " + offset);
        log(methodName, printData("data", data));
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkOffsetMinus(offset)) return false;
        if ((data == null) || (data.length < 1) || (data.length > MAXIMUM_FILE_SIZE)) {
            log(methodName, "data length not in range 1..MAXIMUM_FILE_SIZE, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data length not in range 1..MAXIMUM_FILE_SIZE";
            return false;
        }
        if (!checkIsoDep()) return false;
        if (!checkFileNumberExisting(fileNumber)) return false;
        if (!checkIsDataFileType(fileNumber)) return false;
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }

        boolean isPlainMode = false;
        boolean isMacedMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            log(methodName, "CommunicationMode is MACed");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        } else {
            if (!isMacedMode) log(methodName, "CommunicationMode is Full enciphered");
        }

        // handling the situation where offset + data length > fileSize
        // priority is the offset, so data that is larger than remaining fileSize is truncated
        int dataLength = data.length;
        int fileSizeInt = fileSettings.getFileSizeInt();
        if ((offset + dataLength) > fileSizeInt) {
            data = Arrays.copyOf(data, (fileSizeInt - offset));
            dataLength = data.length;
            Log.d(TAG, "data is truncated due to offset and fileSize");
            Log.d(TAG, printData("new data", data));
        }

        // The chunking is done to avoid framing as the maximum command APDU length is limited to 66
        // bytes including all overhead and attached MAC

        int numberOfWrites = dataLength / MAXIMUM_WRITE_MESSAGE_LENGTH;
        int numberOfWritesMod = Utils.mod(dataLength, MAXIMUM_WRITE_MESSAGE_LENGTH);
        if (numberOfWritesMod > 0) numberOfWrites++; // one extra write for the remainder
        Log.d(TAG, "data length: " + dataLength + " numberOfWrites: " + numberOfWrites);
        boolean completeSuccess = true;
        int numberOfDataToWrite = MAXIMUM_WRITE_MESSAGE_LENGTH; // we are starting with a maximum length
        int offsetChunk = 0;
        for (int i = 0; i < numberOfWrites; i++) {
            if (offsetChunk + numberOfDataToWrite > dataLength) {
                numberOfDataToWrite = dataLength - offsetChunk;
            }
            byte[] dataToWrite = Arrays.copyOfRange(data, offsetChunk, (offsetChunk + numberOfDataToWrite));
            boolean success;
            if (isPlainMode) {
                success = writeToADataFileRawPlain(fileNumber, offset, dataToWrite);
            } else {
                if (isMacedMode) {
                    success = writeToADataFileRawMac(fileNumber, offset, dataToWrite);
                } else {
                    success = writeToADataFileRawFull(fileNumber, offset, dataToWrite);
                }
            }
            offsetChunk = offsetChunk + numberOfDataToWrite;
            offset = offset + numberOfDataToWrite;
            if (!success) {
                completeSuccess = false;
                Log.e(TAG, methodName + " could not successfully write, aborted");
                log(methodName, "could not successfully write, aborted");
                //errorCode = RESPONSE_FAILURE.clone(); // errorCode was written by the write method
                errorCodeReason = "could not successfully write";
                return false;
            }
        }
        System.arraycopy(RESPONSE_OK, 0, errorCode, 0, 2);
        log(methodName, "SUCCESS");
        return true;
    }

    /**
     * writes a byte array to a Standard or Backup file, beginning at offset position
     * This works for a Data file with CommunicationMode.Plain only
     * Note: as the number of bytes is limited per transmission this method limits the amount
     * of data to a maximum of MAXIMUM_MESSAGE_LENGTH bytes
     * The method does not take care of the offset so 'offset + data.length <= file size' needs to obeyed
     * Do NOT CALL this method from outside this class but use one of the writeToStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31 AND file is a Standard or Backup file
     * @param data       | maximum of 40 bytes to avoid framing
     * @param offset     | offset in the file
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */
    private boolean writeToADataFileRawPlain(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToADataFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + Utils.printData(" data", data));

        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((data == null) || (data.length > 40)) {
            Log.e(TAG, methodName + " data is NULL or length is > 40, aborted");
            log(methodName, "data is NULL or length is > 40, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data is NULL or length is > 40";
            return false;
        }
        if (!checkOffsetMinus(offset)) return false;
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (data.length > fileSize) {
            Log.e(TAG, methodName + " data length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return false;
        }
        if (!checkIsDataFileType(fileNumber)) return false;
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
            apdu = wrapMessage(WRITE_DATA_FILE_COMMAND, commandParameter);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1, even when working in CommMode Plain
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

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
     * writes a byte array to a Standard or Backup file, beginning at offset position
     * This works for a Data file with CommunicationMode.MACed only
     * Note: as the number of bytes is limited per transmission this method limits the amount
     * of data to a maximum of MAXIMUM_MESSAGE_LENGTH bytes
     * The method does not take care of the offset so 'offset + data.length <= file size' needs to obeyed
     * Do NOT CALL this method from outside this class but use one of the writeToStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31 AND file is a Standard or Backup file
     * @param data       | maximum of 40 bytes to avoid framing
     * @param offset     | offset in the file
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean writeToADataFileRawMac(byte fileNumber, int offset, byte[] data) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 53 - 54

        String logData = "";
        final String methodName = "writeToADataFileRawMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + Utils.printData(" data", data));

        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((data == null) || (data.length > MAXIMUM_WRITE_MESSAGE_LENGTH)) {
            Log.e(TAG, methodName + " data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH + ", aborted");
            log(methodName, "data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH;
            return false;
        }
        if (!checkOffsetMinus(offset)) return false;
        // getFileSettings for file type and size information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (data.length > fileSize) {
            Log.e(TAG, methodName + " data length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return false;
        }
        if (!checkIsDataFileType(fileNumber)) return false;
        if (!checkAuthentication()) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength) Note: DataLength and NOT Data, e.g. 190000 for length = 25
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(data.length); // LSB order
        log(methodName, printData("offsetBytes", offsetBytes));
        log(methodName, printData("lengthBytes", lengthBytes));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input
        //(Ins || CmdCounter || TI || CmdHeader || CmdData )
        byte[] macInput = getMacInput(WRITE_DATA_FILE_SECURE_COMMAND, cmdHeader, data);
        log(methodName, printData("macInput", macInput));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full WriteData Command APDU
        // Data (FileNo || Offset || DataLenght || Data)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(data, 0, data.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response;
        byte[] apdu;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_DATA_FILE_SECURE_COMMAND, writeDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        //byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * writes a byte array to a Standard or Backup file, beginning at offset position
     * This works for a Data file with CommunicationMode.Full only
     * Note: as the number of bytes is limited per transmission this method limits the amount
     * of data to a maximum of MAXIMUM_MESSAGE_LENGTH bytes
     * The method does not take care of the offset so 'offset + data.length <= file size' needs to obeyed
     * Do NOT CALL this method from outside this class but use one of the writeToStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31 AND file is a Standard or Backup file
     * @param data       | maximum of 40 bytes to avoid framing
     * @param offset     | offset in the file
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    private boolean writeToADataFileRawFull(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToADataFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + Utils.printData(" data", data));
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((data == null) || (data.length > MAXIMUM_WRITE_MESSAGE_LENGTH)) {
            Log.e(TAG, methodName + " data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH + ", aborted");
            log(methodName, "data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH;
            return false;
        }
        if (!checkOffsetMinus(offset)) return false;
        // getFileSettings for file type and size information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (data.length > fileSize) {
            Log.e(TAG, methodName + " data length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return false;
        }
        if (!checkIsDataFileType(fileNumber)) return false;
        if (!checkAuthentication()) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // next step is to pad the data according to padding rules in DESFire EV2/3 for AES Secure Messaging full mode
        byte[] dataPadded = paddingWriteData(data);
        log(methodName, printData("data unpad", data));
        log(methodName, printData("data pad  ", dataPadded));

        int numberOfDataBlocks = dataPadded.length / 16;
        log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
        List<byte[]> dataBlockList = Utils.divideArrayToList(dataPadded, 16);

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
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
        //        log(methodName, printData("startingIv", startingIv));
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
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "IOException: transceive failed: " + e.getMessage();
                return false;
            }
        }
        byte[] encryptedData = baosDataEncrypted.toByteArray();
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(data.length); // LSB order
        log(methodName, printData("offset", offsetBytes));
        log(methodName, printData("length", lengthBytes));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        byte[] macInput = getMacInput(WRITE_DATA_FILE_SECURE_COMMAND, cmdHeader, encryptedData);

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
            apdu = wrapMessage(WRITE_DATA_FILE_SECURE_COMMAND, writeDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the MAC");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        //byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    // use this if a Transaction MAC file is present in the application
    private boolean writeToADataFileRawFullTmac(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToADataFileRawFullTmac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + Utils.printData(" data", data));
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((data == null) || (data.length > MAXIMUM_WRITE_MESSAGE_LENGTH)) {
            Log.e(TAG, methodName + " data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH + ", aborted");
            log(methodName, "data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data is NULL or length is > " + MAXIMUM_WRITE_MESSAGE_LENGTH;
            return false;
        }
        if (!checkOffsetMinus(offset)) return false;
        // getFileSettings for file type and size information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (data.length > fileSize) {
            Log.e(TAG, methodName + " data length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return false;
        }
        if (!checkIsDataFileType(fileNumber)) return false;
        if (!checkAuthentication()) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated

        // next step is to pad the data according to padding rules in DESFire EV2/3 for AES Secure Messaging full mode
        byte[] dataPadded = paddingWriteData(data);
        log(methodName, printData("data unpad", data));
        log(methodName, printData("data pad  ", dataPadded));

        int numberOfDataBlocks = dataPadded.length / 16;
        log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
        List<byte[]> dataBlockList = Utils.divideArrayToList(dataPadded, 16);

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
        /*
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
         */
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
        //        log(methodName, printData("startingIv", startingIv));
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
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "IOException: transceive failed: " + e.getMessage();
                return false;
            }
        }
        byte[] encryptedData = baosDataEncrypted.toByteArray();
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(data.length); // LSB order
        log(methodName, printData("offset", offsetBytes));
        log(methodName, printData("length", lengthBytes));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        byte[] macInput = getMacInput(WRITE_DATA_FILE_SECURE_COMMAND, cmdHeader, encryptedData);
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
            apdu = wrapMessage(WRITE_DATA_FILE_SECURE_COMMAND, writeDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        //byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * The method reads a byte array from a Data file. A Data file can be a Standard or a Backup file.
     * The selection is done by reading the file settings for this file.
     * The communication mode is read out from 'getFileSettings command'.
     * If the comm mode is 'Plain' it runs the Plain path
     * If the comm mode is 'MACed' it runs the Mac path
     * If the comm mode is 'Full' it runs the Full path
     * If the data length exceeds the MAXIMUM_READ_MESSAGE_LENGTH the data will be read in chunks.
     * If the data length exceeds MAXIMUM_FILE_LENGTH the methods returns a FAILURE
     *
     * @param fileNumber | in range 0..31 AND file is a Standard file
     * @param offset     | the position in file where the read is starting
     * @param length     | the length of data to get read
     * @return the data read
     * Note: check errorCode and errorCodeReason in case of failure
     */
    public byte[] readFromADataFile(byte fileNumber, int offset, int length) {
        String logData = "";
        final String methodName = "readFromADataFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);

        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkFileNumberExisting(fileNumber)) return null;
        if (!checkOffsetMinus(offset)) return null;
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        if (!checkIsDataFileType(fileNumber)) return null;
        // the check on authentication depends on the communication mode in file settings:
        byte commMode = fileSettings.getCommunicationSettings();
        /*
        if (commMode == (byte) 0x00) {
            // Plain
            if (!authenticateAesLegacySuccess) {
                log(methodName, "missing legacy authentication, aborted");
                errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
                errorCodeReason = "missing legacy authentication";
                return null;
            }
        } else {
            if (!checkAuthentication()) return null;
        }

         */
        if (!checkIsoDep()) return null; // logFile and errorCode are updated
        boolean isPlainMode = false;
        boolean isMacedMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            log(methodName, "CommunicationMode is MACed");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        } else {
            if (!isMacedMode) log(methodName, "CommunicationMode is Full enciphered");
        }

        // The chunking is done to avoid framing as the maximum command APDU length is limited
        // bytes including all overhead and attached MAC

        int dataLength = length;
        int numberOfRounds = dataLength / MAXIMUM_READ_MESSAGE_LENGTH;
        int numberOfRoundsMod = Utils.mod(dataLength, MAXIMUM_READ_MESSAGE_LENGTH);
        if (numberOfRoundsMod > 0) numberOfRounds++; // one extra round for the remainder
        Log.d(TAG, "data length: " + dataLength + " numberOfRounds: " + numberOfRounds);
        boolean completeSuccess = true;
        int offsetChunk = offset;
        int numberOfDataToRead = MAXIMUM_READ_MESSAGE_LENGTH; // we are starting with a maximum length
        byte[] dataToRead = new byte[length]; // complete data
        for (int i = 0; i < numberOfRounds; i++) {
            if (offsetChunk + numberOfDataToRead > dataLength) {
                numberOfDataToRead = dataLength - offsetChunk;
            }
            byte[] dataToReadChunk = null;
            if (isPlainMode) {
                //dataToReadChunk = readFromStandardFileRawPlain(fileNumber, offsetChunk, numberOfDataToRead);
                dataToReadChunk = readFromADataFileRawPlain(fileNumber, offsetChunk, numberOfDataToRead);
            } else {
                if (isMacedMode) {
                    dataToReadChunk = readFromADataFileRawMac(fileNumber, offsetChunk, numberOfDataToRead);
                } else {
                    dataToReadChunk = readFromADataFileRawFull(fileNumber, offsetChunk, numberOfDataToRead);
                }
            }
            offsetChunk = offsetChunk + numberOfDataToRead;
            if ((dataToReadChunk == null) || (dataToReadChunk.length < 1)) {
                completeSuccess = false;
                Log.e(TAG, methodName + " could not successfully read, aborted");
                log(methodName, "could not successfully red, aborted");
                //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2); / errorCode is given byte the read method before
                return null;
            }
            {
                // copy the dataToReadChunk in the complete data array
                // in some circumstances some additional data like a CRC or MAC is appended - this needs to get stripped off
                int realLength = (i * MAXIMUM_READ_MESSAGE_LENGTH) + dataToReadChunk.length;
                if (realLength > dataToRead.length) {
                    dataToReadChunk = Arrays.copyOfRange(dataToReadChunk, 0, dataToRead.length - (i * MAXIMUM_READ_MESSAGE_LENGTH));

                }
                System.arraycopy(dataToReadChunk, 0, dataToRead, (i * MAXIMUM_READ_MESSAGE_LENGTH), dataToReadChunk.length);
            }
            log(methodName, Utils.printData("dataToRead", dataToRead));
        }
        errorCode = RESPONSE_OK.clone();
        log(methodName, "SUCCESS");
        return dataToRead;
    }

    public byte[] readFromATransactionMacFile(byte fileNumber) {
        byte[] receivedData = readFromADataFileRawPlain(fileNumber, 0, 12);
        if (receivedData.length == 12) {
            byte[] tmc = Arrays.copyOfRange(receivedData, 0, 4);
            byte[] tmacEnc = Arrays.copyOfRange(receivedData, 4, 12);
            int tmacInt = Utils.intFrom4ByteArrayInversed(tmc);
            Log.d(TAG, "TMAC counter: " + tmacInt + printData(" tmacEnc", tmacEnc));
            // example after a writeRecord operation
            // responseTmcv length: 12 data: 04000000c2e11a34e0513de7
            // readTMACFile length: 12 data: 04000000c2e11a34e0513de7
            // TMAC counter: 4 tmacEnc length: 8 data: c2e11a34e0513de7
            // todo last step is to calculate the TMV

            // example: write To Record file
            // data: length: 256 data: 323032332e30382e32342032333a33333a3032000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebec
            // 2023.08.24 23:33:02?? !"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrstuvwxyz{|}~�������������������������������������������������������������������������������������������������������������
            // TMAC counter: 3 tmacEnc length: 8 data: be8f8ae89f4dc8d4
            // length: 12 data: 03000000 be8f8ae89f4dc8d4
            // The 8-byte Transaction MAC Value (TMV) is computed over the Transaction MAC Input (TMI). This input depends on the commands
            // executed during the transaction, see Section 10.3.4. The applied key is SesTMMACKey, defined in Section 10.3.2.3.
            // The TMV is calculated as follows:
            //         TMV = MACtTM(SesTMMACKey, TMI)
            // using the MAC algorithm of the Secure Messaging with zero byte IV, see Section 9.1.3.
            // Initiating a Transaction MAC calculation consists of the following steps:
            // • Set TMI to the empty byte string.
            // • Set TMRICur to the empty byte string.
            // Once a Transaction MAC calculation is ongoing, the Transaction MAC Input TMI gets updated on each following data manipulation
            // command targeting a file of any file type within the application, except TransactionMAC file itself.




            /*
MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 46
WriteRecord command TMI update
TMI = TMI || Cmd || FileNo || Offset || Length || ZeroPadding || Data
Note that ZeroPadding for the WriteRecord command is actually adding 8 zero bytes after the command parameter fields so that those and the
padding add up to 16 bytes. As the data is always a multiple of 16 bytes, no padding is needed at the end of the TMI.
             */


        }

        return receivedData;
    }

    private byte[] getSesTMMACKey(byte[] tmc, byte[] uid) {

        // status: INCOMPLETE

        // see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 42

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        // the text is: a 1-byte label, distinguishing the purpose of the key: 31h for MACing and 32h for encryption
        // the vector is described as: SV1 = 5Ah||00h||01h||00h||80h||(TMC+1)||UID
        // so is 5A or 31 correct ?
        byte macLabel = (byte) 0x5A;
        //a 2-byte counter, fixed to 0001h as only 128-bit keys are generated.
        byte[] counterLabel = new byte[]{(byte) 0x00, (byte) 0x01};
        // a 2-byte length, fixed to 0080h as only 128-bit keys are generated.
        byte[] lengthLabel = new byte[]{(byte) 0x00, (byte) 0x80};
        byte[] c;
        baos.write(macLabel);
        baos.write(counterLabel, 0, counterLabel.length);
        baos.write(lengthLabel, 0, lengthLabel.length);
        int tmcOld = intFrom4ByteArrayInversed(tmc);
        byte[] tmcNew = intTo2ByteArrayInversed(tmcOld + 1);
        baos.write(tmcNew, 0, tmcNew.length);
        baos.write(uid, 0, uid.length);
        byte[] sv1 = baos.toByteArray();
        Log.d(TAG, "getSesTMMACKey " + printData("sv1", sv1));
        return sv1;
    }


    /**
     * Read data from a Data file in Communication mode Plain, beginning at offset position and length of data.
     * As the amount of data that can be send from PICC to reader is limited and the PICC will chunk the
     * data if exceeding this limit. The method automatically detects this behaviour and send the
     * necessary commands to get all data.
     * DO NOT CALL this method from outside this class but use one of the ReadFromStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31
     * @param offset     | offset in the file
     * @param length     | length of data > 1
     * @return the read data or NULL
     * Note: check errorCode and errorCodeReason in case of failure
     */

    private byte[] readFromADataFileRawPlain(byte fileNumber, int offset, int length) {
        String logData = "";
        final String methodName = "readFromADataFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkOffsetMinus(offset)) return null;
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        //if (!checkIsDataFileType(fileNumber)) return null;
        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        // generate the parameter
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offsetBytes, 0, offsetBytes.length);
        baos.write(lengthBytes, 0, lengthBytes.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] response = sendRequest(READ_DATA_FILE_COMMAND, commandParameter);

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (!checkResponse(response)) {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        errorCode = RESPONSE_OK.clone();
        errorCodeReason = "SUCCESS";
        byte[] readData = Arrays.copyOfRange(getData(response), 0, length);
        return readData;
    }

    /**
     * Read data from a Data file in Communication mode MACed, beginning at offset position and length of data.
     * As the amount of data that can be send from PICC to reader is limited and the PICC will chunk the
     * data if exceeding this limit. The method denies if this limit is reached.
     * DO NOT CALL this method from outside this class but use one of the ReadFromStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31
     * @param offset     | offset in the file
     * @param length     | length of data > 1
     * @return the read data or NULL
     * Note: check errorCode and errorCodeReason in case of failure
     */

    private byte[] readFromADataFileRawMac(byte fileNumber, int offset, int length) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 54 -55

        String logData = "";
        final String methodName = "readFromADataFileRawMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);

        // sanity checks
        if (!checkAuthentication()) return null; // logFile and errorCode are updated
        if (!checkOffsetMinus(offset)) return null;
        if (length > MAXIMUM_READ_MESSAGE_LENGTH) {
            Log.e(TAG, methodName + " length is > MAXIMUM_READ_MESSAGE_LENGTH, aborted");
            log(methodName, "length is > MAXIMUM_READ_MESSAGE_LENGTH, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > MAXIMUM_READ_MESSAGE_LENGTH";
            return null;
        }
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        if (!checkIsDataFileType(fileNumber)) return null;
        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || CmdData )
        byte[] macInput = getMacInput(READ_DATA_FILE_SECURE_COMMAND, cmdHeader);
        log(methodName, printData("macInput", macInput));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full ReadData Command APDU
        // Data (FileNo || Offset || DataLength)
        ByteArrayOutputStream baosReadDataCommand = new ByteArrayOutputStream();
        baosReadDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadDataCommand.toByteArray();
        log(methodName, printData("readDataCommand", readDataCommand));

        byte[] response;
        byte[] apdu;
        byte[] fullMacedData;
        byte[] macedData;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(READ_STANDARD_FILE_SECURE_COMMAND, readDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return null;
        }

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullMacedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        int macedDataLength = fullMacedData.length - 8;
        log(methodName, "The fullMacedData is of length " + fullMacedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The macedData length is " + macedDataLength);
        macedData = Arrays.copyOfRange(fullMacedData, 0, macedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullMacedData, macedDataLength, fullMacedData.length);
        log(methodName, printData("macedData", macedData));
        byte[] readData = Arrays.copyOfRange(macedData, 0, length);
        log(methodName, printData("readData", readData));
        if (verifyResponseMac(responseMACTruncatedReceived, macedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /**
     * Read data from a Data file in Communication mode Full, beginning at offset position and length of data.
     * As the amount of data that can be send from PICC to reader is limited and the PICC will chunk the
     * data if exceeding this limit. The method denies if this limit is reached.
     * DO NOT CALL this method from outside this class but use one of the ReadFromStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31
     * @param offset     | offset in the file
     * @param length     | length of data > 0
     * @return the read data or NULL
     * Note: check errorCode and errorCodeReason in case of failure
     */

    private byte[] readFromADataFileRawFull(byte fileNumber, int offset, int length) {

        // the absolute maximum of data that can be read on a DESFire EV3 in one run is 239 bytes but this is limited
        // here to 128 bytes. If you want to read more use the chunking method readFromStandardFile()

        String logData = "";
        final String methodName = "readFromADataFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);
        // sanity checks
        if (!checkAuthentication()) return null; // logFile and errorCode are updated
        if (!checkOffsetMinus(offset)) return null;
        if (length > MAXIMUM_READ_MESSAGE_LENGTH) {
            Log.e(TAG, methodName + " length is > MAXIMUM_READ_MESSAGE_LENGTH, aborted");
            log(methodName, "length is > MAXIMUM_READ_MESSAGE_LENGTH, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > MAXIMUM_READ_MESSAGE_LENGTH";
            return null;
        }
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        if (!checkIsDataFileType(fileNumber)) return null;
        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        // command header
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input
        byte[] macInput = getMacInput(READ_DATA_FILE_SECURE_COMMAND, cmdHeader);
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length); // fixed to 0x5AA5
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData));
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, length);
        log(methodName, printData("readData", readData));

        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /**
     * section for Value files
     */

    /**
     * read the value of a Value file in Communication modes Plain, MACed or Full enciphered
     *
     * @param fileNumber | in range 0..31
     * @return the integer value or -1 on failure
     */

    public int readFromAValueFile(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 67 - 70
        // Cmd.GetValue in AES Secure Messaging using CommMode.Full
        // this is based on the get value on a value file on a DESFire Light card
        String logData = "";
        final String methodName = "readFromAValueFile";
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "started", true);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return -1;

        // getFileSettings for file type communication mode and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return -1;
        }
        if (!checkIsValueFileType(fileNumber)) return -1;
        if (fileSettings.getFileType() != FileSettings.VALUE_FILE_TYPE) {
            log(methodName, "fileType to read is a " + fileSettings.getFileTypeName() + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not Value file";
            return -1;
        }
        // the check on authentication depends on the communication mode in file settings:
        byte commMode = fileSettings.getCommunicationSettings();
        boolean isPlainCommunicationMode = false;
        /*
        if (commMode == (byte) 0x00) {
            // Plain or MACed
            isPlainCommunicationMode = true;
            if (!authenticateAesLegacySuccess) {
                log(methodName, "missing legacy authentication, aborted");
                errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
                errorCodeReason = "missing legacy authentication";
                return -1;
            }
        } else {
            if (!checkAuthentication()) return -1;
        }
        */
        if (!checkIsoDep()) return -1;

        boolean isPlainMode = false;
        boolean isMacedMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            log(methodName, "CommunicationMode is MACed");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        } else {
            if (!isMacedMode) log(methodName, "CommunicationMode is Full enciphered");
        }

        if (isPlainMode) {
            return readFromAValueFileRawPlain(fileNumber);
        } else {
            if (isMacedMode) {
                return readFromAValueFileRawMac(fileNumber);
            } else {
                return readFromAValueFileRawFull(fileNumber);
            }
        }
    }

    /**
     * read the value of a Value file in Communication mode Plain
     * Note: There are no sanity checks on parameter, Communication mode or authentication status
     * so this method should be called by 'readFromAValueFile' only.
     *
     * @param fileNumber | in range 0..31
     * @return the integer value or -1 on failure
     */
    private int readFromAValueFileRawPlain(byte fileNumber) {
        String logData = "";
        final String methodName = "readFromAValueFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "started", true);
        if (!checkIsoDep()) return -1;

        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(GET_VALUE_COMMAND, new byte[]{fileNumber});
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return -1;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            errorCodeReason = "SUCCESS";
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "FAILURE";
            return -1;
        }
        byte[] valueBytes = getData(response);
        return Utils.byteArrayLength4InversedToInt(valueBytes);
    }

    /**
     * read the value of a Value file in Communication mode MACed
     * Note: There are no sanity checks on parameter, Communication mode or authentication status
     * so this method should be called by 'readFromAValueFile' only.
     *
     * @param fileNumber | in range 0..31
     * @return the integer value or -1 on failure
     */
    private int readFromAValueFileRawMac(byte fileNumber) {
        String logData = "";
        final String methodName = "readFromAValueFileRawMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        if (!checkIsoDep()) return -1;

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader ( = File number) )
        byte[] macInput = getMacInput(GET_VALUE_COMMAND, new byte[]{fileNumber});
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
        byte[] fullMacedData;
        byte[] macedData;
        try {
            apdu = wrapMessage(GET_VALUE_COMMAND, getValueCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return -1;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received MAC");
            macedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return -1;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        int dataLength = macedData.length - 8;
        log(methodName, "The macedData is of length " + macedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The data length is " + dataLength);
        byte[] data = Arrays.copyOfRange(macedData, 0, dataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(macedData, dataLength, macedData.length);
        log(methodName, printData("data", data));

        // verifying the received Response MAC
        if (verifyResponseMac(responseMACTruncatedReceived, data)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return byteArrayLength4InversedToInt(data);
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return -1;
        }
    }

    /**
     * read the value of a Value file in Communication mode Full
     * Note: There are no sanity checks on parameter, Communication mode or authentication status
     * so this method should be called by 'readFromAValueFile' only.
     *
     * @param fileNumber | in range 0..31
     * @return the integer value or -1 on failure
     */
    private int readFromAValueFileRawFull(byte fileNumber) {
        String logData = "";
        final String methodName = "readFromAValueFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        if (!checkIsoDep()) return -1;

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader ( = File number) )
        byte[] macInput = getMacInput(GET_VALUE_COMMAND, new byte[]{fileNumber});
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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
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
        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return byteArrayLength4InversedToInt(decryptedData);
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return -1;
        }
    }

    /**
     * credits or debits the value of a Value file in Communication modes Plain, MACed or Full enciphered
     *
     * @param fileNumber  | in range 0..31
     * @param changeValue | minimum 1, maximum depending on fileSettings
     * @param isCredit    | true for crediting, false for debiting
     * @return | true on success
     */

    public boolean changeAValueFile(byte fileNumber, int changeValue, boolean isCredit) {
        String logData = "";
        final String methodName = "changeAValueFile";
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "started", true);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkValueMinus(changeValue)) return false;
        // getFileSettings for file type communication mode and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        if (!checkIsValueFileType(fileNumber)) return false;
        // the check on authentication depends on the communication mode in file settings:
        byte commMode = fileSettings.getCommunicationSettings();
        boolean isPlainCommunicationMode = false;
        /*
        if ((commMode == (byte) 0x00)) {
            // Plain
            isPlainCommunicationMode = true;
            if (!authenticateAesLegacySuccess) {
                log(methodName, "missing legacy authentication, aborted");
                errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
                errorCodeReason = "missing legacy authentication";
                return false;
            }
        } else {
            if (!checkAuthentication()) return false;
        }

         */
        if (!checkIsoDep()) return false;

        boolean isPlainMode = false;
        boolean isMacedMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            log(methodName, "CommunicationMode is MACed");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        } else {
            if (!isMacedMode) log(methodName, "CommunicationMode is Full enciphered");
        }

        if (isPlainMode) {
            return changeAValueFileRawPlain(fileNumber, changeValue, isCredit);
        } else {
            if (isMacedMode) {
                return changeAValueFileRawMac(fileNumber, changeValue, isCredit);
            } else {
                return changeAValueFileRawFull(fileNumber, changeValue, isCredit);
            }
        }
    }

    /**
     * credits or debits the value of a Value file in Communication mode Plain.
     * Note: There are no sanity checks on parameter, Communication mode or authentication status
     * so this method should be called by 'changeAValueFile' only.
     *
     * @param fileNumber  | in range 0..31
     * @param changeValue | minimum 1, maximum depending on fileSettings
     * @param isCredit    | true for crediting, false for debiting
     * @return | true on success
     */
    private boolean changeAValueFileRawPlain(byte fileNumber, int changeValue, boolean isCredit) {
        String logData = "";
        final String methodName = "changeAValueFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "changeValue: " + changeValue);
        log(methodName, "isCredit: " + isCredit);

        if (!checkValueMinus(changeValue)) return false;
        if (!checkIsoDep()) return false;

        byte[] changeValueBytes = Utils.intTo4ByteArrayInversed(changeValue);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(changeValueBytes, 0, changeValueBytes.length);
        byte[] commandParameter = baos.toByteArray();
        byte[] apdu;
        byte[] response;
        try {
            if (isCredit) {
                apdu = wrapMessage(CREDIT_VALUE_FILE_COMMAND, commandParameter);
            } else {
                apdu = wrapMessage(DEBIT_VALUE_FILE_COMMAND, commandParameter);
            }
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1, even when working in CommMode Plain
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "FAILURE";
            return false;
        }
    }

    /**
     * credits or debits the value of a Value file in Communication mode MACed.
     * Note: There are no sanity checks on parameter, Communication mode or authentication status
     * so this method should be called by 'changeAValueFile' only.
     *
     * @param fileNumber  | in range 0..31
     * @param changeValue | minimum 1, maximum depending on fileSettings
     * @param isCredit    | true for crediting, false for debiting
     * @return | true on success
     */

    private boolean changeAValueFileRawMac(byte fileNumber, int changeValue, boolean isCredit) {
        String logData = "";
        final String methodName = "changeAValueFileRawMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "changeValue: " + changeValue);
        log(methodName, "isCredit: " + isCredit);

        if (!checkValueMinus(changeValue)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 70 - 71
        // Cmd.CreditValue in AES Secure Messaging using CommMode.Full
        // this is based on the credit a value on a value file on a DESFire Light card
        // Note: this document does not mention to submit a COMMIT command !

        if (changeValue < 1) {
            Log.e(TAG, methodName + " minimum changeValue is 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader ( = File number || changeValueLength) )
        byte[] changeValueBytes = intTo4ByteArrayInversed(changeValue);
        byte[] macInput;
        if (isCredit) {
            macInput = getMacInput(CREDIT_VALUE_FILE_COMMAND, new byte[]{fileNumber}, changeValueBytes);
        } else {
            macInput = getMacInput(DEBIT_VALUE_FILE_COMMAND, new byte[]{fileNumber}, changeValueBytes);
        }
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Data (CmdHeader = File number || changeValue || MAC)
        ByteArrayOutputStream baosChangeValueCommand = new ByteArrayOutputStream();
        baosChangeValueCommand.write(fileNumber);
        baosChangeValueCommand.write(changeValueBytes, 0, changeValueBytes.length);
        baosChangeValueCommand.write(macTruncated, 0, macTruncated.length);
        byte[] changeValueCommand = baosChangeValueCommand.toByteArray();
        log(methodName, printData("changeValueCommand", changeValueCommand));

        byte[] response;
        byte[] apdu;
        byte[] responseMACTruncatedReceived;
        try {
            if (isCredit) {
                apdu = wrapMessage(CREDIT_VALUE_FILE_COMMAND, changeValueCommand);
            } else {
                apdu = wrapMessage(DEBIT_VALUE_FILE_COMMAND, changeValueCommand);
            }
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * credits or debits the value of a Value file in Communication mode Full enciphered.
     * Note: There are no sanity checks on parameter, Communication mode or authentication status
     * so this method should be called by 'changeAValueFile' only.
     *
     * @param fileNumber  | in range 0..31
     * @param changeValue | minimum 1, maximum depending on fileSettings
     * @param isCredit    | true for crediting, false for debiting
     * @return | true on success
     */

    private boolean changeAValueFileRawFull(byte fileNumber, int changeValue, boolean isCredit) {
        String logData = "";
        final String methodName = "changeAValueFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "changeValue: " + changeValue);
        log(methodName, "isCredit: " + isCredit);

        if (!checkValueMinus(changeValue)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 70 - 71
        // Cmd.CreditValue in AES Secure Messaging using CommMode.Full
        // this is based on the credit a value on a value file on a DESFire Light card
        // Note: this document does not mention to submit a COMMIT command !

        if (changeValue < 1) {
            Log.e(TAG, methodName + " minimum changeValue is 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // encrypting the command data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
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
        byte[] macInput;
        if (isCredit) {
            macInput = getMacInput(CREDIT_VALUE_FILE_COMMAND, new byte[]{fileNumber}, encryptedData);
        } else {
            macInput = getMacInput(DEBIT_VALUE_FILE_COMMAND, new byte[]{fileNumber}, encryptedData);
        }
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
        ByteArrayOutputStream baosChangeValueCommand = new ByteArrayOutputStream();
        baosChangeValueCommand.write(fileNumber);
        baosChangeValueCommand.write(encryptedData, 0, encryptedData.length);
        baosChangeValueCommand.write(macTruncated, 0, macTruncated.length);
        byte[] changeValueCommand = baosChangeValueCommand.toByteArray();
        log(methodName, printData("changeCommand", changeValueCommand));

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        byte[] responseMACTruncatedReceived;
        try {
            if (isCredit) {
                apdu = wrapMessage(CREDIT_VALUE_FILE_COMMAND, changeValueCommand);
            } else {
                apdu = wrapMessage(DEBIT_VALUE_FILE_COMMAND, changeValueCommand);
            }
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
            //Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * section for record files
     */

    /**
     * The method writes a byte array to a Linear or Cyclic Record file. The communication mode is read out from
     * 'getFileSettings command'. If the comm mode is 'Plain' it runs the Plain path, otherwise it
     * uses the 'Full' path. If the comm mode is 'MACed' the method ends a there is no method available
     * within this class to handle those files, sorry.
     * The data is written to the offset position of the file
     * If the data length exceeds the MAXIMUM_WRITE_MESSAGE_LENGTH the data will be written in chunks.
     * If the data length exceeds MAXIMUM_FILE_LENGTH the methods returns a FAILURE
     * If the data length exceeds record size the data is truncated
     *
     * @param fileNumber | in range 0..31 AND file is a Linear or Cyclic Record file
     * @param offset     | position to write the data, starting with 0
     * @param data
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */
    public boolean writeToARecordFile(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToARecordFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offset: " + offset);
        log(methodName, printData("data", data));
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkOffsetMinus(offset)) return false;
        if ((data == null) || (data.length < 1) || (data.length > MAXIMUM_FILE_SIZE)) {
            log(methodName, "data length not in range 1..MAXIMUM_FILE_SIZE, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data length not in range 1..MAXIMUM_FILE_SIZE";
            return false;
        }
        if (!checkIsoDep()) return false;
        if (!checkFileNumberExisting(fileNumber)) return false;
        // checking fileSettings for Communication.mode
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        if (!checkIsRecordFileType(fileNumber)) return false;

        boolean isPlainMode = false;
        boolean isMacedMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            log(methodName, "CommunicationMode is MACed");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        } else {
            if (!isMacedMode) log(methodName, "CommunicationMode is Full enciphered");
        }
        // handling the situation where offset + data length > fileSize
        // priority is the offset, so data that is larger than remaining fileSize is truncated
        int dataLength = data.length;
        int fileSizeInt = fileSettings.getRecordSizeInt();
        if ((offset + dataLength) > fileSizeInt) {
            data = Arrays.copyOf(data, (fileSizeInt - offset));
            dataLength = data.length;
            Log.d(TAG, "data is truncated due to offset and fileSize");
            Log.d(TAG, printData("new data", data));
        }

        // The chunking is done to avoid framing as the maximum command APDU length is limited to 66
        // bytes including all overhead and attached MAC

        int numberOfWrites = dataLength / MAXIMUM_WRITE_MESSAGE_LENGTH;
        int numberOfWritesMod = Utils.mod(dataLength, MAXIMUM_WRITE_MESSAGE_LENGTH);
        if (numberOfWritesMod > 0) numberOfWrites++; // one extra write for the remainder
        Log.d(TAG, "data length: " + dataLength + " numberOfWrites: " + numberOfWrites);
        boolean completeSuccess = true;
        int numberOfDataToWrite = MAXIMUM_WRITE_MESSAGE_LENGTH; // we are starting with a maximum length
        int offsetChunk = 0;
        for (int i = 0; i < numberOfWrites; i++) {
            if (offsetChunk + numberOfDataToWrite > dataLength) {
                numberOfDataToWrite = dataLength - offsetChunk;
            }
            byte[] dataToWrite = Arrays.copyOfRange(data, offsetChunk, (offsetChunk + numberOfDataToWrite));
            boolean success;
            if (isPlainMode) {
                success = writeToARecordFileRawPlain(fileNumber, offset, dataToWrite);
            } else {
                if (isMacedMode) {
                    success = writeToARecordFileRawMac(fileNumber, offset, dataToWrite);
                } else {
                    success = writeToARecordFileRawFull(fileNumber, offset, dataToWrite);
                }
            }
            offsetChunk = offsetChunk + numberOfDataToWrite;
            offset = offset + numberOfDataToWrite;
            if (!success) {
                completeSuccess = false;
                Log.e(TAG, methodName + " could not successfully write, aborted");
                log(methodName, "could not successfully write, aborted");
                //errorCode = RESPONSE_FAILURE.clone(); // errorCode was written by the write method
                errorCodeReason = "could not successfully write";
                return false;
            }
        }
        System.arraycopy(RESPONSE_OK, 0, errorCode, 0, 2);
        log(methodName, "SUCCESS");
        return true;
    }

    public boolean writeToARecordFileRawPlain(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToARecordFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offset: " + offset);
        log(methodName, printData("data", data));

        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkOffsetMinus(offset)) return false;
        if ((data == null) || (data.length < 1)) {
            log(methodName, "data is NULL or length is < 1, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data length not in range 1..MAXIMUM_FILE_SIZE";
            return false;
        }
        if (!checkIsoDep()) return false;

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
            apdu = wrapMessage(WRITE_RECORD_FILE_SECURE_COMMAND, commandParameter);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "FAILURE";
            return false;
        }
    }

    public boolean writeToARecordFileRawMac(byte fileNumber, int offset, byte[] data) {
        String logData = "";
        final String methodName = "writeToARecordFileRawMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offset: " + offset);
        log(methodName, printData("data", data));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength) Note: DataLength and NOT Data, e.g. 190000 for length = 25
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(data.length); // LSB order
        log(methodName, printData("offsetBytes", offsetBytes));
        log(methodName, printData("lengthBytes", lengthBytes));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input
        //(Ins || CmdCounter || TI || CmdHeader || CmdData )
        byte[] macInput = getMacInput(WRITE_RECORD_FILE_SECURE_COMMAND, cmdHeader, data);
        log(methodName, printData("macInput", macInput));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full WriteData Command APDU
        // Data (FileNo || Offset || DataLength || Data)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        baosWriteDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosWriteDataCommand.write(data, 0, data.length);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();
        log(methodName, printData("writeDataCommand", writeDataCommand));

        byte[] response;
        byte[] apdu;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_RECORD_FILE_SECURE_COMMAND, writeDataCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        //byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean writeToARecordFileRawFull(byte fileNumber, int offset, byte[] data) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65

        String logData = "";
        final String methodName = "writeToARecordFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, printData("dataToWrite", data));
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkOffsetMinus(offset)) return false;
        if ((data == null) || (data.length < 1)) {
            log(methodName, "data is NULL or length is < 1, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data length not in range 1..MAXIMUM_FILE_SIZE";
            return false;
        }
        if (!checkIsoDep()) return false;

        // next step is to pad the data according to padding rules in DESFire EV2/3 for AES Secure Messaging full mode
        byte[] dataPadded = paddingWriteData(data);
        log(methodName, printData("data unpad", data));
        log(methodName, printData("data pad  ", dataPadded));

        int numberOfDataBlocks = dataPadded.length / 16;
        log(methodName, "number of dataBlocks: " + numberOfDataBlocks);
        List<byte[]> dataBlockList = Utils.divideArrayToList(dataPadded, 16);

        // Encrypting the Command Data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
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
        // log(methodName, printData("startingIv", startingIv));
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
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "IOException: transceive failed: " + e.getMessage();
                return false;
            }
        }
        byte[] encryptedData = baosDataEncrypted.toByteArray();
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        int dataSizeInt = data.length;
        //int offsetBytes = 0; // read from the beginning
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] dataSizeBytes = Utils.intTo3ByteArrayInversed(dataSizeInt); // LSB order
        log(methodName, printData("dataSizeBytes", dataSizeBytes));
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(dataSizeBytes, 0, dataSizeBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || Encrypted CmdData )
        byte[] macInput = getMacInput(WRITE_RECORD_FILE_SECURE_COMMAND, cmdHeader, encryptedData);
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

        byte[] response;
        byte[] apdu;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(WRITE_RECORD_FILE_SECURE_COMMAND, writeRecordCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * section for record files
     */

    /**
     * section for record files
     *
     * @param fileNumber
     * @param offsetRecord
     * @param numberOfRecordsToRead
     * @return
     */

    public byte[] readFromARecordFile(byte fileNumber, int offsetRecord, int numberOfRecordsToRead) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 65 - 67
        /*
        The first parameter is of one byte length and codes the file number in the range from 0x00 to 0x07.
        The next parameter is three bytes long and codes the offset of the newest record which is read out.
        In case of 0x00 00 00 the latest record is read out. The offset value must be in the range from 0x00
        to number of existing records – 1.
        The third parameter is another three bytes which code the number of records to be read from the PICC.
        Records are always transmitted by the PICC in chronological order (= starting with the oldest, which
        is number of records – 1 before the one addressed by the given offset). If this parameter is set to
        0x00 00 00 then all records, from the oldest record up to and including the newest record (given by
        the offset parameter) are read.
        The allowed range for the number of records parameter is from 0x00 00 00 to number of existing
        records – offset.
        In short: if offsetRecord and numberOfRecordsToRead are '0' all records will be read
         */

        String logData = "";
        final String methodName = "readFromARecordFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offsetRecord: " + offsetRecord);
        log(methodName, "numberOfRecordsToRead: " + numberOfRecordsToRead);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkOffsetMinus(offsetRecord)) return null;
        if (!checkOffsetMinus(numberOfRecordsToRead)) return null;
        if (!checkIsoDep()) return null;

        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getRecordSizeInt(); // size of a single record
        if (!checkIsRecordFileType(fileNumber)) return null;
        // the check on authentication depends on the communication mode in file settings:
        byte commMode = fileSettings.getCommunicationSettings();
/*
        if (commMode == (byte) 0x00) {
            // Plain
            if (!authenticateAesLegacySuccess) {
                log(methodName, "missing legacy authentication, aborted");
                errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
                errorCodeReason = "missing legacy authentication";
                return null;
            }
        } else {
            if (!checkAuthentication()) return null;
        }

 */
        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        boolean isPlainMode = false;
        boolean isMacedMode = false;
        boolean isFullMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            log(methodName, "CommunicationMode is MACed");
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_FULL) {
            isFullMode = true;
            log(methodName, "CommunicationMode is Full");
        }

        // The chunking is done to avoid framing as the maximum command APDU length is limited
        // bytes including all overhead and attached MAC
        // As the PICC is chunking already we do no have to worry about this and as long we read
        // the data with 'sendRequest' everything is OK

        byte[] dataToRead = null;
        if (isPlainMode) {
            dataToRead = readFromARecordFileRawPlain(fileNumber, offsetRecord, numberOfRecordsToRead);
        }
        if (isMacedMode) {
            dataToRead = readFromARecordFileRawMac(fileNumber, offsetRecord, numberOfRecordsToRead);
        }
        if (isFullMode) {
            dataToRead = readFromARecordFileRawFull(fileNumber, offsetRecord, numberOfRecordsToRead);
        }
        return dataToRead;
    }

    private byte[] readFromARecordFileRawPlain(byte fileNumber, int offsetRecord, int numberOfRecordsToRead) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 65 - 67
        /*
        The first parameter is of one byte length and codes the file number in the range from 0x00 to 0x07.
        The next parameter is three bytes long and codes the offset of the newest record which is read out.
        In case of 0x00 00 00 the latest record is read out. The offset value must be in the range from 0x00
        to number of existing records – 1.
        The third parameter is another three bytes which code the number of records to be read from the PICC.
        Records are always transmitted by the PICC in chronological order (= starting with the oldest, which
        is number of records – 1 before the one addressed by the given offset). If this parameter is set to
        0x00 00 00 then all records, from the oldest record up to and including the newest record (given by
        the offset parameter) are read.
        The allowed range for the number of records parameter is from 0x00 00 00 to number of existing
        records – offset.
        In short: if offsetRecord and numberOfRecordsToRead are '0' all records will be read
         */

        String logData = "";
        final String methodName = "readFromARecordFileRawPlain";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offsetRecord: " + offsetRecord);
        log(methodName, "numberOfRecordsToRead: " + numberOfRecordsToRead);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkOffsetMinus(offsetRecord)) return null;
        if (!checkOffsetMinus(numberOfRecordsToRead)) return null;
        if (!checkIsoDep()) return null;

        byte[] offsetRecordBytes = Utils.intTo3ByteArrayInversed(offsetRecord);
        byte[] numberOfRecordsToReadBytes = Utils.intTo3ByteArrayInversed(numberOfRecordsToRead);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offsetRecordBytes, 0, offsetRecordBytes.length);
        baos.write(numberOfRecordsToReadBytes, 0, numberOfRecordsToReadBytes.length);
        byte[] commandParameter = baos.toByteArray();

        byte[] response;
        byte[] fullData;
        response = sendRequest(READ_RECORD_FILE_COMMAND, commandParameter);

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
            fullData = getData(response);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        // as we authenticated before reading the PICC is adding 8 bytes long MAC that is stripped off
        return Arrays.copyOf(fullData, fullData.length - 8);
    }


    private byte[] readFromARecordFileRawMac(byte fileNumber, int offsetRecord, int numberOfRecordsToRead) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 65 - 67
        /*
        The first parameter is of one byte length and codes the file number in the range from 0x00 to 0x07.
        The next parameter is three bytes long and codes the offset of the newest record which is read out.
        In case of 0x00 00 00 the latest record is read out. The offset value must be in the range from 0x00
        to number of existing records – 1.
        The third parameter is another three bytes which code the number of records to be read from the PICC.
        Records are always transmitted by the PICC in chronological order (= starting with the oldest, which
        is number of records – 1 before the one addressed by the given offset). If this parameter is set to
        0x00 00 00 then all records, from the oldest record up to and including the newest record (given by
        the offset parameter) are read.
        The allowed range for the number of records parameter is from 0x00 00 00 to number of existing
        records – offset.
        In short: if offsetRecord and numberOfRecordsToRead are '0' all records will be read
         */

        String logData = "";
        final String methodName = "readFromARecordFileRawMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offsetRecord: " + offsetRecord);
        log(methodName, "numberOfRecordsToRead: " + numberOfRecordsToRead);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkOffsetMinus(offsetRecord)) return null;
        if (!checkOffsetMinus(numberOfRecordsToRead)) return null;
        if (!checkIsoDep()) return null;

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength) or (FileNo || OffsetRecord || NumberOfRecordsToReadLength)
        byte[] offsetRecordBytes = Utils.intTo3ByteArrayInversed(offsetRecord); // LSB order
        byte[] numberOfRecordsToReadBytes = Utils.intTo3ByteArrayInversed(numberOfRecordsToRead); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetRecordBytes, 0, offsetRecordBytes.length);
        baosCmdHeader.write(numberOfRecordsToReadBytes, 0, numberOfRecordsToReadBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || CmdData )
        byte[] macInput = getMacInput(READ_RECORD_FILE_COMMAND, cmdHeader);
        log(methodName, printData("macInput", macInput));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full ReadData Command APDU
        // Data (FileNo || Offset || DataLength)
        ByteArrayOutputStream baosReadDataCommand = new ByteArrayOutputStream();
        baosReadDataCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadDataCommand.toByteArray();
        log(methodName, printData("readDataCommand", readDataCommand));

        byte[] response;
        byte[] fullMacedData;
        byte[] macedData;
        byte[] responseMACTruncatedReceived;
        response = sendRequest(READ_RECORD_FILE_COMMAND, readDataCommand);
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now check the received MAC");
            fullMacedData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        int macedDataLength = fullMacedData.length - 8;
        log(methodName, "The fullMacedData is of length " + fullMacedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The macedData length is " + macedDataLength);
        macedData = Arrays.copyOfRange(fullMacedData, 0, macedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullMacedData, macedDataLength, fullMacedData.length);
        log(methodName, printData("macedData", macedData));

        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int recordSize = fileSettings.getRecordSizeInt();
        int fullLength = macedData.length;
        int fullRecords = fullLength / recordSize;
        Log.e(TAG, "fullRecords: " + fullRecords);
        byte[] readData = Arrays.copyOfRange(macedData, 0, (fullRecords * recordSize)); // just return the real data
        //byte[] readData = Arrays.copyOfRange(decryptedData, 0, ((fullRecords - 1) * recordSize)); // just return the real data, -1 is for adjusting the padding
        log(methodName, printData("readData", readData));

        if (verifyResponseMac(responseMACTruncatedReceived, macedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    private byte[] readFromARecordFileRawFull(byte fileNumber, int offsetRecord, int numberOfRecordsToRead) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 65 - 67
        /*
        The first parameter is of one byte length and codes the file number in the range from 0x00 to 0x07.
        The next parameter is three bytes long and codes the offset of the newest record which is read out.
        In case of 0x00 00 00 the latest record is read out. The offset value must be in the range from 0x00
        to number of existing records – 1.
        The third parameter is another three bytes which code the number of records to be read from the PICC.
        Records are always transmitted by the PICC in chronological order (= starting with the oldest, which
        is number of records – 1 before the one addressed by the given offset). If this parameter is set to
        0x00 00 00 then all records, from the oldest record up to and including the newest record (given by
        the offset parameter) are read.
        The allowed range for the number of records parameter is from 0x00 00 00 to number of existing
        records – offset.
        In short: if offsetRecord and numberOfRecordsToRead are '0' all records will be read
         */

        String logData = "";
        final String methodName = "readFromARecordFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        log(methodName, "offsetRecord: " + offsetRecord);
        log(methodName, "numberOfRecordsToRead: " + numberOfRecordsToRead);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkOffsetMinus(offsetRecord)) return null;
        if (!checkOffsetMinus(numberOfRecordsToRead)) return null;
        if (!checkIsoDep()) return null;

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || RecordNo || RecordCount)
        byte[] offsetRecordBytes = Utils.intTo3ByteArrayInversed(offsetRecord); // LSB order
        byte[] numberOfRecordsToReadBytes = Utils.intTo3ByteArrayInversed(numberOfRecordsToRead); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetRecordBytes, 0, offsetRecordBytes.length);
        baosCmdHeader.write(numberOfRecordsToReadBytes, 0, numberOfRecordsToReadBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader )
        byte[] macInput = getMacInput(READ_RECORD_FILE_COMMAND, cmdHeader);
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full ReadRecords Command APDU
        // Data (CmdHeader || MAC)
        // Constructing the full ReadData Command APDU
        ByteArrayOutputStream baosReadRecordCommand = new ByteArrayOutputStream();
        baosReadRecordCommand.write(cmdHeader, 0, cmdHeader.length);
        baosReadRecordCommand.write(macTruncated, 0, macTruncated.length);
        byte[] readDataCommand = baosReadRecordCommand.toByteArray();
        log(methodName, printData("readRecordCommand", readDataCommand));
        byte[] response;
        byte[] apdu;
        byte[] fullEncryptedData;
        byte[] encryptedData;
        byte[] responseMACTruncatedReceived;
        response = sendRequest(READ_RECORD_FILE_COMMAND, readDataCommand);
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

        // e.g. the fullEncryptedData is 56 bytes long, the first 48 bytes are encryptedData and the last 8 bytes are the responseMAC
        int encryptedDataLength = fullEncryptedData.length - 8;
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
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
        // the decrypted data contains the padding that needs to get removed
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int recordSize = fileSettings.getRecordSizeInt();
        int fullLength = decryptedData.length;
        int fullRecords = fullLength / recordSize;
        Log.e(TAG, "fullRecords: " + fullRecords);
        //byte[] readData = Arrays.copyOfRange(decryptedData, 0, (fullRecords * recordSize)); // just return the real data
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, ((fullRecords - 1) * recordSize)); // just return the real data, -1 is for adjusting the padding
        log(methodName, printData("readData", readData));

        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    public boolean clearARecordFile(byte fileNumber) {
        String logData = "";
        final String methodName = "clearARecordFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false;
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;
        if (!checkFileNumberExisting(fileNumber)) return false;
        // checking fileSettings for Communication.mode
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        if (!checkIsRecordFileType(fileNumber)) return false;

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo)
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader || CmdData )
        byte[] macInput = getMacInput(CLEAR_RECORD_FILE_COMMAND, cmdHeader);
        log(methodName, printData("macInput", macInput));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full ReadData Command APDU
        // Data (FileNo || Offset || DataLength)
        ByteArrayOutputStream baosCommand = new ByteArrayOutputStream();
        baosCommand.write(cmdHeader, 0, cmdHeader.length);
        baosCommand.write(macTruncated, 0, macTruncated.length);
        byte[] clearRecordFileCommand = baosCommand.toByteArray();
        log(methodName, printData("clearRecordFileCommand", clearRecordFileCommand));

        byte[] response;
        byte[] fullMacedData;
        byte[] macedData;
        byte[] responseMACTruncatedReceived;
        response = sendRequest(CLEAR_RECORD_FILE_COMMAND, clearRecordFileCommand);

        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the MAC");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        //byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * section for transaction MAC files
     */


    // todo clean code
    public boolean deleteTransactionMacFile(byte fileNumber) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 81 - 83
        // this is based on the creation of a TransactionMac file on a DESFire Light card
        // Cmd.DeleteTransactionMACFile
        String logData = "";
        final String methodName = "deleteTransactionMacFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks

        // as the TMAC file was created as Plain communication the authentication was done using
        // authenticateAesLegacy meaning n authenticateEv2FirstSuccess
        /*
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            Log.d(TAG, "missing successful authentication with EV2First or EV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            return false;
        }

         */
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        if ((isoDep == null) || (!isoDep.isConnected())) {
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // Generating the MAC for the Command APDU
        // missing in Features and Hints
        // CmdHeader, here just the fileNumber

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = fileNumber)
        byte[] macInput = getMacInput(DELETE_TRANSACTION_MAC_FILE_COMMAND, new byte[]{fileNumber});
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }


    /**
     * section for committing a transaction
     */

    public boolean commitReaderIdPlain(byte[] readerId) {
        String logData = "";
        final String methodName = "commitReaderIdPlain";
        log(methodName, "started", true);

        // status: NOT WORKING

        // todo sanity checks

        boolean isEnabledCommitReaderIdFeature = transactionMacFileSettings.isEnabledCommitReaderIdFeature();
        if (!isEnabledCommitReaderIdFeature) {
            Log.e(TAG, "Commit ReaderId feature is not enabled, aborted");
            errorCode = RESPONSE_FAILURE;
            errorCodeReason = "Commit ReaderId feature is not enabled";
            return false;
        }
        byte[] response;
        byte[] apdu;
        try {
            apdu = wrapMessage(COMMIT_READER_ID_SECURE_COMMAND, readerId);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

    }

    public boolean commitTransactionPlain() {
        // status: not working after authentication with authenticateEv2First/NonFirst
        String logData = "";
        final String methodName = "commitTransactionPlain";
        log(methodName, "started", true);
        // sanity checks
        if (!checkIsoDep()) return false;
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION});
            apdu = Utils.hexStringToByteArray("90c70000010000");
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        System.arraycopy(returnStatusBytes(response), 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            return true;
        } else {
            return false;
        }
    }

    public boolean commitTransactionPlainNew() {
        // status: not working after authentication with authenticateEv2First/NonFirst
        String logData = "";
        final String methodName = "commitTransactionPlain";
        log(methodName, "started", true);
        // sanity checks
        if (!checkIsoDep()) return false;
        //byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU

        //byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION});
        byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, null);
        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Constructing the full WriteData Command APDU
        // Data (FileNo || Offset || DataLenght || Data)
        ByteArrayOutputStream baosWriteDataCommand = new ByteArrayOutputStream();
        //baosWriteDataCommand.write(COMMIT_TRANSACTION_OPTION);
        baosWriteDataCommand.write(macTruncated, 0, macTruncated.length);
        byte[] writeDataCommand = baosWriteDataCommand.toByteArray();

        byte[] apdu;
        byte[] response;
        //response = sendData(writeDataCommand);

        try {
            //apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION});
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, null);
            response = sendData(apdu);
            //response = sendData(writeDataCommand);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        System.arraycopy(returnStatusBytes(response), 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            return true;
        } else {
            return false;
        }
    }

    /**
     * On file types Backup, Value, Linear Record and Cyclic Record all write or change values tasks
     * are not final until the transaction was finished by a Commit Transaction.
     * This method is working in CommunicationMode Full only.
     *
     * @param isEnabledReturnTmcv | if true the TransactionMAC counter and Value is returned after successful commit and written to internal variables
     *                            | This option is available when a TransactionMAC file is present in application
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */


    public boolean commitTransactionFull(boolean isEnabledReturnTmcv) {
        String logData = "";
        final String methodName = "commitTransactionFull";
        log(methodName, "started", true);
        log(methodName, "isEnabledReturnTmcv: " + isEnabledReturnTmcv);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;
        transactionMacFileReturnedTmcv = null;

        // check that a Transaction File is present in application
        if (!isTransactionMacFilePresent) {
            if (isEnabledReturnTmcv) {
                log(methodName, "As no TransactionMAC file is present in the application the enabled ReturnTmcv setting is discarded");
            }
            return commitTransactionWithoutTmacFull();
        } else {
            // tmac file is  present
            // check for commitReaderId option
            boolean isEnabledCommitReaderIdFeature = transactionMacFileSettings.isEnabledCommitReaderIdFeature();
            if (!isEnabledCommitReaderIdFeature) {
                log(methodName, "A TransactionMAC file is present in the application wit DISABLED Commit Reader Id Feature");
                return commitTransactionWithTmacFull(isEnabledReturnTmcv);
            } else {
                log(methodName, "A TransactionMAC file is present in the application with ENABLED Commit Reader Id Feature");
                // before sending the CommitTransaction command we need to send a CommitReaderId command
                boolean successCommitReaderId = commitReaderIdFull();
                if (!successCommitReaderId) {
                    log(methodName, "commitReaderId FAILURE"); // commitReaderId updated the errorCodes
                    return false;
                }
                return commitTransactionWithTmacFull(isEnabledReturnTmcv);
            }
        }
    }

    /**
     * On file types Backup, Value, Linear Record and Cyclic Record all write or change values tasks
     * are not final until the transaction was finished by a Commit Transaction.
     * This method is working in CommunicationMode Full only.
     * This method is called when NO Transaction MAC file is present in the selected application.
     * Please do no call this method from outside the library, use 'commitTransactionFull' instead
     *
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean commitTransactionWithoutTmacFull() {
        /**
         * see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
         * see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 106 - 107
         */
        String logData = "";
        final String methodName = "commitTransactionWithoutTmacFull";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;
        transactionMacFileReturnedTmcv = null;

        // here we are using just the commit command without preceding commitReaderId command
        // Constructing the full CommitTransaction Command APDU
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU, 00 = no TMC and TMV is returned in the R-APDU, fixed

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION});
        log(methodName, printData("macInput", macInput));
        // c707002c2b4e8e00

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
        byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, commitTransactionCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
            fullResponseData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "checkResponseData failed";
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

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * On file types Backup, Value, Linear Record and Cyclic Record all write or change values tasks
     * are not final until the transaction was finished by a Commit Transaction.
     * This method is working in CommunicationMode Full only.
     * This method is called when a Transaction MAC file is present in the selected application.
     * Please do no call this method from outside the library, use 'commitTransactionFull' instead
     *
     * @return true on success
     * Note: check errorCode and errorCodeReason in case of failure
     * @parameter isEnabledReturnTmcv | on success returns the TransactionMAC counter and Value to internal variables
     */

    public boolean commitTransactionWithTmacFull(boolean isEnabledReturnTmcv) {
        String logData = "";
        final String methodName = "commitTransactionWithTmacFull";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;
        transactionMacFileReturnedTmcv = null;

        // here we are using just the commit command without preceding commitReaderId command
        // Constructing the full CommitTransaction Command APDU
        final byte COMMIT_TRANSACTION_OPTION_DISABLED = (byte) 0x00; // 00 meaning TMC and TMV NOT to be returned in the R-APDU
        final byte COMMIT_TRANSACTION_OPTION_ENABLED = (byte) 0x01; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte commitTransactionOptionEnabledReturnTmcv;
        if (isEnabledReturnTmcv) {
            commitTransactionOptionEnabledReturnTmcv = COMMIT_TRANSACTION_OPTION_ENABLED;
        } else {
            commitTransactionOptionEnabledReturnTmcv = COMMIT_TRANSACTION_OPTION_DISABLED;
        }

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, new byte[]{commitTransactionOptionEnabledReturnTmcv});
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the commitTransactionData
        // this  is working ONLY when a TMAC file is present, otherwise the CommitTransaction command  is  rejected !
        //byte enableTmcTmvReturn = (byte) 0x01; // TMC and TMV returned
        //byte disableTmcTmvReturn = (byte) 0x00; // No TMC and TMV returned

        ByteArrayOutputStream baosCommitTransactionCommand = new ByteArrayOutputStream();
        //baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION);
        baosCommitTransactionCommand.write(commitTransactionOptionEnabledReturnTmcv);
        baosCommitTransactionCommand.write(macTruncated, 0, macTruncated.length);
        byte[] commitTransactionCommand = baosCommitTransactionCommand.toByteArray();
        log(methodName, printData("commitTransactionCommand", commitTransactionCommand));
        byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, commitTransactionCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
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
        int fullResponseDataLength = fullResponseData.length;
        if (fullResponseDataLength > 8) {
            log(methodName, "the fullResponseData has a length of " + fullResponseDataLength + " bytes, so the TMC and TMV are included");
            transactionMacFileReturnedTmcv = Arrays.copyOfRange(fullResponseData, 0, (fullResponseDataLength - 8));
            responseMACTruncatedReceived = Arrays.copyOfRange(fullResponseData, (fullResponseDataLength - 8), fullResponseDataLength);
            log(methodName, printData("responseTmcv", transactionMacFileReturnedTmcv));
        } else {
            responseMACTruncatedReceived = fullResponseData.clone();
        }

        if (verifyResponseMac(responseMACTruncatedReceived, transactionMacFileReturnedTmcv)) { // transactionMacFileReturnedTmcv is null in case NO TransactionMAC file is present or gets the TMC || TMV data
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    private boolean commitReaderIdFull() {
        final String methodName = "commitReaderIdFull";
        log(methodName, "started", true);

        // MIFARE DESFire Light contactless application IC MF2DLHX0.pdf page 109 ff
        // AUTHENTICATION_ERROR AEh : No active authentication with AppCommitReaderIDKey
        /*
        The AppCommitReaderIDKey refers to one of the AppKey and is used for the Transaction MAC feature is
        described in Section 10.3. Its key number is specified in Section 8.2.3.6 and is assigned at creation
        time of the TransactionMAC file.
         */

        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // Constructing the full CommitReaderID Command APDU
        log(methodName, printData("transactionMacReaderId", transactionMacReaderId));
        //byte[] READER_ID = hexStringToByteArray("28BF1982BE086FBC60A22DAEB66613EE"); // 16 bytes
        byte[] iv0Reader = new byte[16];
        //log(methodName, printData("READER_ID", READER_ID));
        log(methodName, printData("iv0Reader", iv0Reader));

        // MAC_Input (Ins || CmdCounter || TI || Data (= Reader ID) )
        byte[] macInput = getMacInput(COMMIT_READER_ID_SECURE_COMMAND, transactionMacReaderId);

        log(methodName, printData("macInput", macInput));

        // MAC = CMAC(KSesAuthMAC, MAC_ Input)
        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFullReader = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFullReader", macFullReader));
        // now truncate the MAC
        byte[] macTruncatedReader = truncateMAC(macFullReader);
        log(methodName, printData("macTruncatedReader", macTruncatedReader));

        // construction of the commitTransactionData Data (Encrypted Data || MAC)
        ByteArrayOutputStream baosCommitTransactionReaderCommand = new ByteArrayOutputStream();
        baosCommitTransactionReaderCommand.write(transactionMacReaderId, 0, transactionMacReaderId.length);
        baosCommitTransactionReaderCommand.write(macTruncatedReader, 0, macTruncatedReader.length);
        byte[] commitTransactionReaderCommand = baosCommitTransactionReaderCommand.toByteArray();
        log(methodName, printData("commitTransactionReaderCommand", commitTransactionReaderCommand));


        byte[] response;
        byte[] apdu;
        byte[] encryptedResponseData;
        try {
            apdu = wrapMessage(COMMIT_READER_ID_SECURE_COMMAND, commitTransactionReaderCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        int encryptedDataLength = encryptedResponseData.length - 8; // strip off the MAC
        log(methodName, "The encryptedResponseData is of length " + encryptedResponseData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        byte[] encryptedData = Arrays.copyOfRange(encryptedResponseData, 0, encryptedDataLength);
        byte[] responseMACTruncatedReceived = Arrays.copyOfRange(encryptedResponseData, encryptedDataLength, encryptedResponseData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        boolean isTestMode = false;
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
        log(methodName, "decryptedData is previous TMRI (latest TransactionMAC Reader ID");
        // Decrypted Response Data = (TMRI) : BDD40ED9F434F9DDCBF5821299CD2119 (16 bytes)

        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }

    }

    public boolean abortATransaction() {
        String logData = "";
        final String methodName = "abortATransaction";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are using just the abort command
        // Constructing the full AbortTransaction Command APDU

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(ABORT_TRANSACTION_COMMAND, null);
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the abort Transaction
        ByteArrayOutputStream baosAbortTransactionCommand = new ByteArrayOutputStream();
        baosAbortTransactionCommand.write(macTruncated, 0, macTruncated.length);
        byte[] abortTransactionCommand = baosAbortTransactionCommand.toByteArray();
        log(methodName, printData("abortTransactionCommand", abortTransactionCommand));
        byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(ABORT_TRANSACTION_COMMAND, abortTransactionCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received MAC");
            fullResponseData = Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        //byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        byte[] responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * For operations in Communication.Mode MACed or Full we need to get a MacInput method
     *
     * @param command
     * @param options
     * @return
     */
    private byte[] getMacInput(byte command, byte[] options) {
        String methodName = "getMacInput";
        log(methodName, "started", true);
        log(methodName, printData("options", options));
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(command);
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        if ((options != null) && (options.length > 0)) {
            baosMacInput.write(options, 0, options.length);
        }
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));
        return macInput;
    }

    /**
     * For operations in Communication.Mode MACed or Full we need to get a MacInput method
     *
     * @param command
     * @param options
     * @param data
     * @return
     */

    private byte[] getMacInput(byte command, byte[] options, byte[] data) {
        String methodName = "getMacInput";
        log(methodName, "started", true);
        log(methodName, printData("options", options));
        log(methodName, printData("data", data));
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(command);
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        if ((options != null) && (options.length > 0)) {
            baosMacInput.write(options, 0, options.length);
        }
        if ((data != null) && (data.length > 0)) {
            baosMacInput.write(data, 0, data.length);
        }
        byte[] macInput = baosMacInput.toByteArray();
        log(methodName, printData("macInput", macInput));
        return macInput;
    }

    /**
     * For operations in Communication.Mode Full we need to get an IvInput method
     *
     * @return
     */

    private byte[] getIvInput() {
        String methodName = "getIvInput";
        log(methodName, "started", true);
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
        return ivInput;
    }


    public boolean commitTransactionFull() {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
        // Cmd.Commit in AES Secure Messaging using CommMode.MAC
        // this is based on the write of a record file on a DESFire Light card
        // additionally see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 106 - 107
        // Note: this is working ONLY when a Transaction MAC file is NOT present in the application
        // If a TMAC file is present use the commitTMACTransactionEv2 method !

        String logData = "";
        final String methodName = "commitTransactionFull";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are using just the commit command without preceding commitReaderId command
        // Constructing the full CommitTransaction Command APDU
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte[] startingIv = new byte[16];

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION});
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
        byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, commitTransactionCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
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

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean commitTransactionFullReturnTmv() {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
        // Cmd.Commit in AES Secure Messaging using CommMode.MAC
        // this is based on the write of a record file on a DESFire Light card
        // additionally see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 106 - 107
        // Note: this is working ONLY when a Transaction MAC file is NOT present in the application
        // If a TMAC file is present use the commitTMACTransactionEv2 method !

        String logData = "";
        final String methodName = "commitTransactionFullReturnTmv";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are using just the commit command without preceding commitReaderId command
        // Constructing the full CommitTransaction Command APDU
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte COMMIT_TRANSACTION_OPTION_ENABLED = (byte) 0x01; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte[] startingIv = new byte[16];

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION_ENABLED});
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the commitTransactionData
        // this  is working ONLY when a TMAC file is present, otherwise the CommitTransaction command  is  rejected !
        //byte enableTmcTmvReturn = (byte) 0x01; // TMC and TMV returned
        //byte disableTmcTmvReturn = (byte) 0x00; // No TMC and TMV returned

        ByteArrayOutputStream baosCommitTransactionCommand = new ByteArrayOutputStream();
        //baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION);
        baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION_ENABLED);
        baosCommitTransactionCommand.write(macTruncated, 0, macTruncated.length);
        byte[] commitTransactionCommand = baosCommitTransactionCommand.toByteArray();
        log(methodName, printData("commitTransactionCommand", commitTransactionCommand));
        byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, commitTransactionCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
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
        int fullResponseDataLength = fullResponseData.length;
        if (fullResponseDataLength > 8) {
            log(methodName, "the fullResponseData has a length of " + fullResponseDataLength + " bytes, so the TMC and TMV are included");
            transactionMacFileReturnedTmcv = Arrays.copyOfRange(fullResponseData, 0, (fullResponseDataLength - 8));
            responseMACTruncatedReceived = Arrays.copyOfRange(fullResponseData, (fullResponseDataLength - 8), fullResponseDataLength);
            log(methodName, printData("transactionMacFileReturnedTmcv", transactionMacFileReturnedTmcv));
        } else {
            responseMACTruncatedReceived = fullResponseData.clone();
        }

        if (verifyResponseMac(responseMACTruncatedReceived, transactionMacFileReturnedTmcv)) { // transactionMacFileReturnedTmcv is null in case NO TransactionMAC file is present or gets the TMC || TMV data
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }

    }

    public boolean commitTransactionReaderIdFullReturnTmv() {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 61 - 65
        // Cmd.Commit in AES Secure Messaging using CommMode.MAC
        // this is based on the write of a record file on a DESFire Light card
        // additionally see MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 106 - 107
        // Note: this is working ONLY when a Transaction MAC file is NOT present in the application
        // If a TMAC file is present use the commitTMACTransactionEv2 method !

        // example with commitReaderId: Mifare DESFire Light Features and Hints AN12343.pdf pages

        String logData = "";
        final String methodName = "commitTransactionReaderIdFullReturnTmv";
        log(methodName, "started", true);
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;

        // here we are using just the commit command without preceding commitReaderId command
        // Constructing the full CommitTransaction Command APDU
        byte COMMIT_TRANSACTION_OPTION = (byte) 0x00; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte COMMIT_TRANSACTION_OPTION_ENABLED = (byte) 0x01; // 01 meaning TMC and TMV to be returned in the R-APDU
        byte[] startingIv = new byte[16];

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(COMMIT_TRANSACTION_COMMAND, new byte[]{COMMIT_TRANSACTION_OPTION_ENABLED});
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the commitTransactionData
        // this  is working ONLY when a TMAC file is present, otherwise the CommitTransaction command  is  rejected !
        //byte enableTmcTmvReturn = (byte) 0x01; // TMC and TMV returned
        //byte disableTmcTmvReturn = (byte) 0x00; // No TMC and TMV returned

        ByteArrayOutputStream baosCommitTransactionCommand = new ByteArrayOutputStream();
        //baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION);
        baosCommitTransactionCommand.write(COMMIT_TRANSACTION_OPTION_ENABLED);
        baosCommitTransactionCommand.write(macTruncated, 0, macTruncated.length);
        byte[] commitTransactionCommand = baosCommitTransactionCommand.toByteArray();
        log(methodName, printData("commitTransactionCommand", commitTransactionCommand));
        byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        try {
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, commitTransactionCommand);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
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
        int fullResponseDataLength = fullResponseData.length;
        if (fullResponseDataLength > 8) {
            log(methodName, "the fullResponseData has a length of " + fullResponseDataLength + " bytes, so the TMC and TMV are included");
            transactionMacFileReturnedTmcv = Arrays.copyOfRange(fullResponseData, 0, (fullResponseDataLength - 8));
            responseMACTruncatedReceived = Arrays.copyOfRange(fullResponseData, (fullResponseDataLength - 8), fullResponseDataLength);
            log(methodName, printData("transactionMacFileReturnedTmcv", transactionMacFileReturnedTmcv));
        } else {
            responseMACTruncatedReceived = fullResponseData.clone();
        }

        if (verifyResponseMac(responseMACTruncatedReceived, transactionMacFileReturnedTmcv)) { // transactionMacFileReturnedTmcv is null in case NO TransactionMAC file is present or gets the TMC || TMV data
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
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
        byte[] macInputReader = getMacInput(COMMIT_READER_ID_SECURE_COMMAND, READER_ID);
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        byte[] encryptedData = Arrays.copyOfRange(encryptedResponseData, 0, encryptedDataLength);
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
        baosMacInput.write(COMMIT_TRANSACTION_COMMAND); // 0xC7
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
            apdu = wrapMessage(COMMIT_TRANSACTION_COMMAND, commitTransactionCommand);
            log(methodName, printData("apdu", apdu));
            response = isoDep.transceive(apdu);
            log(methodName, printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            byte[] tmvByte = Arrays.copyOfRange(responseTmcv, 4, 12);
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
     * section for Transaction Timer feature
     */

    /*
     * WARNING: this is an experimental feature
     */
    public boolean enableTransactionTimerFull() {

        // see example in Mifare DESFire Light Features and Hints AN12343.pdf pages 12 ff
        // and MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 61 ff
        // for value file see page 64
        // error 7E = length error is thrown when length of command data != expected length
        // error 9D = PERMISSION_DENIED
        //            .. Option 09h: file configuration not allowed anymore as already done once or targeted file is not a Value file

        // status: NOT WORKING (throwing AE error ?)

        logData = "";
        final String methodName = "enableTransactionTimerFull";
        //log(methodName, "fileNumber: " + fileNumber, true);

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

        byte optionOfSetConfiguration = (byte) 0x55;
        byte transactionTimerEnable = (byte) 0x01;
        byte transactionTimerDisable = (byte) 0x00;
        int transactionTimerNumberOfSeconds = 1;
        byte[] transactionTimerNumberOfSecondsBytes = intTo4ByteArrayInversed(transactionTimerNumberOfSeconds);
        //byte[] transactionTimerNumberOfSecondsBytes = intTo3ByteArrayInversed(transactionTimerNumberOfSeconds);
        log(methodName, printData("transactionTimerNumberOfSecondsBytes", transactionTimerNumberOfSecondsBytes));

        // using a fixed fileNumber for Value file enciphered = 0x08
        // upper limit is 0xE8030000 = 1000
        // lower limit is (unchanged) 0
        // value is 0
        // last 01 means: Free GetValue not allowed, LimitedCredit enabled

        // Data (FileNo || Lower Limit || Upper Limit || Value || ValueOption)

        // Data is timer in seconds (4 bytes)
        //byte[] data = hexStringToByteArray("0800000000E80300000000000001"); // 12 bytes, first 08 is fileNumber

        ByteArrayOutputStream baosData = new ByteArrayOutputStream();
        baosData.write(transactionTimerEnable);
        baosData.write(transactionTimerNumberOfSecondsBytes, 0, transactionTimerNumberOfSecondsBytes.length);
        byte[] data = baosData.toByteArray();
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

        // next step is to pad the data according to padding rules in DESFire EV2/3 for AES Secure Messaging full mode
        byte[] dataPadded = paddingWriteData(data);
        log(methodName, printData("data unpad", data));
        log(methodName, printData("data pad  ", dataPadded));

        // padding is 12 bytes

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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
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
     * section for files in general
     */

    /**
     * Deletes (better deactivates) a file in the selected application permanently. The space for
     * the file is NOT released (only possible on formatting the PICC).
     * Note: Depending on the application master key settings, see chapter 4.3.2, a preceding
     * authentication with the application master key is required.
     *
     * @param fileNumber
     * @return true on success
     */

    public boolean deleteFile(byte fileNumber) {
        final String methodName = "deleteFile";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];
        // sanity checks
        if (!checkApplicationIdentifier(selectedApplicationId))
            return false; // logFile and errorCode are updated
        if (checkAuthentication()) {
            // as the command won't run in authenticated state the method denies to work further
            Log.e(TAG, methodName + " cannot run this command after authentication, aborted");
            log(methodName, "cannot run this command after authentication, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "cannot run this command after authentication";
            return false; // logFile and errorCode are updated
        }
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(DELETE_FILE_COMMAND, new byte[]{fileNumber});
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        if (!checkApplicationIdentifier(selectedApplicationId)) return null;
        if (!checkIsoDep()) return null;
        byte[] apdu;
        byte[] response;
        try {
            apdu = wrapMessage(GET_FILE_IDS_COMMAND, null);
            response = sendData(apdu);
        } catch (Exception e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return null;
        }
        System.arraycopy(returnStatusBytes(response), 0, errorCode, 0, 2);
        byte[] responseData = Arrays.copyOfRange(response, 0, response.length - 2);
        if (checkResponse(response)) {
            Log.d(TAG, "response SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = "SUCCESS";
            APPLICATION_ALL_FILE_IDS = responseData.clone();
            return responseData;
        } else {
            Log.d(TAG, "response FAILURE");
            //System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, RESPONSE_FAILURE.length);
            errorCodeReason = "response FAILURE";
            return null;
        }
    }

    /**
     * get the file settings of all files within an application
     * Note: depending on the application master key settings this requires an preceding authentication
     * with the application master key
     *
     * @return an array with all available file settings
     */
    public FileSettings[] getAllFileSettings() {
        final String methodName = "getAllFileSettings";
        logData = "";
        log(methodName, "started", true);
        errorCode = new byte[2];
        // sanity checks
        if (!checkApplicationIdentifier(selectedApplicationId)) return null;
        if (APPLICATION_ALL_FILE_IDS == null) {
            Log.e(TAG, methodName + " select an application first, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "no application selected before";
            return null;
        }
        if (APPLICATION_ALL_FILE_IDS.length == 0) {
            Log.e(TAG, methodName + " there are no files available, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "there are no files available";
            return null;
        }
        if (!checkIsoDep()) return null;
        int numberOfFileIds = APPLICATION_ALL_FILE_IDS.length;
        APPLICATION_ALL_FILE_SETTINGS = new FileSettings[MAXIMUM_NUMBER_OF_FILES];
        for (int i = 0; i < numberOfFileIds; i++) {
            byte fileId = APPLICATION_ALL_FILE_IDS[i];
            byte[] fileSettingsByte = getFileSettings(fileId);
            Log.d(TAG, "i: " + i + printData(" fileSettingsByte", fileSettingsByte));
            Log.d(TAG, printData("errorCode", errorCode));
            Log.d(TAG, "errorCodeReason: " + errorCodeReason);
            if (fileSettingsByte != null) {
                FileSettings fileSettings = new FileSettings(fileId, fileSettingsByte);
                if (fileSettings != null) {
                    APPLICATION_ALL_FILE_SETTINGS[fileId] = fileSettings;
                    // check if this file is a TransactionMac file
                    if (checkIsTransactionMacFileType(fileId)) {
                        isTransactionMacFilePresent = true;
                        transactionMacFileSettings = fileSettings;
                        int tmacRWKey = transactionMacFileSettings.getAccessRightsRw();
                        if (tmacRWKey != 15) isTransactionMacCommitReaderId = true;
                    }
                }
            }
        }
        log(methodName, "ended");
        /* debug
        Log.d(TAG, "allFileSettings");
        for (int i = 0; i < APPLICATION_ALL_FILE_SETTINGS.length; i++) {
            FileSettings fs = APPLICATION_ALL_FILE_SETTINGS[i];
            if (fs == null) {
                Log.d(TAG, "i: " + i + ":" + "null");
            } else {
                Log.d(TAG, "i: " + i + ":" + APPLICATION_ALL_FILE_SETTINGS[i].dump());
            }
        }
         */
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
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        if (!checkIsoDep()) return null;

        if (checkAuthentication()) {
            log(methodName, "previous authenticateAesEv2First/NonFirst, run getFileSettingsMac");
            return getFileSettingsMac(fileNumber);
        }

        byte[] getFileSettingsParameters = new byte[1];
        getFileSettingsParameters[0] = fileNumber;
        byte[] apdu;
        byte[] response;
        response = sendRequest(GET_FILE_SETTINGS_COMMAND, getFileSettingsParameters);
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
     * get the file settings of a file within an application after a preceding authenticateAesEv2First/NonFirst
     * Note: depending on the application master key settings this requires a preceding authentication
     * with the application master key
     * This is called from getFileSettings after successful checkAuthentication
     * @return an array of bytes with all available fileSettings
     * @fileNumber: the file number we need to read the settings from
     */

    private byte[] getFileSettingsMac(byte fileNumber) {
        // this is using MACed communication - use this after a authenticateAesEv2First/NonFirst
        String logData = "";
        final String methodName = "getFileSettingsMac";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return null;
        // Constructing the full GetFileSettings Command APDU

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(GET_FILE_SETTINGS_COMMAND, new byte[]{fileNumber});
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the abort Transaction
        ByteArrayOutputStream baosGetFileSettingsCommand = new ByteArrayOutputStream();
        baosGetFileSettingsCommand.write(fileNumber);
        baosGetFileSettingsCommand.write(macTruncated, 0, macTruncated.length);
        byte[] getFileSettingsCommand = baosGetFileSettingsCommand.toByteArray();
        log(methodName, printData("getFileSettingsCommand", getFileSettingsCommand));
        //byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        response = sendRequest(GET_FILE_SETTINGS_COMMAND, getFileSettingsCommand);
        //response = sendData(apdu);
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received MAC");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "checkResponse data failure";
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] fullMacedData = getData(response);
        if ((fullMacedData == null) || (fullMacedData.length < 6)) {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "data returned too small";
            return null;
        }
        int macedDataLength = fullMacedData.length - 8;
        log(methodName, "The fullMacedData is of length " + fullMacedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The macedData length is " + macedDataLength);
        byte[] macedData = Arrays.copyOfRange(fullMacedData, 0, macedDataLength);
        byte[] responseMACTruncatedReceived = Arrays.copyOfRange(fullMacedData, macedDataLength, fullMacedData.length);
        log(methodName, printData("macedData", macedData));
        byte[] readData = Arrays.copyOfRange(macedData, 0, macedDataLength);
        log(methodName, printData("readData", readData));
        if (verifyResponseMac(responseMACTruncatedReceived, macedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /**
     * Change the settings of a file in the selected application. This is used to change the communication mode and/or the
     * authentication key numbers of the file.
     * Note: a preceding authentication with the Change Access Key is necessary
     * Note: if the file is of communication mode Plain you need to use authenticateEv2First instead of Legacy authentication
     *
     * @param fileNumber            | in range 00..31
     * @param communicationSettings | new CommunicationMode Plain, MACed or Full
     * @param keyRW                 | new key number for Read & Write access rights key
     * @param keyCar                | new key number for Change Access Rights key
     * @param keyR                  | new key number for Read access rights key
     * @param keyW                  | new key number for Write access rights key
     * @return | true on success
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public boolean changeFileSettings(byte fileNumber, CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW) {
        String logData = "";
        final String methodName = "changeFileSettings";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber);
        // sanity checks
        errorCode = new byte[2];
        // sanity checks
        if ((keyRW < 0) || (keyCar < 0) || (keyR < 0) || (keyW < 0)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "a key number is < 0, aborted";
            return false;
        }
        if ((keyRW > 15) || (keyCar > 15) || (keyR > 15) || (keyW > 15)) {
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "a key number is > 15, aborted";
            return false;
        }
        if (!checkAuthentication()) return false;
        if (!checkIsoDep()) return false;
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication, did you forget to authenticate with the application Master key (0x00) ?), aborted";
            return false;
        }

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        // Generating the MAC for the Command APDU
        byte[] ivInput = getIvInput();
        log(methodName, printData("ivInput", ivInput));

        // IV for CmdData = Enc(KSesAuthENC, IV_Input)
        log(methodName, printData("SesAuthENCKey", SesAuthENCKey));
        byte[] startingIv = new byte[16];
        byte[] ivForCmdData = AES.encrypt(startingIv, SesAuthENCKey, ivInput);
        log(methodName, printData("ivForCmdData", ivForCmdData));

        // build the command data
        byte communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.Plain.name()))
            communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.MACed.name()))
            communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(CommunicationSettings.Full.name()))
            communicationSettingsByte = (byte) 0x03;
        byte fileOption = communicationSettingsByte;
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
        byte[] commandData = baosCommandData.toByteArray();
        log(methodName, printData("commandData", commandData));

        // eventually some padding is necessary with 0x80..00
        byte[] commandDataPadded = paddingWriteData(commandData);
        log(methodName, printData("commandDataPadded", commandDataPadded));

        // E(KSesAuthENC, IVc, CmdData || Padding (if necessary))
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, commandDataPadded);
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // Cmd || CmdCounter || TI || CmdHeader = fileNumber || E(KSesAuthENC, CmdData)
        byte[] macInput = getMacInput(CHANGE_FILE_SETTINGS_COMMAND, new byte[]{fileNumber}, encryptedData);
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
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
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

    public boolean changeFileSettingsNtag424Dna(byte fileNumber, CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable) {

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
        if (communicationSettings.name().equals(CommunicationSettings.Plain.name()))
            communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.MACed.name()))
            communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(CommunicationSettings.Full.name()))
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
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean changeFileSettingsNtag424Dna(byte fileNumber, CommunicationSettings communicationSettings, int keyRW, int keyCar, int keyR, int keyW, boolean sdmEnable, int encPiccDataOffset, int sdmMacOffset, int sdmMacInputOffset) {

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
        if (communicationSettings.name().equals(CommunicationSettings.Plain.name()))
            communicationSettingsByte = (byte) 0x00;
        if (communicationSettings.name().equals(CommunicationSettings.MACed.name()))
            communicationSettingsByte = (byte) 0x01;
        if (communicationSettings.name().equals(CommunicationSettings.Full.name()))
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
                    errorCode = RESPONSE_FAILURE.clone();
                    errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCode = RESPONSE_FAILURE.clone();
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
                    errorCode = RESPONSE_FAILURE.clone();
                    errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCode = RESPONSE_FAILURE.clone();
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
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = "SUCCESS";
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            errorCode = RESPONSE_FAILURE;
            errorCodeReason = "responseMAC FAILURE";
            return false;
        }
    }

    // response code is usually 0x00 but if "unneccessary authentication" it is 0x90
    private boolean verifyResponseMac(byte[] responseMAC, byte[] responseData, byte responseCode) {
        final String methodName = "verifyResponseMac";
        byte[] commandCounterLsb = intTo2ByteArrayInversed(CmdCounter);
        ByteArrayOutputStream responseMacBaos = new ByteArrayOutputStream();
        responseMacBaos.write(responseCode); // response code 00 means success
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
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = "SUCCESS";
            return true;
        } else {
            Log.d(TAG, "responseMAC FAILURE");
            errorCode = RESPONSE_FAILURE;
            errorCodeReason = "responseMAC FAILURE";
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
     * @param key       (AES key with length of 16 bytes)
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
        if (!checkKeyNumber(keyNumber)) return false;
        if (!checkKey(key)) return false;
        if (!checkIsoDep()) return false;
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        if (debug)
            log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
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
        if (debug)
            log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        if (debug) log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug)
                log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            invalidateAllAesLegacyData();
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
            invalidateAllAesLegacyData();
        }
        if (debug) log(methodName, "*********************");
        return rndAEqual;
    }

    // no check on key number
    public boolean authenticateAesEv2FirstProximity(byte keyNumber, byte[] key) {

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
        final String methodName = "authenticateAesEv2FirstProximity";
        log(methodName, printData("key", key) + " keyNumber: " + keyNumber, true);
        errorCode = new byte[2];
        // sanity checks
        //if (!checkKeyNumber(keyNumber)) return false;
        if (!checkKey(key)) return false;
        if (!checkIsoDep()) return false;
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        if (debug)
            log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
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
        if (debug)
            log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        if (debug) log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug)
                log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            invalidateAllAesLegacyData();
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
            invalidateAllAesLegacyData();
        }
        if (debug) log(methodName, "*********************");
        return rndAEqual;
    }

    /**
     * authenticateAesEv2NonFirst uses the EV2NonFirst authentication method with command 0x77
     *
     * @param keyNumber (00..14) but maximum is defined during application setup
     * @param key       (AES key with length of 16 bytes)
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
        if (!checkKeyNumber(keyNumber)) return false;
        if (!checkKey(key)) return false;
        if (!checkIsoDep()) return false;
        invalidateAllData();
        if (debug) log(methodName, "step 01 get encrypted rndB from card");
        if (debug)
            log(methodName, "This method is using the AUTHENTICATE_AES_EV2_NON_FIRST_COMMAND so it will work with AES-based application only");
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        if (debug)
            log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
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
        if (debug)
            log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        if (debug) log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug)
                log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            invalidateAllAesLegacyData();
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
            invalidateAllAesLegacyData();
        }
        if (debug) log(methodName, "*********************");
        return rndAEqual;
    }

    /**
     * authenticateAesLegacy uses the legacy authentication method with command 0xAA
     * This method is good for authentication only - NOT FOR ENCRYPTION as no
     * session key will be generated.
     *
     * @param keyNumber (00..13) but maximum is defined during application setup
     * @param key       (AES key with length of 16 bytes)
     * @return TRUE when authentication was successful
     * <p>
     * <p>
     * Note: the code was adopted from the nfcjlib written by Daniel Andrade
     * source: https://github.com/andrade/nfcjlib
     */

    public boolean authenticateAesLegacy(byte keyNumber, byte[] key) {
        boolean debug = false;
        logData = "";
        invalidateAllData();
        invalidateAllAesLegacyData();
        String methodName = "authenticateAesLegacy";
        log(methodName, "keyNumber: " + keyNumber + printData(" key", key), true);
        errorCode = new byte[2];
        // sanity checks
        if (!checkKeyNumber(keyNumber)) return false;
        if (!checkKey(key)) return false;
        if (!checkIsoDep()) return false;
        if (debug) log(methodName, "step 01 get encrypted rndB from card");
        // authenticate 1st part
        byte[] apdu;
        byte[] response = new byte[0];
        try {
            apdu = wrapMessage(AUTHENTICATE_AES_COMMAND, new byte[]{keyNumber});
            if (debug) log(methodName, "get enc rndB " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug) log(methodName, "get enc rndB " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        if (debug) log(methodName, printData("encryptedRndB", rndB_enc));

        // start the decryption
        //byte[] iv0 = new byte[8];
        byte[] iv0 = new byte[16];
        if (debug) log(methodName, "step 02 initial iv0 is 16 zero bytes " + printData("iv0", iv0));
        if (debug)
            log(methodName, "step 03 decrypt the encryptedRndB using AES.decrypt with key " + printData("key", key) + printData(" iv0", iv0));
        byte[] rndB = AES.decrypt(iv0, key, rndB_enc);
        byte[] rndBSession = rndB.clone();
        if (debug) log(methodName, printData("rndB", rndB));

        if (debug) log(methodName, "step 04 rotate rndB to LEFT");
        byte[] rndB_leftRotated = rotateLeft(rndB);
        if (debug) log(methodName, printData("rndB_leftRotated", rndB_leftRotated));

        // authenticate 2nd part
        if (debug) log(methodName, "step 05 generate a random rndA");
        byte[] rndA = new byte[16]; // this is an AES key
        rndA = getRandomData(rndA);
        if (debug) log(methodName, printData("rndA", rndA));
        byte[] rndASession = rndA.clone();

        if (debug) log(methodName, "step 06 concatenate rndA | rndB_leftRotated");
        byte[] rndArndB_leftRotated = concatenate(rndA, rndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated", rndArndB_leftRotated));

        // IV is now encrypted RndB received from the tag
        if (debug) log(methodName, "step 07 iv1 is encryptedRndB received from the tag");
        byte[] iv1 = rndB_enc.clone();
        if (debug) log(methodName, printData("iv1", iv1));

        // Encrypt RndAB_rot
        if (debug)
            log(methodName, "step 08 encrypt rndArndB_leftRotated using AES.encrypt and iv1");
        byte[] rndArndB_leftRotated_enc = AES.encrypt(iv1, key, rndArndB_leftRotated);
        if (debug) log(methodName, printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));

        // send encrypted data to PICC
        if (debug) log(methodName, "step 09 send the encrypted data to the PICC");
        try {
            apdu = wrapMessage(MORE_DATA_COMMAND, rndArndB_leftRotated_enc);
            if (debug) log(methodName, "send rndArndB_leftRotated_enc " + printData("apdu", apdu));
            response = sendData(apdu);
            if (debug)
                log(methodName, "send rndArndB_leftRotated_enc " + printData("response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        if (debug) log(methodName, "step 10 received encrypted rndA LEFT rotated from PICC");
        byte[] rndA_leftRotated_enc = getData(response);
        if (debug) log(methodName, printData("rndA_leftRotated_enc", rndA_leftRotated_enc));

        //IV is now the last 16 bytes of RndAB_rot_enc
        if (debug)
            log(methodName, "step 11 iv2 is now the last 16 bytes of rndArndB_leftRotated_enc: " + printData("rndArndB_leftRotated_enc", rndArndB_leftRotated_enc));
        int rndArndB_leftRotated_encLength = rndArndB_leftRotated_enc.length;
        byte[] iv2 = Arrays.copyOfRange(rndArndB_leftRotated_enc,
                rndArndB_leftRotated_encLength - 16, rndArndB_leftRotated_encLength);
        if (debug) log(methodName, printData("iv2", iv2));

        // Decrypt encrypted RndA_rot
        if (debug) log(methodName, "step 12 decrypt rndA_leftRotated_enc with iv2 and key");
        byte[] rndA_leftRotated = AES.decrypt(iv2, key, rndA_leftRotated_enc);
        if (debug) log(methodName, printData("rndA_leftRotated", rndA_leftRotated));

        if (debug) log(methodName, "step 13 rotate rndA_leftRotated to RIGHT");
        byte[] rndA_received = rotateRight(rndA_leftRotated);
        if (debug) log(methodName, printData("rndA_received", rndA_received));

        boolean rndAEqual = Arrays.equals(rndA, rndA_received);

        if (debug) log(methodName, printData("rndA received ", rndA_received));
        if (debug) log(methodName, printData("rndA          ", rndA));
        if (debug) log(methodName, "rndA and rndA received are equal: " + rndAEqual);
        if (debug) log(methodName, printData("rndB          ", rndB));
        log(methodName, "**** auth result ****");
        if (rndAEqual) {
            log(methodName, "*** AUTHENTICATED ***");
            authenticateAesLegacySuccess = true;
            keyNumberUsedForLegacyAuthentication = keyNumber;
            invalidateAllData();
        } else {
            log(methodName, "****   FAILURE   ****");
            invalidateAllData();
        }
        log(methodName, "*********************");
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
     * section for keys
     */

    public boolean changeApplicationKeyFull(byte keyNumber, byte keyVersion, byte[] keyNew, byte[] keyOld) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 76 - 80
        // this is based on the key change of an application key on a DESFire Light card
        // Cmd.ChangeKey Case 1: Key number to be changed ≠ Key number for currently authenticated session.
        // Case 2: Key number to be changed == Key number for currently authenticated session.

        String logData = "";
        final String methodName = "changeApplicationKeyFull";
        log(methodName, "started", true);
        log(methodName, "keyNumber: " + keyNumber);
        log(methodName, "keyVersion: " + keyVersion);
        log(methodName, printData("keyNew", keyNew));
        log(methodName, printData("keyOld", keyOld));
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkKeyNumber(keyNumber)) return false;
        if (!checkKey(keyNew)) return false;
        if (!checkKey(keyOld)) return false;
        if (!checkIsoDep()) return false;


        final byte KEY_VERSION = (byte) 0x00; // fixed

        // Encrypting the Command Data

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
        /*
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();*/
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

        byte[] data;
        if (keyNumberUsedForAuthentication != keyNumber) {
            // this is for case 1, auth key number != key number to change
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
            data = baosData.toByteArray();
        } else {
            // this is for case 2, auth key number == key number to change
            byte[] padding = hexStringToByteArray("800000000000000000000000000000");
            ByteArrayOutputStream baosData = new ByteArrayOutputStream();
            baosData.write(keyNew, 0, keyNew.length);
            baosData.write(KEY_VERSION);
            baosData.write(padding, 0, padding.length);
            data = baosData.toByteArray();
        }
        log(methodName, printData("data", data));

        // Encrypt the Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = keyNumber || Encrypted CmdData )
        // C40000BC354CD50180D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        // C4 0000 BC354CD5 01 80D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        byte[] macInput = getMacInput(CHANGE_KEY_SECURE_COMMAND, new byte[]{keyNumber}, encryptedData);
        /*
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_KEY_SECURE_COMMAND); // 0xC4
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(keyNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();*/
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // in case 2 (auth key number == key number to change) there is NO received MAC so 0x9100 tells us - everything was OK
        if (keyNumberUsedForAuthentication == keyNumber) return true;

        // the MAC verification is done in case 1 (auth key number != key number to change)
        // verifying the received Response MAC
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean changeMasterApplicationKeyFull(byte keyNumber, byte keyVersion, byte[] keyNew, byte[] keyOld) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 76 - 80
        // this is based on the key change of an application key on a DESFire Light card
        // Cmd.ChangeKey Case 1: Key number to be changed ≠ Key number for currently authenticated session.
        // Case 2: Key number to be changed == Key number for currently authenticated session.

        String logData = "";
        final String methodName = "changeApplicationKeyFull";
        log(methodName, "started", true);
        log(methodName, "keyNumber: " + keyNumber);
        log(methodName, "keyVersion: " + keyVersion);
        log(methodName, printData("keyNew", keyNew));
        log(methodName, printData("keyOld", keyOld));
        // sanity checks
        if (!checkAuthentication()) return false;
        //if (!checkKeyNumber(keyNumber)) return false;
        if (!checkKey(keyNew)) return false;
        if (!checkKey(keyOld)) return false;
        if (!checkIsoDep()) return false;


        final byte KEY_VERSION = (byte) 0x00; // fixed

        // Encrypting the Command Data

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
        /*
        byte[] commandCounterLsb1 = intTo2ByteArrayInversed(CmdCounter);
        log(methodName, "CmdCounter: " + CmdCounter);
        log(methodName, printData("commandCounterLsb1", commandCounterLsb1));
        byte[] padding1 = hexStringToByteArray("0000000000000000"); // 8 bytes
        ByteArrayOutputStream baosIvInput = new ByteArrayOutputStream();
        baosIvInput.write(IV_LABEL_ENC, 0, IV_LABEL_ENC.length);
        baosIvInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosIvInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosIvInput.write(padding1, 0, padding1.length);
        byte[] ivInput = baosIvInput.toByteArray();*/
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

        byte[] data;
        if (keyNumberUsedForAuthentication != keyNumber) {
            // this is for case 1, auth key number != key number to change
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
            data = baosData.toByteArray();
        } else {
            // this is for case 2, auth key number == key number to change
            byte[] padding = hexStringToByteArray("800000000000000000000000000000");
            ByteArrayOutputStream baosData = new ByteArrayOutputStream();
            baosData.write(keyNew, 0, keyNew.length);
            baosData.write(KEY_VERSION);
            baosData.write(padding, 0, padding.length);
            data = baosData.toByteArray();
        }
        log(methodName, printData("data", data));

        // Encrypt the Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = keyNumber || Encrypted CmdData )
        // C40000BC354CD50180D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        // C4 0000 BC354CD5 01 80D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        byte[] macInput = getMacInput(CHANGE_KEY_SECURE_COMMAND, new byte[]{keyNumber}, encryptedData);
        /*
        ByteArrayOutputStream baosMacInput = new ByteArrayOutputStream();
        baosMacInput.write(CHANGE_KEY_SECURE_COMMAND); // 0xC4
        baosMacInput.write(commandCounterLsb1, 0, commandCounterLsb1.length);
        baosMacInput.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        baosMacInput.write(keyNumber);
        baosMacInput.write(encryptedData, 0, encryptedData.length);
        byte[] macInput = baosMacInput.toByteArray();*/
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // in case 2 (auth key number == key number to change) there is NO received MAC so 0x9100 tells us - everything was OK
        if (keyNumberUsedForAuthentication == keyNumber) return true;

        // the MAC verification is done in case 1 (auth key number != key number to change)
        // verifying the received Response MAC
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    public boolean changeApplicationKeyToDesFull(byte keyNumber, byte keyVersion, byte[] keyNew, byte[] keyOld) {
        // see Mifare DESFire Light Features and Hints AN12343.pdf pages 76 - 80
        // this is based on the key change of an application key on a DESFire Light card
        // Cmd.ChangeKey Case 1: Key number to be changed ≠ Key number for currently authenticated session.
        // Case 2: Key number to be changed == Key number for currently authenticated session.

        String logData = "";
        final String methodName = "changeApplicationKeyToDesFull";
        log(methodName, "started", true);
        log(methodName, "keyNumber: " + keyNumber);
        log(methodName, "keyVersion: " + keyVersion);
        log(methodName, printData("keyNew", keyNew));
        log(methodName, printData("keyOld", keyOld));
        // sanity checks
        if (!checkAuthentication()) return false;
        if (!checkKeyNumber(keyNumber)) return false;
        // todo change for DES key length: if (!checkKey(keyNew)) return false;
        if (!checkKey(keyOld)) return false;
        if (!checkIsoDep()) return false;

        final byte KEY_VERSION = (byte) 0x00; // fixed

        // Encrypting the Command Data

        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
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

        byte[] data;
        if (keyNumberUsedForAuthentication != keyNumber) {
            // this is for case 1, auth key number != key number to change
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
            data = baosData.toByteArray();
        } else {
            // this is for case 2, auth key number == key number to change
            byte[] padding = hexStringToByteArray("800000000000000000000000000000");
            ByteArrayOutputStream baosData = new ByteArrayOutputStream();
            baosData.write(keyNew, 0, keyNew.length);
            baosData.write(KEY_VERSION);
            baosData.write(padding, 0, padding.length);
            data = baosData.toByteArray();
        }
        log(methodName, printData("data", data));

        // Encrypt the Command Data = E(KSesAuthENC, Data)
        byte[] encryptedData = AES.encrypt(ivForCmdData, SesAuthENCKey, data);
        log(methodName, printData("encryptedData", encryptedData));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader = keyNumber || Encrypted CmdData )
        // C40000BC354CD50180D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        // C4 0000 BC354CD5 01 80D40DB52D5D8CA136249A0A14154DBA1BE0D67C408AB24CF0F3D3B4FE333C6A
        byte[] macInput = getMacInput(CHANGE_KEY_SECURE_COMMAND, new byte[]{keyNumber}, encryptedData);
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);

        // in case 2 (auth key number == key number to change) there is NO received MAC so 0x9100 tells us - everything was OK
        if (keyNumberUsedForAuthentication == keyNumber) return true;

        // the MAC verification is done in case 1 (auth key number != key number to change)
        // verifying the received Response MAC
        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);

        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }

    /**
     * section for proximity check
     */

    public boolean runProximityCheck() {
        String logData = "";
        final String methodName = "runProximityCheck";
        log(methodName, "started", true);

        String stepString = "phase 1: prepare the check";
        final byte PREPARE_PROXIMITY_CHECK_COMMAND = (byte) 0xF0;
        final byte RUN_PROXIMITY_CHECK_COMMAND = (byte) 0xF2;
        final byte VERIFY_PROXIMITY_CHECK_COMMAND = (byte) 0xFD;

        byte[] response = new byte[0];
        byte[] apdu;
        try {
            apdu = wrapMessage(PREPARE_PROXIMITY_CHECK_COMMAND, null);
            Log.d(TAG, printData("apdu", apdu));
            response = sendData(apdu);
            Log.d(TAG, printData("response", response));
            System.arraycopy(response, 0, errorCode, 0, 2);
            // unauthenticated response: response IS NOT 9100 but 010320009190
            /*
            if (checkResponse(response)) {
                Log.d(TAG, stepString + " SUCCESS");
                return true;
            } else {
                Log.d(TAG, stepString + " FAILURE");
                return false;
            }
             */
        } catch (IOException e) {
            Log.d(TAG, stepString + " FAILURE, Exception: " + e.getMessage());
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }

                /*
                stepString = "phase 1: prepare the check";
                final byte PREPARE_PROXIMITY_CHECK_COMMAND = (byte) 0xF0;
                final byte RUN_PROXIMITY_CHECK_COMMAND = (byte) 0xF2;
                final byte VERIFY_PROXIMITY_CHECK_COMMAND = (byte) 0xFD;

                byte[] apdu;
                byte[] response;
                try {
                    apdu = wrapMessage(PREPARE_PROXIMITY_CHECK_COMMAND, null);
                    Log.d(TAG, printData(" apdu", apdu));
                    response = isoDep.transceive(apdu);
                    writeToUiAppend(output, printData("response", response));
                    Log.d(TAG, printData(" response", response));
                } catch (IOException e) {
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException", COLOR_RED);
                    return;
                }

                // unauthenticated response: 010320009190
                // 01 032000 9190 || 9190 = Permission denied

                if (!checkResponse(response)) {
                    writeToUiAppend(output, "we received not 9100, aborted");
                    //return;
                }
                responseData = Arrays.copyOfRange(response, 0, response.length - 2);
                writeToUiAppend(output, printData("responseData", responseData));
                byte OTP = responseData[0];
                byte[] pubRespTime = Arrays.copyOfRange(responseData, 1, 4);
                byte PPS1;
                if (OTP == (byte) 0x01) {
                    PPS1 = responseData[3];
                } else {
                    PPS1 = -1;
                }

                // printing some data
                // print("SC = %02X, OPT = %02X, pubRespTime = %02X %02X, PPS1 = %02X" %(SC, OPT, pubRespTime[0], pubRespTime[1], PPS1))
                writeToUiAppend(output, "OTP: " + Utils.byteToHex(OTP));
                writeToUiAppend(output, printData("pubRespTime", pubRespTime));
                writeToUiAppend(output, "PPS1: " + Utils.byteToHex(PPS1));

                // phase 2: run the check
                stepString = "phase 2: run the check";
                int NUMBER_OF_ROUNDS = 1; // 1, 2, 4 or 8 rounds
                int PART_LEN = 8 / NUMBER_OF_ROUNDS;
                byte[] RANDOM_CHALLENGE = new byte[] {(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06, (byte) 0x07};

                 */
                /*
                String MAC_PARTS = "";
                int j = 0;
                for (int i = 0; i < NUMBER_OF_ROUNDS; i++) {
                    byte[] cmdArrayByte = new byte[8]; // ?? length
                    String cmdArray = "";
                    byte[] pRndC = new byte[8];
                    cmdArray += (byte) PART_LEN;
                    for (int k = 0; k < PART_LEN; k++) {
                        cmdArray
                    }
                }
                */
/*
                byte[] challenge1 = Utils.hexStringToByteArray("08F6DE23025C46DAE7");
                try {
                    apdu = wrapMessage(RUN_PROXIMITY_CHECK_COMMAND, challenge1);
                    Log.d(TAG, printData(" apdu", apdu));
                    response = isoDep.transceive(apdu);
                    writeToUiAppend(output, printData("response", response));
                    Log.d(TAG, printData(" response", response));
                    // 910c
                } catch (IOException e) {
                    writeToUiAppend(output, "IOException: " + e.getMessage());
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException", COLOR_RED);
                    return;
                }
*/


        return false;
    }

    /**
     * section for general tasks
     */

    /**
     * gets the technical data of the tapped tag
     *
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
     * checks that the tapped tag is of type DESFire EV1
     * As some commands do work on a DESFire EV1 tag only we need to check for that tag type
     *
     * @return true on success
     */
    public boolean checkForDESFireEv1() {
        // todo work on this, hardware version may be wrong !
        VersionInfo versionInfo = getVersionInformation();
        if (versionInfo == null) return false;
        Log.d(TAG, versionInfo.dump());
        int hardwareType = versionInfo.getHardwareType(); // 1 = DESFire, 4 = NTAG family 4xx
        int hardwareVersion = versionInfo.getHardwareVersionMajor(); // 51 = DESFire EV3, 48 = NTAG 424 DNA
        return ((hardwareType == 1) && (hardwareVersion == 01));
    }

    /**
     * checks that the tapped tag is of type DESFire EV2
     * As some commands do work on a DESFire EV2 tag only we need to check for that tag type
     *
     * @return true on success
     */
    public boolean checkForDESFireEv2XX() {
        // todo work on this, hardware version may be wrong !
        VersionInfo versionInfo = getVersionInformation();
        if (versionInfo == null) return false;
        Log.d(TAG, versionInfo.dump());
        int hardwareType = versionInfo.getHardwareType(); // 1 = DESFire, 4 = NTAG family 4xx
        int hardwareVersion = versionInfo.getHardwareVersionMajor(); // 51 = DESFire EV3, 48 = NTAG 424 DNA
        return ((hardwareType == 1) && (hardwareVersion == 18));
    }

    /**
     * checks that the tapped tag is of type DESFire EV3
     * As some commands do work on a DESFire EV3 tag only we need to check for that tag type
     * (e.g. enabling of the SUN/SDM feature)
     *
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

    /*
    MIFARE DESFire Light contactless application IC MF2DLHX0.pdf pages 70 ff
    GetCardUID command is required to get the 7-byte UID from the card. In case "Random ID" at activation is configured,
    encrypted secure messaging is applied for this command and response. An authentication with any key needs to be
    performed prior to the command GetCardUID. This command returns the UID and gives the opportunity to retrieve the
    UID, even if the Random ID is used.
     */
    public byte[] getCardUidFull() {
        logData = "";
        final String methodName = "getCardUidFull";
        log(methodName, methodName);

        if (!checkAuthentication()) return null;
        if (!checkIsoDep()) return null;

        // Constructing the full GetCardUID Command APDU
        // Data = MAC over command = MACKSesAuthMACKey(Ins || CmdCtr || TI)
        byte[] macInput = getMacInput(GET_CARD_UID_COMMAND, null);
        log(methodName, printData("macInput", macInput));

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Cmd.GetCardUID C-APDU (Part 1)
        //(Cmd || Ins || P1 || P2 || Lc || Data || Le)

        // Data (CmdHeader = keyNumber || Encrypted Data || MAC)
        ByteArrayOutputStream baosCommand = new ByteArrayOutputStream();
        baosCommand.write(macTruncated, 0, macTruncated.length);
        byte[] command = baosCommand.toByteArray();
        log(methodName, printData("command", command));

        byte[] response;
        byte[] apdu;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(GET_CARD_UID_COMMAND, command);

            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        // the fullEncryptedData is 56 bytes long, the first 48 bytes are encryptedData and the last 8 bytes are the responseMAC
        byte[] fullEncryptedData = getData(response);
        int encryptedDataLength = fullEncryptedData.length - 8;
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        byte[] encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length); // fixed to 0x5AA5
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData));
        final int UIDLength = 7;
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, UIDLength);
        log(methodName, printData("readData", readData));

        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    public boolean formatPicc() {
        logData = "";
        final String methodName = "formatPicc";
        log(methodName, methodName);

        if (!checkIsoDep()) return false;
        /*
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log(methodName, "no or lost connection to the card, aborted");
            Log.e(TAG, methodName + " no or lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }*/

        // the first step is to select the Master Application
        boolean success = selectApplicationByAid(MASTER_APPLICATION_IDENTIFIER);
        if (!success) {
            log(methodName, "selection of Master Application failed, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return false;
        }

        // the second step is to authentication with Master Application key
        log(methodName, "trying to authenticate with MASTER_APPLICATION_KEY_NUMBER 00 DES DEFAULT");
        success = desfireD40.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT);
        if (!success) {
            log(methodName, "authenticate failed, aborted");
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return false;
        }
    }

    /**
     * get the key settings of the actual = selected application. If no application was
     * selected the key settings of the MASTER APPLICATION get returned.
     * Uses the helper library 'ApplicationKeySettings' for convenient support
     * @return
     */

    public ApplicationKeySettings getApplicationKeySettings() {
        if (!checkIsoDep()) return null;
        byte[] keySettings = getKeySettings();
        if ((keySettings == null) || (keySettings.length != 2)) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "could not retrieve the key settings";
            return null;
        }
        byte[] selAppId;
        if ((selectedApplicationId == null) || (selectedApplicationId.length != 3)) {
            selAppId = MASTER_APPLICATION_IDENTIFIER.clone();
        } else {
            selAppId = selectedApplicationId.clone();
        }
        return new ApplicationKeySettings(selAppId, keySettings);
    }

    /**
     * Get the key settings of the actual = selected application. If no application was
     * selected the key settings of the MASTER APPLICATION get returned.
     * If a preceding authentication was done the methods calls 'getKeySettingsMac'
     * @return a 2 byte array on success or null on failure
     */

    public byte[] getKeySettings() {

        // todo fill with life, see protocol page 5 and D40 page 36
        // returns 2 bytes: key settings || max number of keys
        logData = "";
        final String methodName = "getKeySettings";
        log(methodName, methodName + " started");

        // sanity checks
        if (!checkIsoDep()) return null;

        if (checkAuthentication()) {
            log(methodName, "previous authenticateAesEv2First/NonFirst, run getFileSettingsMac");
            return getKeySettingsMac();
        }
        byte[] response;
        byte[] apdu;
        try {
            apdu = wrapMessage(GET_KEY_SETTINGS_COMMAND, null);
            response = sendData(apdu);
        } catch (IOException e) {
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return null;
        }
        System.arraycopy(response, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            errorCodeReason = "success";
            return getData(response);
        } else {
            errorCodeReason = "checkResponse failure";
            return null;
        }
    }

    /**
     * get the get key settings of an application after a preceding authenticateAesEv2First/NonFirst
     * Note: depending on the application master key settings this requires a preceding authentication
     * with the application master key
     * This is called from getKeySettings after successful checkAuthentication
     * @return a 2 byte array on success or null on failure
     */

    private byte[] getKeySettingsMac() {
        // this is using MACed communication - use this after a authenticateAesEv2First/NonFirst
        String logData = "";
        final String methodName = "getKeySettingsMac";
        log(methodName, "started", true);
        // sanity checks

        // Constructing the full GetKeySettings Command APDU

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader (=Option) )
        byte[] macInput = getMacInput(GET_KEY_SETTINGS_COMMAND, null);
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // construction the abort Transaction
        ByteArrayOutputStream baosGetKeySettingsCommand = new ByteArrayOutputStream();
        baosGetKeySettingsCommand.write(macTruncated, 0, macTruncated.length);
        byte[] getKeySettingsCommand = baosGetKeySettingsCommand.toByteArray();
        log(methodName, printData("getKeySettingsCommand", getKeySettingsCommand));
        //byte[] apdu = new byte[0];
        byte[] response = new byte[0];
        byte[] fullResponseData;
        response = sendRequest(GET_KEY_SETTINGS_COMMAND, getKeySettingsCommand);
        //response = sendData(apdu);
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now verifying the received MAC");
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "checkResponse data failure";
            return null;
        }
        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        byte[] fullMacedData = getData(response);
        if ((fullMacedData == null) || (fullMacedData.length < 6)) {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            errorCodeReason = "data returned too small";
            return null;
        }
        int macedDataLength = fullMacedData.length - 8;
        log(methodName, "The fullMacedData is of length " + fullMacedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The macedData length is " + macedDataLength);
        byte[] macedData = Arrays.copyOfRange(fullMacedData, 0, macedDataLength);
        byte[] responseMACTruncatedReceived = Arrays.copyOfRange(fullMacedData, macedDataLength, fullMacedData.length);
        log(methodName, printData("macedData", macedData));
        byte[] readData = Arrays.copyOfRange(macedData, 0, macedDataLength);
        log(methodName, printData("readData", readData));
        if (verifyResponseMac(responseMACTruncatedReceived, macedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /*
    Mifare DESFire Light MF2DLHX0.pdf pages 117 ff:
    The asymmetric originality signature is based on ECC and only requires a public key for the verification, which is done
    outside the card. The Read_Sig command can be used in both ISO/IEC 14443-3 and ISO/IEC 14443-4 protocols to retrieve the
    signature. If the PICC is not configured for Random ID, the command is freely available. There is no authentication
    required. If the PICC is configured for Random ID, an authentication is required.

    The Read_Sig retrieves the asymmetric originality signature based on an asymmetric cryptographic algorithm Elliptic Curve
    Cryptography Digital Signature Algorithm (ECDSA), see [14] and can be used in both ISO/IEC 14443-3 and ISO/IEC 14443-4
    protocol. The purpose of originality check signature is to protect from mass copying of non NXP originated ICs. The
    purpose of originality check signature is not to completely prevent HW copy or emulation of individual ICs.
    A public key is required for the verification, which is done outside the card. The NXPOriginalitySignature is computed
    over the UID and written during manufacturing. If the PICC is not configured for Random ID, the command is freely available.
    There is no authentication required. If the PICC is configured for Random ID, an authentication with any authentication key
    is required. If there is an active authentication, the command requires encrypted secure messaging.
    Remark: The originality function is provided to prove that the IC has been manufactured by NXP Semiconductors.
     */


    public byte[] readSignaturePlain() {

        // Mifare DESFire Light MF2DLHX0.pdf pages 117 ff
        // returns 2 bytes: key settings || max number of keys
        logData = "";
        final String methodName = "readSignature";
        log(methodName, methodName + " started");

        // sanity checks
        if (!checkIsoDep()) return null;

        if (checkAuthentication()) {
            log(methodName, "previous authenticateAesEv2First/NonFirst, run readSignatureFull");
            return readSignatureFull();
        }
        byte[] response;
        byte[] apdu;
        try {
            apdu = wrapMessage(READ_SIGNATURE_COMMAND, new byte[]{(byte) 0x00});
            response = sendData(apdu);
            System.out.println(printData("res1", response));
        } catch (IOException e) {
            log(methodName, "IOException: " + e.getMessage());
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return null;
        }
        System.out.println(printData("res", response));
        System.arraycopy(response, 0, errorCode, 0, 2);
        if (checkResponse(response)) {
            errorCodeReason = "success";
            return getData(response);
        } else {
            // additional check for 0x9190
            if (checkResponseUnauthenticated(response)) {
                errorCodeReason = "success";
                return getData(response);
            }
            errorCodeReason = "checkResponse failure";
            return null;
        }
    }

    public byte[] readSignatureFull() {
        logData = "";
        final String methodName = "readSignatureFull";
        log(methodName, methodName + " started");

        if (!checkAuthentication()) return null;
        if (!checkIsoDep()) return null;

        // encrypting the command data
        // IV_Input (IV_Label || TI || CmdCounter || Padding)
        byte[] ivInput = getIvInput();
        log(methodName, printData("ivInput", ivInput));

        // MAC_Input (Ins || CmdCounter || TI || CmdHeader ( = File number) )
        byte TargetingNXPOriginalitySignature = (byte) 0x00;
        byte[] macInput = getMacInput(READ_SIGNATURE_COMMAND, new byte[]{TargetingNXPOriginalitySignature});
        log(methodName, printData("macInput", macInput));

        // generate the (truncated) MAC (CMAC) with the SesAuthMACKey: MAC = CMAC(KSesAuthMAC, MAC_ Input)
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

        // Data (CmdHeader = File number || MAC)
        ByteArrayOutputStream baosCommand = new ByteArrayOutputStream();
        baosCommand.write(TargetingNXPOriginalitySignature);
        baosCommand.write(macTruncated, 0, macTruncated.length);
        byte[] command = baosCommand.toByteArray();
        log(methodName, printData("command", command));

        byte[] response;
        byte[] apdu;
        byte[] responseMACTruncatedReceived;
        try {
            apdu = wrapMessage(READ_SIGNATURE_COMMAND, command);
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, errorCode, 0, 2);
        byte responseCode = (byte) 0x00;
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS, now decrypting the received data");
        } else {
            // check for 0x9190
            if (checkResponseUnauthenticated(response)) {
                log(methodName, "we received the status code 0x9190 meaning that the command is run unnecessary in Full mode, proceed");
                responseCode = (byte) 0x90;
            } else {
                Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
                Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
                return null;
            }
        }

        // note: after sending data to the card the commandCounter is increased by 1
        CmdCounter++;
        log(methodName, "the CmdCounter is increased by 1 to " + CmdCounter);

        // the fullEncryptedData is 72 bytes long, the first 56 bytes are encryptedData || padding 8 bytes || the last 8 bytes are the responseMAC
        byte[] fullEncryptedData = getData(response);
        int encryptedDataLength = fullEncryptedData.length - 8;
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        byte[] encryptedDataD = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedDataD", encryptedDataD));

        // start decrypting the data
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIvD = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length); // fixed to 0x5AA5
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIvD, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedDataD);
        log(methodName, printData("decryptedData", decryptedData));
        final int SignatureLength = 56;
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, SignatureLength);
        log(methodName, printData("readData", readData));
        // we need to use the responseCode option/parameter as if "unnecessary authentication" response
        // from PICC (0x9190) the verification of the response MAC fails on regular method
        if (verifyResponseMac(responseMACTruncatedReceived, encryptedDataD, responseCode)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    /**
     * section for command and response handling
     */

    /**
     * The 'sendRequest' methods automatically detect an '0xAF' status meaning that more data is available,
     * e.g. when reading of a Standard file and the amount of data exceeds the maximum data length the data
     * is chunked by the PICC. The method will read as long as '0xAF' status bytes appear. When all data is
     * read the PICC sends a '0x00' meaning success and all data is provided.
     *
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "TagLostException: " + e.getMessage();
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

    // this may occur when a command is run in Plain communication, it better should be run in MACed or Full communication (e.g. readSignature)
    private boolean checkResponseUnauthenticated(byte[] data) {
        if (data == null) return false;
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_UNAUTHENTICATED_OK, returnStatusBytes(data))) {
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

    private boolean checkIsMasterApplication() {
        if (!Arrays.equals(selectedApplicationId, MASTER_APPLICATION_IDENTIFIER)) {
            log("checkIsMasterApplication", "selectedApplicationId is not Master Application Identifier, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "selectedApplicationId is not Master Application Identifier";
            return false;
        }
        return true;
    }

    private boolean checkApplicationIdentifier(byte[] applicationIdentifier) {
        if ((applicationIdentifier == null) || (applicationIdentifier.length != 3)) {
            log("checkApplicationIdentifier", "applicationIdentifier is NULL or not of length 3, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "applicationIdentifier is NULL or not of length 3";
            return false;
        }
        return true;
    }

    private boolean checkFileNumber(byte fileNumber) {
        if ((fileNumber < 0) || (fileNumber > 31)) {
            log("checkFileNumber", "fileNumber is not in range 0..31, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileNumber is not in range 0..31";
            return false;
        }
        return true;
    }

    private boolean checkFileSize0(int fileSize) {
        if (fileSize < 1) {
            log("checkFileSize0", "fileSize is < 1, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileSize is < 1";
            return false;
        }
        return true;
    }

    private boolean checkOffsetMinus(int offset) {
        if (offset < 0) {
            Log.e(TAG, "checkOffsetMinus" + " offset is < 0, aborted");
            log("checkOffsetMinus", "offset is < 0, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "offset is < 0";
            return false;
        }
        return true;
    }

    private boolean checkValueMinus(int offset) {
        if (offset < 0) {
            Log.e(TAG, "checkValueMinus" + " value is < 0, aborted");
            log("checkValueMinus", "value is < 0, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "value is < 0";
            return false;
        }
        return true;
    }

    public boolean checkFileNumberExisting(byte fileNumber) {
        if (!checkFileNumber(fileNumber)) return false;
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
            int fileSize = fileSettings.getFileSizeInt(); // if the file is not existing we get an NPE
        } catch (NullPointerException e) {
            Log.d(TAG, "fileNumber " + fileNumber + " is not existing");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileNumber " + fileNumber + " is not existing";
            return false;
        }
        Log.d(TAG, "fileNumber " + fileNumber + " is existing");
        return true;
    }

    private boolean checkFileTypeStandard(byte fileNumber) {
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings.getFileType() == FileSettings.STANDARD_FILE_TYPE) {
            return true;
        } else {
            Log.d(TAG, "fileType is not a Standard file type");
            return false;
        }
    }

    private boolean checkFileTypeBackup(byte fileNumber) {
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings.getFileType() == FileSettings.BACKUP_FILE_TYPE) {
            return true;
        } else {
            Log.d(TAG, "fileType is not a Backup file type");
            return false;
        }
    }

    private boolean checkFileTypeValue(byte fileNumber) {
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings.getFileType() == FileSettings.VALUE_FILE_TYPE) {
            return true;
        } else {
            Log.d(TAG, "fileType is not a Value file type");
            return false;
        }
    }

    private boolean checkFileTypeLinearRecord(byte fileNumber) {
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings.getFileType() == FileSettings.LINEAR_RECORD_FILE_TYPE) {
            return true;
        } else {
            Log.d(TAG, "fileType is not a Linear Record file type");
            return false;
        }
    }

    private boolean checkFileTypeCyclicRecord(byte fileNumber) {
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings.getFileType() == FileSettings.CYCLIC_RECORD_FILE_TYPE) {
            return true;
        } else {
            Log.d(TAG, "fileType is not a Cyclic Record file type");
            return false;
        }
    }

    private boolean checkFileTypeTransactionMac(byte fileNumber) {
        FileSettings fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        if (fileSettings.getFileType() == FileSettings.TRANSACTION_MAC_FILE_TYPE) {
            return true;
        } else {
            Log.d(TAG, "fileType is not a Transaction MAC file type");
            return false;
        }
    }

    // note: this does not check if in application creation all keys got created
    private boolean checkAccessRights(byte[] accessRights) {
        if ((accessRights == null) || (accessRights.length != 2)) {
            log("checkAccessRights", "accessRights are NULL or not of length 2, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "accessRights are NULL or not of length 2";
            return false;
        }
        return true;
    }

    // note: this does not check if in application creation all keys got created
    private byte[] modifyTmacAccessRights(byte[] tmacAccessRights) {
        // keys are RW || CAR || R || W
        if ((tmacAccessRights == null) || (tmacAccessRights.length != 2)) {
            log("checkTmacAccessRights", "tmacAccessRights are NULL or not of length 2, aborted");
            System.arraycopy(RESPONSE_PARAMETER_ERROR, 0, errorCode, 0, 2);
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "accessRights are NULL or not of length 2";
            return null;
        }
        // the write key is RFU so the write key is fixed to 'F'
        byte r_w_key = tmacAccessRights[1];
        char r_key = Utils.byteToUpperNibble(r_w_key);
        char w_key = Utils.byteToLowerNibble(r_w_key);
        byte r_w_key_new = Utils.nibblesToByte(r_key, 'F');
        // I'm disabling the TMAC ReaderId Option
        byte rw_car_key = tmacAccessRights[0];
        char rw_key = Utils.byteToUpperNibble(rw_car_key);
        char car_key = Utils.byteToLowerNibble(rw_car_key);
        byte rw_car_key_new = Utils.nibblesToByte('F', car_key);
        byte[] dataReturned = new byte[2];
        dataReturned[0] = rw_car_key_new;
        dataReturned[1] = r_w_key_new;
        return dataReturned;
    }

    private boolean checkKeyNumber(int keyNumber) {
        String methodName = "checkKeyNumber";
        if (keyNumber < 0) {
            Log.e(TAG, methodName + " keyNumber is < 0, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is < 0";
            return false;
        }
        if (keyNumber > 15) {
            Log.e(TAG, methodName + " keyNumber is > 15, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "keyNumber is > 15";
            return false;
        }
        return true;
    }

    private boolean checkKey(byte[] key) {
        String methodName = "checkKey";
        if ((key == null) || (key.length != 16)) {
            Log.e(TAG, methodName + " key length is not 16, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "key length is not 16";
            return false;
        }
        return true;
    }

    private boolean checkCommunicationModeMaced() {
        String methodName = "checkCommunicationModeMaced";
        if (selectedFileSetting.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            Log.e(TAG, methodName + " CommunicationMode MACed is not supported, aborted");
            log(methodName, "CommunicationMode MACed is not supported, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "CommunicationMode MACed is not supported";
            return true;
        }
        return false;
    }

    private boolean checkIsDataFileType(byte fileNumber) {
        String methodName = "checkIsDataFileType";
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        if ((fileSettings.getFileType() == FileSettings.STANDARD_FILE_TYPE) ||
                (fileSettings.getFileType() == FileSettings.BACKUP_FILE_TYPE)) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
            return true;
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not a Standard or Backup file";
            return false;
        }
    }

    private boolean checkIsValueFileType(byte fileNumber) {
        String methodName = "checkIsValueFileType";
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        if (fileSettings.getFileType() == FileSettings.VALUE_FILE_TYPE) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
            return true;
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not a Value file";
            return false;
        }
    }

    private boolean checkIsRecordFileType(byte fileNumber) {
        String methodName = "checkIsRecordFileType";
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        if ((fileSettings.getFileType() == FileSettings.LINEAR_RECORD_FILE_TYPE) ||
                (fileSettings.getFileType() == FileSettings.CYCLIC_RECORD_FILE_TYPE)) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
            return true;
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not a Linear or Cyclic Record file";
            return false;
        }
    }

    // should be available from outside for easy checking
    public boolean checkIsTransactionMacFileType(byte fileNumber) {
        String methodName = "checkIsTransactionFileType";
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
            log(methodName, "fileNumber is a " + fileSettings.getFileTypeName());
            if (fileSettings.getFileType() == FileSettings.TRANSACTION_MAC_FILE_TYPE) {
                log(methodName, "Transaction MAC file detected");
                return true;
            } else {
                return false;
            }
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
    }

    private boolean checkAuthentication() {
        if ((!authenticateEv2FirstSuccess) & (!authenticateEv2NonFirstSuccess)) {
            log("checkAuthentication", "missing authentication with authenticateEV2First or authenticateEV2NonFirst, aborted");
            System.arraycopy(RESPONSE_FAILURE_MISSING_AUTHENTICATION, 0, errorCode, 0, 2);
            errorCode = RESPONSE_FAILURE_MISSING_AUTHENTICATION.clone();
            errorCodeReason = "missing authentication with authenticateEV2First or authenticateEV2NonFirst";
            return false;
        }
        return true;
    }

    private boolean checkIsoDep() {
        if ((isoDep == null) || (!isoDep.isConnected())) {
            log("checkIsoDep", "lost connection to the card, aborted");
            errorCode = RESPONSE_FAILURE.clone();
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

    /**
     * splits a byte array in chunks
     *
     * @param source
     * @param chunksize
     * @return a List<byte[]> with sets of chunksize
     */
    private static List<byte[]> divideArray(byte[] source, int chunksize) {
        List<byte[]> result = new ArrayList<byte[]>();
        int start = 0;
        while (start < source.length) {
            int end = Math.min(source.length, start + chunksize);
            result.add(Arrays.copyOfRange(source, start, end));
            start += chunksize;
        }
        return result;
    }

    /**
     * checks the position of a smallerArray within a larger=outer array
     *
     * @param outerArray
     * @param smallerArray
     * @return position on success or -1 on failure
     */

    public int indexOf(byte[] outerArray, byte[] smallerArray) {
        for (int i = 0; i < outerArray.length - smallerArray.length + 1; ++i) {
            boolean found = true;
            for (int j = 0; j < smallerArray.length; ++j) {
                if (outerArray[i + j] != smallerArray[j]) {
                    found = false;
                    break;
                }
            }
            if (found) return i;
        }
        return -1;
    }

    private void invalidateAllNonAuthenticationData() {
        selectedApplicationId = null;
        APPLICATION_ALL_FILE_SETTINGS = null;
        isTransactionMacFilePresent = false;
        transactionMacFileSettings = null;
        isTransactionMacCommitReaderId = false;
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

    private void invalidateAllAesLegacyData() {
        authenticateAesLegacySuccess = false;
        keyNumberUsedForLegacyAuthentication = -1;
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

    public boolean isApplicationSelected() {
        return isApplicationSelected;
    }

    public byte getKeyNumberUsedForAuthentication() {
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

    public byte getKeyNumberUsedForLegacyAuthentication() {
        return keyNumberUsedForLegacyAuthentication;
    }

    public static byte[] getApplicationAllFileIds() {
        return APPLICATION_ALL_FILE_IDS;
    }

    public static FileSettings[] getApplicationAllFileSettings() {
        return APPLICATION_ALL_FILE_SETTINGS;
    }

    public List<byte[]> getIsoFileIdsList() {
        return isoFileIdsList;
    }

    public List<byte[]> getIsoDfNamesList() {
        return isoDfNamesList;
    }

    public boolean isTransactionMacFilePresent() {
        return isTransactionMacFilePresent;
    }

    public boolean isTransactionMacCommitReaderId() {
        return isTransactionMacCommitReaderId;
    }

    public byte[] getTransactionMacFileReturnedTmcv() {
        return transactionMacFileReturnedTmcv;
    }

    public byte[] getTransactionMacReaderId() {
        return transactionMacReaderId;
    }
    /**
     * deprecated methods, will be removed !
     */

    // todo work on length = 0 = read complete file and set offset to 0 or
    //  length to fileSize-offset to read all remaining data ?

    /**
     * The method reads a byte array from a Standard file. The communication mode is read out from
     * 'getFileSettings command'. If the comm mode is 'Plain' it runs the Plain path, otherwise it
     * uses the 'Full' path. If the comm mode is 'MACed' the method ends a there is no method available
     * within this class to handle those files, sorry.
     * <p>
     * If the data length exceeds the MAXIMUM_READ_MESSAGE_LENGTH the data will be read in chunks.
     * If the data length exceeds MAXIMUM_FILE_LENGTH the methods returns a FAILURE
     *
     * @param fileNumber | in range 0..31 AND file is a Standard file
     * @param offset     | the position in file where the read is starting
     * @param length     | the length of data to get read
     * @return the data read
     * Note: check errorCode and errorCodeReason in case of failure
     */
    public byte[] readFromAStandardFile(byte fileNumber, int offset, int length) {
        String logData = "";
        final String methodName = "readFromAStandardFile";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);

        // sanity checks
        if (!checkAuthentication()) return null; // logFile and errorCode are updated
        if (!checkOffsetMinus(offset)) return null;
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        if (!checkFileTypeStandard(fileNumber)) {
            Log.e(TAG, methodName + " fileType is not Standard file, aborted");
            log(methodName, "fileType is not Standard file, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "ileType is not Standard file";
            return null;
        }
        /*
        if ((fileSettings.getFileType() == FileSettings.STANDARD_FILE_TYPE) ||
                (fileSettings.getFileType() == FileSettings.BACKUP_FILE_TYPE)) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
         */
        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        boolean isPlainMode = false;
        boolean isMacedMode = false;
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_MACED) {
            isMacedMode = true;
            Log.e(TAG, methodName + " CommunicationMode MACed is not supported, aborted");
            log(methodName, "CommunicationMode MACed is not supported, aborted");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "CommunicationMode MACed is not supported, aborted";
            return null;
        }
        if (fileSettings.getCommunicationSettings() == FILE_COMMUNICATION_SETTINGS_PLAIN) {
            isPlainMode = true;
            log(methodName, "CommunicationMode is Plain");
        } else {
            log(methodName, "CommunicationMode is Full enciphered");
        }

        // The chunking is done to avoid framing as the maximum command APDU length is limited
        // bytes including all overhead and attached MAC

        int dataLength = length;
        int numberOfRounds = dataLength / MAXIMUM_READ_MESSAGE_LENGTH;
        int numberOfRoundsMod = Utils.mod(dataLength, MAXIMUM_READ_MESSAGE_LENGTH);
        if (numberOfRoundsMod > 0) numberOfRounds++; // one extra round for the remainder
        Log.d(TAG, "data length: " + dataLength + " numberOfRounds: " + numberOfRounds);
        boolean completeSuccess = true;
        int offsetChunk = offset;
        int numberOfDataToRead = MAXIMUM_READ_MESSAGE_LENGTH; // we are starting with a maximum length
        byte[] dataToRead = new byte[length]; // complete data
        for (int i = 0; i < numberOfRounds; i++) {
            if (offsetChunk + numberOfDataToRead > dataLength) {
                numberOfDataToRead = dataLength - offsetChunk;
            }
            byte[] dataToReadChunk;
            if (isPlainMode) {
                dataToReadChunk = readFromStandardFileRawPlain(fileNumber, offsetChunk, numberOfDataToRead);
            } else {
                dataToReadChunk = readFromStandardFileRawFull(fileNumber, offsetChunk, numberOfDataToRead);
            }
            offsetChunk = offsetChunk + numberOfDataToRead;
            if ((dataToReadChunk == null) || (dataToReadChunk.length < 1)) {
                completeSuccess = false;
                Log.e(TAG, methodName + " could not successfully read, aborted");
                log(methodName, "could not successfully red, aborted");
                System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
                return null;
            }
            {
                // copy the dataToReadChunk in the complete data array
                System.arraycopy(dataToReadChunk, 0, dataToRead, (i * MAXIMUM_READ_MESSAGE_LENGTH), dataToReadChunk.length);
            }
            log(methodName, Utils.printData("dataToRead", dataToRead));
        }
        errorCode = RESPONSE_OK.clone();
        log(methodName, "SUCCESS");
        return dataToRead;
    }


    /**
     * reads a Standard file in communication mode Plain from the beginning (offset = 0)
     *
     * @param fileNumber
     * @param length
     * @return
     */
    public byte[] readFromStandardFilePlain(byte fileNumber, int length) {
        return readFromStandardFileRawPlain(fileNumber, 0, length);
    }

    /**
     * Read data from a Standard file, beginning at offset position and length of data.
     * As the amount of data that can be send from PICC to reader is limited and the PICC will chunk the
     * data if exceeding this limit. The method automatically detects this behaviour and send the
     * necessary commands to get all data.
     * DO NOT CALL this method from outside this class but use one of the ReadFromStandardFile callers
     * as it uses the pre-read fileSettings
     *
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
        if (!checkOffsetMinus(offset)) return null;
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        if (!checkFileTypeStandard(fileNumber)) {
            Log.e(TAG, methodName + " fileType is not Standard file, aborted");
            log(methodName, "fileType is not Standard file, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not Standard file";
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
     * Read data from a Standard file, beginning at offset position and length of data.
     * As the amount of data that can be send from PICC to reader is limited and the PICC will chunk the
     * data if exceeding this limit. The method denies if this limit is reached.
     * DO NOT CALL this method from outside this class but use one of the ReadFromStandardFile callers
     * as it uses the pre-read fileSettings
     *
     * @param fileNumber | in range 0..31
     * @param offset     | offset in the file
     * @param length     | length of data > 1
     * @return the read data or NULL
     * Note: check errorCode and errorCodeReason in case of failure
     */

    public byte[] readFromStandardFileRawFull(byte fileNumber, int offset, int length) {

        // the absolute maximum of data that can be read on a DESFire EV3 in one run is 239 bytes but this is limited
        // here to 128 bytes. If you want to read more use the chunking method readFromStandardFile()

        String logData = "";
        final String methodName = "readFromStandardFileRawFull";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + " offset: " + offset + " size: " + length);
        // sanity checks
        if (!checkAuthentication()) return null; // logFile and errorCode are updated
        if (!checkOffsetMinus(offset)) return null;
        if (length > MAXIMUM_READ_MESSAGE_LENGTH) {
            Log.e(TAG, methodName + " length is > MAXIMUM_READ_MESSAGE_LENGTH, aborted");
            log(methodName, "length is > MAXIMUM_READ_MESSAGE_LENGTH, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > MAXIMUM_READ_MESSAGE_LENGTH";
            return null;
        }
        // getFileSettings for file type and length information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings, aborted");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return null;
        }
        int fileSize = fileSettings.getFileSizeInt();
        if (length > fileSize) {
            Log.e(TAG, methodName + " length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return null;
        }
        if ((offset + length) > fileSize) {
            Log.e(TAG, methodName + " (offset + length) is > fileSize, aborted");
            log(methodName, "(offset + length) is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "(offset + length) is > fileSize";
            return null;
        }
        if (!checkFileTypeStandard(fileNumber)) {
            Log.e(TAG, methodName + " fileType is not Standard file, aborted");
            log(methodName, "fileType is not Standard file, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not Standard file";
            return null;
        }
        /*
        if ((fileSettings.getFileType() == FileSettings.STANDARD_FILE_TYPE) ||
                (fileSettings.getFileType() == FileSettings.BACKUP_FILE_TYPE)) {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", proceed");
        } else {
            log(methodName, "fileNumber to read is a " + fileSettings.getFileTypeName() + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, errorCode, 0, 2);
            return null;
        }
         */
        if (!checkIsoDep()) return null; // logFile and errorCode are updated

        // command header
        byte[] offsetBytes = Utils.intTo3ByteArrayInversed(offset); // LSB order
        byte[] lengthBytes = Utils.intTo3ByteArrayInversed(length); // LSB order
        ByteArrayOutputStream baosCmdHeader = new ByteArrayOutputStream();
        baosCmdHeader.write(fileNumber);
        baosCmdHeader.write(offsetBytes, 0, offsetBytes.length);
        baosCmdHeader.write(lengthBytes, 0, lengthBytes.length);
        byte[] cmdHeader = baosCmdHeader.toByteArray();
        log(methodName, printData("cmdHeader", cmdHeader));

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

        // generate the MAC (CMAC) with the SesAuthMACKey
        log(methodName, printData("SesAuthMACKey", SesAuthMACKey));
        byte[] macFull = calculateDiverseKey(SesAuthMACKey, macInput);
        log(methodName, printData("macFull", macFull));
        // now truncate the MAC
        byte[] macTruncated = truncateMAC(macFull);
        log(methodName, printData("macTruncated", macTruncated));

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
            response = sendData(apdu);
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            log(methodName, "transceive failed: " + e.getMessage(), false);
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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
        log(methodName, "The fullEncryptedData is of length " + fullEncryptedData.length + " that includes 8 bytes for MAC");
        log(methodName, "The encryptedData length is " + encryptedDataLength);
        encryptedData = Arrays.copyOfRange(fullEncryptedData, 0, encryptedDataLength);
        responseMACTruncatedReceived = Arrays.copyOfRange(fullEncryptedData, encryptedDataLength, fullEncryptedData.length);
        log(methodName, printData("encryptedData", encryptedData));

        // start decrypting the data
        byte[] commandCounterLsb2 = intTo2ByteArrayInversed(CmdCounter);
        byte[] padding = hexStringToByteArray("0000000000000000");
        byte[] startingIv = new byte[16];
        ByteArrayOutputStream decryptBaos = new ByteArrayOutputStream();
        decryptBaos.write(IV_LABEL_DEC, 0, IV_LABEL_DEC.length); // fixed to 0x5AA5
        decryptBaos.write(TransactionIdentifier, 0, TransactionIdentifier.length);
        decryptBaos.write(commandCounterLsb2, 0, commandCounterLsb2.length);
        decryptBaos.write(padding, 0, padding.length);
        byte[] ivInputResponse = decryptBaos.toByteArray();
        log(methodName, printData("ivInputResponse", ivInputResponse));
        byte[] ivResponse = AES.encrypt(startingIv, SesAuthENCKey, ivInputResponse);
        log(methodName, printData("ivResponse", ivResponse));
        byte[] decryptedData = AES.decrypt(ivResponse, SesAuthENCKey, encryptedData);
        log(methodName, printData("decryptedData", decryptedData));
        byte[] readData = Arrays.copyOfRange(decryptedData, 0, length);
        log(methodName, printData("readData", readData));


        if (verifyResponseMac(responseMACTruncatedReceived, encryptedData)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return readData;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return null;
        }
    }

    // todo remove, old method just to check
    public boolean writeStandardFileEv2(byte fileNumber, int offsetInt, byte[] dataToWrite) {

        String logData = "";
        //int offsetA = 0;
        final String methodName = "writeToStandardFileRawFull EV2";
        log(methodName, "started", true);
        log(methodName, "fileNumber: " + fileNumber + Utils.printData(" data", dataToWrite) + " offset: " + offsetInt);
        // sanity checks
        if (!checkFileNumber(fileNumber)) return false; // logFile and errorCode are updated
        if ((dataToWrite == null) || (dataToWrite.length > 40)) {
            Log.e(TAG, methodName + " data is NULL or length is > 40, aborted");
            log(methodName, "data is NULL or length is > 40, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "data is NULL or length is > 40";
            return false;
        }
        if (checkOffsetMinus(offsetInt)) return false;
        // getFileSettings for file type and size information
        FileSettings fileSettings;
        try {
            fileSettings = APPLICATION_ALL_FILE_SETTINGS[fileNumber];
        } catch (NullPointerException e) {
            Log.e(TAG, methodName + " could not read fileSettings, aborted");
            log(methodName, "could not read fileSettings");
            errorCode = RESPONSE_FAILURE_MISSING_GET_FILE_SETTINGS.clone();
            errorCodeReason = "could not read fileSettings, aborted";
            return false;
        }
        int fileSizeFs = fileSettings.getFileSizeInt();
        if (dataToWrite.length > fileSizeFs) {
            Log.e(TAG, methodName + " data length is > fileSize, aborted");
            log(methodName, "length is > fileSize, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "length is > fileSize";
            return false;
        }
        if (!checkFileTypeStandard(fileNumber)) {
            Log.e(TAG, methodName + " fileType is not Standard file, aborted");
            log(methodName, "fileType is not Standard file, aborted");
            errorCode = RESPONSE_PARAMETER_ERROR.clone();
            errorCodeReason = "fileType is not Standard file";
            return false; // logFile and errorCode are updated
        }
        if (!checkAuthentication()) return false; // logFile and errorCode are updated
        if (!checkIsoDep()) return false; // logFile and errorCode are updated


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

        // next step is to pad the data according to padding rules in DESFire EV2/3 for AES Secure Messaging fullMode
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
        //baosIvInput.write(header, 0, header.length);
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

        List<byte[]> dataBlockEncryptedList = new ArrayList<>();
        byte[] ivDataEncryption = ivForCmdData.clone(); // the "starting iv"

        for (int i = 0; i < numberOfDataBlocks; i++) {
            byte[] dataBlockEncrypted = AES.encrypt(ivDataEncryption, SesAuthENCKey, dataBlockList.get(i));
            dataBlockEncryptedList.add(dataBlockEncrypted);
            ivDataEncryption = dataBlockEncrypted.clone(); // new, subsequent iv for next encryption
        }

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
                errorCode = RESPONSE_FAILURE.clone();
                errorCodeReason = "IOException: transceive failed: " + e.getMessage();
                return false;
            }
        }
        byte[] encryptedData = baosDataEncrypted.toByteArray();
        log(methodName, printData("encryptedData", encryptedData));

        // Generating the MAC for the Command APDU
        // CmdHeader (FileNo || Offset || DataLength)
        int fileSize = selectedFileSize;
        //int offsetBytes = 0; // read from the beginning
        //byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetInt); // LSB order
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
        baosMacInput.write(WRITE_STANDARD_FILE_SECURE_COMMAND); // 0x8D
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
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = "IOException: transceive failed: " + e.getMessage();
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

        responseMACTruncatedReceived = Arrays.copyOf(response, response.length - 2);
        if (verifyResponseMac(responseMACTruncatedReceived, null)) {
            log(methodName, methodName + " SUCCESS");
            errorCode = RESPONSE_OK.clone();
            errorCodeReason = methodName + " SUCCESS";
            return true;
        } else {
            log(methodName, methodName + " FAILURE");
            errorCode = RESPONSE_FAILURE.clone();
            errorCodeReason = methodName + " FAILURE";
            return false;
        }
    }


}
