package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.Build;
import android.os.Bundle;
import android.os.VibrationEffect;
import android.os.Vibrator;
import android.text.TextUtils;
import android.util.Log;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.CompoundButton;
import android.widget.RadioButton;
import android.widget.TextView;

import com.google.android.material.textfield.TextInputLayout;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = MainActivity.class.getName();

    private com.google.android.material.textfield.TextInputEditText output, errorCode;
    private com.google.android.material.textfield.TextInputLayout errorCodeLayout;


    //private FileSettings selectedFileSettings;

    /**
     * section for application handling
     */

    private com.google.android.material.textfield.TextInputEditText numberOfKeys, applicationId, applicationSelected;
    private Button applicationList, applicationCreate, applicationSelect;

    // experimental:

    private byte[] selectedApplicationId = null;
    private Button applicationCreateAes;
    /**
     * section for files
     */

    private Button fileList, fileSelect, getFileSettings, changeFileSettings;
    private com.google.android.material.textfield.TextInputEditText fileSelected;
    private String selectedFileId = "";
    private int selectedFileSize;
    private FileSettings selectedFileSettings;

    /**
     * section for standard file handling
     */

    private Button fileStandardCreate, fileStandardWrite, fileStandardRead;
    private com.google.android.material.textfield.TextInputEditText fileStandardFileId, fileStandardSize, fileStandardData;
    RadioButton rbFileFreeAccess, rbFileKeySecuredAccess;

    /**
     * section for authentication
     */

    private Button authDM0D, authD0D, authD1D, authD2D, authD3D, authD4D; // auth with default DES keys
    private Button authDM0DC, authD0DC, authD1DC, authD2DC, authD3DC, authD4DC; // auth with changed DES keys

    private byte KEY_NUMBER_USED_FOR_AUTHENTICATION; // the key number used for a successful authentication
    private byte[] SESSION_KEY_DES; // filled in authenticate, simply the first (leftmost) 8 bytes of SESSION_KEY_TDES
    private byte[] SESSION_KEY_AES; // filled in authenticate
    private byte[] SESSION_KEY_TDES; // filled in authenticate

    /**
     * section for general
     */

    private Button getCardUidDes, getCardUidAes; // get cardUID * encrypted

    /**
     * section for constants
     */

    private final byte[] APPLICATION_IDENTIFIER = Utils.hexStringToByteArray("D1D2D3"); // AID 'D1 D2 D3'
    private final byte APPLICATION_NUMBER_OF_KEYS = (byte) 0x05; // maximum 5 keys for secured access
    private final byte APPLICATION_MASTER_KEY_SETTINGS = (byte) 0x0F; // 'amks'
    /**
     * for explanations on Master Key Settings see M075031_desfire.pdf page 35:
     * left '0' = Application master key authentication is necessary to change any key (default)
     * right 'f' = bits 3..0
     * bit 3: 1: this configuration is changeable if authenticated with the application master key (default setting)
     * bit 2: 1: CreateFile / DeleteFile is permitted also without application master key authentication (default setting)
     * bit 1: 1: GetFileIDs, GetFileSettings and GetKeySettings commands succeed independently of a preceding application master key authentication (default setting)
     * bit 0: 1: Application master key is changeable (authentication with the current application master key necessary, default setting)
     */

    private final byte FILE_COMMUNICATION_SETTINGS = (byte) 0x00; // plain communication
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
    private int MAXIMUM_FILE_SIZE = 32; // do not increase this value to avoid framing !

    /**
     * section for application keys
     */

    private final byte[] APPLICATION_KEY_MASTER_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_MASTER_DES = Utils.hexStringToByteArray("D000000000000000");
    private final byte APPLICATION_KEY_MASTER_NUMBER = (byte) 0x00;

    private final byte[] APPLICATION_KEY_RW_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_RW_DES = Utils.hexStringToByteArray("D100000000000000");
    private final byte APPLICATION_KEY_RW_NUMBER = (byte) 0x01;
    private final byte[] APPLICATION_KEY_CAR_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_CAR_DES = Utils.hexStringToByteArray("D2100000000000000");
    private final byte[] APPLICATION_KEY_CAR_AES_DEFAULT = Utils.hexStringToByteArray("00000000000000000000000000000000"); // default AES key with 8 nulls
    private final byte APPLICATION_KEY_CAR_NUMBER = (byte) 0x02;
    private final byte[] APPLICATION_KEY_R_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_R_DES = Utils.hexStringToByteArray("D3100000000000000");
    private final byte APPLICATION_KEY_R_NUMBER = (byte) 0x03;
    private final byte[] APPLICATION_KEY_W_DES_DEFAULT = Utils.hexStringToByteArray("0000000000000000"); // default DES key with 8 nulls
    private final byte[] APPLICATION_KEY_W_DES = Utils.hexStringToByteArray("D4100000000000000");
    private final byte APPLICATION_KEY_W_NUMBER = (byte) 0x04;

    /**
     * section for commands and responses
     */

    private final byte CREATE_APPLICATION_COMMAND = (byte) 0xCA;
    private final byte SELECT_APPLICATION_COMMAND = (byte) 0x5A;
    private final byte CREATE_STANDARD_FILE_COMMAND = (byte) 0xCD;
    private final byte READ_STANDARD_FILE_COMMAND = (byte) 0xBD;
    private final byte WRITE_STANDARD_FILE_COMMAND = (byte) 0x3D;
    private final byte GET_FILE_SETTINGS_COMMAND = (byte) 0xF5;
    private final byte CHANGE_FILE_SETTINGS_COMMAND = (byte) 0x5F;

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;

    private final byte APPLICATION_CRYPTO_DES = 0x00; // add this to number of keys for DES
    private final byte APPLICATION_CRYPTO_AES = (byte) 0x80; // add this to number of keys for AES

    private final byte GET_CARD_UID_COMMAND = (byte) 0x51;
    private final byte GET_VERSION_COMMAND = (byte) 0x60;

    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_MORE_DATA_AVAILABLE = new byte[]{(byte) 0x91, (byte) 0xAF};
    private final byte[] RESPONSE_FAILURE = new byte[]{(byte) 0x91, (byte) 0xFF};

    /**
     * general constants
     */

    int COLOR_GREEN = Color.rgb(0, 255, 0);
    int COLOR_RED = Color.rgb(255, 0, 0);

    // variables for NFC handling

    private NfcAdapter mNfcAdapter;
    //private CommunicationAdapter adapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    // DesfireAuthentication is used for all authentication tasks. The constructor needs the isoDep object so it is initialized in 'onTagDiscovered'
    DesfireAuthenticate desfireAuthenticate;

    // DesfireAuthenticationProximity is used for old DES d40 authenticate tasks. The constructor needs the isoDep object so it is initialized in 'onTagDiscovered'
    DesfireAuthenticateProximity desfireAuthenticateProximity;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        errorCode = findViewById(R.id.etErrorCode);
        errorCodeLayout = findViewById(R.id.etErrorCodeLayout);

        // application handling
        applicationCreate = findViewById(R.id.btnCreateApplication);
        applicationSelect = findViewById(R.id.btnSelectApplication);
        applicationSelected = findViewById(R.id.etSelectedApplicationId);
        numberOfKeys = findViewById(R.id.etNumberOfKeys);
        applicationId = findViewById(R.id.etApplicationId);

        // experimental:
        applicationCreateAes = findViewById(R.id.btnCreateApplicationAes);


        // file handling

        fileList = findViewById(R.id.btnListFiles); // this is misused for getSesAuthEncKey
        fileSelect = findViewById(R.id.btnSelectFile);
        getFileSettings = findViewById(R.id.btnGetFileSettings);
        changeFileSettings = findViewById(R.id.btnChangeFileSettings);
        fileSelected = findViewById(R.id.etSelectedFileId);
        rbFileFreeAccess = findViewById(R.id.rbFileAccessTypeFreeAccess);
        rbFileKeySecuredAccess = findViewById(R.id.rbFileAccessTypeKeySecuredAccess);
        // standard files
        fileStandardCreate = findViewById(R.id.btnCreateStandardFile);
        fileStandardRead = findViewById(R.id.btnReadStandardFile);
        fileStandardWrite = findViewById(R.id.btnWriteStandardFile);
        fileStandardFileId = findViewById(R.id.etFileStandardFileId);
        fileStandardSize = findViewById(R.id.etFileStandardSize);
        fileStandardData = findViewById(R.id.etFileStandardData);

        // authentication handling DES default keys
        authDM0D = findViewById(R.id.btnAuthDM0D);
        authD0D = findViewById(R.id.btnAuthD0D);
        authD1D = findViewById(R.id.btnAuthD1D);
        authD2D = findViewById(R.id.btnAuthD2D);
        authD3D = findViewById(R.id.btnAuthD3D);
        authD4D = findViewById(R.id.btnAuthD4D);
        // authentication handling DES changed keys
        authD0DC = findViewById(R.id.btnAuthD0DC);
        authD1DC = findViewById(R.id.btnAuthD1DC);
        authD2DC = findViewById(R.id.btnAuthD2DC);
        authD3DC = findViewById(R.id.btnAuthD3DC);
        authD4DC = findViewById(R.id.btnAuthD4DC);

        // general handling
        getCardUidDes = findViewById(R.id.btnGetCardUidDes);
        getCardUidAes = findViewById(R.id.btnGetCardUidAes);

        // some presets
        applicationId.setText(Utils.bytesToHexNpeUpperCase(APPLICATION_IDENTIFIER));
        numberOfKeys.setText(String.valueOf((int) APPLICATION_NUMBER_OF_KEYS));
        fileStandardFileId.setText(String.valueOf((int) STANDARD_FILE_FREE_ACCESS_ID)); // preset is FREE ACCESS


        rbFileFreeAccess.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                if (b) {
                    // free access
                    fileStandardFileId.setText(String.valueOf((int) STANDARD_FILE_FREE_ACCESS_ID));
                } else {
                    // key secured access
                    fileStandardFileId.setText(String.valueOf((int) STANDARD_FILE_KEY_SECURED_ACCESS_ID));
                }
            }
        });

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        /**
         * section for application handling
         */

        applicationCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new application";
                writeToUiAppend(output, logString);
                byte numberOfKeysByte = Byte.parseByte(numberOfKeys.getText().toString());
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = createApplicationPlainCommunicationDes(output, applicationIdentifier, numberOfKeysByte, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // experimental
        applicationCreateAes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new AES application";
                writeToUiAppend(output, logString);
                byte numberOfKeysByte = Byte.parseByte(numberOfKeys.getText().toString());
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = createApplicationPlainCommunicationAes(output, applicationIdentifier, numberOfKeysByte, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        applicationSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select an application";
                writeToUiAppend(output, logString);
                byte[] applicationIdentifier = Utils.hexStringToByteArray(applicationId.getText().toString());
                if (applicationIdentifier == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you entered a wrong application ID", COLOR_RED);
                    return;
                }
                //Utils.reverseByteArrayInPlace(applicationIdentifier); // change to LSB = change the order
                if (applicationIdentifier.length != 3) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you did not enter a 6 hex string application ID", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + applicationId.getText().toString());
                byte[] responseData = new byte[2];
                boolean success = selectApplication(output, applicationIdentifier, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }

            }
        });

        /**
         * section for files and standard files
         */

        // this method is misused for getSesAuthEncKey
        fileList.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "getSesAuthEncKeyMain";
                writeToUiAppend(output, logString);
                byte[] rndA = Utils.hexStringToByteArray("B04D0787C93EE0CC8CACC8E86F16C6FE");
                byte[] rndB = Utils.hexStringToByteArray("FA659AD0DCA738DD65DC7DC38612AD81");
                byte[] key = Utils.hexStringToByteArray("00000000000000000000000000000000");
                // calculate the SesAuthENCKey
                byte[] SesAuthENCKey_expected = Utils.hexStringToByteArray("63DC07286289A7A6C0334CA31C314A04");
                DesfireAuthenticateProximity desfireAuthenticateProximity1 = new DesfireAuthenticateProximity(isoDep, true);
                byte[] SesAuthENCKey = desfireAuthenticateProximity1.getSesAuthEncKey(rndA, rndB, key);
                writeToUiAppend(output, printData("SesAuthENCKey_expected", SesAuthENCKey_expected));
                writeToUiAppend(output, printData("SesAuthENCKey calcultd", SesAuthENCKey));
                // calculate the SesAuthMACKey
                byte[] SesAuthMACKey_expected = Utils.hexStringToByteArray("774F26743ECE6AF5033B6AE8522946F6");
                byte[] SesAuthMACKey = desfireAuthenticateProximity1.getSesAuthMacKey(rndA, rndB, key);
                writeToUiAppend(output, printData("SesAuthMACKey_expected", SesAuthMACKey_expected));
                writeToUiAppend(output, printData("SesAuthMACKey calcultd", SesAuthMACKey));
            }
        });

        fileStandardCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a new standard file";
                writeToUiAppend(output, logString);
                byte fileIdByte = Byte.parseByte(fileStandardFileId.getText().toString());
                int fileSizeInt = Integer.parseInt(fileStandardSize.getText().toString());
                // check that an application was selected before
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                writeToUiAppend(output, logString + " with id: " + fileStandardFileId.getText().toString() + " size: " + fileSizeInt);
                byte[] responseData = new byte[2];
                boolean success = createStandardFilePlainCommunicationDes(output, fileIdByte, fileSizeInt, rbFileFreeAccess.isChecked(), responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        fileSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select a file";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                // at this point we should read the available file ids from the card
                //byte fileIdByte = Byte.parseByte(fileStandardFileId.getText().toString());
                // as well we should read the file settings of the selected file to know about e.g. the file type and file size
                selectedFileId = fileStandardFileId.getText().toString();
                selectedFileSize = MAXIMUM_FILE_SIZE; // this value should be read from file settings
                fileSelected.setText(fileStandardFileId.getText().toString());
                writeToUiAppend(output, "you selected the fileID " + selectedFileId);
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " file selection SUCCESS", COLOR_GREEN);
                vibrateShort();
            }
        });

        fileStandardRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a standard file";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                byte[] result = readFromAStandardFilePlainCommunicationDes(output, fileIdByte, selectedFileSize, responseData);
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " data: " + new String(result, StandardCharsets.UTF_8));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        fileStandardWrite.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a standard file";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                String dataToWrite = fileStandardData.getText().toString();
                if (TextUtils.isEmpty(dataToWrite)) {
                    //writeToUiAppend(errorCode, "please enter some data to write");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "please enter some data to write", COLOR_RED);
                    return;
                }
                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);
                // create an empty array and copy the dataToWrite to clear the complete standard file
                byte[] fullDataToWrite = new byte[selectedFileSize];
                System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = writeToAStandardFilePlainCommunicationDes(output, fileIdByte, fullDataToWrite, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        getFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get file settings";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                byte[] result = getFileSettings(output, fileIdByte, responseData);
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the data I'm receiving is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with the Application Master Key ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + printData(" data", result));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    // get the data in the  FileSettings class
                    selectedFileSettings = new FileSettings(fileIdByte, result);
                    writeToUiAppend(output, selectedFileSettings.dump());
                    vibrateShort();
                }
            }
        });

        changeFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change the fileSettings of a file";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                boolean success = changeFileSettings(output, fileIdByte, responseData);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    // NOTE: don't forget to authenticate with CAR key
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Did you forget to authenticate with the CAR key ?");
                }
            }
        });

        /**
         * section for authentication with DEFAULT DES keys
         */

        authD0D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master key = 00...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x00 = application master key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];

                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES_DEFAULT);

                if (success) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    writeToUiAppend(output, logString + " SUCCESS");
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD1D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateProximity.authenticateD40(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateProximity.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateProximity.getLogData());
                }
            }
        });

        // this method is using the Proximity class
        authD2D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_RW_NUMBER, APPLICATION_KEY_RW_DES_DEFAULT);
                boolean success = desfireAuthenticateProximity.authenticateD40(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticateProximity.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(output, desfireAuthenticateProximity.getLogData());
                }
            }
        });
/*
        authD2D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the CAR key = 02...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
               // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });
*/
        authD3D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        authD4D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the 4write access key = 04...
                clearOutputFields();
                String logString = "authenticate with DEFAULT DES key number 0x04 = write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_W_NUMBER, APPLICATION_KEY_W_DES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        /**
         * section for authentication with CHANGED DES key
         */

        authD0DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the application master access key = 00...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x00 = application master access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE this is using AES auth
        authD1DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read&write access key = 01...
                clearOutputFields();
                //String logString = "authenticate with CHANGED DES key number 0x01 = read & write access key";
                String logString = "authenticate with DEFAULT AES key number 0x02 = CAR key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];

                boolean success = desfireAuthenticateProximity.authenticateAes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                 if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticateProximity.getSessionKey();
                     writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE - this is using AES auth
        authD2DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the car key = 02...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                //boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES);

                boolean success = desfireAuthenticateProximity.authenticateAes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticateProximity.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE: this is using AES EV2 First Authentication
        authD3DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];

                boolean success = desfireAuthenticateProximity.authenticateAesEv2First(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_AES = desfireAuthenticateProximity.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_AES));
                    vibrateShort();
                    // show logData
                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

        // todo CHANGE: this is using AES EV2 Non First Authentication
        authD4DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with DEFAULT AES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                // check that a previous successfull authentication with EV2First was run
                boolean ev2FirstSuccess = desfireAuthenticateProximity.isAuthenticateEv2FirstSuccess();
                if (!ev2FirstSuccess) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to successfully run an 'authenticate EV2 First' before, aborted", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];

                boolean success = desfireAuthenticateProximity.authenticateAesEv2NonFirst(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_AES_DEFAULT);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    //SESSION_KEY_DES = desfireAuthenticateProximity.getSessionKey();
                    // todo work with SesAuthENCKey
                    //writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    //showDialog(MainActivity.this, desfireAuthenticateProximity.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

/*
        authD2DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the car key = 02...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x02 = change access rights key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_CAR_NUMBER, APPLICATION_KEY_CAR_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });
*/
        /*
        authD3DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the read access key = 03...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_R_NUMBER, APPLICATION_KEY_R_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

         */
/*
        authD4DC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // authenticate with the write access key = 04...
                clearOutputFields();
                String logString = "authenticate with CHANGED DES key number 0x04 = write access key";
                writeToUiAppend(output, logString);
                if (selectedApplicationId == null) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
                    return;
                }
                byte[] responseData = new byte[2];
                // this is the authentication method from the NFCJLIB, working correctly
                boolean success = desfireAuthenticate.authenticateWithNfcjlibDes(APPLICATION_KEY_W_NUMBER, APPLICATION_KEY_W_DES);
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    SESSION_KEY_DES = desfireAuthenticate.getSessionKey();
                    writeToUiAppend(output, printData("the session key is", SESSION_KEY_DES));
                    vibrateShort();
                    // show logData
                    showDialog(MainActivity.this, desfireAuthenticate.getLogData());
                } else {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                }
            }
        });

 */


        /**
         * section for general handling
         */


        getCardUidDes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // status: WORKING

                clearOutputFields();
                String logString = "get card UID (DES encrypted)";
                writeToUiAppend(output, logString);
                // check that an authentication was done before ?

                byte[] responseData = new byte[2];
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

                    // correct result is 04597a32501490 (7 bytes)
                    // encrypt result is length: 16 data: f3cea1277fde140b04513f15412904e9
                    // decrypt result is length: 16 data: 04597a32501490074400000000000000
                    // correct result is                  04597a32501490 (7 bytes)
                    byte[] encryptionKeyDes = SESSION_KEY_DES;
                    byte[] encryptionKeyTDes = desfireAuthenticateProximity.getModifiedKey(encryptionKeyDes);

                    writeToUiAppend(output, printData("encryptionKey DES", encryptionKeyDes));
                    writeToUiAppend(output, printData("encryptionKey TDES", encryptionKeyTDes));
                    writeToUiAppend(output, printData("encrypted UID", result));
                    byte[] iv = new byte[8]; // a DES IV is 8 bytes long
                    writeToUiAppend(output, printData("IV", iv));
                    byte[] decryptedData = TripleDES.decrypt(iv, encryptionKeyTDes, result);
                    writeToUiAppend(output, printData("decryptedData", decryptedData));
                    // decryptedData is 7 bytes UID || 2 bytes CRC16 || 7 bytes RFU = 00's
                    byte[] cardUid = Arrays.copyOfRange(decryptedData, 0, 7);
                    byte[] crc16Received = Arrays.copyOfRange(decryptedData, 7, 9);
                    writeToUiAppend(output, printData("cardUid", cardUid));
                    writeToUiAppend(output, printData("crc16 received", crc16Received));

                    // check crc16 over received DATA (only)
                    int cardUidLength = 7;
                    byte[] crc16Data = new byte[cardUidLength];
                    System.arraycopy(decryptedData, 0, crc16Data, 0, cardUidLength);
                    byte[] crc16Calculated = CRC16.get(crc16Data);
                    writeToUiAppend(output, printData("crc16 calcultd", crc16Calculated));
                    if (Arrays.equals(crc16Received, crc16Calculated)) {
                        writeToUiAppend(output, "CRC16 matches calculated CRC16");
                    } else {
                        writeToUiAppend(output, "CRC16 DOES NOT matches calculated CRC16");
                    }
                    vibrateShort();
                }
            }
        });

        getCardUidAes.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {

                // status: NOT working, wrong cardUID

                clearOutputFields();
                String logString = "get card UID (AES encrypted)";
                writeToUiAppend(output, logString);
                // check that an authentication was done before ?

                byte[] responseData = new byte[2];

                // no parameter
                byte[] response = new byte[0];
                byte[] apdu = new byte[0];
                try {
                    apdu = wrapMessage(GET_CARD_UID_COMMAND, null);
                    Log.d(TAG, logString + printData(" apdu", apdu));
                    response = isoDep.transceive(apdu);
                    Log.d(TAG, logString + printData(" response", response));
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    System.arraycopy(RESPONSE_FAILURE, 0, responseData, 0, 2);
                    return;
                }
                byte[] responseBytes = returnStatusBytes(response);
                System.arraycopy(responseBytes, 0, responseData, 0, 2);
                if (checkResponse(response)) {
                    Log.d(TAG, logString + " SUCCESS");
                    Arrays.copyOf(response, response.length - 2);
                } else {
                    Log.d(TAG, logString + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
                    Log.d(TAG, logString + " error code: " + EV3.getErrorCode(responseBytes));
                    return;
                }

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

                    // correct result is 045e0832501490 (7 bytes)
                    // encrypt result is length: 16 data: 359734583048c7ea0e6352f0478c6068
                    // decrypt result is length: 16 data: 7a4f24afd255ab778cbc1b9fae1c6cad
                    // correct result is                  045e0832501490 (7 bytes)
                    byte[] encryptionKeyAes = SESSION_KEY_AES;
                    writeToUiAppend(output, printData("encryptionKey AES", encryptionKeyAes));
                    writeToUiAppend(output, printData("encrypted UID", result));
                    byte[] iv = new byte[16]; // an AES IV is 16 bytes long
                    writeToUiAppend(output, printData("IV", iv));
                    byte[] cmacIv = calculateApduCMAC(apdu, encryptionKeyAes, iv);
                    writeToUiAppend(output, printData("cmacIv", cmacIv));
                    byte[] decryptedData = AES.decrypt(cmacIv, encryptionKeyAes, result);
                    writeToUiAppend(output, printData("decryptedData", decryptedData));
                    // decryptedData is 7 bytes UID || 2 bytes CRC16 || 7 bytes RFU = 00's
                    byte[] cardUid = Arrays.copyOfRange(decryptedData, 0, 7);
                    byte[] crc16Received = Arrays.copyOfRange(decryptedData, 7, 9);
                    writeToUiAppend(output, printData("cardUid", cardUid));
                    writeToUiAppend(output, printData("crc16 received", crc16Received));

                    // check crc16 over received DATA (only)
                    int cardUidLength = 7;
                    byte[] crc16Data = new byte[cardUidLength];
                    System.arraycopy(decryptedData, 0, crc16Data, 0, cardUidLength);
                    byte[] crc16Calculated = CRC16.get(crc16Data);
                    // iv = Arrays.copyOfRange(apdu, apdu.length - 2 - iv.length, apdu.length - 2);
                    // crc = calculateApduCRC32R(plaintext, length);

                    writeToUiAppend(output, printData("crc16 calcultd", crc16Calculated));
                    if (Arrays.equals(crc16Received, crc16Calculated)) {
                        writeToUiAppend(output, "CRC16 matches calculated CRC16");
                    } else {
                        writeToUiAppend(output, "CRC16 DOES NOT matches calculated CRC16");
                    }
                    vibrateShort();

                    // original AES card: 045e0832501490
                    // decr               046feadd1b0e57
                }
            }
        });

    }

    /**
     * section for application handling
     */

    private boolean createApplicationPlainCommunicationDes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] methodResponse) {
        final String methodName = "createApplicationPlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier == null) {
            Log.e(TAG, methodName + " applicationIdentifier is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier.length != 3) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 3, found: " + applicationIdentifier.length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys < 1) {
            Log.e(TAG, methodName + " numberOfKeys is < 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys > 14) {
            Log.e(TAG, methodName + " numberOfKeys is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, 3);
        baos.write(APPLICATION_MASTER_KEY_SETTINGS);
        baos.write(numberOfKeys);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(CREATE_APPLICATION_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }

    private boolean createApplicationPlainCommunicationAes(TextView logTextView, byte[] applicationIdentifier, byte numberOfKeys, byte[] methodResponse) {
        final String methodName = "createApplicationPlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier == null) {
            Log.e(TAG, methodName + " applicationIdentifier is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier.length != 3) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 3, found: " + applicationIdentifier.length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys < 1) {
            Log.e(TAG, methodName + " numberOfKeys is < 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (numberOfKeys > 14) {
            Log.e(TAG, methodName + " numberOfKeys is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(applicationIdentifier, 0, 3);
        baos.write(APPLICATION_MASTER_KEY_SETTINGS);
        baos.write(numberOfKeys | APPLICATION_CRYPTO_AES); // here we decide if the application is DES or AES
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(CREATE_APPLICATION_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }


    private boolean selectApplication(TextView logTextView, byte[] applicationIdentifier, byte[] methodResponse) {
        final String methodName = "selectApplication";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier == null) {
            Log.e(TAG, methodName + " applicationIdentifier is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (applicationIdentifier.length != 3) {
            Log.e(TAG, methodName + " applicationIdentifier length is not 3, found: " + applicationIdentifier.length + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }

        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(SELECT_APPLICATION_COMMAND, applicationIdentifier);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            selectedApplicationId = applicationIdentifier.clone();
            applicationSelected.setText(Utils.bytesToHexNpeUpperCase(applicationIdentifier));
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }

    /**
     * section for file handling
     */

    private boolean createStandardFilePlainCommunicationDes(TextView logTextView, byte fileNumber, int fileSize, boolean isFreeAccess, byte[] methodResponse) {
        final String methodName = "createFilePlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileSize < 1) {
            Log.e(TAG, methodName + " fileSize is < 1, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileSize > MAXIMUM_FILE_SIZE) {
            Log.e(TAG, methodName + " fileSize is > " + MAXIMUM_FILE_SIZE + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (isFreeAccess) {
            Log.d(TAG, methodName + " file is created with FREE access");
        } else {
            Log.d(TAG, methodName + " file is created with KEY SECURED access");
        }
        byte[] fileSizeArray = Utils.intTo3ByteArrayInversed(fileSize); // lsb order
        // generate the parameter
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(FILE_COMMUNICATION_SETTINGS);
        // the access rights depend on free access or not
        if (isFreeAccess) {
            baos.write(ACCESS_RIGHTS_RW_CAR_FREE);
            baos.write(ACCESS_RIGHTS_R_W_FREE);
        } else {
            baos.write(ACCESS_RIGHTS_RW_CAR_SECURED);
            baos.write(ACCESS_RIGHTS_R_W_SECURED);
        }
        baos.write(fileSizeArray, 0, 3);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(CREATE_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return false;
        }
    }

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

    private boolean writeToAStandardFilePlainCommunicationDes(TextView logTextView, byte fileNumber, byte[] data, byte[] methodResponse) {
        final String methodName = "writeToAStandardFilePlainCommunicationDes";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber < 0) {
            Log.e(TAG, methodName + " fileNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (fileNumber > 14) {
            Log.e(TAG, methodName + " fileNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((data == null) || (data.length < 1) || (data.length > selectedFileSize)) {
            Log.e(TAG, "data length not in range 1.." + MAXIMUM_FILE_SIZE + ", aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        // generate the parameter
        int numberOfBytes = data.length;
        int offsetBytes = 0; // write from the beginning
        byte[] offset = Utils.intTo3ByteArrayInversed(offsetBytes); // LSB order
        byte[] length = Utils.intTo3ByteArrayInversed(numberOfBytes); // LSB order
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        baos.write(fileNumber);
        baos.write(offset, 0, 3);
        baos.write(length, 0, 3);
        baos.write(data, 0, numberOfBytes);
        byte[] parameter = baos.toByteArray();
        Log.d(TAG, methodName + printData(" parameter", parameter));
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(WRITE_STANDARD_FILE_COMMAND, parameter);
            Log.d(TAG, methodName + printData(" apdu", apdu));
            response = isoDep.transceive(apdu);
            Log.d(TAG, methodName + printData(" response", response));
        } catch (IOException e) {
            Log.e(TAG, methodName + " transceive failed, IOException:\n" + e.getMessage());
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return true;
        } else {
            return false;
        }
    }

    private byte[] getFileSettings(TextView logTextView, byte fileNumber, byte[] methodResponse) {
        final String methodName = "getFileSettings";
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
            writeToUiAppend(logTextView, "transceive failed: " + e.getMessage());
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        byte[] responseBytes = returnStatusBytes(response);
        System.arraycopy(responseBytes, 0, methodResponse, 0, 2);
        if (checkResponse(response)) {
            Log.d(TAG, methodName + " SUCCESS");
            return Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }


    private boolean changeFileSettings(TextView logTextView, byte fileNumber, byte[] methodResponse) {
        // NOTE: don't forget to authenticate with CAR key

        if (SESSION_KEY_DES == null) {
            writeToUiAppend(logTextView, "the SESSION KEY DES is null, did you forget to authenticate with a CAR key first ?");
            return false;
        }

        int selectedFileIdInt = Integer.parseInt(selectedFileId);
        byte selectedFileIdByte = Byte.parseByte(selectedFileId);
        Log.d(TAG, "changeTheFileSettings for selectedFileId " + selectedFileIdInt);
        Log.d(TAG, printData("DES session key", SESSION_KEY_DES));

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
        byte[] tripleDES_SESSION_KEY = new byte[24];
        System.arraycopy(SESSION_KEY_DES, 0, tripleDES_SESSION_KEY, 0, 8);
        System.arraycopy(SESSION_KEY_DES, 0, tripleDES_SESSION_KEY, 8, 8);
        System.arraycopy(SESSION_KEY_DES, 0, tripleDES_SESSION_KEY, 16, 8);
        Log.d(TAG, printData("tripleDES Session Key", tripleDES_SESSION_KEY));
        byte[] IV_DES = new byte[8];
        Log.d(TAG, printData("IV_DES", IV_DES));
        byte[] decryptedData = TripleDES.decrypt(IV_DES, tripleDES_SESSION_KEY, bytesForDecryption);
        Log.d(TAG, printData("decryptedData", decryptedData));
        // the parameter for wrapping
        byte[] parameter = new byte[9];
        parameter[0] = selectedFileIdByte;
        System.arraycopy(decryptedData, 0, parameter, 1, 8);
        Log.d(TAG, printData("parameter", parameter));
        byte[] wrappedCommand;
        byte[] response;
        try {
            wrappedCommand = wrapMessage(CHANGE_FILE_SETTINGS_COMMAND, parameter);
            Log.d(TAG, printData("wrappedCommand", wrappedCommand));
            response = isoDep.transceive(wrappedCommand);
            Log.d(TAG, printData("response", response));
            System.arraycopy(response, 0, methodResponse, 0, 2);
            if (checkResponse(response)) {
                return true;
            } else {
                return false;
            }
        } catch (IOException e) {
            writeToUiAppend(output, "IOException: " + e.getMessage());
            e.printStackTrace();
        }
        return false;
    }

    /**
     * section for key handling
     */

    private boolean changeDesKey(TextView logTextView, byte authenticationKeyNumber, byte[] authenticationKey, byte changeKeyNumber,
                                 byte[] changeKeyNew, byte[] changeKeyOld, String changeKeyName, byte[] methodResponse) {
        final String methodName = "changeDesKey";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (authenticationKeyNumber < 0) {
            Log.e(TAG, methodName + " authenticationKeyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (authenticationKeyNumber > 14) {
            Log.e(TAG, methodName + " authenticationKeyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((authenticationKey == null) || (authenticationKey.length != 8)) {
            Log.e(TAG, methodName + " authenticationKey is NULL or of wrong length, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (changeKeyNumber < 0) {
            Log.e(TAG, methodName + " changeKeyNumber is < 0, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (changeKeyNumber > 14) {
            Log.e(TAG, methodName + " changeKeyNumber is > 14, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((changeKeyNew == null) || (changeKeyNew.length != 8)) {
            Log.e(TAG, methodName + " changeKeyNew is NULL or of wrong length, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((changeKeyOld == null) || (changeKeyOld.length != 8)) {
            Log.e(TAG, methodName + " changeKeyOld is NULL or of wrong length, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if (TextUtils.isEmpty(changeKeyName)) {
            Log.e(TAG, methodName + " changeKeyNamr is empty, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        if ((isoDep == null) || (!isoDep.isConnected())) {
            writeToUiAppend(logTextView, methodName + " lost connection to the card, aborted");
            Log.e(TAG, methodName + " lost connection to the card, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return false;
        }
        return false;
    }


    /**
     * section for general handling
     */

    private byte[] getCardUid(TextView logTextView, byte[] methodResponse) {
        final String methodName = "getCardUid";
        Log.d(TAG, methodName);
        // sanity checks
        if (logTextView == null) {
            Log.e(TAG, methodName + " logTextView is NULL, aborted");
            System.arraycopy(RESPONSE_FAILURE, 0, methodResponse, 0, 2);
            return null;
        }
        // no parameter
        byte[] response = new byte[0];
        byte[] apdu = new byte[0];
        try {
            apdu = wrapMessage(GET_CARD_UID_COMMAND, null);
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
            return Arrays.copyOf(response, response.length - 2);
        } else {
            Log.d(TAG, methodName + " FAILURE with error code " + Utils.bytesToHexNpeUpperCase(responseBytes));
            Log.d(TAG, methodName + " error code: " + EV3.getErrorCode(responseBytes));
            return null;
        }
    }


    /**
     * copied from DESFireEV1.java class
     * necessary for calculation the  new IV for decryption of getCardUid
     * @param apdu
     * @param sessionKey
     * @param iv
     * @param type --> fixed to AES
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
        /*
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x9100) {
            return true;
        } else {
            return false;
        }
         */
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
        /*
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AF) {
            return true;
        } else {
            return false;
        }
         */
    }

    /**
     * checks if the response has an 0x'91AE' at the end means
     * that an authentication with an appropriate key is missing
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkAuthenticationError(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_AUTHENTICATION_ERROR, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
        /*
        int status = ((0xff & data[data.length - 2]) << 8) | (0xff & data[data.length - 1]);
        if (status == 0x91AE) {
            return true;
        } else {
            return false;
        }
         */
    }

    /**
     * section for NFC handling
     */

    // This method is run in another thread when a card is discovered
    // !!!! This method cannot cannot direct interact with the UI Thread
    // Use `runOnUiThread` method to change the UI from this method
    @Override
    public void onTagDiscovered(Tag tag) {

        clearOutputFields();
        invalidateAllSelections();
        writeToUiAppend(output, "NFC tag discovered");
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(150, 10));
                } else {
                    Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
                    v.vibrate(200);
                }

                runOnUiThread(() -> {
                    output.setText("");
                    errorCode.setText("");
                    errorCode.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }
                desfireAuthenticate = new DesfireAuthenticate(isoDep, true); // true means all data is logged

                desfireAuthenticateProximity = new DesfireAuthenticateProximity(isoDep, true); // true means all data is logged

                // setup the communication adapter
                //adapter = new CommunicationAdapter(isoDep, true);

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend(output, "tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppend(output, "NFC tag connected");
                writeToUiAppendBorderColor(errorCode, errorCodeLayout, "The app and DESFire tag are ready to use", COLOR_GREEN);
            }

        } catch (IOException e) {
            writeToUiAppend(output, "ERROR: IOException " + e.getMessage());
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppend(output, "ERROR: Exception " + e.getMessage());
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "Exception: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        }

    }

    @Override
    protected void onResume() {
        super.onResume();

        if (mNfcAdapter != null) {

            Bundle options = new Bundle();
            // Work around for some broken Nfc firmware implementations that poll the card too fast
            options.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, 250);

            // Enable ReaderMode for all types of card and disable platform sounds
            // the option NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK is NOT set
            // to get the data of the tag afer reading
            mNfcAdapter.enableReaderMode(this,
                    this,
                    NfcAdapter.FLAG_READER_NFC_A |
                            NfcAdapter.FLAG_READER_NFC_B |
                            NfcAdapter.FLAG_READER_NFC_F |
                            NfcAdapter.FLAG_READER_NFC_V |
                            NfcAdapter.FLAG_READER_NFC_BARCODE |
                            NfcAdapter.FLAG_READER_NO_PLATFORM_SOUNDS,
                    options);
        }
    }

    @Override
    protected void onPause() {
        super.onPause();
        if (mNfcAdapter != null)
            mNfcAdapter.disableReaderMode(this);
    }

    /**
     * section for layout handling
     */
    private void allLayoutsInvisible() {
        //llApplicationHandling.setVisibility(View.GONE);
        //llStandardFile.setVisibility(View.GONE);
    }

    /**
     * section for UI handling
     */

    private void writeToUiAppend(TextView textView, String message) {
        runOnUiThread(() -> {
            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void writeToUiAppendBorderColor(TextView textView, TextInputLayout textInputLayout, String message, int color) {
        runOnUiThread(() -> {

            // set the color to green
            //Color from rgb
            // int color = Color.rgb(255,0,0); // red
            //int color = Color.rgb(0,255,0); // green
            //Color from hex string
            //int color2 = Color.parseColor("#FF11AA"); light blue
            int[][] states = new int[][]{
                    new int[]{android.R.attr.state_focused}, // focused
                    new int[]{android.R.attr.state_hovered}, // hovered
                    new int[]{android.R.attr.state_enabled}, // enabled
                    new int[]{}  //
            };
            int[] colors = new int[]{
                    color,
                    color,
                    color,
                    //color2
                    color
            };
            ColorStateList myColorList = new ColorStateList(states, colors);
            textInputLayout.setBoxStrokeColorStateList(myColorList);

            String oldString = textView.getText().toString();
            if (TextUtils.isEmpty(oldString)) {
                textView.setText(message);
            } else {
                String newString = message + "\n" + oldString;
                textView.setText(newString);
                System.out.println(message);
            }
        });
    }

    private void clearOutputFields() {
        runOnUiThread(() -> {
            output.setText("");
            errorCode.setText("");
        });
        // reset the border color to primary for errorCode
        int color = R.color.colorPrimary;
        int[][] states = new int[][]{
                new int[]{android.R.attr.state_focused}, // focused
                new int[]{android.R.attr.state_hovered}, // hovered
                new int[]{android.R.attr.state_enabled}, // enabled
                new int[]{}  //
        };
        int[] colors = new int[]{
                color,
                color,
                color,
                color
        };
        ColorStateList myColorList = new ColorStateList(states, colors);
        errorCodeLayout.setBoxStrokeColorStateList(myColorList);
    }

    private void invalidateAllSelections() {
        selectedApplicationId = null;
        selectedFileId = "";
        runOnUiThread(() -> {
            applicationSelected.setText("");
            fileSelected.setText("");
        });
        KEY_NUMBER_USED_FOR_AUTHENTICATION = -1;
        SESSION_KEY_DES = null;
        SESSION_KEY_TDES = null;
    }

    private void invalidateEncryptionKeys() {
        KEY_NUMBER_USED_FOR_AUTHENTICATION = -1;
        SESSION_KEY_DES = null;
        SESSION_KEY_TDES = null;
    }

    private void vibrateShort() {
        // Make a Sound
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ((Vibrator) getSystemService(VIBRATOR_SERVICE)).vibrate(VibrationEffect.createOneShot(50, 10));
        } else {
            Vibrator v = (Vibrator) getSystemService(Context.VIBRATOR_SERVICE);
            v.vibrate(50);
        }
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mApplications = menu.findItem(R.id.action_applications);
        mApplications.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                allLayoutsInvisible();
                //llApplicationHandling.setVisibility(View.VISIBLE);
                return false;
            }
        });

        MenuItem mStandardFile = menu.findItem(R.id.action_standard_file);
        mStandardFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                allLayoutsInvisible();
                //llStandardFile.setVisibility(View.VISIBLE);
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    public void showDialog(Activity activity, String msg){
        final Dialog dialog = new Dialog(activity);
        dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
        dialog.setCancelable(true);
        dialog.setContentView(R.layout.logdata);
        TextView text = dialog.findViewById(R.id.tvLogData);
        //text.setMovementMethod(new ScrollingMovementMethod());
        text.setText(msg);
        Button dialogButton = dialog.findViewById(R.id.btnLogDataOk);
        dialogButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                dialog.dismiss();
            }
        });
        dialog.show();
    }
}