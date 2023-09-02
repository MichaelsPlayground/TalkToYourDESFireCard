package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.Utils.divideArrayToList;
import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.net.Uri;
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
import android.widget.LinearLayout;
import android.widget.TextView;
import android.widget.Toast;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.SwitchCompat;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.textfield.TextInputLayout;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;


public class MainActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = MainActivity.class.getName();

    private com.google.android.material.textfield.TextInputEditText output, errorCode;
    private com.google.android.material.textfield.TextInputLayout errorCodeLayout;

    private byte[] selectedApplicationId = null;


    /**
     * section for basics workflow
     */

    private LinearLayout llSectionMenue1;
    private Button applicationSelect, fileSelect;
    private boolean isTransactionMacFilePresent = false; // tries to detect a TMAC file when selecting application or files
    private boolean isCommitReaderIdEnabled = false;
    private com.google.android.material.textfield.TextInputEditText applicationSelected;

    /**
     * section for Data file - can be Standard or Backup files
     */

    private LinearLayout llSectionDataFiles;
    private Button fileDataRead, fileDataWrite;

    /**
     * section for Value files
     */

    private LinearLayout llSectionValueFiles;
    private Button fileValueRead, fileValueCredit, fileValueDebit;

    private LinearLayout llSectionRecordFiles;
    private Button fileRecordRead, fileRecordWrite;


    /**
     * section for authentication
     * note: the character at the end 'D' or 'C' is meaning 'default' or 'changed'
     */

    private LinearLayout llSectionAuthentication;
    private SwitchCompat swAuthenticateEv2First;
    private Button authM0D, authM0C; // Master Application key
    private Button authA0DLeg, authA0CLeg, authA0DEv2, authA0CEv2; // application master key, legacy or EV2First auth
    private Button authA1D, authA1C, authA2D, authA2C, authA3D, authA3C, authA4D, authA4C; // application keys

    /**
     * section for key handling
     */

    private LinearLayout llSectionChangeKey;
    private Button changeKeyA1ToC, changeKeyA1ToD;

    /**
     * section for file related action handling
     */

    private LinearLayout llSectionFileActions;
    private Button changeFileSettings0000, changeFileSettings1234;

    /**
     * section for Transaction MAC file
     * note: this is visible always for create and delte of the file
     */

    private LinearLayout llSectionTransactionMacFile;
    private Button fileTransactionMacCreate, fileTransactionMacCreateReaderId, fileTransactionMacDelete, fileTransactionMacRead;

    /**
     * section for files
     */

    private Button getFileSettings;
    private com.google.android.material.textfield.TextInputEditText fileSelected;
    private boolean isFileListRead = false; // 'fileSelect' will read all fileIds and fileSettings for all files, on SUCCESS isFileRead is set to true and an applicationSelect sets it to false;
    private String selectedFileId = ""; // cached data, filled by file select
    private byte[] allFileIds; // cached data, filled by file select
    private FileSettings[] allFileSettings; // cached data, filled by file select
    private int selectedFileSize; // cached data, filled by file select

    private FileSettings selectedFileSettings; // cached data, filled by file select
    private byte selectedFileType; // cached data, filled by file select

    /**
     * section for tests
     */

    private Button test;

    /**
     * section for general
     */

    private Button getTagVersion, formatPicc;


    /**
     * section for constants
     */

    // see Mifare DESFire Light Features and Hints AN12343.pdf, page 83-84
    private final byte[] TRANSACTION_MAC_KEY_AES = Utils.hexStringToByteArray("F7D23E0C44AFADE542BFDF2DC5C6AE02"); // taken from Mifare DESFire Light Features and Hints AN12343.pdf, pages 83-84


    /**
     * section for commands and responses
     */

    private final byte MORE_DATA_COMMAND = (byte) 0xAF;

    private final byte APPLICATION_CRYPTO_AES = (byte) 0x80; // add this to number of keys for AES

    private final byte GET_CARD_UID_COMMAND = (byte) 0x51;
    private final byte GET_VERSION_COMMAND = (byte) 0x60;

    private final byte[] RESPONSE_OK = new byte[]{(byte) 0x91, (byte) 0x00};
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};
    private final byte[] RESPONSE_BOUNDARY_ERROR = new byte[]{(byte) 0x91, (byte) 0xBE};
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

    private String exportString = "Desfire Authenticate"; // takes the log data for export
    private String exportStringFileName = "auth.html"; // takes the log data for export


    // DesfireAuthentication is used for all authentication tasks. The constructor needs the isoDep object so it is initialized in 'onTagDiscovered'

    // DesfireAuthenticationProximity is used for old DES d40 authenticate tasks. The constructor needs the isoDep object so it is initialized in 'onTagDiscovered'
    //DesfireAuthenticateProximity desfireAuthenticateProximity;
    DesfireAuthenticateLegacy desfireAuthenticateLegacy;
    DesfireEv3 desfireEv3;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etOutput);
        errorCode = findViewById(R.id.etErrorCode);
        errorCodeLayout = findViewById(R.id.etErrorCodeLayout);

        // basic workflow
        applicationSelect = findViewById(R.id.btnSelectApplication);
        applicationSelected = findViewById(R.id.etSelectedApplicationId);
        fileSelect = findViewById(R.id.btnSelectFile);
        fileSelected = findViewById(R.id.etSelectedFileId);

        // data file workflow - can be Standard or Backup files
        llSectionDataFiles = findViewById(R.id.llSectionDataFiles);
        fileDataRead = findViewById(R.id.btnDataFileRead);
        fileDataWrite = findViewById(R.id.btnDataFileWrite);
        llSectionDataFiles.setVisibility(View.GONE);

        // value file workflow
        llSectionValueFiles = findViewById(R.id.llSectionValueFiles);
        fileValueRead = findViewById(R.id.btnValueFileRead);
        fileValueCredit = findViewById(R.id.btnValueFileCredit);
        fileValueDebit = findViewById(R.id.btnValueFileDebit);
        llSectionValueFiles.setVisibility(View.GONE);

        // record file workflow
        llSectionRecordFiles = findViewById(R.id.llSectionRecordFiles);
        fileRecordRead = findViewById(R.id.btnRecordFileRead);
        fileRecordWrite = findViewById(R.id.btnRecordFileWrite);
        llSectionRecordFiles.setVisibility(View.GONE);

        // authenticate workflow
        llSectionAuthentication = findViewById(R.id.llSectionAuthentication);
        swAuthenticateEv2First = findViewById(R.id.swAuthenticationEv2First);
        authM0D = findViewById(R.id.btnAuthM0D);
        authM0C = findViewById(R.id.btnAuthM0C);
        authA0DLeg = findViewById(R.id.btnAuthA0DLeg);
        authA0DEv2 = findViewById(R.id.btnAuthA0DEv2);
        authA1D = findViewById(R.id.btnAuthA1D);
        authA2D = findViewById(R.id.btnAuthA2D);
        authA3D = findViewById(R.id.btnAuthA3D);
        authA4D = findViewById(R.id.btnAuthA4D);
        authA0CLeg = findViewById(R.id.btnAuthA0CLeg);
        authA0CEv2 = findViewById(R.id.btnAuthA0CEv2);
        authA1C = findViewById(R.id.btnAuthA1C);
        authA2C = findViewById(R.id.btnAuthA2C);
        authA3C = findViewById(R.id.btnAuthA3C);
        authA4C = findViewById(R.id.btnAuthA4C);

        // change key workflow
        llSectionChangeKey = findViewById(R.id.llSectionChangeKey);
        changeKeyA1ToC = findViewById(R.id.btnChangeKeyA1ToC);
        changeKeyA1ToD = findViewById(R.id.btnChangeKeyA1ToD);

        // file related actions workflow
        llSectionFileActions = findViewById(R.id.llSectionFileActions);
        changeFileSettings0000 = findViewById(R.id.btnChangeFileSettings0000);
        changeFileSettings1234 = findViewById(R.id.btnChangeFileSettings1234);

        // transaction mac file workflow
        fileTransactionMacCreate = findViewById(R.id.btnTransactionMacFileCreate);
        fileTransactionMacCreateReaderId = findViewById(R.id.btnTransactionMacFileCreateReaderId);
        fileTransactionMacDelete = findViewById(R.id.btnTransactionMacFileDelete);
        fileTransactionMacRead = findViewById(R.id.btnTransactionMacFileRead);

        getFileSettings = findViewById(R.id.btnGetFileSettings);

        // general handling
        getTagVersion = findViewById(R.id.btnGetTagVersion);
        formatPicc = findViewById(R.id.btnFormatPicc);

        // test section
        test = findViewById(R.id.btnTest);

        allLayoutsInvisible(); // except select application & file


        /**
         * select application and file
         */

        applicationSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select an application";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                isFileListRead = false; // invalidates the data

                // select Master Application first
                boolean success = desfireEv3.selectApplicationByAid(DesfireEv3.MASTER_APPLICATION_IDENTIFIER);
                byte[] errorCodeDf = desfireEv3.getErrorCode();
                String errorCodeReason = desfireEv3.getErrorCodeReason();
                if (!success) {
                    writeToUiAppend(output, "cannot select Master Application, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(errorCodeDf), COLOR_RED);
                    return;
                }

                List<byte[]> applicationIdList = desfireEv3.getApplicationIdsList();
                errorCodeDf = desfireEv3.getErrorCode();
                errorCodeReason = desfireEv3.getErrorCodeReason();
                if ((applicationIdList == null) || (applicationIdList.size() == 0)) {
                    writeToUiAppend(output, "there are no application IDs on the  PICC");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(errorCodeDf), COLOR_RED);
                    return;
                }

                String[] applicationList = new String[applicationIdList.size()];
                for (int i = 0; i < applicationIdList.size(); i++) {
                    byte[] aid = applicationIdList.get(i);
                    //Utils.reverseByteArrayInPlace(aid);
                    applicationList[i] = Utils.bytesToHexNpeUpperCase(aid);
                }

                // setup the alert builder
                AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());
                builder.setTitle("Choose an application");

                builder.setItems(applicationList, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        writeToUiAppend(output, "you  selected nr " + which + " = " + applicationList[which]);
                        selectedApplicationId = Utils.hexStringToByteArray(applicationList[which]);
                        // now we run the command to select the application
                        byte[] responseData = new byte[2];
                        byte[] aid = selectedApplicationId.clone();
                        //Utils.reverseByteArrayInPlace(aid);
                        boolean result = desfireEv3.selectApplicationByAid(aid);
                        responseData = desfireEv3.getErrorCode();
                        writeToUiAppend(output, "result of selectApplication: " + result);
                        int colorFromErrorCode = EV3.getColorFromErrorCode(responseData);
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "selectApplication: " + EV3.getErrorCode(responseData), colorFromErrorCode);
                        applicationSelected.setText(applicationList[which]);
                        selectedApplicationId = Utils.hexStringToByteArray(applicationList[which]);

                        // try to read all fileIds and fileSettings within this application
                        Log.d(TAG, "getAllFileIds and allFileSettings");
                        allFileIds = desfireEv3.getAllFileIds();
                        allFileSettings = desfireEv3.getAllFileSettings();
                        byte[] responseCode = desfireEv3.getErrorCode();
                        if ((allFileIds == null) || (allFileIds.length == 0)) {
                            writeToUiAppend(output, "no file IDs found, aborted");
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                            return;
                        }
                        if ((allFileSettings == null) || (allFileSettings.length == 0)) {
                            writeToUiAppend(output, "no file settings found, aborted");
                            writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                            return;
                        }
                        isFileListRead = true;
                        isTransactionMacFilePresent = desfireEv3.isTransactionMacFilePresent();
                        isCommitReaderIdEnabled = desfireEv3.isTransactionMacCommitReaderId();

                        // for some actions we do need active authentication and key changing
                        llSectionAuthentication.setVisibility(View.VISIBLE);
                        llSectionChangeKey.setVisibility((View.VISIBLE));
                    }
                });
                // create and show the alert dialog
                AlertDialog dialog = builder.create();
                dialog.show();
            }
        });

        fileSelect.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "select a file";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                // on application selection the file ids where read from the application, together with the file settings
                // if we already got this information this steps are skipped
                if (!isFileListRead) {
                    Log.d(TAG, "getAllFileIds and allFileSettings");
                    allFileIds = desfireEv3.getAllFileIds();
                    allFileSettings = desfireEv3.getAllFileSettings();
                    byte[] responseCode = desfireEv3.getErrorCode();
                    if ((allFileIds == null) || (allFileIds.length == 0)) {
                        writeToUiAppend(output, "no file IDs found, aborted");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                        return;
                    }
                    if ((allFileSettings == null) || (allFileSettings.length == 0)) {
                        writeToUiAppend(output, "no file settings found, aborted");
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                        return;
                    }
                    isFileListRead = true;
                    isTransactionMacFilePresent = desfireEv3.isTransactionMacFilePresent();
                    isCommitReaderIdEnabled = desfireEv3.isTransactionMacCommitReaderId();
                } else {
                    Log.d(TAG, "getAllFileIds and allFileSettings SKIPPED");
                }

                String[] fileList = new String[allFileIds.length];
                for (int i = 0; i < allFileIds.length; i++) {
                    // get the file type for each entry
                    byte fileId = allFileIds[i];
                    FileSettings fileSettings = allFileSettings[fileId];
                    //Log.d(TAG, fileSettings.dump());
                    String fileTypeName = "unknown";
                    fileTypeName = fileSettings.getFileTypeName();
                    String communicationMode = fileSettings.getCommunicationSettingsName();
                    fileList[i] = String.valueOf(fileId) + " (" + fileTypeName + "|" + communicationMode + ")";
                }


                // setup the alert builder
                AlertDialog.Builder builder = new AlertDialog.Builder(view.getContext());
                builder.setTitle("Choose a file");

                FileSettings[] finalAllFileSettings = allFileSettings;
                builder.setItems(fileList, new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        allLayoutsInvisible();
                        writeToUiAppend(output, "you  selected nr " + which + " = " + fileList[which]);
                        selectedFileId = String.valueOf(allFileIds[which]);
                        // here we are reading the fileSettings
                        String outputString = fileList[which] + " ";
                        byte fileIdByte = Byte.parseByte(selectedFileId);
                        selectedFileSettings = finalAllFileSettings[fileIdByte];
                        outputString += "(" + selectedFileSettings.getFileTypeName();
                        selectedFileSize = selectedFileSettings.getFileSizeInt();
                        outputString += " size: " + selectedFileSize + ")";
                        writeToUiAppend(output, outputString);
                        fileSelected.setText(fileList[which]);
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "file selected", COLOR_GREEN);
                        selectedFileType = selectedFileSettings.getFileType();
                        if (selectedFileType == FileSettings.STANDARD_FILE_TYPE) {
                            llSectionDataFiles.setVisibility(View.VISIBLE);
                        }
                        if (selectedFileType == FileSettings.BACKUP_FILE_TYPE) {
                            llSectionDataFiles.setVisibility(View.VISIBLE);
                        }
                        if (selectedFileType == FileSettings.VALUE_FILE_TYPE) {
                            llSectionValueFiles.setVisibility(View.VISIBLE);
                        }
                        if (selectedFileType == FileSettings.LINEAR_RECORD_FILE_TYPE) {
                            llSectionRecordFiles.setVisibility(View.VISIBLE);
                        }
                        if (selectedFileType == FileSettings.CYCLIC_RECORD_FILE_TYPE) {
                            llSectionRecordFiles.setVisibility(View.VISIBLE);
                        }
                        llSectionAuthentication.setVisibility(View.VISIBLE);
                        llSectionFileActions.setVisibility(View.VISIBLE);

                        if (selectedFileSettings.getCommunicationSettings() == (byte) 0x00) {
                            // make a switch visible
                            swAuthenticateEv2First.setVisibility(View.VISIBLE);
                            swAuthenticateEv2First.setChecked(false);
                        } else {
                            swAuthenticateEv2First.setVisibility(View.GONE);
                            swAuthenticateEv2First.setChecked(false);
                        }
                        vibrateShort();
                    }
                });

                // Transaction MAC file is present in this application
                if ((isTransactionMacFilePresent) && (isCommitReaderIdEnabled)) {
                    showDialogWarningCommitReaderId();
                }

                // create and show the alert dialog
                AlertDialog dialog = builder.create();
                dialog.show();
            }
        });

        getFileSettings.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "get file settings";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                byte[] responseData = new byte[2];
                byte[] result = desfireAuthenticateLegacy.getFileSettings(fileIdByte);
                responseData = desfireAuthenticateLegacy.getErrorCode();
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
                    writeToUiAppend(output, desfireAuthenticateLegacy.getLogData());
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

        /**
         * data file actions - could be a Standard or Backup file
         */

        fileDataRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a data file";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                int fileSizeInt = selectedFileSettings.getFileSizeInt();

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                byte[] result = desfireEv3.readFromADataFile(fileIdByte, 0, fileSizeInt);
                responseData = desfireEv3.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                } else {
                    writeToUiAppend(output, logString + " fileNumber: " + fileIdByte + printData(" data", result));
                    writeToUiAppend(output, logString + " fileNumber: " + fileIdByte + " data: \n" + new String(result, StandardCharsets.UTF_8));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        fileDataWrite.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a data file";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                int fileSizeInt = selectedFileSettings.getFileSizeInt();

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }

                // we are going to write a timestamp to the file, filled up with testData
                byte[] fullDataToWrite = new byte[fileSizeInt];
                String dataToWrite = Utils.getTimestamp();
                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);
                if (dataToWriteBytes.length >= fileSizeInt) {
                    // if the file is smaller than the timestamp we do write only parts of the timestamp
                    System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, fileSizeInt);
                } else {
                    System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);
                    // now filling up the fullData with testData
                    byte[] testData = Utils.generateTestData(fileSizeInt - dataToWriteBytes.length);
                    System.arraycopy(testData, 0, fullDataToWrite, dataToWriteBytes.length, testData.length);
                }

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.writeToADataFile(fileIdByte, 0, fullDataToWrite);

                responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
                if (selectedFileSettings.getFileType() == FileSettings.STANDARD_FILE_TYPE) {
                    vibrateShort();
                }
                ;

                if (selectedFileSettings.getFileType() == FileSettings.BACKUP_FILE_TYPE) {
                    // it is a Backup file where we need to submit a commit command to confirm the write
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " is a Backup file, run COMMIT");
                    byte commMode = selectedFileSettings.getCommunicationSettings();
                    if (commMode == (byte) 0x00) {
                        // Plain
                        // this fails when a Transaction MAC file with enabled Commit ReaderId option is existent
                        success = desfireEv3.commitTransactionPlain();
                    }
                    if ((commMode == (byte) 0x01) || (commMode == (byte) 0x03)) {
                        // MACed or Full enciphered
                        if (desfireEv3.isTransactionMacFilePresent()) {
                            if (desfireEv3.isTransactionMacCommitReaderId()) {
                                // this  is hardcoded when working with TransactionMAC files AND enabled CommitReaderId feature
                                writeToUiAppend(output, "A TransactionMAC file is present with ENABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFull(true);
                            } else {
                                writeToUiAppend(output, "A TransactionMAC file is present with DISABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFullReturnTmv();
                            }
                        } else {
                            // no transaction mac file is present
                            writeToUiAppend(output, "A TransactionMAC file is NOT present, running regular commitTransaction");
                            success = desfireEv3.commitTransactionWithoutTmacFull();
                            Log.d(TAG, desfireEv3.getLogData());
                        }
                    }

                    responseData = desfireEv3.getErrorCode();
                    if (success) {
                        writeToUiAppend(output, "data is written to Backup file number " + fileIdByte);
                        // return the Transaction MAC counter and value
                        if (isTransactionMacFilePresent) {
                            byte[] returnedTmacCV = desfireEv3.getTransactionMacFileReturnedTmcv();
                            writeToUiAppend(output, printData("returned TMAC counter and value", returnedTmacCV));
                            if ((returnedTmacCV != null) && (returnedTmacCV.length == 12)) {
                                byte[] tmc = Arrays.copyOfRange(returnedTmacCV, 0, 4);
                                byte[] tmacEnc = Arrays.copyOfRange(returnedTmacCV, 4, 12);
                                int tmcInt = Utils.intFrom4ByteArrayInversed(tmc);
                                writeToUiAppend(output, "TMAC counter: " + tmcInt + printData(" tmacEnc", tmacEnc));
                            }
                        }
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                        vibrateShort();
                    } else {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit" + " FAILURE with error code: " + EV3.getErrorCode(responseData), COLOR_RED);
                        writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                        return;
                    }
                }
            }
        });

        /**
         * value file actions
         */

        fileValueRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "fileValueRead";
                writeToUiAppend(output, logString);

                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                int result = desfireEv3.readFromAValueFile(fileIdByte);
                responseData = desfireEv3.getErrorCode();
                if (result < 0) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    return;
                } else {
                    writeToUiAppend(output, logString + " ID: " + fileIdByte + " value: " + result);
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        fileValueCredit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "fileValueCredit";
                writeToUiAppend(output, logString);

                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }
                int creditValueChange = 123; // fixed for demonstration
                writeToUiAppend(output, "CREDIT the value by " + creditValueChange + " units");

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.changeAValueFile(fileIdByte, creditValueChange, true);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    if (checkBoundaryError(responseData)) {
                        writeToUiAppend(output, "as we received a Boundary Error - did you try to CREDIT upper of MAXIMUM LIMIT ?");
                        writeToUiAppend(output, "Note: you need to AUTHENTICATE again when trying to access the Value file again !");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }

                if (selectedFileSettings.getFileType() == FileSettings.VALUE_FILE_TYPE) {
                    // it is a Value file where we need to submit a commit command to confirm the write
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " is a Value file, run COMMIT");
                    byte commMode = selectedFileSettings.getCommunicationSettings();
                    if (commMode == (byte) 0x00) {
                        // Plain
                        // this fails when a Transaction MAC file with enabled Commit ReaderId option is existent
                        success = desfireEv3.commitTransactionPlain();
                    }
                    if ((commMode == (byte) 0x01) || (commMode == (byte) 0x03)) {
                        // MACed or Full enciphered
                        if (desfireEv3.isTransactionMacFilePresent()) {
                            if (desfireEv3.isTransactionMacCommitReaderId()) {
                                // this  is hardcoded when working with TransactionMAC files AND enabled CommitReaderId feature
                                writeToUiAppend(output, "A TransactionMAC file is present with ENABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFull(true);
                            } else {
                                writeToUiAppend(output, "A TransactionMAC file is present with DISABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFullReturnTmv();
                            }
                        } else {
                            // no transaction mac file is present
                            writeToUiAppend(output, "A TransactionMAC file is NOT present, running regular commitTransaction");
                            success = desfireEv3.commitTransactionWithoutTmacFull();
                            Log.d(TAG, desfireEv3.getLogData());
                        }
                    }

                    responseData = desfireEv3.getErrorCode();
                    if (success) {
                        writeToUiAppend(output, "data is written to Value file number " + fileIdByte);
                        // return the Transaction MAC counter and value
                        if (isTransactionMacFilePresent) {
                            byte[] returnedTmacCV = desfireEv3.getTransactionMacFileReturnedTmcv();
                            writeToUiAppend(output, printData("returned TMAC counter and value", returnedTmacCV));
                            if ((returnedTmacCV != null) && (returnedTmacCV.length == 12)) {
                                byte[] tmc = Arrays.copyOfRange(returnedTmacCV, 0, 4);
                                byte[] tmacEnc = Arrays.copyOfRange(returnedTmacCV, 4, 12);
                                int tmcInt = Utils.intFrom4ByteArrayInversed(tmc);
                                writeToUiAppend(output, "TMAC counter: " + tmcInt + printData(" tmacEnc", tmacEnc));
                            }
                        }
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                        vibrateShort();
                    } else {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit" + " FAILURE with error code: " + EV3.getErrorCode(responseData), COLOR_RED);
                        writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                        return;
                    }
                }
            }
        });

        fileValueDebit.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "fileValueDebit";
                writeToUiAppend(output, logString);

                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }
                int creditValueChange = 111; // fixed for demonstration
                writeToUiAppend(output, "DEBIT the value by " + creditValueChange + " units");

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.changeAValueFile(fileIdByte, creditValueChange, false);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    if (checkBoundaryError(responseData)) {
                        writeToUiAppend(output, "as we received a Boundary Error - did you try to DEBIT below MINIMUM LIMIT ?");
                        writeToUiAppend(output, "Note: you need to authenticate again when trying to access the Value file again !");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }

                if (selectedFileSettings.getFileType() == FileSettings.VALUE_FILE_TYPE) {
                    // it is a Value file where we need to submit a commit command to confirm the write
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " is a Value file, run COMMIT");
                    byte commMode = selectedFileSettings.getCommunicationSettings();
                    if (commMode == (byte) 0x00) {
                        // Plain
                        // this fails when a Transaction MAC file with enabled Commit ReaderId option is existent
                        success = desfireEv3.commitTransactionPlain();
                    }
                    if ((commMode == (byte) 0x01) || (commMode == (byte) 0x03)) {
                        // MACed or Full enciphered
                        if (desfireEv3.isTransactionMacFilePresent()) {
                            if (desfireEv3.isTransactionMacCommitReaderId()) {
                                // this  is hardcoded when working with TransactionMAC files AND enabled CommitReaderId feature
                                writeToUiAppend(output, "A TransactionMAC file is present with ENABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFull(true);
                            } else {
                                writeToUiAppend(output, "A TransactionMAC file is present with DISABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFullReturnTmv();
                            }
                        } else {
                            // no transaction mac file is present
                            writeToUiAppend(output, "A TransactionMAC file is NOT present, running regular commitTransaction");
                            success = desfireEv3.commitTransactionWithoutTmacFull();
                            Log.d(TAG, desfireEv3.getLogData());
                        }
                    }

                    responseData = desfireEv3.getErrorCode();
                    if (success) {
                        writeToUiAppend(output, "data is written to Value file number " + fileIdByte);
                        // return the Transaction MAC counter and value
                        if (isTransactionMacFilePresent) {
                            byte[] returnedTmacCV = desfireEv3.getTransactionMacFileReturnedTmcv();
                            writeToUiAppend(output, printData("returned TMAC counter and value", returnedTmacCV));
                            if ((returnedTmacCV != null) && (returnedTmacCV.length == 12)) {
                                byte[] tmc = Arrays.copyOfRange(returnedTmacCV, 0, 4);
                                byte[] tmacEnc = Arrays.copyOfRange(returnedTmacCV, 4, 12);
                                int tmcInt = Utils.intFrom4ByteArrayInversed(tmc);
                                writeToUiAppend(output, "TMAC counter: " + tmcInt + printData(" tmacEnc", tmacEnc));
                            }
                        }
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                        vibrateShort();
                    } else {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit" + " FAILURE with error code: " + EV3.getErrorCode(responseData), COLOR_RED);
                        writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                        return;
                    }
                }
            }
        });

        /**
         * record file actions - could be a Linear or Cyclic file
         */

        fileRecordRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a record file";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                int fileSizeInt = selectedFileSettings.getRecordSizeInt();

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                //byte[] result = desfireEv3.readFromARecordFile(fileIdByte, 0, fileSizeInt);
                byte[] result = desfireEv3.readFromARecordFile(fileIdByte, 0, 0);
                responseData = desfireEv3.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    if (checkBoundaryError(responseData)) {
                        writeToUiAppend(output, "as we received a Boundary Error - there might be NO records to read");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                } else {
                    // split the records
                    List<byte[]> recordList = divideArrayToList(result, selectedFileSettings.getRecordSizeInt());
                    for (int i = 0; i < recordList.size(); i++) {
                        writeToUiAppend(output, logString + " fileNumber: " + fileIdByte + " record: " + i + "\n");
                        writeToUiAppend(output, printData("\ndata", recordList.get(i)));
                        writeToUiAppend(output, "data: \n" + new String(recordList.get(i), StandardCharsets.UTF_8));
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    }
                    vibrateShort();
                }
            }
        });

        fileRecordWrite.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "write to a record file";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                int fileSizeInt = selectedFileSettings.getRecordSizeInt();

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }

                // we are going to write a timestamp to the file, filled up with testData
                byte[] fullDataToWrite = new byte[fileSizeInt];
                String dataToWrite = Utils.getTimestamp();
                byte[] dataToWriteBytes = dataToWrite.getBytes(StandardCharsets.UTF_8);
                if (dataToWriteBytes.length >= fileSizeInt) {
                    // if the file is smaller than the timestamp we do write only parts of the timestamp
                    System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, fileSizeInt);
                } else {
                    System.arraycopy(dataToWriteBytes, 0, fullDataToWrite, 0, dataToWriteBytes.length);
                    // now filling up the fullData with testData
                    byte[] testData = Utils.generateTestData(fileSizeInt - dataToWriteBytes.length);
                    System.arraycopy(testData, 0, fullDataToWrite, dataToWriteBytes.length, testData.length);
                }

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.writeToARecordFile(fileIdByte, 0, fullDataToWrite);
                responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
                if ((selectedFileSettings.getFileType() == FileSettings.LINEAR_RECORD_FILE_TYPE) || (selectedFileSettings.getFileType() == FileSettings.CYCLIC_RECORD_FILE_TYPE)) {
                    // it is a Record file where we need to submit a commit command to confirm the write
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " is a Record file, run COMMIT");
                    byte commMode = selectedFileSettings.getCommunicationSettings();
                    if (commMode == (byte) 0x00) {
                        // Plain
                        // this fails when a Transaction MAC file with enabled Commit ReaderId option is existent
                        success = desfireEv3.commitTransactionPlain();
                    }
                    if ((commMode == (byte) 0x01) || (commMode == (byte) 0x03)) {
                        // MACed or Full enciphered

                        if (desfireEv3.isTransactionMacFilePresent()) {
                            if (desfireEv3.isTransactionMacCommitReaderId()) {
                                // this  is hardcoded when working with TransactionMAC files AND enabled CommitReaderId feature
                                writeToUiAppend(output, "A TransactionMAC file is present with ENABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFull(true);
                            } else {
                                writeToUiAppend(output, "A TransactionMAC file is present with DISABLED CommitReaderId");
                                success = desfireEv3.commitTransactionFullReturnTmv();
                            }
                        } else {
                            // no transaction mac file is present
                            writeToUiAppend(output, "A TransactionMAC file is NOT present, running regular commitTransaction");
                            success = desfireEv3.commitTransactionWithoutTmacFull();
                            Log.d(TAG, desfireEv3.getLogData());
                        }
                    }

                    responseData = desfireEv3.getErrorCode();
                    if (success) {
                        writeToUiAppend(output, "data is written to Record file number " + fileIdByte);
                        // return the Transaction MAC counter and value
                        if (isTransactionMacFilePresent) {
                            byte[] returnedTmacCV = desfireEv3.getTransactionMacFileReturnedTmcv();
                            writeToUiAppend(output, printData("returned TMAC counter and value", returnedTmacCV));
                            if ((returnedTmacCV != null) && (returnedTmacCV.length == 12)) {
                                byte[] tmc = Arrays.copyOfRange(returnedTmacCV, 0, 4);
                                byte[] tmacEnc = Arrays.copyOfRange(returnedTmacCV, 4, 12);
                                int tmcInt = Utils.intFrom4ByteArrayInversed(tmc);
                                writeToUiAppend(output, "TMAC counter: " + tmcInt + printData(" tmacEnc", tmacEnc));
                            }
                        }
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit SUCCESS", COLOR_GREEN);
                        vibrateShort();
                    } else {
                        writeToUiAppendBorderColor(errorCode, errorCodeLayout, "commit" + " FAILURE with error code: " + EV3.getErrorCode(responseData), COLOR_RED);
                        writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                        return;
                    }
                }
            }
        });


        /**
         * section for authentication using Legacy authenticationEv2First in DESFire EV3 class
         */

        // there are 2 authentication methods for the Application Master Key (0x00) because this can be run without selecting a file before

        authA0DLeg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate Legacy with DEFAULT AES key number 0x00 = application master key";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.authenticateAesLegacy(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    Log.d(TAG, logString + " SUCCESS");
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                    return;
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
            }
        });

        authA0DEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with DEFAULT AES key number 0x00 = application master key";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    Log.d(TAG, logString + " SUCCESS");
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                    return;
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
            }
        });

        authA0CLeg.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate Legacy with CHANGED AES key number 0x00 = application master key";
                writeToUiAppend(output, logString);
                byte[] responseData = new byte[2];
                boolean success = desfireEv3.authenticateAesLegacy(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    Log.d(TAG, logString + " SUCCESS");
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                    return;
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
            }
        });

        authA0CEv2.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with CHANGED AES key number 0x00 = application master key";
                writeToUiAppend(output, logString);

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    Log.d(TAG, logString + " SUCCESS");
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                    return;
                } else {
                    writeToUiAppend(output, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData));
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
            }
        });

        // the application keys 1..4
        // the authentication method is choosen by the selected file communication type

        authA1D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with DEFAULT AES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_RW_NUMBER, Constants.APPLICATION_KEY_RW_AES_DEFAULT);
            }
        });

        authA1C.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with CHANGED AES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_RW_NUMBER, Constants.APPLICATION_KEY_RW_AES);
            }
        });

        authA2D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with DEFAULT AES key number 0x02 = change rights access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_CAR_NUMBER, Constants.APPLICATION_KEY_CAR_AES_DEFAULT);
            }
        });

        authA2C.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with CHANGED AES key number 0x02 = change rights access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_CAR_NUMBER, Constants.APPLICATION_KEY_CAR_AES);
            }
        });

        authA3D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with DEFAULT AES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_R_NUMBER, Constants.APPLICATION_KEY_R_AES_DEFAULT);
            }
        });

        authA3C.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with CHANGED AES key number 0x03 = read access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_R_NUMBER, Constants.APPLICATION_KEY_R_AES);
            }
        });

        authA4D.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with DEFAULT AES key number 0x04 = write access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_W_NUMBER, Constants.APPLICATION_KEY_W_AES_DEFAULT);
            }
        });

        authA4C.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "authenticate EV2 First with CHANGED AES key number 0x04 = write access key";
                writeToUiAppend(output, logString);
                // the method runs all outputs
                boolean success = authAesEv3(Constants.APPLICATION_KEY_W_NUMBER, Constants.APPLICATION_KEY_W_AES);

                /*
                // this is getting the  key from customKeystore as test
                CustomKeystore customKeystore = new CustomKeystore(view.getContext());

                boolean isInitialized = customKeystore.isLibraryInitialized();
                if (!isInitialized) {
                    customKeystore.initialize("123456".toCharArray());
                }

                List<String> keyAliasesList = customKeystore.getKeystoreAliases();

                boolean isInitializedRecovery = customKeystore.recoveryInitialization("123456".toCharArray());
                if (!isInitializedRecovery) {
                    Log.d(TAG, "Error during recovery initialization of CustomKeystore");
                    return;
                }


                byte[] keyToStore = '12345678901234567890123456789012';
                boolean writeSuccess = customKeystore.storeKey((byte) 0x02, keyToStore);
                if (!writeSuccess) {
                    Log.d(TAG, "Error during storing a key in the CustomKeystore with this key number");
                    return;
                }

                byte[] key = customKeystore.readKey(Constants.APPLICATION_KEY_W_NUMBER);
                if (key == null) {
                    writeToUiAppend(output, "There is no key stored in the CustomKeystore with this key number");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE, you did not store a key in CustomKeystore, aorted", COLOR_RED);
                    return;
                }
                boolean success = authAesEv3(Constants.APPLICATION_KEY_W_NUMBER, key);
                //boolean success = authAesEv3(Constants.APPLICATION_KEY_W_NUMBER, Constants.APPLICATION_KEY_W_AES);
                */
            }
        });

        /**
         * section for keys
         */

        changeKeyA1ToC.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change key to CHANGED for AES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);

                if (selectedApplicationId == null) {
                    writeToUiAppend(output, "You need to select an application first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                byte keyVersion = (byte) 0x01;
                boolean success = desfireEv3.changeApplicationKeyFull(Constants.APPLICATION_KEY_RW_NUMBER, keyVersion, Constants.APPLICATION_KEY_RW_AES, Constants.APPLICATION_KEY_RW_AES_DEFAULT);
                byte[] responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " keyVersion " + keyVersion + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " keyVersion " + keyVersion + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a APPLICATION MASTER KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
            }
        });

        changeKeyA1ToD.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change key to DEFAULT for AES key number 0x01 = read & write access key";
                writeToUiAppend(output, logString);
                byte keyVersion = (byte) 0x01;
                boolean success = changeApplicationKey(Constants.APPLICATION_KEY_RW_NUMBER, keyVersion, Constants.APPLICATION_KEY_RW_AES_DEFAULT, Constants.APPLICATION_KEY_RW_AES);
                byte[] responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " keyVersion " + keyVersion + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " keyVersion " + keyVersion + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a APPLICATION MASTER KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
            }
        });

        /**
         * section for file related actions
         */

        changeFileSettings0000.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change the fileSettings (all keys to 0000)";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                DesfireEv3.CommunicationSettings commSettings = selectedFileSettings.getDesfireEv3CommunicationSettings();
                // this leaves the existing communication mode settings
                int keyRw = 0;
                int keyCar = 0;
                int keyR = 0;
                int keyW = 0;
                byte[] responseData = new byte[2];
                boolean success = desfireEv3.changeFileSettings(fileIdByte, commSettings, keyRw, keyCar, keyR, keyW);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    // NOTE: don't forget to authenticate with CAR key
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(errorCode, "Did you forget to authenticate with the CAR key ?");
                    }
                }
            }
        });

        changeFileSettings1234.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "change the fileSettings (all keys to 1234 = default)";
                writeToUiAppend(output, logString);
                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);
                DesfireEv3.CommunicationSettings commSettings = selectedFileSettings.getDesfireEv3CommunicationSettings();
                // this leaves the existing communication mode settings
                int keyRw = 1;
                int keyCar = 2;
                int keyR = 3;
                int keyW = 4;
                byte[] responseData = new byte[2];
                boolean success = desfireEv3.changeFileSettings(fileIdByte, commSettings, keyRw, keyCar, keyR, keyW);
                responseData = desfireEv3.getErrorCode();
                if (success) {
                    writeToUiAppend(output, logString + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    // NOTE: don't forget to authenticate with CAR key
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(errorCode, "Did you forget to authenticate with the CAR key ?");
                    }
                }
            }
        });


        /**
         * section for Transaction MAC file handling
         */

        fileTransactionMacCreate.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a TransactionMAC file Disabled Commit ReaderId";
                writeToUiAppend(output, logString);

                byte fileIdByte = DesfireEv3.TRANSACTION_MAC_FILE_NUMBER;
                writeToUiAppend(output, "using a pre defined fileNumber: " + fileIdByte);
                writeToUiAppend(output, printData("using a predefined TMAC key", TRANSACTION_MAC_KEY_AES));
                writeToUiAppend(output, "Note: you need to authenticate with the Application Master Key and EV2-type first !");

                byte[] responseData = new byte[2];

                // this is the file creation with disabled Commit Reader Id option
                boolean success = desfireEv3.createATransactionMacFileFull(fileIdByte, DesfireEv3.CommunicationSettings.Plain, 2, 1, TRANSACTION_MAC_KEY_AES);

                // this is the file creation with enabled Commit Reader Id option
                //boolean success = desfireEv3.createATransactionMacFileExtendedFull(fileIdByte, DesfireEv3.CommunicationSettings.Plain, 1, 2, 1, true, TRANSACTION_MAC_KEY_AES);

                responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
            }
        });

        fileTransactionMacCreateReaderId.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "create a TransactionMAC file Enabled Commit ReaderId";
                writeToUiAppend(output, logString);

                byte fileIdByte = DesfireEv3.TRANSACTION_MAC_FILE_NUMBER;
                writeToUiAppend(output, "using a pre defined fileNumber: " + fileIdByte);
                writeToUiAppend(output, printData("using a predefined TMAC key", TRANSACTION_MAC_KEY_AES));
                writeToUiAppend(output, "Note: you need to authenticate with the Application Master Key and EV2-type first !");

                byte[] responseData = new byte[2];

                // this is the file creation with disabled Commit Reader Id option
                //boolean success = desfireEv3.createATransactionMacFileFull(fileIdByte, DesfireEv3.CommunicationSettings.Plain, 2, 1, TRANSACTION_MAC_KEY_AES);

                // this is the file creation with enabled Commit Reader Id option
                boolean success = desfireEv3.createATransactionMacFileExtendedFull(fileIdByte, DesfireEv3.CommunicationSettings.Plain, 1, 2, 1, true, TRANSACTION_MAC_KEY_AES);

                responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
            }
        });

        fileTransactionMacDelete.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "delete a TransactionMAC file";
                writeToUiAppend(output, logString);
                byte fileIdByte = DesfireEv3.TRANSACTION_MAC_FILE_NUMBER;
                writeToUiAppend(output, "using a pre defined fileNumber: " + fileIdByte);
                writeToUiAppend(output, printData("using a predefined TMAC key", TRANSACTION_MAC_KEY_AES));
                writeToUiAppend(output, "Note: DO NOT authenticate with the Application Master Key first !");

                byte[] responseData = new byte[2];
                boolean success = desfireEv3.deleteFile(fileIdByte);
                responseData = desfireEv3.getErrorCode();

                if (success) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " SUCCESS");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                } else {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a WRITE ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                }
            }
        });

        fileTransactionMacRead.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "read from a transaction MAC file";
                writeToUiAppend(output, logString);
                if (!isDesfireEv3Available()) return;

                // check that a file was selected before
                if (TextUtils.isEmpty(selectedFileId)) {
                    writeToUiAppend(output, "You need to select a file first, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }
                byte fileIdByte = Byte.parseByte(selectedFileId);

                // pre-check if fileNumber is existing
                boolean isFileExisting = desfireEv3.checkFileNumberExisting(fileIdByte);
                if (!isFileExisting) {
                    writeToUiAppend(output, logString + " The file does not exist, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " File not found error", COLOR_RED);
                    return;
                }

                boolean isTransactionMacFile = desfireEv3.checkIsTransactionMacFileType(fileIdByte);
                if (!isTransactionMacFile) {
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " is NOT a TransactionMAC file, aborted");
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE", COLOR_RED);
                    return;
                }

                byte[] responseData = new byte[2];
                byte[] result = desfireEv3.readFromATransactionMacFile(fileIdByte);
                responseData = desfireEv3.getErrorCode();
                if (result == null) {
                    // something gone wrong
                    writeToUiAppend(output, logString + " fileNumber " + fileIdByte + " FAILURE with error " + EV3.getErrorCode(responseData));
                    if (checkResponseMoreData(responseData)) {
                        writeToUiAppend(output, "the file is too long to read, sorry");
                    }
                    if (checkAuthenticationError(responseData)) {
                        writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a READ ACCESS KEY ?");
                    }
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                    writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
                    return;
                } else {
                    writeToUiAppend(output, logString + " fileNumber: " + fileIdByte + printData(" data", result));
                    // todo: verify tmacEnc page 64 and some more pages
                    if (result.length == 12) {
                        byte[] tmc = Arrays.copyOfRange(result, 0, 4);
                        byte[] tmacEnc = Arrays.copyOfRange(result, 4, 12);
                        int tmcInt = Utils.intFrom4ByteArrayInversed(tmc);
                        writeToUiAppend(output, "TMAC counter: " + tmcInt + printData(" tmacEnc", tmacEnc));
                    }
                    // see Mifare DESFire Light Features and Hints AN12343.pdf
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                    vibrateShort();
                }
            }
        });

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);


        /**
         * section for general handling
         */

        getTagVersion.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the tag version data
                clearOutputFields();
                String logString = "getCardVersion";
                writeToUiAppend(output, logString);

                // this predefined in the header
                // GET_VERSION_COMMAND = (byte) 0x60;

                // manually building the command string
                byte[] command = new byte[5];
                command[0] = (byte) 0x90; // fixed as trailer for wrapped commands
                command[1] = GET_VERSION_COMMAND;
                command[2] = (byte) 0x00; // is 0x00
                command[3] = (byte) 0x00; // length of data, i 0 because we do not have any additional data to send
                command[4] = (byte) 0x00; // trailing '00'
                writeToUiAppend(output, "build the getVersion command manually");
                writeToUiAppend(output, printData("command", command));

                // we are sending this command to the PICC
                byte[] response = new byte[0];
                try {
                    response = isoDep.transceive(command);
                    writeToUiAppend(output, printData("response from PICC", response));
                } catch (NullPointerException e) {
                    Log.e(TAG, logString + " transceive failed, NullPointerException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed, did you forget to tap a tag first ? : " + e.getMessage());
                    return;
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    return;
                }
                // example response: length: 9 data: 0401013300160591af

                writeToUiAppend(output, "we received two information's from PICC:");
                byte[] responseData1 = Arrays.copyOfRange(response, 0, response.length - 2);
                byte[] responseStatus1 = Arrays.copyOfRange(response, response.length - 2, response.length);
                writeToUiAppend(output, printData("responseData1", responseData1));
                writeToUiAppend(output, printData("responseStatus1", responseStatus1));

                // check for status == '0x90af
                final byte[] statusMoreData = new byte[]{(byte) 0x91, (byte) 0xAF};
                // check for status == '0x00
                final byte[] statusOk = new byte[]{(byte) 0x91, (byte) 0x00};

                boolean isResponseStatus1MoreData = Arrays.equals(responseStatus1, statusMoreData);
                writeToUiAppend(output, "checking that more data will follow from PICC: " + isResponseStatus1MoreData);
                if (!isResponseStatus1MoreData) {
                    writeToUiAppend(output, "no more data following, end requesting more data");
                    return;
                }

                // now we are asking to get more data from PICC

                // this predefined in the header
                // MORE_DATA_COMMAND = (byte) 0xAF;

                // manually building the command string
                command = new byte[5];
                command[0] = (byte) 0x90; // fixed as trailer for wrapped commands
                command[1] = MORE_DATA_COMMAND;
                command[2] = (byte) 0x00; // is 0x00
                command[3] = (byte) 0x00; // length of data, i 0 because we do not have any additional data to send
                command[4] = (byte) 0x00; // trailing '00'
                writeToUiAppend(output, "build the getMoreData command manually");
                writeToUiAppend(output, printData("command", command));

                // we are sending this command to the PICC
                response = new byte[0];
                try {
                    response = isoDep.transceive(command);
                    writeToUiAppend(output, printData("response from PICC", response));
                } catch (NullPointerException e) {
                    Log.e(TAG, logString + " transceive failed, NullPointerException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed, did you forget to tap a tag first ? : " + e.getMessage());
                    return;
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    return;
                }
                // example response: length: 9 data: 0401010300160591af

                writeToUiAppend(output, "we received two information's from PICC:");
                byte[] responseData2 = Arrays.copyOfRange(response, 0, response.length - 2);
                byte[] responseStatus2 = Arrays.copyOfRange(response, response.length - 2, response.length);
                writeToUiAppend(output, printData("responseData2", responseData2));
                writeToUiAppend(output, printData("responseStatus2", responseStatus2));

                // check for status == '0x90af
                boolean isResponseStatus2MoreData = Arrays.equals(responseStatus2, statusMoreData);
                writeToUiAppend(output, "checking that more data will follow from PICC: " + isResponseStatus2MoreData);
                if (!isResponseStatus2MoreData) {
                    writeToUiAppend(output, "no more data following, end requesting more data");
                    return;
                }

                // now we are asking to get more data from PICC a second time

                // this predefined in the header
                // MORE_DATA_COMMAND = (byte) 0xAF;

                // manually building the command string
                command = new byte[5];
                command[0] = (byte) 0x90; // fixed as trailer for wrapped commands
                command[1] = MORE_DATA_COMMAND;
                command[2] = (byte) 0x00; // is 0x00
                command[3] = (byte) 0x00; // length of data, i 0 because we do not have any additional data to send
                command[4] = (byte) 0x00; // trailing '00'
                writeToUiAppend(output, "build the getMoreData command manually");
                writeToUiAppend(output, printData("command", command));

                // we are sending this command to the PICC
                response = new byte[0];
                try {
                    response = isoDep.transceive(command);
                    writeToUiAppend(output, printData("response from PICC", response));
                } catch (NullPointerException e) {
                    Log.e(TAG, logString + " transceive failed, NullPointerException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed, did you forget to tap a tag first ? : " + e.getMessage());
                    return;
                } catch (IOException e) {
                    Log.e(TAG, logString + " transceive failed, IOException:\n" + e.getMessage());
                    writeToUiAppend(output, "transceive failed: " + e.getMessage());
                    return;
                }
                // example response: length: 16 data: 04597a32501490204664303048229100

                writeToUiAppend(output, "we received two information's from PICC:");
                byte[] responseData3 = Arrays.copyOfRange(response, 0, response.length - 2);
                byte[] responseStatus3 = Arrays.copyOfRange(response, response.length - 2, response.length);
                writeToUiAppend(output, printData("responseData3", responseData3));
                writeToUiAppend(output, printData("responseStatus3", responseStatus3));

                // check for status == '0x90af
                boolean isResponseStatus3MoreData = Arrays.equals(responseStatus3, statusMoreData);
                writeToUiAppend(output, "checking that more data will follow from PICC: " + isResponseStatus3MoreData);
                if (isResponseStatus3MoreData) {
                    writeToUiAppend(output, "no more data following, end requesting more data");
                    return;
                }

                // check for status == '0x9000
                boolean isResponseStatus3Ok = Arrays.equals(responseStatus3, statusOk);
                writeToUiAppend(output, "checking that the status is OK" + isResponseStatus3Ok);
                if (!isResponseStatus3Ok) {
                    writeToUiAppend(output, "final status is not '0x9100', aborted");
                    return;
                }
                // now the status is OK and we can analyze the  data
                writeToUiAppend(output, "The final status is '0x9100' means SUCCESS");

                // concatenate the 3 parts
                writeToUiAppend(output, "concatenate the 3 response parts");
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                baos.write(responseData1, 0, responseData1.length);
                baos.write(responseData2, 0, responseData2.length);
                baos.write(responseData3, 0, responseData3.length);
                byte[] responseData = baos.toByteArray();
                writeToUiAppend(output, printData("complete responseData", responseData));
                // example length: 28 data: 040101330016050401010300160504597a3250149020466430304822

                // for analysis see the document MIFARE DESFire Light contactless application IC MF2DLHX0.pdf
                // on pages 67 - 69

                // to identify the hardware type see Mifare type identification procedure AN10833.pdf page 5

                // taking just some elements
                byte hardwareType = responseData[1];
                byte hardwareStorageSize = responseData[5];
                byte weekProduction = responseData[26];
                byte yearProduction = responseData[27];

                String hardwareTypeName = " is not a Mifare DESFire tag";
                if (hardwareType == (byte) 0x01) hardwareTypeName = " is a Mifare DESFire tag";
                int hardwareStorageSizeInt = (int) Math.pow(2, hardwareStorageSize >> 1); // get the storage size in bytes

                writeToUiAppend(output, "hardwareType: " + Utils.byteToHex(hardwareType) + hardwareTypeName);
                writeToUiAppend(output, "hardwareStorageSize (byte): " + Utils.byteToHex(hardwareStorageSize));
                writeToUiAppend(output, "hardwareStorageSize (int): " + hardwareStorageSizeInt);
                writeToUiAppend(output, "weekProduction: " + Utils.byteToHex(weekProduction));
                writeToUiAppend(output, "yearProduction: " + Utils.byteToHex(yearProduction));

                vibrateShort();
            }
        });


        formatPicc.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // get the free memory on the tag
                clearOutputFields();
                String logString = "format the PICC";
                writeToUiAppend(output, logString);

                // open a confirmation dialog
                DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialog, int which) {
                        switch (which) {
                            case DialogInterface.BUTTON_POSITIVE:
                                //Yes button clicked

                                boolean success = desfireAuthenticateLegacy.formatPicc();
                                byte[] responseData = desfireAuthenticateLegacy.getErrorCode();
                                if (success) {
                                    writeToUiAppend(output, logString + " SUCCESS");
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " SUCCESS", COLOR_GREEN);
                                    vibrateShort();
                                } else {
                                    writeToUiAppend(output, logString + " FAILURE with error " + EV3.getErrorCode(responseData));
                                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, logString + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
                                }
                                break;
                            case DialogInterface.BUTTON_NEGATIVE:
                                //No button clicked
                                // nothing to do
                                writeToUiAppend(output, "format of the PICC aborted");
                                break;
                        }
                    }
                };
                final String selectedFolderString = "You are going to format the PICC " + "\n\n" +
                        "Do you want to proceed ?";
                AlertDialog.Builder builder = new AlertDialog.Builder(MainActivity.this);

                builder.setMessage(selectedFolderString).setPositiveButton(android.R.string.yes, dialogClickListener)
                        .setNegativeButton(android.R.string.no, dialogClickListener)
                        .setTitle("FORMAT the PICC")
                        .show();
        /*
        If you want to use the "yes" "no" literals of the user's language you can use this
        .setPositiveButton(android.R.string.yes, dialogClickListener)
        .setNegativeButton(android.R.string.no, dialogClickListener)
         */
            }
        });

        /**
         * section for tests
         */

        test.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                clearOutputFields();
                String logString = "Test change Main Application Key to AES DEFAULT";
                writeToUiAppend(output, logString);

                boolean success;
                String stepString = "1 select Master Application";
                success = desfireAuthenticateLegacy.selectApplication(DesfireAuthenticateLegacy.MASTER_APPLICATION_IDENTIFIER);
                writeToUiAppend(output, stepString + " success ? : " + success);
                if (!success) return;

                /*
                // this is DES to AES
                stepString = "2 authenticate Master Application with DEFAULT DES key";
                success = desfireAuthenticateLegacy.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT);
                writeToUiAppend(output, stepString + " success ? : " + success);
                if (!success) return;

                stepString = "3 change Master Application Key 00 from DES DEFAULT to AES DEFAULT";
                success = desfireAuthenticateLegacy.changeDesKeyToAes(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_AES_DEFAULT, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, "Master App Key");
                writeToUiAppend(output, stepString + " success ? : " + success);
                if (!success) return;
                */

                // this is AES to DES
                stepString = "2 authenticate Master Application with DEFAULT AES key";
                byte[] responseData = new byte[2];
                success = desfireAuthenticateLegacy.authenticateAes(null, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_AES_DEFAULT, false, responseData);
                writeToUiAppend(output, stepString + " success ? : " + success);
                if (!success) return;

                stepString = "3 change Master Application Key 00 from AES DEFAULT to DES DEFAULT";
                success = desfireAuthenticateLegacy.changeAesKeyToDes(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, Constants.MASTER_APPLICATION_KEY_AES_DEFAULT, "Master App Key");
                //success = desfireEv3.changeApplicationKeyToDesFull(Constants.MASTER_APPLICATION_KEY_NUMBER, (byte) 0x00, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, Constants.MASTER_APPLICATION_KEY_AES_DEFAULT);
                writeToUiAppend(output, stepString + " success ? : " + success);
                if (!success) return;


            }

        });

    }

    /**
     * section for dialogs
     */

    private void showDialogWarningCommitReaderId() {
        String tmacWarningMessage = "SERIOUS WARNING\n\n" +
                "This application does contain a Transaction MAC file with ENABLED Commit ReaderId feature.\n" +
                "All WRITE operations to a Backup, Value, Linear or Cyclic Record file does need an additional COMMIT READER ID command.\n" +
                "This command is available for communication modes MACed and Full ONLY.\n\n" +
                "You CANNOT WRITE to Backup, Value, Linear or Cyclic Record files in PLAIN communication mode.\n\n" +
                "ALL write commands to a Backup, Value or Record files in PLAIN communication will FAIL !";
        showDialog(MainActivity.this, tmacWarningMessage);
    }

    private void showDialogWarningDesfireEv1() {
        String desfireEv1WarningMessage = "SERIOUS WARNING\n\n" +
                "The tag you are tapping is a Mifare DESFire EV1 tag that does not support the AuthenticateEV2First command.\n" +
                "All AUTHENTICATE operations to a file with Communication Mode MACed and Full enciphered will FAIL\n" +
                "The operations on Plain files will probably run (not tested)\n\n";
        showDialog(MainActivity.this, desfireEv1WarningMessage);
    }

    /**
     * section for AES authentication with EV3
     */

    /**
     * Checks for the communication mode of the selected file number:
     * case Plain: uses authenticateAesLegacy method (no encryption needed)
     * case Full: uses authenticateEv2First method (generate SessionKeys for encryption and decryption)
     *
     * @param keyNumber            | in range 0..13
     * @param keyForAuthentication | AES-128 key, 16 bytes length
     * @return
     */

    private boolean authAesEv3(byte keyNumber, byte[] keyForAuthentication) {
        final String methodName = "authAesEv3";
        Log.d(TAG, methodName);
        writeToUiAppend(output, methodName);
        if (selectedApplicationId == null) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
            return false;
        }
        if (selectedFileSettings == null) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select a file first", COLOR_RED);
            return false;
        }
        // sanity checks
        if ((keyNumber < 0) || keyNumber > 13) {
            Log.e(TAG, "the keyNumber is not in range 0..13, aborted");
            return false;
        }
        if ((keyForAuthentication == null) || (keyForAuthentication.length != 16)) {
            Log.e(TAG, "the keyForAuthentication is NULL or not of length 16, aborted");
            return false;
        }
        byte[] responseData = new byte[2];
        boolean success = false;
        byte commMode = selectedFileSettings.getCommunicationSettings();
        Log.d(TAG, "commMode: " + commMode);
        if (commMode == (byte) 0x00) {
            // Plain
            // as some tasks like changeFileSettings require an authenticationEv2First a switch is
            // visible when a plain file was selected. Here we are checking the state of the switch
            if ((swAuthenticateEv2First.getVisibility() == View.VISIBLE) && (swAuthenticateEv2First.isChecked())) {
                // the switch is visible and checked
                writeToUiAppend(output, methodName + " Using authenticateEv2First instead");
                success = desfireEv3.authenticateAesEv2First(keyNumber, keyForAuthentication);
            } else {
                // the switch is visible but not checked
                success = desfireEv3.authenticateAesLegacy(keyNumber, keyForAuthentication);
            }
        }
        if (commMode == (byte) 0x01) {
            // MACed
            success = desfireEv3.authenticateAesEv2First(keyNumber, keyForAuthentication);
        }
        if (commMode == (byte) 0x03) {
            // Full enciphered
            success = desfireEv3.authenticateAesEv2First(keyNumber, keyForAuthentication);
        }
        responseData = desfireEv3.getErrorCode();
        if (success) {
            Log.d(TAG, methodName + " SUCCESS");
            writeToUiAppend(output, methodName + " SUCCESS");
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, methodName + " SUCCESS", COLOR_GREEN);
            vibrateShort();
            return true;
        } else {
            writeToUiAppend(output, methodName + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData));
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, methodName + " FAILURE", COLOR_RED);
            return false;
        }
    }

    /**
     * section for keys
     */

    private boolean changeApplicationKey(byte keyNumber, byte keyVersion, byte[] keyNew, byte[] keyOld) {
        final String methodName = "changeApplicationKey";
        Log.d(TAG, methodName);
        writeToUiAppend(output, methodName);
        if (selectedApplicationId == null) {
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "you need to select an application first", COLOR_RED);
            return false;
        }

        boolean success = desfireEv3.changeApplicationKeyFull(keyNumber, keyVersion, keyNew, keyOld);
        byte[] responseData = desfireEv3.getErrorCode();

        if (success) {
            writeToUiAppend(output, methodName + " keyVersion " + keyVersion + " SUCCESS");
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, methodName + " SUCCESS", COLOR_GREEN);
            vibrateShort();
            return true;
        } else {
            writeToUiAppend(output, methodName + " keyVersion " + keyVersion + " FAILURE with error " + EV3.getErrorCode(responseData));
            if (checkAuthenticationError(responseData)) {
                writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a APPLICATION MASTER KEY ?");
            }
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, methodName + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
            writeToUiAppend(errorCode, "Error reason: " + desfireEv3.getErrorCodeReason());
            return false;
        }
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
     * checks if the response has an 0x'91BE' at the end means
     * that a change on a value in a Value file (credit or debit) exceeds a limit
     * if any other trailing bytes show up the method returns false
     *
     * @param data
     * @return
     */
    private boolean checkBoundaryError(@NonNull byte[] data) {
        // simple sanity check
        if (data.length < 2) {
            return false;
        } // not ok
        if (Arrays.equals(RESPONSE_BOUNDARY_ERROR, returnStatusBytes(data))) {
            return true;
        } else {
            return false;
        }
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
                    allLayoutsInvisible();
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor(errorCode, errorCodeLayout, "could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }

                desfireAuthenticateLegacy = new DesfireAuthenticateLegacy(isoDep, true); // true means all data is logged
                desfireEv3 = new DesfireEv3(isoDep);

                if (desfireEv3 != null) {
                    runOnUiThread(() -> {
                        boolean isDesfireEv1 = desfireEv3.checkForDESFireEv1();
                        if (isDesfireEv1) {
                            showDialogWarningDesfireEv1();
                            writeToUiAppend(output, "The tag you are tapping is a Mifare DESFire EV1 tag that does not support the AuthenticateEV2First command.\n" +
                                    "All AUTHENTICATE operations to a file with Communication Mode MACed and Full enciphered will FAIL\n" +
                                    "The operations on Plain files will probably run (not tested)\n\n");
                        }
                    });
                }

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
     * checks
     */

    /**
     * checks if the DesfireEv3 class is initialized by tapping a tag
     *
     * @return
     */

    private boolean isDesfireEv3Available() {
        if (desfireEv3 != null) {
            return true;
        } else {
            writeToUiAppend(output, "please tap a DESFire tag to the reader, aborted");
            writeToUiAppendBorderColor(errorCode, errorCodeLayout, "FAILURE - DesfireEv3 class not initialzed", COLOR_RED);
            return false;
        }
    }

    /**
     * section for layout handling
     */
    private void allLayoutsInvisible() {
        //llApplicationHandling.setVisibility(View.GONE);
        llSectionDataFiles.setVisibility(View.GONE);
        llSectionValueFiles.setVisibility(View.GONE);
        llSectionRecordFiles.setVisibility(View.GONE);
        llSectionAuthentication.setVisibility(View.GONE);
        llSectionChangeKey.setVisibility(View.GONE);
        llSectionFileActions.setVisibility(View.GONE);
        llSectionFileActions.setVisibility(View.GONE);
        swAuthenticateEv2First.setVisibility(View.GONE);
        swAuthenticateEv2First.setChecked(false);
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

    private void writeToUiToast(String message) {
        runOnUiThread(() -> {
            Toast.makeText(getApplicationContext(),
                    message,
                    Toast.LENGTH_SHORT).show();
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
        selectedFileType = -1;
        runOnUiThread(() -> {
            applicationSelected.setText("");
            fileSelected.setText("");
        });
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
     * section OptionsMenu export text file methods
     */

    private void exportTextFile() {
        //provideTextViewDataForExport(etLog);
        if (TextUtils.isEmpty(exportString)) {
            writeToUiToast("Log some data before writing files :-)");
            return;
        }
        writeStringToExternalSharedStorage();
    }

    private void writeStringToExternalSharedStorage() {
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        // Optionally, specify a URI for the file that should appear in the
        // system file picker when it loads.
        // boolean pickerInitialUri = false;
        // intent.putExtra(DocumentsContract.EXTRA_INITIAL_URI, pickerInitialUri);
        // get filename from edittext
        String filename = exportStringFileName;
        // sanity check
        if (filename.equals("")) {
            writeToUiToast("scan a tag before writing the content to a file :-)");
            return;
        }
        intent.putExtra(Intent.EXTRA_TITLE, filename);
        selectTextFileActivityResultLauncher.launch(intent);
    }

    ActivityResultLauncher<Intent> selectTextFileActivityResultLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(),
            new ActivityResultCallback<ActivityResult>() {
                @Override
                public void onActivityResult(ActivityResult result) {
                    if (result.getResultCode() == Activity.RESULT_OK) {
                        // There are no request codes
                        Intent resultData = result.getData();
                        // The result data contains a URI for the document or directory that
                        // the user selected.
                        Uri uri = null;
                        if (resultData != null) {
                            uri = resultData.getData();
                            // Perform operations on the document using its URI.
                            try {
                                // get file content from edittext
                                String fileContent = exportString;
                                System.out.println("## data to write: " + exportString);
                                writeTextToUri(uri, fileContent);
                                writeToUiToast("file written to external shared storage: " + uri.toString());
                            } catch (IOException e) {
                                e.printStackTrace();
                                writeToUiToast("ERROR: " + e.toString());
                                return;
                            }
                        }
                    }
                }
            });

    private void writeTextToUri(Uri uri, String data) throws IOException {
        try {
            System.out.println("** data to write: " + data);
            OutputStreamWriter outputStreamWriter = new OutputStreamWriter(getApplicationContext().getContentResolver().openOutputStream(uri));
            outputStreamWriter.write(data);
            outputStreamWriter.close();
        } catch (IOException e) {
            System.out.println("Exception File write failed: " + e.toString());
        }
    }

    /**
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_activity_main, menu);

        MenuItem mFormatPicc = menu.findItem(R.id.action_format_picc);
        mFormatPicc.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(MainActivity.this, FormatPiccActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mSetupTestEnvironment = menu.findItem(R.id.action_setup_test_environment);
        mSetupTestEnvironment.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(MainActivity.this, SetupTestEnvironmentActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mPersonalize = menu.findItem(R.id.action_personalize);
        mPersonalize.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(MainActivity.this, PersonalizeActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mCreateApplication = menu.findItem(R.id.action_create_application);
        mCreateApplication.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(MainActivity.this, CreateApplicationActivity.class);
                startActivity(intent);
                return false;
            }
        });

        MenuItem mCreateFile = menu.findItem(R.id.action_create_file);
        mCreateFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(MainActivity.this, CreateFileActivity.class);
                startActivity(intent);
                return false;
            }
        });


        MenuItem mExportTextFile = menu.findItem(R.id.action_export_text_file);
        mExportTextFile.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Log.i(TAG, "mExportTextFile");
                exportTextFile();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

    public void showDialog(Activity activity, String msg) {
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