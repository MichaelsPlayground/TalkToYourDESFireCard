package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.MainActivity.APPLICATION_KEY_MASTER_AES_DEFAULT;
import static de.androidcrypto.talktoyourdesfirecard.MainActivity.APPLICATION_KEY_MASTER_NUMBER;
import static de.androidcrypto.talktoyourdesfirecard.Utils.printData;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultCallback;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
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
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.LinearLayout;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.io.OutputStreamWriter;

public class ActivateSdmActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = ActivateSdmActivity.class.getName();

    /**
     * UI elements
     */
    private LinearLayout llUrl;
    private com.google.android.material.textfield.TextInputEditText output, etCommunicationSettings, etAccessRights;
    private com.google.android.material.textfield.TextInputEditText etSdmReadCounterLimit, etSdmAccessRights, etBaseUrl, etTemplateUrl;
    private com.google.android.material.textfield.TextInputLayout outputLayout, etSdmReadCounterLimitLayout, etSdmAccessRightsLayout;
    private RadioGroup rgStatus;
    private RadioButton rbActivateSdmGetStatus, rbActivateSdmOn, rbActivateSdmOff;
    private CheckBox cbSdmEnabled, cbAsciiEncoding, cbUidMirror, cbReadCounterMirror, cbUidReadCounterEncrypted, cbReadCounterLimit, cbEncryptedFileDataMirror;

    /**
     * general constants
     */

    private byte[] NDEF_APPLICATION_ID = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x00};
    private byte NDEF_FILE_ID = (byte) 0x02;
    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);


    // variables for NFC handling
    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;
    private DesfireEv3Light desfireEv3;
    private FileSettings fileSettings;
    private boolean isEncryptedPiccData = false;
    private boolean isDesfireEv3 = false;

    // general variables

    // todo remove with OptionMenu
    private String exportString = "Desfire Authenticate Legacy"; // takes the log data for export
    private String exportStringFileName = "auth.html"; // takes the log data for export

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_activate_sdm);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etActivateSdmOutput);
        outputLayout = findViewById(R.id.etActivateSdmOutputLayout);

        llUrl = findViewById(R.id.llUrlSettings);
        rgStatus = findViewById(R.id.rgActivateSdmStatus);
        rbActivateSdmGetStatus = findViewById(R.id.rbActivateSdmShowStatus);
        rbActivateSdmOn = findViewById(R.id.rbActivateSdmOn);
        rbActivateSdmOff = findViewById(R.id.rbActivateSdmOff);

        etCommunicationSettings = findViewById(R.id.etActivateSdmCommunicationSettings);
        etAccessRights = findViewById(R.id.etActivateSdmAccessRights);
        cbSdmEnabled = findViewById(R.id.cbActivateSdmAccessSdmEnabled);
        cbAsciiEncoding = findViewById(R.id.cbActivateSdmAsciiEncoding);
        cbUidMirror = findViewById(R.id.cbActivateSdmUidMirror);
        cbReadCounterMirror = findViewById(R.id.cbActivateSdmReadCounterMirror);
        cbUidReadCounterEncrypted = findViewById(R.id.cbActivateSdmUidReadCounterEncrypted);
        cbReadCounterLimit = findViewById(R.id.cbActivateSdmReadCounterLimit);
        cbEncryptedFileDataMirror = findViewById(R.id.cbActivateSdmEncryptedFileDataMirror);
        etSdmReadCounterLimit = findViewById(R.id.etActivateSdmReadCounterLimit);
        etSdmReadCounterLimitLayout = findViewById(R.id.etActivateSdmAccessReadCounterLimitLayout);
        etSdmAccessRights = findViewById(R.id.etActivateSdmSdmAccessRights);
        etSdmAccessRightsLayout = findViewById(R.id.etActivateSdmAccessSdmAccessRightsLayout);
        etBaseUrl = findViewById(R.id.etActivateSdmBaseUrl);
        etTemplateUrl = findViewById(R.id.etActivateSdmTemplateUrl);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        etBaseUrl.setText(NdefForSdm.SAMPLE_BASE_URL);

        showSdmParameter(false);
        clickableSdmParameter(false);

        // get status on what to do
        int checkedRadioButtonId = rgStatus.getCheckedRadioButtonId();
        rgStatus.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(RadioGroup radioGroup, int id) {
                if (id == R.id.rbActivateSdmOn) {
                    Log.d(TAG, "rb Activate On");
                    llUrl.setVisibility(View.VISIBLE);
                    showSdmParameter(true);
                    clickableSdmParameter(true);
                    etSdmAccessRightsLayout.setVisibility(View.VISIBLE);
                    etSdmReadCounterLimitLayout.setVisibility(View.GONE);
                    cbSdmEnabled.setChecked(true);
                    etCommunicationSettings.setText("Plain communication"); // fixed
                    etAccessRights.setText("RW: 0 | CAR: 0 | R: 14 | W:0"); // fixed
                } else if (id == R.id.rbActivateSdmOff) {
                    Log.d(TAG, "rb Activate Off");
                    llUrl.setVisibility(View.GONE);
                    showSdmParameter(false);
                    clickableSdmParameter(false);
                    etSdmAccessRightsLayout.setVisibility(View.GONE);
                    etSdmReadCounterLimitLayout.setVisibility(View.GONE);
                    cbSdmEnabled.setChecked(false);
                    etCommunicationSettings.setText("Plain communication"); // fixed
                    etAccessRights.setText("RW: 0 | CAR: 0 | R: 14 | W:0"); // fixed
                } else if (id == R.id.rbActivateSdmShowStatus) {
                    Log.d(TAG, "rb Show Status");
                    llUrl.setVisibility(View.GONE);
                    showSdmParameter(true);
                    clickableSdmParameter(false);
                    etSdmAccessRightsLayout.setVisibility(View.VISIBLE);
                    cbSdmEnabled.setChecked(false);
                }
            }
        });

        // checking on setReadCounterLimit
        cbReadCounterLimit.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                if (cbReadCounterLimit.isChecked()) {
                    etSdmReadCounterLimitLayout.setVisibility(View.VISIBLE);
                    etSdmReadCounterLimit.setVisibility(View.VISIBLE);
                    etSdmReadCounterLimit.setText("16777214");
                    //etSdmReadCounterLimit.setFocusable(true);
                } else {
                    etSdmReadCounterLimitLayout.setVisibility(View.GONE);
                    etSdmReadCounterLimit.setVisibility(View.GONE);
                    etSdmReadCounterLimit.setText("0");
                    //etSdmReadCounterLimit.setFocusable(false);
                }
            }
        });

        // checking on UidReadCounterEncrypted
        cbUidReadCounterEncrypted.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override
            public void onCheckedChanged(CompoundButton compoundButton, boolean b) {
                String metaRight;
                if (cbUidReadCounterEncrypted.isChecked()) {
                    metaRight = "3";
                } else {
                    metaRight = "14";
                }
                StringBuilder sbSdmAccessRights = new StringBuilder();
                sbSdmAccessRights.append("Meta Read: ").append(metaRight);
                sbSdmAccessRights.append(" | File Read: ").append("3");
                sbSdmAccessRights.append(" | Counter Read: ").append("3");
                writeToUi(etSdmAccessRights, sbSdmAccessRights.toString());
                if (cbUidReadCounterEncrypted.isChecked()) {
                    cbUidMirror.setChecked(true);
                    cbReadCounterMirror.setChecked(true);
                    cbUidMirror.setClickable(false);
                    cbReadCounterMirror.setClickable(false);
                } else {
                    cbUidMirror.setChecked(false);
                    cbReadCounterMirror.setChecked(false);
                    cbUidMirror.setClickable(true);
                    cbReadCounterMirror.setClickable(true);
                }
            }
        });

    }

    /**
     * get file settings from tag
     * This is using a fixed applicationId of '0x010000' and a fixed fileId of '0x02'
     * There are 3 steps to get the file settings:
     * 1) select the NDEF application
     * 2) authenticate with Application Master Key
     * 3) get the fileSettings
     */

    private void getFileSettings() {
        // clearOutputFields();
        //
        writeToUiAppend("get FileSettings for fileId 0x02");
        writeToUiAppend("step 1: select application with ID 0x010000");
        boolean success = desfireEv3.selectApplicationByAid(NDEF_APPLICATION_ID);
        byte[] responseData;
        responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("selection of the application SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("selection of the application FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }
        //writeToUiAppend("step 2: authenticate with default Application Master Key");

        //writeToUiAppend("step 3: get the file settings for file ID 0x02");
        writeToUiAppend("step 2: get the file settings for file ID 0x02");
        byte[] response = desfireEv3.getFileSettings(NDEF_FILE_ID);
        responseData = desfireEv3.getErrorCode();
        if (response == null) {
            writeToUiAppendBorderColor("get the file settings for file ID 0x02 FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }
        fileSettings = new FileSettings(NDEF_FILE_ID, response);
        writeToUiAppendBorderColor(fileSettings.dump(), COLOR_GREEN);
        vibrateShort();

/*
sample data with enabled SDM
fileNumber: 02
fileType: 0 (Standard)
communicationSettings: 00 (Plain)
accessRights RW | CAR: 00
accessRights R | W: E0
accessRights RW:  0
accessRights CAR: 0
accessRights R:   14
accessRights W:   0
fileSize: 256
non standard fileOption found
sdmFileOption: 40
isSdmEnabled: true
isSdmOptionsBit0_Encode: true
isSdmOptionsBit4_SDMENCFileData: true
isSdmOptionsBit5_SDMReadCtrLimit: false
isSdmOptionsBit6_SDMReadCtr: true
isSdmOptionsBit7_UID: true
SDM_AccessRights: F111
SDM_MetaReadAccessRight: 01
SDM_FileReadAccessRight: 01
SDM_CtrRetAccessRight: 01
optional values depending on bit settings (LSB)
SDM_UIDOffset
SDM_ReadCtrOffset
SDM_PICCDataOffset 2A0000
SDM_MACInputOffset 4F0000
SDM_ENCOffset      4F0000
SDM_ENCLength      200000
SDM_MACOffset      750000
SDM_ReadCtrLimit

sample data with disabled SDM

 */

        // now we analyze the data
        if (fileSettings != null) {
            // communication settings (Plain / MACed / Full)
            String communicationSettings = fileSettings.getCommunicationSettingsName();
            writeToUi(etCommunicationSettings, communicationSettings + " communication");

            // access rights RW || CAR || R || W
            StringBuilder sbAccessRights = new StringBuilder();
            sbAccessRights.append("RW: ").append(fileSettings.getAccessRightsRw());
            sbAccessRights.append(" | CAR: ").append(fileSettings.getAccessRightsCar());
            sbAccessRights.append(" | R: ").append(fileSettings.getAccessRightsR());
            sbAccessRights.append(" | W: ").append(fileSettings.getAccessRightsW());
            writeToUi(etAccessRights, sbAccessRights.toString());

            // SDM enabled
            boolean isSdmEnabled = fileSettings.isSdmEnabled();
            if (isSdmEnabled) {
                cbSdmEnabled.setChecked(true);
                showSdmParameter(true);
            } else {
                cbSdmEnabled.setChecked(false);
                showSdmParameter(false);
            }

            if (isSdmEnabled) {
                // ASCII encode
                cbAsciiEncoding.setChecked(fileSettings.isSdmOptionsBit0_Encode());

                // UID mirror active
                cbUidMirror.setChecked(fileSettings.isSdmOptionsBit7_UID());

                // ReadCounter mirror active
                cbReadCounterMirror.setChecked(fileSettings.isSdmOptionsBit6_SDMReadCtr());

                // ReadCounterLimit active
                cbReadCounterLimit.setChecked(fileSettings.isSdmOptionsBit5_SDMReadCtrLimit());
                if (cbReadCounterLimit.isChecked()) {
                    int readCounterLimit = Utils.intFrom3ByteArrayInversed(fileSettings.getSDM_ReadCtrLimit());
                    etSdmReadCounterLimitLayout.setVisibility(View.VISIBLE);
                    etSdmReadCounterLimit.setVisibility(View.VISIBLE);
                    runOnUiThread(() -> {
                        etSdmReadCounterLimit.setText(String.valueOf(readCounterLimit));
                    });
                } else {
                    runOnUiThread(() -> {
                        etSdmReadCounterLimitLayout.setVisibility(View.GONE);
                        etSdmReadCounterLimit.setVisibility(View.GONE);
                    });
                }

                // UID and/or Read Counter data Encrypted
                // this option depends on SDMMetaRead access right = 0h..4h -> encrypted [value for NTAG 424 DNA]
                byte sdmMetaReadAccessKey = fileSettings.getSDM_MetaReadAccessRight();
                isEncryptedPiccData = false;
                if (sdmMetaReadAccessKey < (byte) 0x0E) {
                    cbUidReadCounterEncrypted.setChecked(true);
                    isEncryptedPiccData = true;
                } else {
                    cbUidReadCounterEncrypted.setChecked(false);
                    isEncryptedPiccData = false;
                }

                // SDMENC mirror active
                cbEncryptedFileDataMirror.setChecked(fileSettings.isSdmOptionsBit4_SDMENCFileData());

                // SDM access rights Meta Data Read || File Read || Counter Reading
                StringBuilder sbSdmAccessRights = new StringBuilder();
                sbSdmAccessRights.append("Meta Read: ").append(fileSettings.getSDM_MetaReadAccessRight());
                sbSdmAccessRights.append(" | File Read: ").append(fileSettings.getSDM_FileReadAccessRight());
                sbSdmAccessRights.append(" | Counter Read: ").append(fileSettings.getSDM_CtrRetAccessRight());
                writeToUi(etSdmAccessRights, sbSdmAccessRights.toString());

                if (isSdmEnabled) {
                    writeToUiAppend("Secure Dynamic Messages (SDM) / SUN is ENABLED");
                } else {
                    writeToUiAppend("Secure Dynamic Messages (SDM) / SUN is DISABLED");
                }
                ;
            } else {
                // unset all checkboxes and edit text
                //cbAsciiEncoding.setChecked(false);
                cbUidMirror.setChecked(false);
                cbReadCounterMirror.setChecked(false);
                cbReadCounterLimit.setChecked(false);
                cbEncryptedFileDataMirror.setChecked(false);
                //cbAsciiEncoding.setChecked(false);
                writeToUi(etSdmAccessRights, "no rights are set");
            }
        }
    }

    /**
     * Enabling  the SDM/SUN feature
     * This is using a fixed applicationId of '0x010000' and a fixed fileId of '0x02'
     * The method will run an authenticateEv2First command with default Application Master Key (zeroed AES-128 key)
     * <p>
     * steps:
     * 1) select applicationId '0x010000'
     * 2) authenticateFirstEv2 with default Application Master Key (zeroed AES-128 key)
     * 3) change file settings on fileId '0x02' with these parameters
     * - file option byte is set to '0x40' = CommunicationMode.Plain and enabled SDM feature
     * - file access rights are set to '0x00E0' (Read & Write access key: 0, CAR key: 0, Read access key: E (free), Write access key: 0
     * - sdm access rights are set to '0xF3x3' (F = RFU, 3 = SDM Read Counter right, x = Read Meta Data right, 3 = Read File Data right)
     * The Read Meta Data right depends on the option 'Are UID & Read Counter mirroring Encrypted
     * if checked the value is set to '3' else to '14' ('0xE')
     * - sdm options byte is set to a value that reflects the selected options
     * - offset parameters are set to a value that reflects the selected options
     * Limitations:
     * - the ASCII encoding is fixed to true
     * - the size for encrypted file data is limited to 16 bytes (the parameter for the complexUrlBuilder is 2 * 16 = 32)
     * 4) the new template URL is written to the fileId '0x02'
     */

    private void enableSdm() {
        writeToUiAppend("disable the SDM feature for fileId 0x02");
        writeToUiAppend("step 1: select application with ID 0x010000");
        boolean success = desfireEv3.selectApplicationByAid(NDEF_APPLICATION_ID);
        byte[] responseData;
        responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("selection of the application SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("selection of the application FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 2: authenticate with default Application Master Key");
        success = desfireEv3.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
        responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("authenticate with default Application Master Key SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("authenticate with default Application Master Key FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: enabling the SDM feature on fileId 0x02");
        // to get the offsets we are building the template URL right now
        NdefForSdm ndefForSdm = new NdefForSdm(NdefForSdm.SAMPLE_BASE_URL);
        int readCounterLimit = Integer.parseInt(etSdmReadCounterLimit.getText().toString());
        int keySdmMetaRead = 14; // free access, no encrypted data
        if (cbUidReadCounterEncrypted.isChecked()) {
            keySdmMetaRead = 3;
        }
        String templateUrl = ndefForSdm.complexUrlBuilder(DesfireEv3Light.NDEF_FILE_02_NUMBER, NdefForSdm.CommunicationSettings.Plain,
                0, 0, 14, 0, true, cbUidMirror.isChecked(), cbReadCounterMirror.isChecked(),
                cbReadCounterLimit.isChecked(), readCounterLimit, cbEncryptedFileDataMirror.isChecked(), 32,
                true, 3, keySdmMetaRead, 3);
        Log.d(TAG, "templateUrl: " + templateUrl);
        if (TextUtils.isEmpty(templateUrl)) {
            writeToUiAppendBorderColor("building of the Template URL FAILURE, aborted", COLOR_RED);
            return;
        }
        byte[] commandData = ndefForSdm.getCommandData(); // this is the complete data
        Log.d(TAG, printData("commandData", commandData));
        if (commandData == null) {
            writeToUiAppendBorderColor("building of the commandData FAILURE, aborted", COLOR_RED);
            return;
        }
        // enabling the feature
        success = desfireEv3.changeFileSettingsNtag424Dna(DesfireEv3Light.NDEF_FILE_02_NUMBER, commandData);
        if (success) {
            writeToUiAppendBorderColor("enabling the SDM feature on fileId 0x02 SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("enabling the SDM feature on fileId 0x02 FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 4: write the template URL to fileId 0x02");
        //success = desfireEv3.writeToNdefFile2(templateUrl);
        success = desfireEv3.writeToStandardFileUrlPlain(DesfireEv3Light.NDEF_FILE_02_NUMBER, templateUrl);
        if (success) {
            writeToUiAppendBorderColor("write the template URL to fileId 0x02 SUCCESS", COLOR_GREEN);
            runOnUiThread(() -> {
                etTemplateUrl.setText(templateUrl);
            });
            vibrateShort();
        } else {
            writeToUiAppendBorderColor("write the template URL to fileId 0x02 FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }
    }


    /**
     * Disabling the SDM/SUN feature
     * This is using a fixed applicationId of '0x010000' and a fixed fileId of '0x02'
     * The method will run an authenticateEv2First command with default Application Master Key (zeroed AES-128 key)
     * <p>
     * steps:
     * 1) select applicationId '0x010000'
     * 2) authenticateFirstEv2 with default Application Master Key (zeroed AES-128 key)
     * 3) change file settings on fileId '0x02' with these parameters
     * - file option byte is set to '0x00' = CommunicationMode.Plain and disabled SDM feature
     * - file access rights are set to '0x00E0' (Read & Write access key: 0, CAR key: 0, Read access key: E (free), Write access key: 0
     */
    private void disableSdm() {
        writeToUiAppend("disable the SDM feature for fileId 0x02");
        writeToUiAppend("step 1: select application with ID 0x010000");
        boolean success = desfireEv3.selectApplicationByAid(NDEF_APPLICATION_ID);
        byte[] responseData;
        responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("selection of the application SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("selection of the application FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 2: authenticate with default Application Master Key");
        success = desfireEv3.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
        responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("authenticate with default Application Master Key SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("authenticate with default Application Master Key FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: disabling the SDM feature on fileId 0x02");
        success = desfireEv3.changeFileSettingsNtag424Dna(NDEF_FILE_ID, DesfireAuthenticateEv2.CommunicationSettings.Plain, 0, 0, 14, 0, false, 0, 0, 0);
        responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("disabling the SDM feature on fileId 0x02 SUCCESS", COLOR_GREEN);
            vibrateShort();
        } else {
            writeToUiAppendBorderColor("disabling the SDM feature on fileId 0x02 FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }
    }

    /**
     * changes the visibility of SDM parameter
     *
     * @param isShowSdmParameter
     */
    private void showSdmParameter(boolean isShowSdmParameter) {
        runOnUiThread(() -> {
            int visibility = View.GONE;
            if (isShowSdmParameter) visibility = View.VISIBLE;
            cbAsciiEncoding.setVisibility(visibility);
            cbUidMirror.setVisibility(visibility);
            cbReadCounterMirror.setVisibility(visibility);
            cbUidReadCounterEncrypted.setVisibility(visibility);
            cbReadCounterLimit.setVisibility(visibility);
            cbEncryptedFileDataMirror.setVisibility(visibility);
            //etSdmReadCounterLimitLayout.setVisibility(visibility); // visibility is set depending of cbReadCounterLimit
            //etSdmReadCounterLimit.setVisibility(visibility); // visibility is set depending of cbReadCounterLimit
            etSdmAccessRights.setVisibility(visibility);
        });
    }

    /**
     * changes the click ability of SDM parameter
     *
     * @param isClickableSdmParameter
     */
    private void clickableSdmParameter(boolean isClickableSdmParameter) {
        runOnUiThread(() -> {
            boolean clickable = false;
            if (isClickableSdmParameter) clickable = true;
            //cbAsciiEncoding.setClickable(clickable); // this needs to be enabled
            cbUidMirror.setClickable(clickable);
            cbReadCounterMirror.setClickable(clickable);
            cbUidReadCounterEncrypted.setClickable(clickable);
            cbReadCounterLimit.setClickable(clickable);
            cbEncryptedFileDataMirror.setClickable(clickable);
            //etSdmReadCounterLimitLayout.setFocusable(clickable);
            //etSdmReadCounterLimit.setFocusable(clickable);
            etSdmAccessRights.setFocusable(clickable);
        });
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
        writeToUiAppend("NFC tag discovered");
        isoDep = null;
        try {
            isoDep = IsoDep.get(tag);
            if (isoDep != null) {
                // Make a Vibration
                vibrateShort();

                runOnUiThread(() -> {
                    output.setText("");
                    output.setBackgroundColor(getResources().getColor(R.color.white));
                });
                isoDep.connect();
                if (!isoDep.isConnected()) {
                    writeToUiAppendBorderColor("could not connect to the tag, aborted", COLOR_RED);
                    isoDep.close();
                    return;
                }
                desfireEv3 = new DesfireEv3Light(isoDep);
                isDesfireEv3 = desfireEv3.checkForDESFireEv3();
                if (!isDesfireEv3) {
                    writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                    return;
                }

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend("tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);

                if (rbActivateSdmGetStatus.isChecked()) {
                    getFileSettings();
                }
                if (rbActivateSdmOn.isChecked()) {
                    enableSdm();
                }
                if (rbActivateSdmOff.isChecked()) {
                    disableSdm();
                }
            }
        } catch (IOException e) {
            writeToUiAppendBorderColor("IOException: " + e.getMessage(), COLOR_RED);
            e.printStackTrace();
        } catch (Exception e) {
            writeToUiAppendBorderColor("Exception: " + e.getMessage(), COLOR_RED);
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
     * section for UI elements
     */

    private void writeToUiAppend(String message) {
        writeToUiAppend(output, message);
    }

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

    private void writeToUi(TextView textView, String message) {
        runOnUiThread(() -> {
            textView.setText(message);
        });
    }

    private void writeToUiAppendBorderColor(String message, int color) {
        writeToUiAppendBorderColor(output, outputLayout, message, color);
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
        outputLayout.setBoxStrokeColorStateList(myColorList);
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
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(ActivateSdmActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}