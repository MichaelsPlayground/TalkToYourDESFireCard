package de.androidcrypto.talktoyourdesfirecard;

import androidx.annotation.NonNull;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.Intent;
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
import android.widget.RadioButton;
import android.widget.TextView;
import android.widget.Toast;

import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import java.util.Arrays;
import java.util.List;

public class PersonalizeActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = PersonalizeActivity.class.getName();

    /**
     * UI elements
     */

    private com.google.android.material.textfield.TextInputEditText output;
    private com.google.android.material.textfield.TextInputLayout outputLayout;
    private Button moreInformation;

    private RadioButton rbDoNothing, rbChangeAppKeysToChanged, rbChangeAppKeysToDefault,
            rbChangeMasterAppKeyToChanged, rbChangeMasterAppKeyToDefault,
            rbChangeMasterAppKeyDesToAesDefault;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);
    private final byte[] RESPONSE_AUTHENTICATION_ERROR = new byte[]{(byte) 0x91, (byte) 0xAE};

    /**
     * NFC handling
     */

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;

    private DesfireEv3 desfireEv3;
    private DesfireAuthenticateLegacy desfireLegacy;

    private byte[] errorCode;
    private String errorCodeReason = "";
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_personalize);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etPersonalizeOutput);
        outputLayout = findViewById(R.id.etPersonalizeOutputLayout);
        moreInformation = findViewById(R.id.btnPersonalizeMoreInformation);
        rbDoNothing = findViewById(R.id.rbPersonalizeDoNothing);
        rbChangeAppKeysToChanged = findViewById(R.id.rbPersonalizeAppKeysToChanged);
        rbChangeAppKeysToDefault = findViewById(R.id.rbPersonalizeAppKeysToDefault);
        rbChangeMasterAppKeyToChanged = findViewById(R.id.rbPersonalizeMasterAppKeyToChanged);
        rbChangeMasterAppKeyToDefault = findViewById(R.id.rbPersonalizeMasterAppKeyToDefault);
        rbChangeMasterAppKeyDesToAesDefault = findViewById(R.id.rbPersonalizeDesMasterAppKeyToAesDefault);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(PersonalizeActivity.this, getResources().getString(R.string.more_information_personalize));
            }
        });

        Button storageTest = findViewById(R.id.buttonStorageTest);
        storageTest.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                runKeystores();
            }
        });
    }

    private void runChangeAppKeysToChanged() {
        clearOutputFields();
        String logString = "runChangeAppKeysToChanged";
        writeToUiAppend(output, logString);
        /**
         * the method will do these steps to change the application keys from DEFAULT to CHANGED
         * 1) select the application ("A1A2A3")
         * 2) authenticate with the DEFAULT application master key
         * 3) change the application keys Read & Write Access, Change Access, Read Access and Write Access rights (key numbers 01..04)
         * 4) change the Application Master key (key number 00)
         */

        boolean success;

        writeToUiAppend("step 1: select the application (\"A1A2A3\")");
        success = desfireEv3.selectApplicationByAid(Constants.APPLICATION_IDENTIFIER_AES);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 2: authenticate with the DEFAULT application master key (key number 00)");
        success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: change the application keys Read & Write Access, Change Access, Read Access and Write Access rights (key numbers 01..04)");
        // all key versions get fixed to 0x01
        byte keyVersion = (byte) 0x01;
        success = changeApplicationKey(Constants.APPLICATION_KEY_RW_NUMBER, keyVersion, Constants.APPLICATION_KEY_RW_AES, Constants.APPLICATION_KEY_RW_AES_DEFAULT, "key number 01");
        if (!success) return;
        success = changeApplicationKey(Constants.APPLICATION_KEY_CAR_NUMBER, keyVersion, Constants.APPLICATION_KEY_CAR_AES, Constants.APPLICATION_KEY_CAR_AES_DEFAULT, "key number 02");
        if (!success) return;
        success = changeApplicationKey(Constants.APPLICATION_KEY_R_NUMBER, keyVersion, Constants.APPLICATION_KEY_R_AES, Constants.APPLICATION_KEY_R_AES_DEFAULT, "key number 03");
        if (!success) return;
        success = changeApplicationKey(Constants.APPLICATION_KEY_W_NUMBER, keyVersion, Constants.APPLICATION_KEY_W_AES, Constants.APPLICATION_KEY_W_AES_DEFAULT, "key number 04");
        if (!success) return;

        writeToUiAppend("step 4: change the Application Master key (key number 00)");
        success = changeApplicationKey(Constants.APPLICATION_KEY_MASTER_NUMBER, keyVersion, Constants.APPLICATION_KEY_MASTER_AES, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT, "key number 00");
        if (!success) return;
        writeToUiAppend("\nAll keys got changed from DEFAULT to CHANGED");
        vibrateShort();
    }

    private void runChangeAppKeysToDefault() {
        clearOutputFields();
        String logString = "runChangeAppKeysToDefault";
        writeToUiAppend(output, logString);
        /**
         * the method will do these steps to change the application keys from CHANGED to DEFAULT
         * 1) select the application ("A1A2A3")
         * 2) authenticate with the DEFAULT application master key
         * 3) change the application keys Read & Write Access, Change Access, Read Access and Write Access rights (key numbers 01..04)
         * 4) change the Application Master key (key number 00)
         */

        boolean success;

        writeToUiAppend("step 1: select the application (\"A1A2A3\")");
        success = desfireEv3.selectApplicationByAid(Constants.APPLICATION_IDENTIFIER_AES);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 2: authenticate with the CHANGED application master key (key number 00)");
        success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: change the application keys Read & Write Access, Change Access, Read Access and Write Access rights (key numbers 01..04)");
        // all key versions get fixed to 0x02
        byte keyVersion = (byte) 0x02;
        success = changeApplicationKey(Constants.APPLICATION_KEY_RW_NUMBER, keyVersion, Constants.APPLICATION_KEY_RW_AES_DEFAULT, Constants.APPLICATION_KEY_RW_AES, "key number 01");
        if (!success) return;
        success = changeApplicationKey(Constants.APPLICATION_KEY_CAR_NUMBER, keyVersion, Constants.APPLICATION_KEY_CAR_AES_DEFAULT, Constants.APPLICATION_KEY_CAR_AES, "key number 02");
        if (!success) return;
        success = changeApplicationKey(Constants.APPLICATION_KEY_R_NUMBER, keyVersion, Constants.APPLICATION_KEY_R_AES_DEFAULT, Constants.APPLICATION_KEY_R_AES, "key number 03");
        if (!success) return;
        success = changeApplicationKey(Constants.APPLICATION_KEY_W_NUMBER, keyVersion, Constants.APPLICATION_KEY_W_AES_DEFAULT, Constants.APPLICATION_KEY_W_AES, "key number 04");
        if (!success) return;

        writeToUiAppend("step 4: change the Application Master key (key number 00)");
        success = changeApplicationKey(Constants.APPLICATION_KEY_MASTER_NUMBER, keyVersion, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT, Constants.APPLICATION_KEY_MASTER_AES, "key number 00");
        if (!success) return;
        writeToUiAppend("\nAll keys got changed from CHANGED to DEFAULT");
        vibrateShort();
    }

    private boolean changeApplicationKey(byte keyNumber, byte keyVersion, byte[] keyNew, byte[] keyOld, String keyName) {
        final String methodName = "changeApplicationKey";
        Log.d(TAG, methodName);
        writeToUiAppend(output, methodName);

        boolean success = desfireEv3.changeApplicationKeyFull(keyNumber, keyVersion, keyNew, keyOld);
        byte[] responseData = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppend(output, methodName + " keyVersion " + keyVersion + " SUCCESS");
            writeToUiAppendBorderColor(methodName + " SUCCESS", COLOR_GREEN);
            //vibrateShort();
            return true;
        } else {
            writeToUiAppend(output, methodName + " keyVersion " + keyVersion + " FAILURE with error " + EV3.getErrorCode(responseData));
            if (checkAuthenticationError(responseData)) {
                writeToUiAppend(output, "as we received an Authentication Error - did you forget to AUTHENTICATE with a APPLICATION MASTER KEY ?");
            }
            writeToUiAppendBorderColor(methodName + " FAILURE with error code: " + Utils.bytesToHexNpeUpperCase(responseData), COLOR_RED);
            writeToUiAppend("Error reason: " + desfireEv3.getErrorCodeReason());
            return false;
        }
    }

    private void runChangeMasterAppKeyToChanged() {
        clearOutputFields();
        String logString = "runChangeMasterAppKeyToChanged";
        writeToUiAppend(output, logString);
        /**
         * the method will do these steps to change the Master Application key from DEFAULT DES to CHANGED DES
         * 1) select the master application ("000000")
         * 2) authenticate with the DEFAULT master application key
         * 3) change the master application key (key number 00)
         */

        boolean success;

        writeToUiAppend("step 1: select the application (\"000000\")");
        success = desfireLegacy.selectApplication(Constants.MASTER_APPLICATION_IDENTIFIER);
        //success = desfireEv3.selectApplicationByAid(Constants.APPLICATION_IDENTIFIER_AES);
        errorCode = desfireLegacy.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 2: authenticate with the DEFAULT Master Application key (key number 00)");
        success = desfireLegacy.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT);
        //success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
        errorCode = desfireLegacy.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("authenticate with the CHANGED AES Master Application key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("authenticate with the CHANGED AES Master Application key FAILURE, aborted");
            writeToUiAppendBorderColor("authenticate with the CHANGED AES Master Application key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: change the Master Application key (key number 00) to CHANGED");
        // key version is fixed to 0x00
        success = desfireLegacy.changeDesKey(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, "key number 00");
        errorCode = desfireLegacy.getErrorCode();
        writeToUiAppend(desfireLegacy.getLogData());
        if (success) {
            writeToUiAppendBorderColor("change the Master Application key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("change the Master Application key FAILURE, aborted");
            writeToUiAppendBorderColor("change the Master Application key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + ", aborted", COLOR_RED);
            return;
        }
/*
        writeToUiAppend("step 4: change the Application Master key (key number 00)");
        //success = changeApplicationKey(Constants.APPLICATION_KEY_MASTER_NUMBER, keyVersion, Constants.APPLICATION_KEY_MASTER_AES, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT, "key number 00");
        if (!success) return;
        writeToUiAppend("\nAll keys got changed from DEFAULT to CHANGED");
 */
        vibrateShort();
    }

    private void runChangeMasterAppKeyToDefault() {
        clearOutputFields();
        String logString = "runChangeMasterAppKeyToDefault";
        writeToUiAppend(output, logString);
        /**
         * the method will do these steps to change the Master Application key from CHANGED DES to DEFAULT DES
         * 1) select the master application ("000000")
         * 2) authenticate with the DEFAULT master application key
         * 3) change the master application key (key number 00)
         */

        boolean success;

        writeToUiAppend("step 1: select the application (\"000000\")");
        success = desfireLegacy.selectApplication(Constants.MASTER_APPLICATION_IDENTIFIER);
        //success = desfireEv3.selectApplicationByAid(Constants.APPLICATION_IDENTIFIER_AES);
        errorCode = desfireLegacy.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 2: authenticate with the DEFAULT Master Application key (key number 00)");
        //success = desfireLegacy.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT);
        success = desfireLegacy.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES);
        //success = desfireEv3.authenticateAesEv2First(Constants.APPLICATION_KEY_MASTER_NUMBER, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT);
        errorCode = desfireLegacy.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("authenticate with the CHANGED AES Master Application key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("authenticate with the CHANGED AES Master Application key FAILURE, aborted");
            writeToUiAppendBorderColor("authenticate with the CHANGED AES Master Application key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: change the Master Application key (key number 00) to DEFAULT");
        // key version is fixed to 0x00
        success = desfireLegacy.changeDesKey(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, Constants.MASTER_APPLICATION_KEY_DES, "key number 00");
        errorCode = desfireLegacy.getErrorCode();
        writeToUiAppend(desfireLegacy.getLogData());
        if (success) {
            writeToUiAppendBorderColor("change the Master Application key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("change the Master Application key FAILURE, aborted");
            writeToUiAppendBorderColor("change the Master Application key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + ", aborted", COLOR_RED);
            return;
        }
/*
        writeToUiAppend("step 4: change the Application Master key (key number 00)");
        //success = changeApplicationKey(Constants.APPLICATION_KEY_MASTER_NUMBER, keyVersion, Constants.APPLICATION_KEY_MASTER_AES, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT, "key number 00");
        if (!success) return;
        writeToUiAppend("\nAll keys got changed from DEFAULT to CHANGED");
 */
        vibrateShort();
    }
    /*
    private void rbChangeMasterAppKeyToDefault() {
        clearOutputFields();
        String logString = "runChangeMasterAppKeyToDefault";
        writeToUiAppend(output, logString);*/
        /**
         * the method will do these steps to change the Master Application key from DEFAULT DES to CHANGED AES
         * 1) select the master application ("000000")
         * 2) authenticate with the CHANGED AES master application key
         * 3) change the master application key (key number 00)
         */
/*
        boolean success;

        writeToUiAppend("step 1: select the application (\"000000\")");
        //success = desfireLegacy.selectApplication(Constants.MASTER_APPLICATION_IDENTIFIER);
        success = desfireEv3.selectApplicationByAid(Constants.MASTER_APPLICATION_IDENTIFIER);
        errorCode = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("select the application FAILURE, aborted");
            writeToUiAppendBorderColor("select the application FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        //writeToUiAppend("step 2: authenticate with the DEFAULT Master Application key (key number 00)");
        writeToUiAppend("step 2: authenticate with the CHANGED AES Master Application key (key number 00)");
        //success = desfireLegacy.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT);
        success = desfireEv3.authenticateAesEv2First(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_AES);
        errorCode = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("authenticate with the CHANGED AES Master Application key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("authenticate with the CHANGED AES Master Application key FAILURE, aborted");
            writeToUiAppendBorderColor("authenticate with the CHANGED AES Master Application key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + " = "
                    + errorCodeReason + ", aborted", COLOR_RED);
            return;
        }

        writeToUiAppend("step 3: change the Master Application key (key number 00)");
        // key version is fixed to 0x00
        //success = desfireLegacy.changeDesKeyToAes(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_AES, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, "key number 00");
        // key version get fixed to 0x02
        byte keyVersion = (byte) 0x02;
        success = changeApplicationKey(Constants.MASTER_APPLICATION_KEY_NUMBER, keyVersion, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, Constants.MASTER_APPLICATION_KEY_AES, "key number 00");
        errorCode = desfireEv3.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("change the Master Application key SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppend("change the Master Application key FAILURE, aborted");
            writeToUiAppendBorderColor("change the Master Application key FAILURE with error code: "
                    + EV3.getErrorCode(errorCode) + ", aborted", COLOR_RED);
            return;
        }

 */
/*
        writeToUiAppend("step 4: change the Application Master key (key number 00)");
        //success = changeApplicationKey(Constants.APPLICATION_KEY_MASTER_NUMBER, keyVersion, Constants.APPLICATION_KEY_MASTER_AES, Constants.APPLICATION_KEY_MASTER_AES_DEFAULT, "key number 00");
        if (!success) return;
        writeToUiAppend("\nAll keys got changed from DEFAULT to CHANGED");
 */
        /*
        vibrateShort();
    }
*/

        private void runChangeMasterAppKeyDesToAesDefault() {
            clearOutputFields();
            String logString = "runChangeMasterAppKeyDesToAesDefault";
            writeToUiAppend(output, logString);
            /**
             * the method will do these steps to change the Master Application key from DEFAULT DES to DEFAULT AES
             * 1) select the master application ("000000")
             * 2) authenticate with the DEFAULT master application key
             * 3) change the master application key (key number 00)
             */

            boolean success;

            writeToUiAppend("step 1: select the application (\"000000\")");
            success = desfireLegacy.selectApplication(Constants.MASTER_APPLICATION_IDENTIFIER);
            errorCode = desfireLegacy.getErrorCode();
            if (success) {
                writeToUiAppendBorderColor("select the application SUCCESS", COLOR_GREEN);
            } else {
                writeToUiAppend("select the application FAILURE, aborted");
                writeToUiAppendBorderColor("select the application FAILURE with error code: "
                        + EV3.getErrorCode(errorCode) + " = "
                        + errorCodeReason + ", aborted", COLOR_RED);
                return;
            }

            writeToUiAppend("step 2: authenticate with the DEFAULT Master Application key (key number 00)");
            success = desfireLegacy.authenticateD40(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT);
            errorCode = desfireLegacy.getErrorCode();
            if (success) {
                writeToUiAppendBorderColor("authenticate with the DEFAULT AES Master Application key SUCCESS", COLOR_GREEN);
            } else {
                writeToUiAppend("authenticate with the DEFAULT AES Master Application key FAILURE, aborted");
                writeToUiAppendBorderColor("authenticate with the DEFAULT AES Master Application key FAILURE with error code: "
                        + EV3.getErrorCode(errorCode) + " = "
                        + errorCodeReason + ", aborted", COLOR_RED);
                return;
            }

            writeToUiAppend("step 3: change the Master Application key (key number 00) DES to AES DEFAULT");
            // key version is fixed to 0x00
            success = desfireLegacy.changeDesKeyToAes(Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_NUMBER, Constants.MASTER_APPLICATION_KEY_AES_DEFAULT, Constants.MASTER_APPLICATION_KEY_DES_DEFAULT, "key number 00");
            errorCode = desfireLegacy.getErrorCode();
            writeToUiAppend(desfireLegacy.getLogData());
            if (success) {
                writeToUiAppendBorderColor("change the Master Application key SUCCESS", COLOR_GREEN);
            } else {
                writeToUiAppend("change the Master Application key FAILURE, aborted");
                writeToUiAppendBorderColor("change the Master Application key FAILURE with error code: "
                        + EV3.getErrorCode(errorCode) + ", aborted", COLOR_RED);
                return;
            }
            vibrateShort();
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

    private byte[] returnStatusBytes(byte[] data) {
        return Arrays.copyOfRange(data, (data.length - 2), data.length);
    }

    private void runKeystores() {
        clearOutputFields();
        String logString = "runKeystores";
        writeToUiAppend(output, logString);
        /**

        /*
available KeyStores in Samsung A5 / Android 9
Keystore: KeyStore.BouncyCastle available in provider: BC
Keystore: KeyStore.PKCS12 available in provider: BC
Keystore: KeyStore.BKS available in provider: BC
Keystore: KeyStore.AndroidCAStore available in provider: HarmonyJSSE
Keystore: KeyStore.AndroidKeyStore available in provider: AndroidKeyStore
Keystore: KeyStore.KnoxAndroidKeyStore available in provider: KnoxAndroidKeyStore
Keystore: KeyStore.TimaKeyStore available in provider: TimaKeyStore
         */

        // Iterate in security providers
        for(Provider provider: Security.getProviders()) {
            for(Object item: provider.keySet()) {
                if(item.toString().startsWith("KeyStore.")) { // grep KeyStores
                    Log.d(TAG, "Keystore: " + item.toString() + " available in provider: " + provider.getName());
                }
            }
        }

        CustomKeystore customKeystore = new CustomKeystore(getApplicationContext());
        if (!customKeystore.isLibraryInitialized()) {
            customKeystore.initialize("123456".toCharArray());
        }
        customKeystore.storeKey(Constants.APPLICATION_KEY_W_NUMBER, Constants.APPLICATION_KEY_W_AES.clone());
        customKeystore.storeKey(Constants.APPLICATION_KEY_CAR_NUMBER, Constants.APPLICATION_KEY_CAR_AES.clone());

        ConstantsKeystore constantsKeystore = new ConstantsKeystore(getApplicationContext(), Constants.KEYSTORE_PASSWORD);
        byte[] appKey = Constants.APPLICATION_KEY_MASTER_AES.clone();
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.M) {
            boolean sucStore = constantsKeystore.storeKey(Constants.APPLICATION_KEY_R_NUMBER, appKey);
            sucStore = constantsKeystore.storeKey(Constants.APPLICATION_KEY_W_NUMBER, Constants.APPLICATION_KEY_W_AES.clone());
            sucStore = constantsKeystore.storeKey(Constants.APPLICATION_KEY_CAR_NUMBER, Constants.APPLICATION_KEY_CAR_AES.clone());
            sucStore = constantsKeystore.storeKey(Constants.APPLICATION_KEY_RW_NUMBER, Constants.APPLICATION_KEY_RW_AES.clone());
            Log.d(TAG, "sucStore: " + sucStore);
        } else {
            Log.d(TAG, "Android SDK version is not >= M / 23, no storage");
        }

        // read the key
        byte[] appKeyRetrieved = constantsKeystore.readKey(Constants.APPLICATION_KEY_R_NUMBER);
        Log.d(TAG, Utils.printData("appKey S", appKey));
        Log.d(TAG, Utils.printData("appKey R", appKeyRetrieved));
        List<String> storedAliases = constantsKeystore.getKeystoreAliases();
        Log.d(TAG, "stored aliases: " + Arrays.toString(storedAliases.toArray()));

        vibrateShort();
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
                desfireEv3 = new DesfireEv3(isoDep);
                desfireLegacy = new DesfireAuthenticateLegacy(isoDep, false);

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

                if (rbDoNothing.isChecked()) {
                    writeToUiAppend("nothing was changed");
                    runKeystores();
                    return;
                };
                if (rbChangeAppKeysToChanged.isChecked()) {
                    runChangeAppKeysToChanged();
                }
                if (rbChangeAppKeysToDefault.isChecked()) {
                    runChangeAppKeysToDefault();
                }
                if (rbChangeMasterAppKeyToChanged.isChecked()) {
                    runChangeMasterAppKeyToChanged();
                }
                if (rbChangeMasterAppKeyToDefault.isChecked()) {
                    runChangeMasterAppKeyToDefault();
                }
                if (rbChangeMasterAppKeyDesToAesDefault.isChecked()) {
                    runChangeMasterAppKeyDesToAesDefault();
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
                Intent intent = new Intent(PersonalizeActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}