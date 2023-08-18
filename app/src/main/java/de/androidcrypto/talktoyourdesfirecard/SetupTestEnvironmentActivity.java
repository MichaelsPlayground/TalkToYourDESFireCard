package de.androidcrypto.talktoyourdesfirecard;

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
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.widget.Toolbar;

import com.google.android.material.textfield.TextInputLayout;

import java.io.IOException;
import java.util.Arrays;

public class SetupTestEnvironmentActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = SetupTestEnvironmentActivity.class.getName();

    /**
     * UI elements
     */

    private com.google.android.material.textfield.TextInputEditText output;
    private TextInputLayout outputLayout;
    private Button moreInformation;

    /**
     * general constants
     */

    private final int COLOR_GREEN = Color.rgb(0, 255, 0);
    private final int COLOR_RED = Color.rgb(255, 0, 0);


    /**
     * NFC handling
     */

    private NfcAdapter mNfcAdapter;
    private IsoDep isoDep;
    private byte[] tagIdByte;
    private DesfireEv3 desfireEv3;
    private FileSettings fileSettings;
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_setup_test_environment);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etSetupTestEnvironmentOutput);
        outputLayout = findViewById(R.id.etSetupTestEnvironmentOutputLayout);
        moreInformation = findViewById(R.id.btnSetupTestEnvironmentMoreInformation);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);

        moreInformation.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View view) {
                // provide more information about the application and file
                showDialog(SetupTestEnvironmentActivity.this, getResources().getString(R.string.more_information_setup_test_environment));
            }
        });
    }

    private void runPrepareSdm() {
        clearOutputFields();
        String logString = "runPrepareSdm";
        writeToUiAppend(output, logString);
        /**
         * the method will do these 5 steps to prepare the tag for SDM
         * 1) create a new application ("NDEF application")
         * 2) select the new application
         * 3) create a new Standard File 01
         * 4) write the NDEF Container to the file 01
         * 5) create a new Standard File 02
         * 6) write an URL as Link NDEF Record/Message to file 02
         */

        boolean success;
        byte[] errorCode;
        String errorCodeReason = "";
        writeToUiAppend(output, "");
        String stepString = "1 create a new application (\"NDEF application\")";
        writeToUiAppend(output, stepString);
        success = desfireEv3.createApplicationAesIso(DesfireEv3.NDEF_APPLICATION_IDENTIFIER, DesfireEv3.NDEF_ISO_APPLICATION_IDENTIFIER,
                DesfireEv3.NDEF_APPLICATION_DF_NAME, 5);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            if (Arrays.equals(errorCode, DesfireEv3.RESPONSE_DUPLICATE_ERROR)) {
                writeToUiAppendBorderColor(stepString + " FAILURE because application already exits", COLOR_GREEN);
            } else {
                writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
                return;
            }
        }

        writeToUiAppend(output, "");
        stepString = "2 select the new application";
        writeToUiAppend(output, stepString);
        success = desfireEv3.selectApplicationByAid(DesfireEv3.NDEF_APPLICATION_IDENTIFIER);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
            return;
        }

        writeToUiAppend(output, "");
        stepString = "3 create a new Standard File 01";
        writeToUiAppend(output, stepString);
        success = desfireEv3.createStandardFileIso(DesfireEv3.NDEF_FILE_01_NUMBER, DesfireEv3.NDEF_FILE_01_ISO_NAME,
                DesfireEv3.CommunicationSettings.Plain, DesfireEv3.NDEF_FILE_01_ACCESS_RIGHTS, DesfireEv3.NDEF_FILE_01_SIZE, false);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            if (Arrays.equals(errorCode, DesfireEv3.RESPONSE_DUPLICATE_ERROR)) {
                writeToUiAppendBorderColor(stepString + " FAILURE because file already exits", COLOR_GREEN);
            } else {
                writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
                return;
            }
        }

        writeToUiAppend(output, "");
        stepString = "4 write the NDEF Container to the file 01";
        writeToUiAppend(output, stepString);
        success = desfireEv3.writeToStandardFileNdefContainerPlain(DesfireEv3.NDEF_FILE_01_NUMBER);
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
            return;
        }

        writeToUiAppend(output, "");
        stepString = "5 create a new Standard File 02";
        writeToUiAppend(output, stepString);
        success = desfireEv3.createStandardFileIso(DesfireEv3.NDEF_FILE_02_NUMBER, DesfireEv3.NDEF_FILE_02_ISO_NAME,
                DesfireEv3.CommunicationSettings.Plain, DesfireEv3.NDEF_FILE_02_ACCESS_RIGHTS, DesfireEv3.NDEF_FILE_02_SIZE, true);
        errorCode = desfireEv3.getErrorCode();
        errorCodeReason = desfireEv3.getErrorCodeReason();
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            if (Arrays.equals(errorCode, DesfireEv3.RESPONSE_DUPLICATE_ERROR)) {
                writeToUiAppendBorderColor(stepString + " FAILURE because file already exits", COLOR_GREEN);
            } else {
                writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
                return;
            }
        }

        writeToUiAppend(output, "");
        stepString = "6 write an URL as Link NDEF Record/Message to file 02";
        writeToUiAppend(output, stepString);
        String urlToWrite = NdefForSdm.SAMPLE_URL;
        writeToUiAppend("Base url: " + urlToWrite);
        success = desfireEv3.writeToStandardFileUrlPlain(DesfireEv3.NDEF_FILE_02_NUMBER, urlToWrite);
        if (success) {
            writeToUiAppendBorderColor(stepString + " SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor(stepString + " FAILURE with ErrorCode " + EV3.getErrorCode(errorCode) + " reason: " + errorCodeReason, COLOR_RED);
            return;
        }



        writeToUiAppend(output, "");
        stepString = "";

        writeToUiAppend(output, desfireEv3.getLogData());

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
                desfireEv3 = new DesfireEv3(isoDep); // true means all data is logged

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

                //runPrepareSdm();

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
                Intent intent = new Intent(SetupTestEnvironmentActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }

}