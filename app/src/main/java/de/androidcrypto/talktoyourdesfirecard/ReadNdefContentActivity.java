package de.androidcrypto.talktoyourdesfirecard;

import static de.androidcrypto.talktoyourdesfirecard.MainActivity.APPLICATION_KEY_MASTER_AES_DEFAULT;
import static de.androidcrypto.talktoyourdesfirecard.MainActivity.APPLICATION_KEY_MASTER_AES;
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
import android.nfc.FormatException;
import android.nfc.NdefMessage;
import android.nfc.NdefRecord;
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
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ReadNdefContentActivity extends AppCompatActivity implements NfcAdapter.ReaderCallback {

    private static final String TAG = ReadNdefContentActivity.class.getName();

    /**
     * UI elements
     */
    private com.google.android.material.textfield.TextInputEditText output;
    private com.google.android.material.textfield.TextInputLayout outputLayout;
    private RadioGroup rgStatus;
    private RadioButton rbReadNdefContentNoAuth, rbReadNdefContentAuthKey0, rbReadNdefContentAuthKey0Changed;

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
    private DesfireAuthenticateEv2 desfireAuthenticateEv2;
    private DesfireEv3Light desfireEv3;
    private FileSettings fileSettings;
    private boolean isDesfireEv3 = false;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_read_ndef_content);

        Toolbar myToolbar = (Toolbar) findViewById(R.id.main_toolbar);
        setSupportActionBar(myToolbar);

        output = findViewById(R.id.etReadNdefContentOutput);
        outputLayout = findViewById(R.id.etReadNdefContentOutputLayout);

        rgStatus = findViewById(R.id.rgReadNdefContentStatus);
        rbReadNdefContentNoAuth = findViewById(R.id.rbReadNdefContentNoAuth);
        rbReadNdefContentAuthKey0 = findViewById(R.id.rbReadNdefContentAuthKey0);
        rbReadNdefContentAuthKey0Changed = findViewById(R.id.rbReadNdefContentAuthKey0Changed);

        // hide soft keyboard from showing up on startup
        getWindow().setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_ALWAYS_HIDDEN);

        mNfcAdapter = NfcAdapter.getDefaultAdapter(this);
    }

    private void readNdefContent() {
        writeToUiAppend("read NDEF content from fileId 0x02");
        writeToUiAppend("step 1: select application with ID 0x010000");
        boolean success = desfireAuthenticateEv2.selectApplicationByAidEv2(NDEF_APPLICATION_ID);
        byte[] responseData;
        responseData = desfireAuthenticateEv2.getErrorCode();
        if (success) {
            writeToUiAppendBorderColor("selection of the application SUCCESS", COLOR_GREEN);
            //vibrateShort();
        } else {
            writeToUiAppendBorderColor("selection of the application FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
            return;
        }

        byte[] result = desfireAuthenticateEv2.getAllFileIdsEv2();
        FileSettings[] fsResult = desfireAuthenticateEv2.getAllFileSettingsEv2();
        if ((fsResult != null) && (fsResult.length > 2)) {
            //writeToUiAppend(fsResult[2].dump());
            writeToUiAppendBorderColor("get all FileSettings SUCCESS", COLOR_GREEN);
        } else {
            writeToUiAppendBorderColor("get all FileSettings FAILURE, aborted", COLOR_RED);
        }

        if (rbReadNdefContentNoAuth.isChecked()) {
            writeToUiAppend("step 2: NO authentication with Application Key 0x00");
        }
        if (rbReadNdefContentAuthKey0.isChecked()) {
            writeToUiAppend("step 2: authentication with DEFAULT Application Key 0x00");
            success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES_DEFAULT);
            responseData = desfireAuthenticateEv2.getErrorCode();
            if (success) {
                writeToUiAppendBorderColor("authenticate with DEFAULT Application Master Key SUCCESS", COLOR_GREEN);
                //vibrateShort();
            } else {
                writeToUiAppendBorderColor("authenticate with DEFAULT Application Master Key FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
                return;
            }
        }
        if (rbReadNdefContentAuthKey0Changed.isChecked()) {
            writeToUiAppend("step 2: authentication with CHANGED Application Key 0x00");
            success = desfireAuthenticateEv2.authenticateAesEv2First(APPLICATION_KEY_MASTER_NUMBER, APPLICATION_KEY_MASTER_AES);
            responseData = desfireAuthenticateEv2.getErrorCode();
            if (success) {
                writeToUiAppendBorderColor("authenticate with CHANGED Application Master Key SUCCESS", COLOR_GREEN);
                //vibrateShort();
            } else {
                writeToUiAppendBorderColor("authenticate with CHANGED Application Master Key FAILURE with error code: " + EV3.getErrorCode(responseData) + ", aborted", COLOR_RED);
                return;
            }
        }

        writeToUiAppend("step 3: read the content from fileId 0x02");
        // read the complete content and present in hex encoding
        // second treat content as a NDEF message/record and show String encoded content

        byte[] content = desfireEv3.readFromStandardFileRawPlain(DesfireEv3Light.NDEF_FILE_02_NUMBER, 0, DesfireEv3Light.NDEF_FILE_02_SIZE);
        writeToUiAppend(printData("content", content));
        writeToUiAppend(new String(content, StandardCharsets.UTF_8));

        // content begins: 0051d1014d550473646d2e6e
        //                       ||       01 = ndef record tnf
        //                           ||   55  = type
        //                 |          |   header
        //                             || 04 url type = https://www.
        // for rough interpreting read content[5] for url type
        // read the following data and convert to string (url)
        // concatenate url type clearname with url
        byte ndefUrlTape = content[6];
        // first we need to strip off the first two bytes 0x00 || 0x(length of NDEF message)
        //content = Arrays.copyOf(content, content.length - 2);
        // con we use only ndefLength bytes
        byte ndefLength = content[1];
        content = Arrays.copyOf(content, ndefLength);
        String url = Utils.URI_PREFIX_MAP[ndefUrlTape] + new String(Arrays.copyOfRange(content, 7, content.length));
        writeToUiAppend(url);
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
                desfireAuthenticateEv2 = new DesfireAuthenticateEv2(isoDep, true); // true means all data is logged
                desfireEv3 = new DesfireEv3Light(isoDep);

                isDesfireEv3 = desfireAuthenticateEv2.checkForDESFireEv3();
                if (!isDesfireEv3) {
                    writeToUiAppendBorderColor("The tag is not a DESFire EV3 tag, stopping any further activities", COLOR_RED);
                    return;
                }

                // get tag ID
                tagIdByte = tag.getId();
                writeToUiAppend("tag id: " + Utils.bytesToHex(tagIdByte));
                Log.d(TAG, "tag id: " + Utils.bytesToHex(tagIdByte));
                writeToUiAppendBorderColor("The app and DESFire EV3 tag are ready to use", COLOR_GREEN);

                readNdefContent();
                /*
                if (rbReadNdefContentGetStatus.isChecked()) {
                    getFileSettings();
                }
                if (rbReadNdefContentOn.isChecked()) {
                    enableSdm();
                }
                if (rbReadNdefContentOff.isChecked()) {
                    disableSdm();
                }

                 */
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
     * section for options menu
     */

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.menu_return_home, menu);

        MenuItem mGoToHome = menu.findItem(R.id.action_return_main);
        mGoToHome.setOnMenuItemClickListener(new MenuItem.OnMenuItemClickListener() {
            @Override
            public boolean onMenuItemClick(MenuItem item) {
                Intent intent = new Intent(ReadNdefContentActivity.this, MainActivity.class);
                startActivity(intent);
                finish();
                return false;
            }
        });

        return super.onCreateOptionsMenu(menu);
    }
}