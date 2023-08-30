package de.androidcrypto.talktoyourdesfirecard;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.security.keystore.WrappedKeyEntry;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Enumeration;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is storing sensitive data to Android's keystore
 * The functionality is available on Android SDK 23+ only so all methods are restricted to these SDK versions
 */

public class ConstantsKeystore {

    private static final String TAG = ConstantsKeystore.class.getName();

    //private final String keystoreName = "AndroidKeyStore";
    private final String keystoreName = "BKS"; // Bouncy Castle Keystore
    private final String keystoreFileName = "mykeystore.bks";
    private char[] keystorePassword = "changeit".toCharArray(); // default password
    private final String keyAlias = "key_";
    private boolean isKeyAes = false;
    private Context context;

    public ConstantsKeystore(Context context) {
        this.context = context;
        Log.d(TAG, "initialized");
    }

    public ConstantsKeystore(Context context, char[] keystorePassword) {
        this.context = context;
        this.keystorePassword = keystorePassword;
        Log.d(TAG, "initialized");
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    public boolean storeKey(byte keyNumber, byte[] key) {
        // sanity checks on keys
        if (key == null) {
            Log.e(TAG, "key is NULL, aborted");
            return false;
        }
        if ((key.length != 8) && (key.length != 16)) {
            Log.e(TAG, "key length is not 8 or 16, aborted");
            return false;
        }
        if (key.length == 16) isKeyAes = true;
        // build alias name
        StringBuilder sb = new StringBuilder();
        sb.append(keyAlias);
        sb.append(keyNumber);
        String alias = sb.toString();
        Log.d(TAG, "alias: " + alias);

        if (!isFilePresent(keystoreFileName)) {
            boolean crSuc = createKeyStore();
            Log.d(TAG, "crSuc: " + crSuc);
        } else {
            Log.d(TAG, "keystoreFile exists: " + keystoreFileName);
        }

        try {
            SecretKey secretKey;
            if (isKeyAes) {
                secretKey = new SecretKeySpec(key, "AES");
            } else {
                secretKey = new SecretKeySpec(key, "DES");
            }

            KeyStore keyStore = KeyStore.getInstance(keystoreName);
            FileInputStream fileInputStream = context.openFileInput(keystoreFileName);
            keyStore.load(fileInputStream, keystorePassword);
            //FileOutputStream fileOutputStream = context.openFileOutput(keystoreFileName, Context.MODE_PRIVATE);
            //keyStore.load(fileOutputStream, keystorePassword);

            if (keyStore.containsAlias(alias)) {
                Log.d(TAG, "alias is already present in keyStore, aborted: " + alias);
                return false;
            }

            //Creating the KeyStore.ProtectionParameter object
            KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keystorePassword);
            //Creating SecretKeyEntry object
            KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
            keyStore.setEntry(alias, secretKeyEntry, protectionParam);
            Log.d(TAG, "key is stored");
            FileOutputStream fos = context.openFileOutput(keystoreFileName,Context.MODE_PRIVATE);
            keyStore.store(fos, keystorePassword);
            return true;
        } catch (IOException | GeneralSecurityException e) {
            Log.e(TAG, "Exception on keystore usage, aborted");
            Log.e(TAG, e.getMessage());
            e.printStackTrace();
            return false;
        }
    }

    public byte[] readKey(byte keyNumber) {
        // sanity checks on keys

        // build alias name
        StringBuilder sb = new StringBuilder();
        sb.append(keyAlias);
        sb.append(keyNumber);
        String alias = sb.toString();
        Log.d(TAG, "readKey, alias: " + alias);
        if (!isFilePresent(keystoreFileName)) {
            Log.d(TAG, "No keystoreFile present, aborted: " + keystoreFileName);
            return null;
        } else {
            try {
                KeyStore keyStore = KeyStore.getInstance(keystoreName);
                FileInputStream fileInputStream = context.openFileInput(keystoreFileName);
                keyStore.load(fileInputStream, keystorePassword);

                Enumeration<String> aliases = keyStore.aliases();
                // print the enumeration
                Log.d(TAG, "Enumeration start");
                while (aliases.hasMoreElements())
                    Log.d(TAG, "Value is: " + aliases.nextElement());
                Log.d(TAG, "Enumeration end");

                if (keyStore.containsAlias(alias)) {
                    Log.d(TAG, "alias is present in keyStore: " + alias);
                } else {
                    Log.d(TAG, "alias is NOT present in keyStore: " + alias + " , aborted");
                    return null;
                }

                //Creating the KeyStore.ProtectionParameter object
                KeyStore.ProtectionParameter protectionParam = new KeyStore.PasswordProtection(keystorePassword);

                //Creating the KeyStore.SecretKeyEntry object
                KeyStore.SecretKeyEntry secretKeyEnt = (KeyStore.SecretKeyEntry) keyStore.getEntry(alias, protectionParam);

                //Creating SecretKey object
                SecretKey mysecretKey = secretKeyEnt.getSecretKey();
                Log.d(TAG, "Algorithm used to generate key : " + mysecretKey.getAlgorithm());
                Log.d(TAG, "Format used for the key: " + mysecretKey.getFormat());
                byte[] retrievedKey = mysecretKey.getEncoded();

                return retrievedKey;
            } catch (IOException | GeneralSecurityException e) {
                Log.e(TAG, "Exception on keystore usage, aborted");
                Log.e(TAG, e.getMessage());
                e.printStackTrace();
                return null;
            }
        }
    }

    private boolean createKeyStore() {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance(keystoreName);
            ks.load(null, keystorePassword);
            FileOutputStream fos = context.openFileOutput(keystoreFileName,Context.MODE_PRIVATE);
            ks.store(fos, keystorePassword);
            return true;
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean isFilePresent(String fileName) {
        File path = context.getFilesDir();
        File file = new File(path, fileName);
        return file.exists();
    }


}
