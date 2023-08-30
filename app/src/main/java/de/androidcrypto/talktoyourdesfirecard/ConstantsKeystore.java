package de.androidcrypto.talktoyourdesfirecard;

import android.content.Context;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.WrappedKeyEntry;
import android.util.Log;

import androidx.annotation.RequiresApi;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * This class is storing sensitive data to Android's keystore
 * The functionality is available on Android SDK 23+ only so all methods are restricted to these SDK versions
 */

public class ConstantsKeystore {

    private static final String TAG = ConstantsKeystore.class.getName();

    private final String keystoreName = "AndroidKeyStore";

    // as we do need aliases for the safe storage this is the placeholder
    private final String keyAlias = "key_";
    private final String nameDelimiter = "_";
    private boolean iskeyAes = false;
    private byte keyNumber;
    private byte[] key;
    private Context context;

    public ConstantsKeystore(Context context) {
        this.context = context;
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
        if (key.length == 16) iskeyAes = true;
        // build alias name
        StringBuilder sb = new StringBuilder();
        sb.append(keyAlias);
        sb.append(keyNumber);
        String alias = sb.toString();
        try {
            SecretKeyWrapper secretKeyWrapper = new SecretKeyWrapper(context, alias);
            SecretKey secretKey;
            if (iskeyAes) {
                secretKey = new SecretKeySpec(key, "AES");
            } else {
                secretKey = new SecretKeySpec(key, "DES");
            }
            byte[] wrappedKey = secretKeyWrapper.wrap(secretKey);
            KeyStore keyStore = KeyStore.getInstance(keystoreName);
            keyStore.load(null);
            if (keyStore.containsAlias(alias)) {
                Log.d(TAG, "alias is already present in keyStore, aborted");
                return false;
            }
            AlgorithmParameterSpec spec = new KeyGenParameterSpec.Builder(WRAP_KEY_ALIAS, KeyProperties.PURPOSE_WRAP_KEY)
                    .setDigests(KeyProperties.DIGEST_SHA256)
                    .build();
            KeyStore.Entry wrappedKeyEntry = new WrappedKeyEntry(wrappedKeySequence, WRAP_KEY_ALIAS, WRAP_ALGORITHM, spec);
            String keyAlias = "SECRET_KEY";


            WrappedKeyEntry wrappedKeyEntry = new WrappedKeyEntry(wrappedKey, alias, "RSA/ECB/OAEPPadding", )
            KeyStore.Entry entry = new KeyStore.SecretKeyEntry(a);
            keyStore.setEntry(alias, entry);
            Log.d(TAG, "key is stored");
            return true;
        } catch (IOException | GeneralSecurityException e) {
            Log.e(TAG, "Exception on keystore usage, aborted");
            Log.e(TAG, e.getMessage());
            return false;
        }
    }



}
