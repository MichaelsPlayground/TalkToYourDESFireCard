package de.androidcrypto.talktoyourdesfirecard;

import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


/**
 * The class is responsible for all cryptographic operations:
 * - generate an ECDSA keypair
 * - convert a Private or Public key to encoded and back
 * - sign a signature with the Private Key
 * - verify a signature with the Public Key
 * The class uses the Elliptic Curve (EC) cryptography with this parameter:
 * algorithm: ECDSA with SHA-256 hashing of the  message
 *
 */

public class Cryptography {

    private static final String TAG = Cryptography.class.getName();

    private final String EC_CURVE = "secp256k1";
    private final String SIGNATURE_ALGORITHM = "EC";
    private final String ECDSA_ALGORITHM = "SHA256withECDSA";

    public KeyPair generateAnEcdsaKeypair() {
        ECGenParameterSpec ecGenParameterSpec = new ECGenParameterSpec(EC_CURVE);
        KeyPairGenerator keyPairGenerator = null;
        try {
            keyPairGenerator = KeyPairGenerator.getInstance(SIGNATURE_ALGORITHM);
            keyPairGenerator.initialize(ecGenParameterSpec, new SecureRandom());
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            return keyPair;
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            Log.e(TAG, "generateAnEcdsaKeypair Exception: " + e.getMessage());
            return null;
        }
    }

    public PrivateKey getEcPrivateKeyFromKeyPair(KeyPair keyPair) {
        return keyPair.getPrivate();
    }

    public PublicKey getEcPublicKeyFromKeyPair(KeyPair keyPair) {
        return keyPair.getPublic();
    }

    public byte[] getEcPrivateKeyEncoded(PrivateKey privateKeyEc) {
        return privateKeyEc.getEncoded();
    };

    public byte[] getEcPublicKeyEncoded(PublicKey publicKeyEc) {
        return publicKeyEc.getEncoded();
    }

    public PrivateKey getEcPrivateKeyFromEncoded(byte[] privateKeyEcEncoded) {
        if ((privateKeyEcEncoded == null) || (privateKeyEcEncoded.length < 32)) return null;
        KeyFactory kf = null;
        try {
            kf = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyEcEncoded);
            PrivateKey privateKey = (PrivateKey) kf.generatePrivate(keySpec);
            return privateKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "getEcPrivateKeyFromEncoded Exception: " + e.getMessage());
            return null;
        }

    }

    public PublicKey getEcPublicKeyFromEncoded(byte[] publicKeyEcEncoded) {
        if ((publicKeyEcEncoded == null) || (publicKeyEcEncoded.length < 32)) return null;
        KeyFactory keyFactory = null;
        try {
            keyFactory = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyEcEncoded);
            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            return publicKey;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            Log.e(TAG, "getEcPublicKeyFromEncoded Exception: " + e.getMessage());
            return null;
        }
    }

    public byte[] signAMessageEcdsa(PrivateKey privateKeyEc, byte[] message) {
        Signature ecdsaSign = null;
        try {
            ecdsaSign = Signature.getInstance(ECDSA_ALGORITHM);
            ecdsaSign.initSign(privateKeyEc);
            ecdsaSign.update(message);
            byte[] signature = ecdsaSign.sign();
            return signature;
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            Log.e(TAG, "signAMessageEcdsa Exception: " + e.getMessage());
            return null;
        }
    }

    public boolean verifyAMessageEcdsa(PublicKey publicKey, byte[] message, byte[] signature) {
        try {
            KeyFactory kf = KeyFactory.getInstance(SIGNATURE_ALGORITHM);
            Signature ecdsaSgnature = Signature.getInstance(ECDSA_ALGORITHM);
            ecdsaSgnature.initVerify(publicKey);
            ecdsaSgnature.update(message);
            boolean result = ecdsaSgnature.verify(signature);
            return result;
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            Log.e(TAG, "verifyAMessageEcdsa Exception: " + e.getMessage());
            return false;
        }
    }

}
