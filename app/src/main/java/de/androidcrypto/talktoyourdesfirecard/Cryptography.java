package de.androidcrypto.talktoyourdesfirecard;

import android.util.Base64;
import android.util.Log;
import android.widget.TextView;

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
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


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

    /**
     * section for signatures
     */
    private final String EC_CURVE = "secp256r1";
    private final String SIGNATURE_ALGORITHM = "EC";
    private final String ECDSA_ALGORITHM = "SHA256withECDSA";

    /**
     * section for Originality check
     */

    private static final byte[] SECP224R1_HEAD = base64Decoding("ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE"); // this is the header of secp224r1

    /**
     * section for signatures
     */

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
        if (keyPair != null) {
            return keyPair.getPrivate();
        } else {
            return null;
        }
    }

    public PublicKey getEcPublicKeyFromKeyPair(KeyPair keyPair) {
        if (keyPair != null) {
            return keyPair.getPublic();
        } else {
            return null;
        }
    }

    // the encoded private key of a secp256r1 curve is 138 bytes long
    public byte[] getEcPrivateKeyEncoded(PrivateKey privateKeyEc) {
        if (privateKeyEc != null) {
            return privateKeyEc.getEncoded();
        } else {
            return null;
        }
    };

    // the encoded public key of a secp256r1 curve is 91 bytes long
    public byte[] getEcPublicKeyEncoded(PublicKey publicKeyEc) {
        if (publicKeyEc != null) {
            return publicKeyEc.getEncoded();
        } else {
            return null;
        }
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
        if (privateKeyEc == null) return null;
        if ((message == null) || (message.length < 1)) return null;
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
        if (publicKey == null) return false;
        if ((message == null) || (message.length < 1)) return false;
        if ((signature == null) || (signature.length < 1)) return false;
        try {
            Signature ecdsaSgnature = Signature.getInstance(ECDSA_ALGORITHM);
            ecdsaSgnature.initVerify(publicKey);
            ecdsaSgnature.update(message);
            boolean result = ecdsaSgnature.verify(signature);
            Log.d(TAG, "verify result: " + result);
            return result;
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            Log.e(TAG, "verifyAMessageEcdsa Exception: " + e.getMessage());
            return false;
        }
    }

/*
usage example:
Cryptography cryptography = new Cryptography();
KeyPair keyPair = cryptography.generateAnEcdsaKeypair();
PrivateKey privateKey = cryptography.getEcPrivateKeyFromKeyPair(keyPair);
PublicKey publicKey = cryptography.getEcPublicKeyFromKeyPair(keyPair);
byte[] privateKeyEncoded = cryptography.getEcPrivateKeyEncoded(privateKey);
byte[] publicKeyEncoded = cryptography.getEcPublicKeyEncoded(publicKey);
Log.d(TAG, printData("private key encoded", privateKeyEncoded));
Log.d(TAG, printData("public  key encoded", publicKeyEncoded));
// do what you want with the encoded forms
PrivateKey privateKeyRestored = cryptography.getEcPrivateKeyFromEncoded(privateKeyEncoded);
PublicKey publicKeyRestored = cryptography.getEcPublicKeyFromEncoded(publicKeyEncoded);
byte[] message = "The quick brown fox jumps over the lazy dog".getBytes(StandardCharsets.UTF_8);
byte[] signature = cryptography.signAMessageEcdsa(privateKeyRestored, message);
boolean verification = cryptography.verifyAMessageEcdsa(publicKeyRestored, message, signature);
Log.d(TAG, printData("message", message));
Log.d(TAG, printData("signature", signature));
Log.d(TAG, "The signature is verified: " + verification);
 */
/*
example output
private key encoded length: 138 data: 308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b020101042046f79ca71265a50d67250ee86fa7f6c837aeac79454a2562625f74a790e9ebcea1440342000488459472add2368cda06dccc99b4a9d067f99961b371a6e83324dea11f2d0f0fa2dab91dbd54dd08b3601be805278879d42728fba0a93221fb4acd642a681249
public  key encoded length: 91 data: 3059301306072a8648ce3d020106082a8648ce3d0301070342000488459472add2368cda06dccc99b4a9d067f99961b371a6e83324dea11f2d0f0fa2dab91dbd54dd08b3601be805278879d42728fba0a93221fb4acd642a681249
message length: 43 data: 54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67
signature length: 71 data: 3045022042e80cf47d0a1dda5d8153d0483af9c7dc81d76d27b93c77881e2210984bcab6022100e46015e80917a3e4346a54c7b3c3bf345a4418a5c6a86ce32c34ca6cba854e75
The signature is verified: true
 */

    /**
     * section for Originality Check
     */

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     *
     * @param w a 64 byte uncompressed EC point starting with <code>04</code>
     * @return an <code>ECPublicKey</code> that the point represents
     */
    public ECPublicKey generateP256PublicKeyFromUncompressedW(byte[] w) throws InvalidKeySpecException {
        if (w[0] != 0x04) {
            throw new InvalidKeySpecException("w is not an uncompressed key");
        }
        return generateP256PublicKeyFromFlatW(Arrays.copyOfRange(w, 1, w.length));
    }

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     *
     * @param w a 64 byte uncompressed EC point consisting of just a 256-bit X and Y
     * @return an <code>ECPublicKey</code> that the point represents
     */
    public ECPublicKey generateP256PublicKeyFromFlatW(byte[] w) throws InvalidKeySpecException {
        byte[] encodedKey = new byte[SECP224R1_HEAD.length + w.length];
        System.arraycopy(SECP224R1_HEAD, 0, encodedKey, 0, SECP224R1_HEAD.length);
        System.arraycopy(w, 0, encodedKey, SECP224R1_HEAD.length, w.length);
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
        return (ECPublicKey) eckf.generatePublic(ecpks);
    }

    public boolean checkEcdsaSignatureEcPubKey(final ECPublicKey
                                                       ecPubKey, final byte[]
                                                       signature, final byte[] data)
            throws NoSuchAlgorithmException {
        try {
            final Signature dsa = Signature.getInstance("NONEwithECDSA");
            dsa.initVerify(ecPubKey);
            dsa.update(data);
            return dsa.verify(derEncodeSignatureSecp224r1(signature));
        } catch (final SignatureException | InvalidKeyException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static byte[] derEncodeSignatureSecp224r1(final byte[] signature) {
        // split into r and s
        final byte[] r = Arrays.copyOfRange(signature, 0, 28);
        final byte[] s = Arrays.copyOfRange(signature, 28, 56);
        /* code for secp128r1
        final byte[] r = Arrays.copyOfRange(signature, 0, 16);
        final byte[] s = Arrays.copyOfRange(signature, 16, 32);
        */
        int rLen = r.length;
        int sLen = s.length;
        if ((r[0] & 0x80) != 0) {
            rLen++;
        }
        if ((s[0] & 0x80) != 0) {
            sLen++;
        }
        final byte[] encodedSig = new byte[rLen + sLen + 6]; // 6 T and L bytes
        encodedSig[0] = 0x30; // SEQUENCE
        encodedSig[1] = (byte) (4 + rLen + sLen);
        encodedSig[2] = 0x02; // INTEGER
        encodedSig[3] = (byte) rLen;
        encodedSig[4 + rLen] = 0x02; // INTEGER
        encodedSig[4 + rLen + 1] = (byte) sLen;

        // copy in r and s
        encodedSig[4] = 0;
        encodedSig[4 + rLen + 2] = 0;
        System.arraycopy(r, 0, encodedSig, 4 + rLen - r.length, r.length);
        System.arraycopy(s, 0, encodedSig, 4 + rLen + 2 + sLen - s.length,
                s.length);

        return encodedSig;
    }

    public static byte[] base64Decoding(String input) {
        return Base64.decode(input, Base64.NO_WRAP);
    }

}
