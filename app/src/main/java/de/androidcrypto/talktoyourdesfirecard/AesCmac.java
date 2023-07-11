package de.androidcrypto.talktoyourdesfirecard;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AesCmac {
    // by atom https://stackoverflow.com/questions/24874176/debugging-aes-cmac-generating-wrong-answer
    // with answer by Maarten Bodewes https://stackoverflow.com/a/24875365/8166854
    // https://csrc.nist.gov/publications/detail/sp/800-38b/final
    // Examples for CMAC are available at the examples page on NIST’s Computer Security Resource
    // Center (CSRC) website: http://csrc.nist.gov/groups/ST/toolkit/examples.html.
    // https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf

/*
usage:
public byte[] calculateDiverseKey(byte [] input) throws InvalidKeyException, NoSuchAlgorithmException {
    AesCmac mac = null;
    mac = new AesCmac();
    SecretKey key = new SecretKeySpec(masterKey, "AES");
    mac.init(key);  //set master key
    mac.updateBlock(input); //given input
    for (byte b: input) System.out.print(" "+b);
    return mac.doFinal();
    }
 */

    private static final byte CONSTANT = (byte) 0x87;
    private static final int BLOCK_SIZE = 16;

    private static final IvParameterSpec ZERO_IV = new IvParameterSpec(new byte[16]);

    private int macLength;
    private Cipher aesCipher;

    private byte[] buffer;
    private int bufferCount;

    private byte[] k1;
    private byte[] k2;

    public AesCmac() throws NoSuchAlgorithmException {
        this(BLOCK_SIZE);
    }

    public AesCmac(int length) throws NoSuchAlgorithmException {
        if (length > BLOCK_SIZE) {
            throw new NoSuchAlgorithmException("AES CMAC maximum length is " + BLOCK_SIZE);
        }

        try {
            macLength = length;
            aesCipher = Cipher.getInstance("AES/CBC/NOPADDING");
            buffer = new byte[BLOCK_SIZE];
        } catch (NoSuchPaddingException nspe) {
            nspe.printStackTrace();
        }
    }

    private byte[] doubleSubKey(byte[] k) {
        byte[] ret = new byte[k.length];

        boolean firstBitSet = ((k[0]&0x80) != 0);
        for (int i=0; i<k.length; i++) {
            ret[i] = (byte) (k[i] << 1);
            if (i+1 < k.length && ((k[i+1]&0x80) != 0)) {
                ret[i] |= 0x01;
            }
        }
        if (firstBitSet) {
            ret[ret.length-1] ^= CONSTANT;
        }
        return ret;
    }

    public final void init(Key key) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (!(key instanceof SecretKeySpec)) {
            throw new InvalidKeyException("Key is not of required type SecretKey.");
        }
        if (!((SecretKeySpec)key).getAlgorithm().equals("AES")) {
            throw new InvalidKeyException("Key is not an AES key.");
        }
        //aesCipher.init(Cipher.ENCRYPT_MODE, key);
        aesCipher.init(Cipher.ENCRYPT_MODE, key, ZERO_IV);

        // First calculate k0 from zero bytes
        byte[] k0 = new byte[BLOCK_SIZE];
        try {
            aesCipher.update(k0, 0, k0.length, k0, 0);
        } catch (ShortBufferException sbe) {}

        // Calculate values for k1 and k2
        k1 = doubleSubKey(k0);
        k2 = doubleSubKey(k1);

        //aesCipher.init(Cipher.ENCRYPT_MODE, key);
        aesCipher.init(Cipher.ENCRYPT_MODE, key, ZERO_IV);
        bufferCount = 0;
    }

    public final void updateByte(byte b) {
        updateBlock(new byte[] { b });
    }

    public final void updateBlock(byte[] data) {
        int currentOffset = 0;

        if (data.length < BLOCK_SIZE-bufferCount) {
            System.arraycopy(data, 0, buffer, bufferCount, data.length);
            bufferCount += data.length;
            return;
        } else if (bufferCount > 0) {
            System.arraycopy(data, 0, buffer, bufferCount, BLOCK_SIZE-bufferCount);
            try {
                aesCipher.update(buffer, 0, BLOCK_SIZE, buffer, 0);
            } catch (ShortBufferException sbe) {}
            currentOffset += BLOCK_SIZE-bufferCount;
            bufferCount = 0;
        }

        // Transform all the full blocks in data
        while (currentOffset+BLOCK_SIZE < data.length) {
            try {
                aesCipher.update(data, currentOffset, BLOCK_SIZE, buffer, 0);
            } catch (ShortBufferException sbe) {}
            currentOffset += BLOCK_SIZE;
        }

        // Save the leftover bytes to buffer
        if (currentOffset != data.length) {
            System.arraycopy(data, currentOffset, buffer, 0, data.length-currentOffset);
            bufferCount = data.length-currentOffset;
        }
    }

    public final byte[] doFinal() {
        byte[] subKey = k1;
        if (bufferCount < BLOCK_SIZE) {
            // Add padding and XOR with k2 instead
            buffer[bufferCount] = (byte) 0x80;
            for (int i=bufferCount+1; i<BLOCK_SIZE; i++)
                buffer[i] = (byte) 0x00;
            subKey = k2;
        }
        for (int i=0; i<BLOCK_SIZE; i++) {
            buffer[i] ^= subKey[i];
        }

        // Calculate the final CMAC calue
        try {
            aesCipher.doFinal(buffer, 0, BLOCK_SIZE, buffer, 0);
        }
        // These should never happen because we pad manually
        catch (ShortBufferException sbe) {}
        catch (IllegalBlockSizeException ibse) {}
        catch (BadPaddingException ibse) {}
        bufferCount = 0;

        byte[] mac = new byte[macLength];
        System.arraycopy(buffer, 0, mac, 0, macLength);
        return  mac;
    }

    public final byte[] calculateHash(byte[] data) {
        updateBlock(data);
        return doFinal();
    }
}
