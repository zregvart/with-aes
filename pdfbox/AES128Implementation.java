package org.apache.pdfbox.pdmodel.encryption;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.pdfbox.exceptions.CryptographyException;

public class AES128Implementation extends BaseAesImplementation implements EncryptionImplementation {

    /*
     * See 7.6.2, page 58, PDF 32000-1:2008
     */
    private final static byte[] AES_SALT = { (byte) 0x73, (byte) 0x41, (byte) 0x6c, (byte) 0x54 };

    public Key computeKey(final SecurityHandler securityHandler, final long objectNumber, final long genNumber) throws CryptographyException {
        final byte[] newKey = generateKeyBase(securityHandler, objectNumber, genNumber);

        // step 3
        byte[] digestedKey = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(newKey);
            md.update(AES_SALT);
            digestedKey = md.digest();
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }

        // step 4
        final int length = Math.min(newKey.length, 16);
        final byte[] finalKey = new byte[length];
        System.arraycopy(digestedKey, 0, finalKey, 0, length);

        final SecretKey key = new SecretKeySpec(finalKey, "AES");

        return key;
    }

}
