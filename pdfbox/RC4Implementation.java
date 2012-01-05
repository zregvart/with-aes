package org.apache.pdfbox.pdmodel.encryption;

import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.pdfbox.exceptions.CryptographyException;

public class RC4Implementation extends BaseEncryptionImplementation implements EncryptionImplementation {

    public Key computeKey(final SecurityHandler securityHandler, final long objectNumber, final long genNumber) throws CryptographyException {
        final byte[] newKey = generateKeyBase(securityHandler, objectNumber, genNumber);

        // step 3
        byte[] digestedKey = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(newKey);
            digestedKey = md.digest();
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }

        // step 4
        final int length = Math.min(newKey.length, 16);
        final byte[] finalKey = new byte[length];
        System.arraycopy(digestedKey, 0, finalKey, 0, length);

        final SecretKey key = new SecretKeySpec(finalKey, "RC4");

        return key;
    }

}
