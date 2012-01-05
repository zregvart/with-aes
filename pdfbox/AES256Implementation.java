package org.apache.pdfbox.pdmodel.encryption;

import java.security.Key;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.apache.pdfbox.exceptions.CryptographyException;

public class AES256Implementation extends BaseAesImplementation implements EncryptionImplementation {

    public Key computeKey(final SecurityHandler securityHandler, final long objectNumber, final long genNumber) throws CryptographyException {
        final SecretKey key = new SecretKeySpec(securityHandler.encryptionKey, "AES");

        return key;
    }

}
