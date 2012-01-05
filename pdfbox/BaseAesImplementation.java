package org.apache.pdfbox.pdmodel.encryption;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.spec.IvParameterSpec;

import org.apache.pdfbox.exceptions.CryptographyException;

public abstract class BaseAesImplementation extends BaseEncryptionImplementation {

    public static final int IV_LENGTH = 16;

    @Override
    protected String algorithmFor(final Key key) {
        return "AES/CBC/PKCS5Padding";
    }

    @Override
    public InputStream decrypt(final Key key, final InputStream encrypted) throws CryptographyException, IOException {
        final byte[] iv = new byte[IV_LENGTH];

        final int read = encrypted.read(iv);

        if (read != IV_LENGTH) {
            throw new IOException("unable to read initialization vector expected: " + IV_LENGTH + ", got: " + read);
        }

        final AlgorithmParameterSpec parameter = new IvParameterSpec(iv);

        return decrypt(key, parameter, encrypted);
    }

    @Override
    public InputStream encrypt(final Key key, final InputStream clear) throws CryptographyException, IOException {
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }

        final byte[] iv = new byte[IV_LENGTH];

        secureRandom.nextBytes(iv);

        final AlgorithmParameterSpec parameter = new IvParameterSpec(iv);

        final InputStream encrypted = encrypt(key, parameter, clear);

        return new SequenceInputStream(new ByteArrayInputStream(iv), encrypted);
    }
}
