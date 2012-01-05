package org.apache.pdfbox.pdmodel.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

import org.apache.pdfbox.exceptions.CryptographyException;

public abstract class BaseEncryptionImplementation {

    /**
     * Standard padding for encryption.
     */
    public static final byte[] ENCRYPT_PADDING = { (byte) 0x28, (byte) 0xBF, (byte) 0x4E, (byte) 0x5E, (byte) 0x4E, (byte) 0x75, (byte) 0x8A, (byte) 0x41, (byte) 0x64, (byte) 0x00, (byte) 0x4E,
            (byte) 0x56, (byte) 0xFF, (byte) 0xFA, (byte) 0x01, (byte) 0x08, (byte) 0x2E, (byte) 0x2E, (byte) 0x00, (byte) 0xB6, (byte) 0xD0, (byte) 0x68, (byte) 0x3E, (byte) 0x80, (byte) 0x2F,
            (byte) 0x0C, (byte) 0xA9, (byte) 0xFE, (byte) 0x64, (byte) 0x53, (byte) 0x69, (byte) 0x7A };

    /**
     * This will compare two byte[] for equality.
     * 
     * @param first
     *            The first byte array.
     * @param second
     *            The second byte array.
     * @param count
     *            to what index should the arrays be equal
     * 
     * @return true If the arrays contain the exact same data up to count bytes.
     */
    private static final boolean arraysEqual(final byte[] first, final byte[] second, final int count) {
        boolean equal = first.length >= count && second.length >= count;
        for (int i = 0; i < count && equal; i++) {
            equal = first[i] == second[i];
        }
        return equal;
    }

    protected String algorithmFor(final Key key) {
        return key.getAlgorithm();
    }

    public byte[] computeEncryptionKey(final byte[] password, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length, final boolean encryptMetadata)
            throws CryptographyException {
        final byte[] result = new byte[length];
        try {
            // PDFReference 1.4 pg 78
            // step1
            final byte[] padded = truncateOrPad(password);

            // step 2
            final MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(padded);

            // step 3
            md.update(o);

            // step 4
            final byte zero = (byte) (permissions >>> 0);
            final byte one = (byte) (permissions >>> 8);
            final byte two = (byte) (permissions >>> 16);
            final byte three = (byte) (permissions >>> 24);

            md.update(zero);
            md.update(one);
            md.update(two);
            md.update(three);

            // step 5
            md.update(id);

            // (Security handlers of revision 4 or greater) If document metadata is not being encrypted,
            // pass 4 bytes with the value 0xFFFFFFFF to the MD5 hash function.
            // see 7.6.3.3 Algorithm 2 Step f of PDF 32000-1:2008
            if (encRevision == 4 && !encryptMetadata) {
                md.update(new byte[] { (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff });
            }

            byte[] digest = md.digest();

            // step 6
            if (encRevision == 3 || encRevision == 4) {
                for (int i = 0; i < 50; i++) {
                    md.reset();
                    md.update(digest, 0, length);
                    digest = md.digest();
                }
            }

            // step 7
            if (encRevision == 2 && length != 5) {
                throw new CryptographyException("Error: length should be 5 when revision is two actual=" + length);
            }
            System.arraycopy(digest, 0, result, 0, length);
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }
        return result;
    }

    public byte[] computeOwnerKey(final byte[] ownerPassword, final byte[] userPassword, final int encRevision, final int length) throws CryptographyException {
        // STEP 1
        final byte[] ownerPadded = truncateOrPad(ownerPassword);

        // STEP 2
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }
        byte[] digest = md.digest(ownerPadded);

        // STEP 3
        if (encRevision == 3 || encRevision == 4) {
            for (int i = 0; i < 50; i++) {
                md.reset();
                md.update(digest, 0, length);
                digest = md.digest();
            }
        }
        if (encRevision == 2 && length != 5) {
            throw new CryptographyException("Error: Expected length=5 actual=" + length);
        }

        // STEP 4
        final byte[] rc4Key = new byte[length];
        System.arraycopy(digest, 0, rc4Key, 0, length);

        // STEP 5
        final byte[] paddedUser = truncateOrPad(userPassword);

        // STEP 6
        final Key key = new SecretKeySpec(rc4Key, "RC4");

        final Cipher rc4Cipher = newRC4Cipher();
        try {
            rc4Cipher.init(Cipher.ENCRYPT_MODE, key);
        } catch (final InvalidKeyException e) {
            throw new CryptographyException(e);
        }

        byte[] crypted;
        try {
            crypted = rc4Cipher.doFinal(paddedUser);
        } catch (final IllegalBlockSizeException e) {
            throw new CryptographyException(e);
        } catch (final BadPaddingException e) {
            throw new CryptographyException(e);
        }

        // STEP 7
        if (encRevision == 3 || encRevision == 4) {
            final byte[] iterationKeyBytes = new byte[rc4Key.length];
            for (int i = 1; i < 20; i++) {
                System.arraycopy(rc4Key, 0, iterationKeyBytes, 0, rc4Key.length);
                for (int j = 0; j < iterationKeyBytes.length; j++) {
                    iterationKeyBytes[j] = (byte) (iterationKeyBytes[j] ^ (byte) i);
                }

                final Key iterationKey = new SecretKeySpec(iterationKeyBytes, "RC4");

                try {
                    rc4Cipher.init(Cipher.ENCRYPT_MODE, iterationKey);
                    crypted = rc4Cipher.doFinal(crypted);
                } catch (final InvalidKeyException e) {
                    throw new CryptographyException(e);
                } catch (final IllegalBlockSizeException e) {
                    throw new CryptographyException(e);
                } catch (final BadPaddingException e) {
                    throw new CryptographyException(e);
                }
            }
        }

        // STEP 8
        return crypted;
    }

    public byte[] computeUserKey(final byte[] password, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length, final boolean encryptMetadata)
            throws CryptographyException {
        // STEP 1
        final byte[] encryptionKey = computeEncryptionKey(password, o, permissions, id, encRevision, length, encryptMetadata);

        final Cipher rc4Cipher = newRC4Cipher();

        if (encRevision == 2) {
            // STEP 2
            final Key rc4Key = new SecretKeySpec(encryptionKey, "RC4");

            try {
                rc4Cipher.init(Cipher.ENCRYPT_MODE, rc4Key);

                return rc4Cipher.doFinal(ENCRYPT_PADDING);
            } catch (final InvalidKeyException e) {
                throw new CryptographyException(e);
            } catch (final IllegalBlockSizeException e) {
                throw new CryptographyException(e);
            } catch (final BadPaddingException e) {
                throw new CryptographyException(e);
            }
        }
        else if (encRevision == 3 || encRevision == 4) {
            try {
                // STEP 2
                final MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(ENCRYPT_PADDING);

                // STEP 3
                md.update(id);
                byte[] cipher = md.digest();

                // STEP 4 and 5
                final byte[] iterationKeyBytes = new byte[encryptionKey.length];
                for (int i = 0; i < 20; i++) {
                    System.arraycopy(encryptionKey, 0, iterationKeyBytes, 0, iterationKeyBytes.length);
                    for (int j = 0; j < iterationKeyBytes.length; j++) {
                        iterationKeyBytes[j] = (byte) (iterationKeyBytes[j] ^ i);
                    }

                    final Key iterationKey = new SecretKeySpec(iterationKeyBytes, "RC4");

                    try {
                        rc4Cipher.init(Cipher.ENCRYPT_MODE, iterationKey);

                        cipher = rc4Cipher.doFinal(cipher);
                    } catch (final InvalidKeyException e) {
                        throw new CryptographyException(e);
                    } catch (final IllegalBlockSizeException e) {
                        throw new CryptographyException(e);
                    } catch (final BadPaddingException e) {
                        throw new CryptographyException(e);
                    }
                }

                // step 6
                final byte[] finalResult = new byte[32];
                System.arraycopy(cipher, 0, finalResult, 0, 16);
                System.arraycopy(ENCRYPT_PADDING, 0, finalResult, 16, 16);

                return finalResult;
            } catch (final NoSuchAlgorithmException e) {
                throw new CryptographyException(e);
            }
        }

        throw new IllegalStateException("unsupported revision: " + encRevision);
    }

    /**
     * This will compute the user password hash.
     * 
     * @param password
     *            The plain text password.
     * @param o
     *            The owner password hash.
     * @param permissions
     *            The document permissions.
     * @param id
     *            The document id.
     * @param encRevision
     *            The revision of the encryption.
     * @param length
     *            The length of the encryption key.
     * 
     * @return The user password.
     * 
     * @throws CryptographyException
     *             If there is an error computing the user password.
     * @throws IOException
     *             If there is an IO error.
     */
    public final byte[] computeUserPassword(final byte[] password, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length, final boolean encryptMetadata)
            throws CryptographyException {
        // STEP 1
        final byte[] encryptionKey = computeEncryptionKey(password, o, permissions, id, encRevision, length, encryptMetadata);

        final Cipher rc4Cipher = newRC4Cipher();

        if (encRevision == 2) {
            // STEP 2
            final Key rc4Key = new SecretKeySpec(encryptionKey, "RC4");

            try {
                rc4Cipher.init(Cipher.ENCRYPT_MODE, rc4Key);

                return rc4Cipher.doFinal(ENCRYPT_PADDING);
            } catch (final InvalidKeyException e) {
                throw new CryptographyException(e);
            } catch (final IllegalBlockSizeException e) {
                throw new CryptographyException(e);
            } catch (final BadPaddingException e) {
                throw new CryptographyException(e);
            }
        }
        else if (encRevision == 3 || encRevision == 4) {
            try {
                // STEP 2
                final MessageDigest md = MessageDigest.getInstance("MD5");
                md.update(ENCRYPT_PADDING);

                // STEP 3
                md.update(id);
                byte[] cipher = md.digest();

                // STEP 4 and 5
                final byte[] iterationKeyBytes = new byte[encryptionKey.length];
                for (int i = 0; i < 20; i++) {
                    System.arraycopy(encryptionKey, 0, iterationKeyBytes, 0, iterationKeyBytes.length);
                    for (int j = 0; j < iterationKeyBytes.length; j++) {
                        iterationKeyBytes[j] = (byte) (iterationKeyBytes[j] ^ i);
                    }

                    final Key iterationKey = new SecretKeySpec(iterationKeyBytes, "RC4");

                    try {
                        rc4Cipher.init(Cipher.ENCRYPT_MODE, iterationKey);

                        cipher = rc4Cipher.doFinal(cipher);
                    } catch (final InvalidKeyException e) {
                        throw new CryptographyException(e);
                    } catch (final IllegalBlockSizeException e) {
                        throw new CryptographyException(e);
                    } catch (final BadPaddingException e) {
                        throw new CryptographyException(e);
                    }
                }

                // step 6
                final byte[] finalResult = new byte[32];
                System.arraycopy(cipher, 0, finalResult, 0, 16);
                System.arraycopy(ENCRYPT_PADDING, 0, finalResult, 16, 16);

                return finalResult;
            } catch (final NoSuchAlgorithmException e) {
                throw new CryptographyException(e);
            }
        }

        throw new IllegalStateException("unsupported revision: " + encRevision);
    }

    protected Cipher createCipher(final Key key, final int mode, final AlgorithmParameterSpec parameters) throws CryptographyException {
        final Cipher cipher;
        try {
            cipher = Cipher.getInstance(algorithmFor(key));

            if (parameters == null) {
                cipher.init(mode, key);
            }
            else {
                cipher.init(mode, key, parameters);
            }
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        } catch (final NoSuchPaddingException e) {
            throw new CryptographyException(e);
        } catch (final InvalidKeyException e) {
            throw new CryptographyException(e);
        } catch (final InvalidAlgorithmParameterException e) {
            throw new CryptographyException(e);
        }

        return cipher;
    }

    public InputStream decrypt(final Key key, final AlgorithmParameterSpec parameters, final InputStream encrypted) throws CryptographyException, IOException {
        final Cipher cipher = createCipher(key, Cipher.DECRYPT_MODE, parameters);

        return new CipherInputStream(encrypted, cipher);
    }

    public InputStream decrypt(final Key key, final InputStream encrypted) throws CryptographyException, IOException {
        return decrypt(key, null, encrypted);
    }

    public InputStream encrypt(final Key key, final AlgorithmParameterSpec parameters, final InputStream clear) throws CryptographyException, IOException {
        final Cipher cipher = createCipher(key, Cipher.ENCRYPT_MODE, parameters);

        return new CipherInputStream(clear, cipher);
    }

    public InputStream encrypt(final Key key, final InputStream clear) throws CryptographyException, IOException {
        return encrypt(key, null, clear);
    }

    protected byte[] generateKeyBase(final SecurityHandler securityHandler, final long objectNumber, final long genNumber) {
        final byte[] newKey = new byte[securityHandler.encryptionKey.length + 5];
        System.arraycopy(securityHandler.encryptionKey, 0, newKey, 0, securityHandler.encryptionKey.length);
        // PDF 1.4 reference pg 73 step 1 we have the reference

        // step 2
        newKey[newKey.length - 5] = (byte) (objectNumber & 0xff);
        newKey[newKey.length - 4] = (byte) (objectNumber >> 8 & 0xff);
        newKey[newKey.length - 3] = (byte) (objectNumber >> 16 & 0xff);
        newKey[newKey.length - 2] = (byte) (genNumber & 0xff);
        newKey[newKey.length - 1] = (byte) (genNumber >> 8 & 0xff);

        return newKey;
    }

    /**
     * Get the user password based on the owner password.
     * 
     * @param ownerPassword
     *            The plaintext owner password.
     * @param o
     *            The o entry of the encryption dictionary.
     * @param encRevision
     *            The encryption revision number.
     * @param length
     *            The key length.
     * 
     * @return The u entry of the encryption dictionary.
     * 
     * @throws CryptographyException
     *             If there is an error generating the user password.
     * @throws IOException
     *             If there is an error accessing data while generating the user password.
     */
    public final byte[] getUserPassword(final byte[] ownerPassword, final byte[] o, final int encRevision, final int length) throws CryptographyException {
        // 3.3 STEP 1
        final byte[] ownerPadded = truncateOrPad(ownerPassword);

        // 3.3 STEP 2
        MessageDigest md;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }

        byte[] digest = md.digest(ownerPadded);

        // 3.3 STEP 3
        if (encRevision == 3 || encRevision == 4) {
            for (int i = 0; i < 50; i++) {
                md.reset();
                md.update(digest);
                digest = md.digest();
            }
        }
        if (encRevision == 2 && length != 5) {
            throw new CryptographyException("Error: Expected length=5 actual=" + length);
        }

        // 3.3 STEP 4
        final byte[] rc4Key = new byte[length];
        System.arraycopy(digest, 0, rc4Key, 0, length);

        // 3.7 step 2
        final Cipher rc4Cipher = newRC4Cipher();

        if (encRevision == 2) {
            final Key key = new SecretKeySpec(rc4Key, "RC4");
            try {
                rc4Cipher.init(Cipher.ENCRYPT_MODE, key);

                return rc4Cipher.doFinal(o);
            } catch (final InvalidKeyException e) {
                throw new CryptographyException(e);
            } catch (final IllegalBlockSizeException e) {
                throw new CryptographyException(e);
            } catch (final BadPaddingException e) {
                throw new CryptographyException(e);
            }
        }
        else if (encRevision == 3 || encRevision == 4) {
            byte[] iterationKey = new byte[rc4Key.length];
            for (int i = 19; i >= 0; i--) {
                System.arraycopy(rc4Key, 0, iterationKey, 0, rc4Key.length);
                for (int j = 0; j < iterationKey.length; j++) {
                    iterationKey[j] = (byte) (iterationKey[j] ^ (byte) i);
                }

                final Key key = new SecretKeySpec(iterationKey, "RC4");
                try {
                    rc4Cipher.init(Cipher.ENCRYPT_MODE, key);

                    iterationKey = rc4Cipher.doFinal(iterationKey);
                } catch (final InvalidKeyException e) {
                    throw new CryptographyException(e);
                } catch (final IllegalBlockSizeException e) {
                    throw new CryptographyException(e);
                } catch (final BadPaddingException e) {
                    throw new CryptographyException(e);
                }
            }

            return iterationKey;
        }

        throw new IllegalStateException("unsupported revision: " + encRevision);
    }

    /**
     * Check for owner password.
     * 
     * @param ownerPassword
     *            The owner password.
     * @param u
     *            The u entry of the encryption dictionary.
     * @param o
     *            The o entry of the encryption dictionary.
     * @param permissions
     *            The set of permissions on the document.
     * @param id
     *            The document id.
     * @param encRevision
     *            The encryption algorithm revision.
     * @param length
     *            The encryption key length.
     * 
     * @return True If the ownerPassword param is the owner password.
     * 
     * @throws CryptographyException
     *             If there is an error during encryption.
     * @throws IOException
     *             If there is an error accessing data.
     */
    public final boolean isOwnerPassword(final byte[] ownerPassword, final byte[] u, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length,
            final boolean encryptMetadata) throws CryptographyException {
        final byte[] userPassword = getUserPassword(ownerPassword, o, encRevision, length);
        return isUserPassword(userPassword, u, o, permissions, id, encRevision, length, encryptMetadata);
    }

    /**
     * Check if a plaintext password is the user password.
     * 
     * @param password
     *            The plaintext password.
     * @param u
     *            The u entry of the encryption dictionary.
     * @param o
     *            The o entry of the encryption dictionary.
     * @param permissions
     *            The permissions set in the the PDF.
     * @param id
     *            The document id used for encryption.
     * @param encRevision
     *            The revision of the encryption algorithm.
     * @param length
     *            The length of the encryption key.
     * 
     * @return true If the plaintext password is the user password.
     * 
     * @throws CryptographyException
     *             If there is an error during encryption.
     * @throws IOException
     *             If there is an error accessing data.
     */
    public final boolean isUserPassword(final byte[] password, final byte[] u, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length,
            final boolean encryptMetadata) throws CryptographyException {
        boolean matches = false;
        // STEP 1
        final byte[] computedValue = computeUserPassword(password, o, permissions, id, encRevision, length, encryptMetadata);
        if (encRevision == 2) {
            // STEP 2
            matches = Arrays.equals(u, computedValue);
        }
        else if (encRevision == 3 || encRevision == 4) {
            // STEP 2
            matches = arraysEqual(u, computedValue, 16);
        }
        else {
            throw new CryptographyException("Unknown Encryption Revision " + encRevision);
        }
        return matches;
    }

    private Cipher newRC4Cipher() throws CryptographyException {
        Cipher rc4Cipher;
        try {
            rc4Cipher = Cipher.getInstance("RC4");
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        } catch (final NoSuchPaddingException e) {
            throw new CryptographyException(e);
        }
        return rc4Cipher;
    }

    /**
     * This will take the password and truncate or pad it as necessary.
     * 
     * @param password
     *            The password to pad or truncate.
     * 
     * @return The padded or truncated password.
     */
    private final byte[] truncateOrPad(final byte[] password) {
        final byte[] padded = new byte[ENCRYPT_PADDING.length];
        final int bytesBeforePad = Math.min(password.length, padded.length);
        System.arraycopy(password, 0, padded, 0, bytesBeforePad);
        System.arraycopy(ENCRYPT_PADDING, 0, padded, bytesBeforePad, ENCRYPT_PADDING.length - bytesBeforePad);
        return padded;
    }
}
