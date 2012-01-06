package org.apache.pdfbox.pdmodel.encryption;

import java.io.IOException;
import java.io.InputStream;
import java.security.Key;

import org.apache.pdfbox.exceptions.CryptographyException;

public interface EncryptionImplementation {

    byte[] computeEncryptionKey(final byte[] password, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length, final boolean encryptMetadata)
            throws CryptographyException;

    Key computeKey(SecurityHandler securityHandler, long objectNumber, long genNumber) throws CryptographyException;

    byte[] computeOwnerKey(final byte[] ownerPassword, final byte[] userPassword, final int encRevision, final int length) throws CryptographyException;

    byte[] computeUserKey(final byte[] password, final byte[] o, final int permissions, final byte[] id, final int encRevision, final int length, final boolean encryptMetadata)
            throws CryptographyException;

    InputStream decrypt(Key key, InputStream encrypted) throws CryptographyException, IOException;

    InputStream encrypt(Key key, InputStream clear) throws CryptographyException, IOException;

    byte[] getUserPassword(byte[] bytes, byte[] o, int dicRevision, int dicLength) throws CryptographyException;

    boolean isOwnerPassword(byte[] bytes, byte[] u, byte[] o, int dicPermissions, byte[] documentIDBytes, int dicRevision, int dicLength, boolean encryptMetadata) throws CryptographyException;

    boolean isUserPassword(byte[] bytes, byte[] u, byte[] o, int dicPermissions, byte[] documentIDBytes, int dicRevision, int dicLength, boolean encryptMetadata) throws CryptographyException;
}

