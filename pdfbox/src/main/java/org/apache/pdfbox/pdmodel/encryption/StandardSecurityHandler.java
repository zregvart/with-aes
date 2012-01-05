/*
 * Licensed to the Apache Software Foundation (ASF) under one or more contributor license agreements. See the NOTICE file distributed with this work for additional information regarding copyright
 * ownership. The ASF licenses this file to You under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the
 * License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied. See the License for the specific language governing permissions and limitations under the License.
 */
package org.apache.pdfbox.pdmodel.encryption;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.exceptions.CryptographyException;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * 
 * The class implements the standard security handler as decribed in the PDF specifications. This security handler protects document with password.
 * 
 * @see StandardProtectionPolicy to see how to protect document with this security handler.
 * 
 * @author <a href="mailto:ben@benlitchfield.com">Ben Litchfield</a>
 * @author Benoit Guillon (benoit.guillon@snv.jussieu.fr)
 * 
 * @version $Revision: 1.5 $
 */

public class StandardSecurityHandler extends SecurityHandler {
    /**
     * Type of security handler.
     */
    public static final String                          FILTER                  = "Standard";

    private StandardProtectionPolicy                    policy;

    /**
     * Protection policy class for this handler.
     */
    public static final Class<StandardProtectionPolicy> PROTECTION_POLICY_CLASS = StandardProtectionPolicy.class;

    /**
     * Constructor.
     */
    public StandardSecurityHandler() {
    }

    /**
     * Constructor used for encryption.
     * 
     * @param p
     *            The protection policy.
     */
    public StandardSecurityHandler(final StandardProtectionPolicy p) {
        policy = p;
        final int keyLength = policy.getEncryptionKeyLength();
        final String algorithm = policy.getEncryptionAlgorithm();

        final EncryptionType encryptionType = EncryptionType.forLengthAndAlgorithm(keyLength, algorithm);

        setEncryptionType(encryptionType);
    }

    /**
     * Computes the revision version of the StandardSecurityHandler to use regarding the version number and the permissions bits set. See PDF Spec 1.6 p98
     * 
     * @param version
     * 
     * @return The computed revision number.
     */
    private int computeRevisionNumber(final int version) {
        if (version == PDEncryptionDictionary.VERSION1_40_BIT_ALGORITHM && !policy.getPermissions().canFillInForm() && !policy.getPermissions().canExtractForAccessibility()
                && !policy.getPermissions().canPrintDegraded()) {
            return 2;
        }

        switch (version) {
            case PDEncryptionDictionary.VERSION1_40_BIT_ALGORITHM:
            case PDEncryptionDictionary.VERSION2_VARIABLE_LENGTH_ALGORITHM:
                return 3;
            case PDEncryptionDictionary.VERSION4_SECURITY_HANDLER:
                return 4;
            case PDEncryptionDictionary.VERSION5_SECURITY_HANDLER:
                return 5;
        }

        throw new IllegalStateException("unsupported version in revision computation: " + version);
    }

    /**
     * Computes the version number of the StandardSecurityHandler regarding the encryption key length. See PDF Spec 1.6 p 93
     * 
     * @return The computed cersion number.
     */
    private int computeVersionNumber() {
        final EncryptionType encryptionType = getEncryptionType();

        switch (encryptionType) {
            case RC4_40BIT:
                return PDEncryptionDictionary.VERSION1_40_BIT_ALGORITHM;
            case RC4_128BIT:
                return PDEncryptionDictionary.VERSION2_VARIABLE_LENGTH_ALGORITHM;
            case AES_128BIT:
                return PDEncryptionDictionary.VERSION4_SECURITY_HANDLER;
            case AES_256BIT:
                return PDEncryptionDictionary.VERSION5_SECURITY_HANDLER;
        }

        throw new IllegalStateException("unsupported encryption type: " + encryptionType);
    }

    /**
     * Decrypt the document.
     * 
     * @param doc
     *            The document to be decrypted.
     * @param decryptionMaterial
     *            Information used to decrypt the document.
     * 
     * @throws IOException
     *             If there is an error accessing data.
     * @throws CryptographyException
     *             If there is an error with decryption.
     */
    @Override
    public void decryptDocument(final PDDocument doc, final DecryptionMaterial decryptionMaterial) throws CryptographyException, IOException {
        document = doc;

        final PDEncryptionDictionary dictionary = document.getEncryptionDictionary();
        if (!(decryptionMaterial instanceof StandardDecryptionMaterial)) {
            throw new CryptographyException("Provided decryption material is not compatible with the document");
        }

        final StandardDecryptionMaterial material = (StandardDecryptionMaterial) decryptionMaterial;

        String password = material.getPassword();
        if (password == null) {
            password = "";
        }

        final int dicPermissions = dictionary.getPermissions();
        final int dicRevision = dictionary.getRevision();
        final int dicLength = dictionary.getLength() / 8;

        // some documents may have not document id, see
        // test\encryption\encrypted_doc_no_id.pdf
        final COSArray documentIDArray = document.getDocument().getDocumentID();
        byte[] documentIDBytes = null;
        if (documentIDArray != null && documentIDArray.size() >= 1) {
            final COSString id = (COSString) documentIDArray.getObject(0);
            documentIDBytes = id.getBytes();
        }
        else {
            documentIDBytes = new byte[0];
        }

        // we need to know whether the meta data was encrypted for password calculation
        final boolean encryptMetadata = dictionary.isEncryptMetaData();

        final byte[] u = dictionary.getUserKey();
        final byte[] o = dictionary.getOwnerKey();

        final int lengthInBits = dictionary.getLength();

        String algorithm = "RC4";
        if (dicRevision > 3) {
            algorithm = "AES";
        }

        final EncryptionType encryptionType = EncryptionType.forLengthAndAlgorithm(lengthInBits, algorithm);
        setEncryptionType(encryptionType);

        final EncryptionImplementation implementation = SUPPORTED_IMPLEMENTATIONS.get(encryptionType);

        final boolean isUserPassword = implementation.isUserPassword(password.getBytes("ISO-8859-1"), u, o, dicPermissions, documentIDBytes, dicRevision, dicLength, encryptMetadata);
        final boolean isOwnerPassword = implementation.isOwnerPassword(password.getBytes("ISO-8859-1"), u, o, dicPermissions, documentIDBytes, dicRevision, dicLength, encryptMetadata);

        if (isUserPassword) {
            currentAccessPermission = new AccessPermission(dicPermissions);
            encryptionKey = implementation.computeEncryptionKey(password.getBytes("ISO-8859-1"), o, dicPermissions, documentIDBytes, dicRevision, dicLength, encryptMetadata);
        }
        else if (isOwnerPassword) {
            currentAccessPermission = AccessPermission.getOwnerAccessPermission();
            final byte[] computedUserPassword = implementation.getUserPassword(password.getBytes("ISO-8859-1"), o, dicRevision, dicLength);
            encryptionKey = implementation.computeEncryptionKey(computedUserPassword, o, dicPermissions, documentIDBytes, dicRevision, dicLength, encryptMetadata);
        }
        else {
            throw new CryptographyException("Error: The supplied password does not match either the owner or user password in the document.");
        }

        this.proceedDecryption();
    }

    /**
     * Prepare document for encryption.
     * 
     * @param doc
     *            The documeent to encrypt.
     * 
     * @throws IOException
     *             If there is an error accessing data.
     * @throws CryptographyException
     *             If there is an error with decryption.
     */
    @Override
    public void prepareDocumentForEncryption(final PDDocument doc) throws CryptographyException, IOException {
        document = doc;
        PDEncryptionDictionary encryptionDictionary = document.getEncryptionDictionary();
        if (encryptionDictionary == null) {
            encryptionDictionary = new PDEncryptionDictionary();
        }

        final EncryptionType encryptionType = getEncryptionType();

        final int keyLength = encryptionType.getKeyLength();

        final int version = computeVersionNumber();
        final int revision = computeRevisionNumber(version);
        encryptionDictionary.setFilter(FILTER);
        encryptionDictionary.setVersion(version);
        encryptionDictionary.setRevision(revision);
        encryptionDictionary.setLength(keyLength);

        String ownerPassword = policy.getOwnerPassword();
        String userPassword = policy.getUserPassword();
        if (ownerPassword == null) {
            ownerPassword = "";
        }
        if (userPassword == null) {
            userPassword = "";
        }

        final int permissionInt = policy.getPermissions().getPermissionBytes();

        final int length = keyLength / 8;

        COSArray idArray = document.getDocument().getDocumentID();

        // check if the document has an id yet. If it does not then
        // generate one
        if (idArray == null || idArray.size() < 2) {
            idArray = new COSArray();
            try {
                final MessageDigest md = MessageDigest.getInstance("MD5");
                final BigInteger time = BigInteger.valueOf(System.currentTimeMillis());
                md.update(time.toByteArray());
                md.update(ownerPassword.getBytes("ISO-8859-1"));
                md.update(userPassword.getBytes("ISO-8859-1"));
                md.update(document.getDocument().toString().getBytes());
                final byte[] id = md.digest(this.toString().getBytes("ISO-8859-1"));
                final COSString idString = new COSString();
                idString.append(id);
                idArray.add(idString);
                idArray.add(idString);
                document.getDocument().setDocumentID(idArray);
            } catch (final NoSuchAlgorithmException e) {
                throw new CryptographyException(e);
            } catch (final IOException e) {
                throw new CryptographyException(e);
            }
        }

        final COSString id = (COSString) idArray.getObject(0);

        final EncryptionImplementation implementation = SUPPORTED_IMPLEMENTATIONS.get(encryptionType);

        final byte[] o = implementation.computeOwnerKey(ownerPassword.getBytes("ISO-8859-1"), userPassword.getBytes("ISO-8859-1"), revision, length);

        final byte[] u = implementation.computeUserKey(userPassword.getBytes("ISO-8859-1"), o, permissionInt, id.getBytes(), revision, length, true);

        encryptionKey = implementation.computeEncryptionKey(userPassword.getBytes("ISO-8859-1"), o, permissionInt, id.getBytes(), revision, length, true);

        encryptionDictionary.setPermissions(permissionInt);
        encryptionDictionary.setOwnerKey(o);
        encryptionDictionary.setUserKey(u);

        if (version == PDEncryptionDictionary.VERSION4_SECURITY_HANDLER || version == PDEncryptionDictionary.VERSION5_SECURITY_HANDLER) {
            final PDCryptFilterDictionary cryptFilterDictionary = new PDCryptFilterDictionary(COSName.STD_CF);

            cryptFilterDictionary.setLength(length);

            cryptFilterDictionary.setCryptFilterMethod(COSName.AESV2);
            if (version == PDEncryptionDictionary.VERSION5_SECURITY_HANDLER) {
                cryptFilterDictionary.setCryptFilterMethod(COSName.AESV3);
            }

            encryptionDictionary.setStreamFilterName(COSName.STD_CF.getName());
            encryptionDictionary.setStringFilterName(COSName.STD_CF.getName());
            encryptionDictionary.setCryptFilterDictionary(COSName.CF, cryptFilterDictionary);

        }

        document.setEncryptionDictionary(encryptionDictionary);
        document.getDocument().setEncryptionDictionary(encryptionDictionary.getCOSDictionary());
    }

}
