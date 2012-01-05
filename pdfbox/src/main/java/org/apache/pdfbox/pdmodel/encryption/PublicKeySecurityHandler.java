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
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.pdfbox.cos.COSDocument;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.exceptions.CryptographyException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.bouncycastle.asn1.DERObject;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.cms.Recipient;
import org.bouncycastle.cms.RecipientInfoGenerator;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.operator.OutputEncryptor;

/**
 * This class implements the public key security handler described in the PDF specification.
 * 
 * @see PDF Spec 1.6 p104
 * 
 * @see PublicKeyProtectionPolicy to see how to protect document with this security handler.
 * 
 * @author Benoit Guillon (benoit.guillon@snv.jussieu.fr)
 * @version $Revision: 1.3 $
 */
public class PublicKeySecurityHandler extends SecurityHandler {

    private static final String                                  SUBFILTER_V4                    = "adbe.pkcs7.s4";

    private static final String                                  SUBFILTER_V5                    = "adbe.pkcs7.s5";

    public static final String                                   DEFAULT_CRYPT_FILTER            = "DefaultCryptFilter";

    private static final int                                     SEED_LENGTH                     = 20;

    /**
     * The filter name.
     */
    public static final String                                   FILTER                          = "Adobe.PubSec";

    private static final Map<EncryptionType, EncryptionDefaults> SUPPORTED_ENCRIPTION_ALGORITHMS = new HashMap<EncryptionType, EncryptionDefaults>();

    private PublicKeyProtectionPolicy                            policy                          = null;

    static {
        SUPPORTED_ENCRIPTION_ALGORITHMS.put(EncryptionType.RC4_40BIT, new EncryptionDefaults(PDEncryptionDictionary.VERSION1_40_BIT_ALGORITHM, COSName.V2, 2, SUBFILTER_V4));
        SUPPORTED_ENCRIPTION_ALGORITHMS.put(EncryptionType.RC4_128BIT, new EncryptionDefaults(PDEncryptionDictionary.VERSION2_VARIABLE_LENGTH_ALGORITHM, COSName.V2, 3, SUBFILTER_V4));
        SUPPORTED_ENCRIPTION_ALGORITHMS.put(EncryptionType.AES_128BIT, new EncryptionDefaults(PDEncryptionDictionary.VERSION4_SECURITY_HANDLER, COSName.AESV2, 4, SUBFILTER_V5));
        SUPPORTED_ENCRIPTION_ALGORITHMS.put(EncryptionType.AES_256BIT, new EncryptionDefaults(PDEncryptionDictionary.VERSION5_SECURITY_HANDLER, COSName.AESV3, 5, SUBFILTER_V5));
    }

    /**
     * Constructor used by SecurityHandlersManager.
     */
    PublicKeySecurityHandler() {
    }

    /**
     * Constructor used for encryption.
     * 
     * @param p
     *            The protection policy.
     */
    public PublicKeySecurityHandler(final PublicKeyProtectionPolicy p) {
        policy = p;

        final int keyLength = policy.getEncryptionKeyLength();

        final String algorithm = this.policy.getEncryptionAlgorithm();

        final EncryptionType encryptionType = EncryptionType.forLengthAndAlgorithm(keyLength, algorithm);

        setEncryptionType(encryptionType);
    }

    private byte[] createRecipientProtectionBytes(final EncryptionType envelopeEncryptionAlgorithm, final byte[] in, final X509Certificate cert) throws CryptographyException, IOException {
        RecipientInfoGenerator recipient;
        try {
            recipient = new JceKeyTransRecipientInfoGenerator(cert);
        } catch (final CertificateEncodingException e) {
            throw new CryptographyException(e);
        }

        final CMSEnvelopedDataGenerator generator = new CMSEnvelopedDataGenerator();

        generator.addRecipientInfoGenerator(recipient);

        final CMSTypedData clearText = new CMSProcessableByteArray(in);

        final JceCMSContentEncryptorBuilder encryptorBuilder = new JceCMSContentEncryptorBuilder(envelopeEncryptionAlgorithm.getAlgorithmIdentifier(), envelopeEncryptionAlgorithm.getKeyLength());

        OutputEncryptor encryptor;
        try {
            encryptor = encryptorBuilder.build();
        } catch (final CMSException e) {
            throw new CryptographyException(e);
        }

        try {
            final CMSEnvelopedData authenticatedData = generator.generate(clearText, encryptor);

            final ContentInfo contentInfo = authenticatedData.getContentInfo();

            final DERObject derContentInfo = contentInfo.getDERObject();

            return derContentInfo.getDEREncoded();
        } catch (final CMSException e) {
            throw new CryptographyException(e);
        }
    }

    /**
     * Decrypt the document.
     * 
     * @param doc
     *            The document to decrypt.
     * @param decryptionMaterial
     *            The data used to decrypt the document.
     * 
     * @throws CryptographyException
     *             If there is an error during decryption.
     * @throws IOException
     *             If there is an error accessing data.
     */
    @Override
    public void decryptDocument(final PDDocument doc, final DecryptionMaterial decryptionMaterial) throws CryptographyException, IOException {
        this.document = doc;

        final PDEncryptionDictionary dictionary = doc.getEncryptionDictionary();

        final int version = dictionary.getVersion();

        final COSName streamFilterName = dictionary.getStreamFilterName();

        final int encryptionDictionaryKeyLength = dictionary.getLength();

        final PDCryptFilterDictionary cryptFilterDictionary = dictionary.getCryptFilterDictionary(streamFilterName);

        final int cryptFilterDictionaryKeyLength;
        if (cryptFilterDictionary == null) {
            cryptFilterDictionaryKeyLength = 0;
        }
        else {
            cryptFilterDictionaryKeyLength = cryptFilterDictionary.getLength();
        }

        final int givenKeyLength;
        if (encryptionDictionaryKeyLength != 0) {
            givenKeyLength = encryptionDictionaryKeyLength;
        }
        else if (cryptFilterDictionaryKeyLength != 0) {
            givenKeyLength = cryptFilterDictionaryKeyLength;
        }
        else {
            givenKeyLength = 0;
        }

        final String algorithm;
        final int keyLength;
        switch (version) {
            case PDEncryptionDictionary.VERSION1_40_BIT_ALGORITHM:
                algorithm = "RC4";
                keyLength = 40;
                break;
            case PDEncryptionDictionary.VERSION2_VARIABLE_LENGTH_ALGORITHM:
                algorithm = "RC4";

                if (givenKeyLength != 0) {
                    keyLength = encryptionDictionaryKeyLength;
                }
                else {
                    keyLength = 128;
                }
                break;
            case PDEncryptionDictionary.VERSION4_SECURITY_HANDLER:
                algorithm = "AES";

                if (givenKeyLength != 0) {
                    keyLength = encryptionDictionaryKeyLength;
                }
                else {
                    keyLength = 128;
                }
                break;
            case PDEncryptionDictionary.VERSION5_SECURITY_HANDLER:
                algorithm = "AES";

                if (givenKeyLength != 0) {
                    keyLength = encryptionDictionaryKeyLength;
                }
                else {
                    keyLength = 256;
                }
                break;
            default:
                throw new CryptographyException("Unsupported encryption dictionary version: " + version);
        }

        final EncryptionType givenEncryptionType = EncryptionType.forLengthAndAlgorithm(keyLength, algorithm);
        setEncryptionType(givenEncryptionType);

        if (!(decryptionMaterial instanceof PublicKeyDecryptionMaterial)) {
            throw new CryptographyException("Provided decryption material is not compatible with the document");
        }

        final PublicKeyDecryptionMaterial material = (PublicKeyDecryptionMaterial) decryptionMaterial;

        PrivateKey privateKey;
        try {
            privateKey = (PrivateKey) material.getPrivateKey();
        } catch (final KeyStoreException e) {
            throw new CryptographyException(e);
        }

        boolean foundRecipient = false;

        // the decrypted content of the enveloped data that match
        // the certificate in the decryption material provided
        byte[] envelopedData = null;

        // the bytes of each recipient in the recipients array
        final byte[][] recipientFieldsBytes = new byte[dictionary.getRecipientsLength()][];

        for (int i = 0; i < dictionary.getRecipientsLength(); i++) {
            final COSString recipientFieldString = dictionary.getRecipientStringAt(i);
            final byte[] recipientBytes = recipientFieldString.getBytes();

            CMSEnvelopedData data;
            try {
                data = new CMSEnvelopedData(recipientBytes);
            } catch (final CMSException e) {
                throw new CryptographyException(e);
            }

            @SuppressWarnings("unchecked")
            final Iterator<RecipientInformation> recipCertificatesIt = data.getRecipientInfos().getRecipients().iterator();

            while (recipCertificatesIt.hasNext()) {
                final RecipientInformation ri = recipCertificatesIt.next();

                // Impl: if a matching certificate was previously found it is an error,
                // here we just don't care about it
                X509Certificate certificate;
                try {
                    certificate = material.getCertificate();
                } catch (final KeyStoreException e) {
                    throw new CryptographyException(e);
                }

                if (ri.getRID().match(certificate) && !foundRecipient) {
                    foundRecipient = true;

                    final Recipient recipient = new JceKeyTransEnvelopedRecipient(privateKey);

                    try {
                        envelopedData = ri.getContent(recipient);
                    } catch (final CMSException e) {
                        throw new CryptographyException(e);
                    }
                }
            }
            recipientFieldsBytes[i] = recipientBytes;
        }

        if (!foundRecipient || envelopedData == null) {
            throw new CryptographyException("The certificate matches no recipient entry");
        }

        if (envelopedData.length != 24) {
            throw new CryptographyException("The enveloped data does not contain 24 bytes");
        }
        // now envelopedData contains:
        // - the 20 bytes seed
        // - the 4 bytes of permission for the current user

        final byte[] accessBytes = new byte[4];
        System.arraycopy(envelopedData, SEED_LENGTH, accessBytes, 0, 4);

        currentAccessPermission = new AccessPermission(accessBytes);
        currentAccessPermission.setReadOnly();

        final MessageDigest md = newMessageDigest(keyLength);

        // what we will put in the digest = the seed + each byte contained in the recipients array

        // put the seed in the digest input
        md.update(envelopedData, 0, 20);

        // put each bytes of the recipients array in the digest input
        for (int i = 0; i < recipientFieldsBytes.length; i++) {
            md.update(recipientFieldsBytes[i]);
        }

        final byte[] mdResult = md.digest();

        // we have the encryption key ...
        encryptionKey = new byte[keyLength / 8];
        System.arraycopy(mdResult, 0, encryptionKey, 0, keyLength / 8);

        proceedDecryption();
    }

    private byte[] generateSeed() throws CryptographyException {
        SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstance("SHA1PRNG");
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }

        return secureRandom.generateSeed(SEED_LENGTH);
    }

    private MessageDigest newMessageDigest(final int keyLength) throws CryptographyException {
        final String digestAlgorithm;

        switch (keyLength) {
            case 40:
            case 128:
                digestAlgorithm = "SHA1";
                break;
            case 256:
                digestAlgorithm = "SHA256";
                break;
            default:
                throw new CryptographyException("unsupported key length:" + keyLength);
        }

        try {
            return MessageDigest.getInstance(digestAlgorithm);
        } catch (final NoSuchAlgorithmException e) {
            throw new CryptographyException(e);
        }
    }

    /**
     * Prepare the document for encryption.
     * 
     * @param doc
     *            The document that will be encrypted.
     * 
     * @throws CryptographyException
     *             If there is an error while encrypting.
     * @throws IOException
     */
    @Override
    public void prepareDocumentForEncryption(final PDDocument doc) throws CryptographyException, IOException {
        PDEncryptionDictionary dictionary = doc.getEncryptionDictionary();

        if (dictionary == null) {
            dictionary = new PDEncryptionDictionary();
        }

        final EncryptionType encryptionType = getEncryptionType();
        final EncryptionDefaults choosen = SUPPORTED_ENCRIPTION_ALGORITHMS.get(encryptionType);

        if (choosen == null) {
            throw new CryptographyException("unable to find implementation options for algorithm: " + encryptionType.getAlgorithmName() + ", and key length: " + encryptionType.getKeyLength());
        }

        final int version = choosen.getVersion();
        final int keyLength = encryptionType.getKeyLength();

        dictionary.setFilter(FILTER);
        dictionary.setSubFilter(choosen.getSubFilter());
        dictionary.setVersion(version);
        dictionary.setRevision(choosen.getRevision());
        dictionary.setLength(keyLength);

        final byte[][] recipientsField = new byte[policy.getRecipientsNumber()][];

        // create the 20 bytes seed
        final byte[] seed = generateSeed();

        final Iterator<PublicKeyRecipient> it = policy.getRecipientsIterator();
        int i = 0;

        final MessageDigest digest = newMessageDigest(keyLength);

        digest.update(seed);

        while (it.hasNext()) {
            final PublicKeyRecipient recipient = it.next();
            final X509Certificate certificate = recipient.getX509();
            final int permission = recipient.getPermission().getPermissionBytesForPublicKey();

            final byte[] pkcs7input = new byte[24];
            final byte one = (byte) permission;
            final byte two = (byte) (permission >>> 8);
            final byte three = (byte) (permission >>> 16);
            final byte four = (byte) (permission >>> 24);

            System.arraycopy(seed, 0, pkcs7input, 0, seed.length); // put this seed in the pkcs7 input

            pkcs7input[seed.length] = four;
            pkcs7input[seed.length + 1] = three;
            pkcs7input[seed.length + 2] = two;
            pkcs7input[seed.length + 3] = one;

            final EncryptionType envelopeEncryptionAlgorithm = this.policy.getEnvelopeEncryptionAlgorithm();

            final byte[] envelopedData = createRecipientProtectionBytes(envelopeEncryptionAlgorithm, pkcs7input, certificate);

            recipientsField[i] = envelopedData;

            digest.update(envelopedData);

            i++;
        }

        if (encryptionType.isAes()) {
            // AES support was introduced in version 1.6
            final COSDocument cosDocument = doc.getDocument();
            cosDocument.setHeaderString("%PDF-1.6");
        }

        switch (version) {
            case PDEncryptionDictionary.VERSION1_40_BIT_ALGORITHM:
                dictionary.setRecipients(recipientsField);
                break;
            case PDEncryptionDictionary.VERSION2_VARIABLE_LENGTH_ALGORITHM:
                dictionary.setLength(keyLength);
                dictionary.setRecipients(recipientsField);
                break;
            case PDEncryptionDictionary.VERSION4_SECURITY_HANDLER:
            case PDEncryptionDictionary.VERSION5_SECURITY_HANDLER:
                dictionary.setStreamFilterName(DEFAULT_CRYPT_FILTER);
                dictionary.setStringFilterName(DEFAULT_CRYPT_FILTER);

                final PDCryptFilterDictionary cryptFilterDictionary = new PDCryptFilterDictionary(DEFAULT_CRYPT_FILTER);

                final COSName method = choosen.getMethod();
                cryptFilterDictionary.setCryptFilterMethod(method);
                cryptFilterDictionary.setLength(keyLength);

                dictionary.setCryptFilterDictionary(COSName.CF, cryptFilterDictionary);

                cryptFilterDictionary.setRecipients(recipientsField);
                break;
            default:
                throw new CryptographyException("Unsupported encryption dictionary version: " + version);
        }

        final byte[] mdResult = digest.digest();

        final int encryptionKeyLengthInBytes = keyLength / 8;

        this.encryptionKey = new byte[encryptionKeyLengthInBytes];
        System.arraycopy(mdResult, 0, this.encryptionKey, 0, encryptionKeyLengthInBytes);

        doc.setEncryptionDictionary(dictionary);
        doc.getDocument().setEncryptionDictionary(dictionary.encryptionDictionary);
    }

}
