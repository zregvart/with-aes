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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.apache.pdfbox.cos.COSArray;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSStream;
import org.apache.pdfbox.cos.COSString;
import org.apache.pdfbox.exceptions.CryptographyException;
import org.apache.pdfbox.pdmodel.PDDocument;

/**
 * This class represents a security handler as described in the PDF specifications. A security handler is responsible of documents protection.
 * 
 * @author <a href="mailto:ben@benlitchfield.com">Ben Litchfield</a>
 * @author Benoit Guillon (benoit.guillon@snv.jussieu.fr)
 * 
 * @version $Revision: 1.4 $
 */

public abstract class SecurityHandler {

    /*
     * ------------------------------------------------ CONSTANTS --------------------------------------------------
     */

    protected static final Map<EncryptionType, EncryptionImplementation> SUPPORTED_IMPLEMENTATIONS;

    static {
        final Map<EncryptionType, EncryptionImplementation> supported = new HashMap<EncryptionType, EncryptionImplementation>();
        supported.put(EncryptionType.RC4_40BIT, new RC4Implementation());
        supported.put(EncryptionType.RC4_128BIT, new RC4Implementation());
        supported.put(EncryptionType.AES_128BIT, new AES128Implementation());
        supported.put(EncryptionType.AES_256BIT, new AES256Implementation());

        SUPPORTED_IMPLEMENTATIONS = Collections.unmodifiableMap(supported);
    }

    /**
     * The encryption key that will used to encrypt / decrypt.
     */
    protected byte[]                                                     encryptionKey;

    /**
     * The document whose security is handled by this security handler.
     */

    protected PDDocument                                                 document;

    private final Set<COSBase>                                           objects                 = new HashSet<COSBase>();

    private final Set<COSDictionary>                                     potentialSignatures     = new HashSet<COSDictionary>();

    private EncryptionType                                               encryptionType;

    /**
     * The access permission granted to the current user for the document. These permissions are computed during decryption and are in read only mode.
     */

    protected AccessPermission                                           currentAccessPermission = null;

    private void addDictionaryAndSubDictionary(final Set<COSDictionary> set, final COSDictionary dic) {
        set.add(dic);
        final COSArray kids = (COSArray) dic.getDictionaryObject(COSName.KIDS);
        for (int i = 0; kids != null && i < kids.size(); i++) {
            addDictionaryAndSubDictionary(set, (COSDictionary) kids.getObject(i));
        }
        final COSBase value = dic.getDictionaryObject(COSName.V);
        if (value instanceof COSDictionary) {
            addDictionaryAndSubDictionary(set, (COSDictionary) value);
        }
    }

    /**
     * This will dispatch to the correct method.
     * 
     * @param obj
     *            The object to decrypt.
     * @param objNum
     *            The object number.
     * @param genNum
     *            The object generation Number.
     * 
     * @throws CryptographyException
     *             If there is an error decrypting the stream.
     * @throws IOException
     *             If there is an error getting the stream data.
     */
    private void decrypt(final COSBase obj, final long objNum, final long genNum) throws CryptographyException, IOException {
        if (!objects.contains(obj)) {
            objects.add(obj);

            if (obj instanceof COSString) {
                decryptString((COSString) obj, objNum, genNum);
            }
            else if (obj instanceof COSStream) {
                decryptStream((COSStream) obj, objNum, genNum);
            }
            else if (obj instanceof COSDictionary) {
                decryptDictionary((COSDictionary) obj, objNum, genNum);
            }
            else if (obj instanceof COSArray) {
                decryptArray((COSArray) obj, objNum, genNum);
            }
        }
    }

    /**
     * This will decrypt an array.
     * 
     * @param array
     *            The array to decrypt.
     * @param objNum
     *            The object number.
     * @param genNum
     *            The object generation number.
     * 
     * @throws CryptographyException
     *             If an error occurs during decryption.
     * @throws IOException
     *             If there is an error accessing the data.
     */
    private void decryptArray(final COSArray array, final long objNum, final long genNum) throws CryptographyException, IOException {
        for (int i = 0; i < array.size(); i++) {
            decrypt(array.get(i), objNum, genNum);
        }
    }

    /**
     * This will decrypt a dictionary.
     * 
     * @param dictionary
     *            The dictionary to decrypt.
     * @param objNum
     *            The object number.
     * @param genNum
     *            The object generation number.
     * 
     * @throws CryptographyException
     *             If there is an error decrypting the document.
     * @throws IOException
     *             If there is an error creating a new string.
     */
    private void decryptDictionary(final COSDictionary dictionary, final long objNum, final long genNum) throws CryptographyException, IOException {
        for (final Map.Entry<COSName, COSBase> entry : dictionary.entrySet()) {
            // if we are a signature dictionary and contain a Contents entry then
            // we don't decrypt it.
            if (!(entry.getKey().getName().equals("Contents") && entry.getValue() instanceof COSString && potentialSignatures.contains(dictionary))) {
                decrypt(entry.getValue(), objNum, genNum);
            }
        }
    }

    /**
     * Prepare the document for decryption.
     * 
     * @param doc
     *            The document to decrypt.
     * @param mat
     *            Information required to decrypt the document.
     * @throws CryptographyException
     *             If there is an error while preparing.
     * @throws IOException
     *             If there is an error with the document.
     */
    public abstract void decryptDocument(PDDocument doc, DecryptionMaterial mat) throws CryptographyException, IOException;

    /**
     * This will decrypt an object in the document.
     * 
     * @param object
     *            The object to decrypt.
     * 
     * @throws CryptographyException
     *             If there is an error decrypting the stream.
     * @throws IOException
     *             If there is an error getting the stream data.
     */
    private void decryptObject(final COSObject object) throws CryptographyException, IOException {
        final long objNum = object.getObjectNumber().intValue();
        final long genNum = object.getGenerationNumber().intValue();
        final COSBase base = object.getObject();
        decrypt(base, objNum, genNum);
    }

    /**
     * This will decrypt a stream.
     * 
     * @param stream
     *            The stream to decrypt.
     * @param objNum
     *            The object number.
     * @param genNum
     *            The object generation number.
     * 
     * @throws CryptographyException
     *             If there is an error getting the stream.
     * @throws IOException
     *             If there is an error getting the stream data.
     */
    public void decryptStream(final COSStream stream, final long objNum, final long genNum) throws CryptographyException, IOException {
        decryptDictionary(stream, objNum, genNum);
        final InputStream encryptedStream = stream.getFilteredStream();
        encryptData(objNum, genNum, encryptedStream, stream.createFilteredStream(), true /* decrypt */);
    }

    /**
     * This will decrypt a string.
     * 
     * @param string
     *            the string to decrypt.
     * @param objNum
     *            The object number.
     * @param genNum
     *            The object generation number.
     * 
     * @throws CryptographyException
     *             If an error occurs during decryption.
     * @throws IOException
     *             If an error occurs writing the new string.
     */
    public void decryptString(final COSString string, final long objNum, final long genNum) throws CryptographyException, IOException {
        final ByteArrayInputStream data = new ByteArrayInputStream(string.getBytes());
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        encryptData(objNum, genNum, data, buffer, true /* decrypt */);
        string.reset();
        string.append(buffer.toByteArray());
    }

    /**
     * Encrypt a set of data.
     * 
     * @param objectNumber
     *            The data object number.
     * @param genNumber
     *            The data generation number.
     * @param data
     *            The data to encrypt.
     * @param output
     *            The output to write the encrypted data to.
     * @throws CryptographyException
     *             If there is an error during the encryption.
     * @throws IOException
     *             If there is an error reading the data.
     * @deprecated While this works fine for RC4 encryption, it will never decrypt AES data You should use encryptData(objectNumber, genNumber, data, output, decrypt) which can do everything. This
     *             function is just here for compatibility reasons and will be removed in the future.
     */
    @Deprecated
    public void encryptData(final long objectNumber, final long genNumber, final InputStream data, final OutputStream output) throws CryptographyException, IOException {
        // default to encrypting since the function is named "encryptData"
        encryptData(objectNumber, genNumber, data, output, false);
    }

    /**
     * Encrypt a set of data.
     * 
     * @param objectNumber
     *            The data object number.
     * @param genNumber
     *            The data generation number.
     * @param data
     *            The data to encrypt.
     * @param output
     *            The output to write the encrypted data to.
     * @param decrypt
     *            true to decrypt the data, false to encrypt it
     * 
     * @throws CryptographyException
     *             If there is an error during the encryption.
     * @throws IOException
     *             If there is an error reading the data.
     */
    public void encryptData(final long objectNumber, final long genNumber, final InputStream data, final OutputStream output, final boolean decrypt) throws CryptographyException, IOException {
        final EncryptionImplementation encryption = SUPPORTED_IMPLEMENTATIONS.get(encryptionType);

        final Key key = encryption.computeKey(this, objectNumber, genNumber);

        final InputStream dataStream;
        if (decrypt) {
            dataStream = encryption.decrypt(key, data);
        }
        else {
            dataStream = encryption.encrypt(key, data);
        }

        try {
            final byte buffer[] = new byte[4096];
            for (int n = 0; -1 != (n = dataStream.read(buffer));) {
                output.write(buffer, 0, n);
            }
        } finally {
            dataStream.close();
        }

        output.flush();
    }

    /**
     * This will encrypt a stream, but not the dictionary as the dictionary is encrypted by visitFromString() in COSWriter and we don't want to encrypt it twice.
     * 
     * @param stream
     *            The stream to decrypt.
     * @param objNum
     *            The object number.
     * @param genNum
     *            The object generation number.
     * 
     * @throws CryptographyException
     *             If there is an error getting the stream.
     * @throws IOException
     *             If there is an error getting the stream data.
     */
    public void encryptStream(final COSStream stream, final long objNum, final long genNum) throws CryptographyException, IOException {
        final InputStream encryptedStream = stream.getFilteredStream();
        encryptData(objNum, genNum, encryptedStream, stream.createFilteredStream(), false /* encrypt */);
    }

    /**
     * Returns the access permissions that were computed during document decryption. The returned object is in read only mode.
     * 
     * @return the access permissions or null if the document was not decrypted.
     */
    public AccessPermission getCurrentAccessPermission() {
        return currentAccessPermission;
    }

    public EncryptionType getEncryptionType() {
        return encryptionType;
    }

    /**
     * Getter of the property <tt>keyLength</tt>.
     * 
     * @return Returns the keyLength.
     * @uml.property name="keyLength"
     */
    public int getKeyLength() {
        return encryptionType.getKeyLength();
    }

    /*
     * True if AES is used for encryption and decryption.
     */
    public boolean isAES() {
        return encryptionType.isAes();
    }

    /**
     * Prepare the document for encryption.
     * 
     * @param doc
     *            The document that will be encrypted.
     * 
     * @throws CryptographyException
     *             If there is an error while preparing.
     * @throws IOException
     *             If there is an error with the document.
     */
    public abstract void prepareDocumentForEncryption(PDDocument doc) throws CryptographyException, IOException;

    /**
     * This method must be called by an implementation of this class to really proceed to decryption.
     * 
     * @throws IOException
     *             If there is an error in the decryption.
     * @throws CryptographyException
     *             If there is an error in the decryption.
     */
    protected void proceedDecryption() throws IOException, CryptographyException {

        final COSDictionary trailer = document.getDocument().getTrailer();
        final COSArray fields = (COSArray) trailer.getObjectFromPath("Root/AcroForm/Fields");

        // We need to collect all the signature dictionaries, for some
        // reason the 'Contents' entry of signatures is not really encrypted
        if (fields != null) {
            for (int i = 0; i < fields.size(); i++) {
                final COSDictionary field = (COSDictionary) fields.getObject(i);
                if (field != null) {
                    addDictionaryAndSubDictionary(potentialSignatures, field);
                }
                else {
                    throw new IOException("Could not decypt document, object not found.");
                }
            }
        }

        final List<COSObject> allObjects = document.getDocument().getObjects();
        final Iterator<COSObject> objectIter = allObjects.iterator();
        while (objectIter.hasNext()) {
            decryptObject(objectIter.next());
        }
        document.setEncryptionDictionary(null);
    }

    public void setEncryptionType(final EncryptionType encryptionType) {
        this.encryptionType = encryptionType;
    }
}
