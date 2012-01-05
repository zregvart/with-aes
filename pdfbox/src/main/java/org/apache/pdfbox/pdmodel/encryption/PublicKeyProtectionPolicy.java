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

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Iterator;

/**
 * This class represents the protection policy to use to protect a document with the public key security handler as described in the PDF specification 1.6 p104.
 * 
 * PDF documents are encrypted so that they can be decrypted by one or more recipients. Each recipient have its own access permission.
 * 
 * The following code sample shows how to protect a document using the public key security handler. In this code sample, <code>doc</code> is a <code>PDDocument</code> object.
 * 
 * <pre>
 * PublicKeyProtectionPolicy policy = new PublicKeyProtectionPolicy();
 * PublicKeyRecipient recip = new PublicKeyRecipient();
 * AccessPermission ap = new AccessPermission();
 * ap.setCanModify(false);
 * recip.setPermission(ap);
 * 
 * // load the recipient's certificate
 * InputStream inStream = new FileInputStream(certificate_path);
 * CertificateFactory cf = CertificateFactory.getInstance(&quot;X.509&quot;);
 * X509Certificate certificate = (X509Certificate) cf.generateCertificate(inStream);
 * inStream.close();
 * 
 * recip.setX509(certificate); // set the recipient's certificate
 * policy.addRecipient(recip);
 * policy.setEncryptionKeyLength(128); // the document will be encrypted with 128 bits secret key
 * doc.protect(policy);
 * doc.save(out);
 * </pre>
 * 
 * 
 * @see org.apache.pdfbox.pdmodel.PDDocument#protect(ProtectionPolicy)
 * @see AccessPermission
 * @see PublicKeyRecipient
 * 
 * @author Benoit Guillon (benoit.guillon@snv.jussieu.fr)
 * 
 * @version $Revision: 1.2 $
 */
public class PublicKeyProtectionPolicy extends ProtectionPolicy {

    /**
     * The list of recipients.
     */
    private ArrayList<PublicKeyRecipient> recipients                  = null;

    /**
     * The X509 certificate used to decrypt the current document.
     */
    private X509Certificate               decryptionCertificate;

    /**
     * Envelope encryption algorithm, for protecting secret key inside the PKCS#7 envelope. The default is 3DES with 168 bit key, from PDF Reference 1.7
     * (http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/acrobat/pdfs/pdf_reference_1-7.pdf) Acrobat used to use 3DES, no idea what it uses now, but 3DES is a sane starting point.
     */
    private EncryptionType                envelopeEncryptionAlgorithm = EncryptionType.DES3_168BIT;

    /**
     * Constructor for encryption. Just creates an empty recipients list.
     */
    public PublicKeyProtectionPolicy() {
        recipients = new ArrayList<PublicKeyRecipient>();
    }

    /**
     * Adds a new recipient to the recipients list.
     * 
     * @param r
     *            A new recipient.
     */
    public void addRecipient(final PublicKeyRecipient r) {
        recipients.add(r);
    }

    /**
     * Getter of the property <tt>decryptionCertificate</tt>.
     * 
     * @return Returns the decryptionCertificate.
     */
    public X509Certificate getDecryptionCertificate() {
        return decryptionCertificate;
    }

    public EncryptionType getEnvelopeEncryptionAlgorithm() {
        return envelopeEncryptionAlgorithm;
    }

    /**
     * Returns an iterator to browse the list of recipients. Object found in this iterator are <code>PublicKeyRecipient</code>.
     * 
     * @return The recipients list iterator.
     */
    public Iterator<PublicKeyRecipient> getRecipientsIterator() {
        return recipients.iterator();
    }

    /**
     * Returns the number of recipients.
     * 
     * @return The number of recipients.
     */
    public int getRecipientsNumber() {
        return recipients.size();
    }

    /**
     * Removes a recipient from the recipients list.
     * 
     * @param r
     *            The recipient to remove.
     * 
     * @return true If a recipient was found and removed.
     */
    public boolean removeRecipient(final PublicKeyRecipient r) {
        return recipients.remove(r);
    }

    /**
     * Setter of the property <tt>decryptionCertificate</tt>.
     * 
     * @param aDecryptionCertificate
     *            The decryption certificate to set.
     */
    public void setDecryptionCertificate(final X509Certificate aDecryptionCertificate) {
        this.decryptionCertificate = aDecryptionCertificate;
    }

    public void setEnvelopeEncryptionAlgorithm(final EncryptionType envelopeEncryptionAlgorithm) {
        this.envelopeEncryptionAlgorithm = envelopeEncryptionAlgorithm;
    }
}
