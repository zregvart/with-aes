package org.apache.pdfbox.pdmodel.encryption;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;

public enum EncryptionType {
    RC4_40BIT(40, "RC4", EncryptionType.RC4), RC4_128BIT(128, "RC4", EncryptionType.RC4), RC4_192BIT(192, "RC4", EncryptionType.RC4), RC4_256BIT(256, "RC4", EncryptionType.RC4), DES(56, "DES",
            new ASN1ObjectIdentifier("1.3.14.3.2.7")), DES3_56BIT(56, "DES", PKCSObjectIdentifiers.des_EDE3_CBC), DES3_112BIT(112, "DES", PKCSObjectIdentifiers.des_EDE3_CBC), DES3_168BIT(168, "DES",
            PKCSObjectIdentifiers.des_EDE3_CBC), AES_128BIT(128, "AES", CMSAlgorithm.AES128_CBC), AES_192BIT(192, "AES", CMSAlgorithm.AES192_CBC), AES_256BIT(256, "AES", CMSAlgorithm.AES256_CBC);

    public static final ASN1ObjectIdentifier RC4 = PKCSObjectIdentifiers.encryptionAlgorithm.branch("4");

    private final int                        keyLength;

    private final String                     algorithm;

    private final ASN1ObjectIdentifier       algorithmIdentifier;

    private EncryptionType(int keyLength, String algorithm, ASN1ObjectIdentifier algorithmIdentifier) {
        this.keyLength = keyLength;
        this.algorithm = algorithm;
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public static EncryptionType forLengthAndAlgorithm(int keyLength, String algorithm) {
        EncryptionType[] values = values();

        for (EncryptionType type : values) {
            if (type.keyLength == keyLength && type.algorithm.equalsIgnoreCase(algorithm)) {
                return type;
            }
        }

        throw new IllegalArgumentException("Unsupported key length (" + keyLength + ") and/or algorithm: '" + algorithm + "'");
    }

    public String getAlgorithmName() {
        return algorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public ASN1ObjectIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public boolean isAes() {
        return "AES".equals(algorithm);
    }
}
package org.apache.pdfbox.pdmodel.encryption;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSAlgorithm;

public enum EncryptionType {
    RC4_40BIT(40, "RC4", EncryptionType.RC4), RC4_128BIT(128, "RC4", EncryptionType.RC4), RC4_192BIT(192, "RC4", EncryptionType.RC4), RC4_256BIT(256, "RC4", EncryptionType.RC4), DES(56, "DES",
            new ASN1ObjectIdentifier("1.3.14.3.2.7")), DES3_56BIT(56, "DES", PKCSObjectIdentifiers.des_EDE3_CBC), DES3_112BIT(112, "DES", PKCSObjectIdentifiers.des_EDE3_CBC), DES3_168BIT(168, "DES",
            PKCSObjectIdentifiers.des_EDE3_CBC), AES_128BIT(128, "AES", CMSAlgorithm.AES128_CBC), AES_192BIT(192, "AES", CMSAlgorithm.AES192_CBC), AES_256BIT(256, "AES", CMSAlgorithm.AES256_CBC);

    public static final ASN1ObjectIdentifier RC4 = PKCSObjectIdentifiers.encryptionAlgorithm.branch("4");

    private final int                        keyLength;

    private final String                     algorithm;

    private final ASN1ObjectIdentifier       algorithmIdentifier;

    private EncryptionType(int keyLength, String algorithm, ASN1ObjectIdentifier algorithmIdentifier) {
        this.keyLength = keyLength;
        this.algorithm = algorithm;
        this.algorithmIdentifier = algorithmIdentifier;
    }

    public static EncryptionType forLengthAndAlgorithm(int keyLength, String algorithm) {
        EncryptionType[] values = values();

        for (EncryptionType type : values) {
            if (type.keyLength == keyLength && type.algorithm.equalsIgnoreCase(algorithm)) {
                return type;
            }
        }

        throw new IllegalArgumentException("Unsupported key length (" + keyLength + ") and/or algorithm: '" + algorithm + "'");
    }

    public String getAlgorithmName() {
        return algorithm;
    }

    public int getKeyLength() {
        return keyLength;
    }

    public ASN1ObjectIdentifier getAlgorithmIdentifier() {
        return algorithmIdentifier;
    }

    public boolean isAes() {
        return "AES".equals(algorithm);
    }
}
