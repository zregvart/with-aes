package org.apache.pdfbox.pdmodel.encryption;

import org.apache.pdfbox.cos.COSName;

public class EncryptionDefaults {
    private final int     version;

    private final COSName method;

    private final String  subFilter;

    private final int     revision;

    public EncryptionDefaults(final int version, final COSName method, final int revision, final String subFilter) {
        this.version = version;
        this.method = method;
        this.revision = revision;
        this.subFilter = subFilter;
    }

    public COSName getMethod() {
        return method;
    }

    public int getRevision() {
        return revision;
    }

    public String getSubFilter() {
        return subFilter;
    }

    public int getVersion() {
        return version;
    }
}
