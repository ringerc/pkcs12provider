package au.com.postnewspapers.pkcs12provider;

/**
 * Exception thrown by CertificateManager on failure
 */
public class CertificateManagerError extends PKCS12Error {

    public CertificateManagerError(String msg) {
        super(msg);
    }

    public CertificateManagerError(String msg, Throwable err) {
        super(msg, err);
    }
}
