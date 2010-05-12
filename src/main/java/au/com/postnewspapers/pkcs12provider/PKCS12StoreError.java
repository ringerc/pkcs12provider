package au.com.postnewspapers.pkcs12provider;

/**
 * Exception thrown by PKCS12Store on failure
 */
public class PKCS12StoreError extends PKCS12Error {

    public PKCS12StoreError(String msg) {
        super(msg);
    }

    public PKCS12StoreError(String msg, Throwable err) {
        super(msg, err);
    }
}
