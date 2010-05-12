package au.com.postnewspapers.pkcs12provider;

public class PKCS12Error extends RuntimeException {

    public PKCS12Error(String msg) {
        super(msg);
    }

    public PKCS12Error(String msg, Throwable err) {
        super(msg, err);
    }
}
