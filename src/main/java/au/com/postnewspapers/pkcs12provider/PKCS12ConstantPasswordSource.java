package au.com.postnewspapers.pkcs12provider;

import java.util.Arrays;

/**
 * A PKCS12PasswordSource that always returns the same password, as
 * determined at initialization.
 * 
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public class PKCS12ConstantPasswordSource implements PKCS12PasswordSource {

    private final char[] pw;

    public PKCS12ConstantPasswordSource(char[] password) {
        this.pw = Arrays.copyOf(password, password.length);
    }

    @Override
    public char[] getPassword(String arg) {
        return pw;
    }
}
