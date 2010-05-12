package au.com.postnewspapers.pkcs12provider;

/**
 * PKCS12PasswordSource provides a generic way for
 * applications to provide PKCS12 decryption passwords
 * to the CertificateManager when they are required.
 *
 * The application will typically prompt the user
 * for a password, or read it from preferences.
 *
 * @warning Be careful about using GUI routines in response
 *          to callbacks here. Consider threading issues.
 * 
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public interface PKCS12PasswordSource {

    /**
     * Obtain a password for the PKCS12 certificate
     * identified by `key' and return it.
     *
     * This method has the same threading and
     * identifier consistency rules as PKCS12DataSource.getPKCS12Data(String).
     *
     * @warning invoking Swing routines directly from this method
     *          is unsafe unless you know it was called on the
     *          Event Dispatch Thread.
     *
     * {@see PKCS12DataSource.getPKCS12Data}
     *
     * @param arg App-specific pkcs12 identifier
     * @return
     */
    char[] getPassword(String arg);
}
