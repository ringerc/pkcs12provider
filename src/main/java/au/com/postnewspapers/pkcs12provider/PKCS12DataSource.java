package au.com.postnewspapers.pkcs12provider;

import java.io.InputStream;

/**
 * PKCS12DataSource provides a customisable way to supply a
 * CertificateManager with PKCS#12 data from
 * application-specific sources. Typically the app
 * will want to open a PKCS#12 file identified in some
 * way by the string arg and return a FileInputStream.
 *
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public interface PKCS12DataSource {

    /**
     * Given the identifier `arg', return an InputStream
     * for the associated PKCS12 data. The app should
     * generally return the same PKCS12 data for the same
     * arg. Failure to do so may result in attempting
     * to decrypt a cert with the wrong passphrase.
     *
     * This method will be called on whatever thread
     * asked the CertificateManager for a PKCS12Store
     * with this identifier. If you must do work
     * on a particular thread, you will need to manage
     * thread synchronization yourself so you can wait
     * for a result and return it when it is ready.
     *
     * @param arg App-specific pkcs12 identifier
     * @return pkcs12 data stream
     */
    InputStream getPKCS12Data(String arg);
}
