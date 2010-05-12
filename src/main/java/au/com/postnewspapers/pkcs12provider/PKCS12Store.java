package au.com.postnewspapers.pkcs12provider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

/**
 *
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public class PKCS12Store {

    private static final String KS_TYPE_PKCS12 = "pkcs12";

    private KeyStore userKeyStore;
    private String userCertificateAlias;
    private X509Certificate[] userCertificateChain;
    private PrivateKey userKey;

    public PKCS12Store(File pkcs12File, char[] pkcs12Password) {
        final String msg = "unable to load pkcs12 file " + pkcs12File;
        loadUserKeyStore(pkcs12File, pkcs12Password, msg);
    }

    public PKCS12Store(InputStream pkcs12Data, char[] pkcs12Password) {
        final String msg = "unable to load pkcs12 data from stream";
        loadUserKeyStore(pkcs12Data, pkcs12Password, msg);
    }

    private void loadUserKeyStore(File userStorePath, char[] pkcs12password, String msg) {
        try {
            InputStream ksStream = new FileInputStream(userStorePath);
            loadUserKeyStore(ksStream, pkcs12password, msg);
            ksStream.close();
        } catch (FileNotFoundException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (IOException ex) {
            throw new PKCS12StoreError(msg, ex);
        }
    }

    private void loadUserKeyStore(InputStream pkcs12Data, char[] ksPass, String msg) {
        KeyStore ks;
        try {
            ks = KeyStore.getInstance(KS_TYPE_PKCS12);
            ks.load(pkcs12Data, ksPass);
            Enumeration<String> aliases = ks.aliases();
            if (!aliases.hasMoreElements()) {
                throw new PKCS12StoreError("No entries found in PKCS#12 certificate file");
            }
            userCertificateAlias = aliases.nextElement();
            if (aliases.hasMoreElements()) {
                throw new PKCS12StoreError("More than one entry found in PKCS#12 file, unsupported");
            }
            Certificate[] certs = ks.getCertificateChain(userCertificateAlias);
            userCertificateChain = new X509Certificate[certs.length];
            for (int i = 0; i < certs.length; i++) {
                // Every cert in a PKCS#12 file must be an X.509 cert
                userCertificateChain[i] = (X509Certificate)certs[i];
            }
            // Yes, I know it's a bit naughty to decrypt this right here and now. But
            // if we don't, we still store their password, which is all that's required
            // to decrypt it later. So there's little difference, really.
            userKey = (PrivateKey) ks.getKey(userCertificateAlias, ksPass);
        } catch (NoSuchAlgorithmException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (KeyStoreException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (UnrecoverableKeyException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (ClassCastException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (CertificateException ex) {
            throw new PKCS12StoreError(msg, ex);
        }  catch (IOException ex) {
            throw new PKCS12StoreError(msg, ex);
        }
        userKeyStore = ks;
    }

    public String getUserCertificateAlias() {
        return userCertificateAlias;
    }

    public X509Certificate[] getUserCertificateChain() {
        return userCertificateChain;
    }

    PrivateKey getUserKey() {
        return userKey;
    }
}