package au.com.postnewspapers.pkcs12provider;

import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
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
    private String userKeyAlias;
    private X509Certificate[] userCertificateChain;
    private PrivateKey userKey;

    public PKCS12Store(InputStream pkcs12Data, char[] pkcs12Password) {
        final String msg = "unable to load pkcs12 data from stream";
        loadUserKeyStore(pkcs12Data, pkcs12Password, msg);
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
            while (aliases.hasMoreElements()) {
                String alias = aliases.nextElement();
                // is it a PrivateKey
                if (ks.isKeyEntry(alias)) {
                    // This is the user's private key and associated cert, possibly
                    // plus the chain of certificates up to the root CA that signed it.
                    if (userKeyAlias != null) {
                        throw new CertificateException("Only one key may be present in a PKCS#12 file, " +
                                "but found aliases \"" + userKeyAlias + "\" and \""
                                + alias + "\" both of key type ");
                    }
                    userKeyAlias = alias;
                    // For a PKCS12 cert the key pass is the same as the package
                    // pass, so we can definitely decrypt this.
                    userKey = (PrivateKey)ks.getKey(alias, ksPass);
                    Certificate[] chain = ks.getCertificateChain(alias);
                    userCertificateChain = new X509Certificate[chain.length];
                    System.arraycopy(chain, 0, userCertificateChain, 0, chain.length);
                } else {
                    // Java's PKCS#12 implementation doesn't support "extra" unrelated
                    // certs in a PKCS#12 file.
                    throw new CertificateException("Unexpected certificate entry found in PKCS#12 data," +
                            "alias \"" + alias + "\" wasn't a PublicKey");
                }
            }
        } catch (NoSuchAlgorithmException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (KeyStoreException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (UnrecoverableKeyException ex) {
            throw new PKCS12StoreError(msg, ex);
        } catch (UnrecoverableEntryException ex) {
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

    /**
     * Get the alias that identifies the user PublicKey entry in this
     * PKCS#12 file.
     * 
     * @return the KeyStore alias for the user cert and key.
     */
    public String getUserCertificateAlias() {
        return userKeyAlias;
    }

    /**
     * Return the X.509 certificate chain for the PKCS#12 file, including
     * the user's own certificate. There is no guarantee that the chain
     * is complete and gapless, nor that it is correctly ordered, as this
     * depends on the PKCS#12 file.
     *
     * @return (possibly partial) X.509 certificate chain from PKCS#12 file
     */
    public X509Certificate[] getUserCertificateChain() {
        return userCertificateChain;
    }

    /**
     * @return Private key from the PKCS#12 file
     */
    PrivateKey getUserKey() {
        return userKey;
    }

    /**
     * @return KeyStore containing the loaded PKCS#12 file contents
     */
    KeyStore getKeyStore() {
        return userKeyStore;
    }
    
}