package au.com.postnewspapers.pkcs12provider;

import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

/**
 * CertificateManager provides a mechanism for PKCS12SSLSocketFactory to look
 * up and load PKCS12 certificates using user-provided implementations of
 * PKCS12DataSource and PKCS12PasswordSource to get the PKCS12 data and
 * passphrase.
 *
 * An arbitrary string key is used to identify certificates. While it is expected
 * that applications will usually interpret this as a path, possibly relative to
 * an app certificate store directory or to the file system root, the
 * CertificateManager assigns it no significance and the app is free to interpret
 * it however it wants. The only rule is that the app should consistently map
 * the same key to the same pkcs12 certificate.
 *
 * CertificateManager may optionally cache credentials, so that once loaded a
 * PKCS12 certificate remains accessicble by key lookup without further
 * contact with the PKCS12PasswordSource or PKCS12DataSource. This requires
 * the storage of key material in memory.
 *
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public class CertificateManager {

    private static CertificateManager _instance = null;

    private final Map<String, PKCS12Store> pkcs12map;
    private final PKCS12DataSource pkcs12DataSource;
    private final PKCS12PasswordSource passwordSource;
    private final Set<X509Certificate> trustedCertificates = new HashSet<X509Certificate>();
    private boolean userKeyIssuerTrusted = true;

    private CertificateManager(PKCS12DataSource fileSource, PKCS12PasswordSource pwsource, boolean caching) {
        this.passwordSource = pwsource;
        this.pkcs12DataSource = fileSource;
        pkcs12map = caching ? Collections.synchronizedMap(new HashMap<String,PKCS12Store>()) : null;
    }

    /**
     * Obtain the single shared instance of CertificateManager. The
     * CertificateManager.init(...) method must have been called before
     * getInstance(...) may be called.
     *
     * @return The CertificateManager instance
     */
    public static CertificateManager getInstance() {
        synchronized(CertificateManager.class) {
            if (_instance == null) {
                throw new IllegalStateException("Not initialized");
            }
            return _instance;
        }
    }

    /**
     * Set up the CertificateTrustManager for use. This method must be called
     * before any of the other static methods.
     *
     * @param pkcs12DataSource caller-supplied source of PKCS#12 file data
     * @param pwsource caller-supplied source of PKCS#12 passwords
     * @param caching if true, cache PKCS12 data in CertificateManager after successful load
     * @param trustUserCertIssuer
     * @throws IllegalStateException if already init()ed
     */
    public static void init(PKCS12DataSource fileSource, PKCS12PasswordSource pwsource, boolean caching) {
        if (fileSource == null || pwsource == null) {
            throw new IllegalArgumentException("fileSource and pwsource must be non-null");
        }
        synchronized(CertificateManager.class) {
            if (_instance != null) {
                throw new IllegalStateException("Already initialized");
            }
            _instance = new CertificateManager(fileSource, pwsource, caching);
            CertificateManager.class.notifyAll();
        }
    }

    /**
     * Block the calling thread until init() has returned and the
     * CertificateManager is ready for use.
     */
    public void waitForInit() {
        synchronized(CertificateManager.class) {
            while (_instance == null) {
                try {
                    wait();
                } catch (InterruptedException ex) {
                    // re-check
                }
            }
        }
    }

    /**
     * @return true if the CertificateManager is ready for use.
     */
    public boolean isInited() {
        return _instance == null;
    }
    
    /**
     * A user PrivateKey (such as a PKCS#12 file) may embed a certificate chain
     * to the ultimate issuer. By default, the CertificateManager trusts the
     * issuer(s) of a user's client certificate when using that client cert
     * in negotiations.
     * 
     * @return true if user cert issuers trusted to authenticate peer
     */
    public boolean isUserKeyIssuerTrusted() {
        return userKeyIssuerTrusted;
    }

    /**
     * See isUserKeyIssuerTrusted
     *
     * @param trusted whether user key issuers should be trusted to authenticate peer
     */
    public void setUserKeyIssuerTrusted(boolean trusted) {
        userKeyIssuerTrusted = trusted;
    }

    /**
     * Given a string key `key', which is of application-defined meaning,
     * obtain PKCS12 data from the PKCS12DataSource and obtain a password
     * from the PKCS12PasswordSource, decrypt the key, and return a PKCS12Store
     * with the loaded certificate and key material.
     *
     * @param key String key to help app identify requested cert
     * @return PKCS12Store with loaded certificate
     */
    public PKCS12Store getStoreForKey(String key) {
        if (pkcs12map != null && pkcs12map.containsKey(key)) {
            return pkcs12map.get(key);
        }
        PKCS12Store store;
        try {
            InputStream pkcs12Data = pkcs12DataSource.getPKCS12Data(key);
            store = new PKCS12Store(pkcs12Data, passwordSource.getPassword(key));
        } catch (RuntimeException ex) {
            throw new CertificateManagerError("Unable to obtain pkcs12 data stream or key", ex);
        }
        if (pkcs12map != null) {
            // Note: if caching is enabled, there's a race between the containsKey() test
            // and the subsequent put() of the loaded key. If _getStoreForKey() is called
            // with the same key in rapid succession it'll land up calling put() repeatedly
            // with the same key. We don't actually care, as they should all contain the
            // same certificate and key data (so long as the app is following the guidance
            // to maintain a consistent and repeatable key->pkcs12data relationship). The
            // last put()ter wins. We're using a synchronized map so we don't need
            // to impose manual synchronization, and the orphaned PKCS12Store instances will
            // get gc'd so there's no cleanup needed.
            pkcs12map.put(key, store);
        }
        return store;
    }

    /**
     * Drop the PKCS12Store associated with `arg' from the cache,
     * if any such key is present in the cache. If the entry is not found,
     * no action is taken.
     *
     * If caching is not enabled this is a no-op.
     *
     * @param key Identifier of store to drop from the cache
     */
    public void dropKeyFromCache(String arg) {
        if (pkcs12map != null) {
            pkcs12map.remove(arg);
        }
    }

    /**
     * Remove all cached PKCS12Store instances, if any.
     *
     * If caching is not enabled this is a no-op.
     */
    public void clearCache() {
        if (pkcs12map != null) {
            pkcs12map.clear();
        }
    }

    /**
     * @return the list of trusted certs managed by the CertificateManager
     */
    public Collection<X509Certificate> getTrustedCertificates() {
        return Collections.unmodifiableCollection(trustedCertificates);
    }

    public void addTrustedCertificate(X509Certificate c) {
        synchronized(trustedCertificates) {
            trustedCertificates.add(c);
        }
    }

    public void addTrustedCertificates(Collection<X509Certificate> c) {
        synchronized(trustedCertificates) {
            trustedCertificates.addAll(c);
        }
    }

    public boolean removeTrustedCertificate(X509Certificate c) {
        synchronized(trustedCertificates) {
            return trustedCertificates.remove(c);
        }
    }
    
    /**
     * Get the set of trusted issuers for PKIX validation
     * of a peer's certificate chain. This set includes all
     * certs in the trusted certificates set (see
     * getTrustedCertificates). Additionally, if isUserKeyIssuerTrusted() and
     * the user's PKCS#12 file includes the required CA certificate, the
     * issuer of the user's client certificate is included in the set.
     * 
     * @param userKey PKCS12Store being used in negotiation with this peer
     * @return set of trusted X.509 certificates for verifying peer
     */
    Set<TrustAnchor> getTrustedIssuers(PKCS12Store userKeyStore) {
        synchronized(trustedCertificates) {
            Set<TrustAnchor> ret = new HashSet<TrustAnchor>();
            for (X509Certificate cert : trustedCertificates) {
                ret.add(new TrustAnchor(cert, null));
            }
            if (isUserKeyIssuerTrusted()) {
                for (X509Certificate cert : userKeyStore.getUserCertificateChain()) {
                   ret.add(new TrustAnchor(cert, null));
                }
            }
            return ret;
        }
    }

    /**
     * As getTrustedIssuers, but returns X509Certificate[] in no particular
     * order.
     */
    X509Certificate[] getTrustedCertificates(PKCS12Store userKeyStore) {
        // Yes, I know it's rather inefficient to tear up the set of
        // trust anchors we just made rather than directly populating
        // the array. OTOH, it ensures these two methods are always
        // consistent, and the cost is trivial compared to the validation.
        Set<TrustAnchor> t = getTrustedIssuers(userKeyStore);
        Iterator<TrustAnchor> it = t.iterator();
        X509Certificate[] ret = new X509Certificate[t.size()];
        for (int i = 0; i < t.size(); i++) {
            ret[i] = it.next().getTrustedCert();
        }
        assert(!it.hasNext());
        return ret;
    }

    /**
     * Create a PKIXParameters instance to control how CertPathValidator
     * validates a peer's certificate chain.
     *
     * The default implementation includes all trusted certificates, and
     * disables revocation checking, otherwise sticking to the defaults
     * provided by PKIXParameters.
     * 
     * @param userKeyStore User keystore to get issuing certs from
     * @return PKIXParameters to control peer validation
     * @throws InvalidAlgorithmParameterException from PKIXParameters construction failure
     */
    PKIXParameters getValidatorParams(PKCS12Store userKeyStore) throws InvalidAlgorithmParameterException {
        PKIXParameters params = new PKIXParameters(getTrustedIssuers(userKeyStore));
        params.setRevocationEnabled(false);
        return params;
    }
}
