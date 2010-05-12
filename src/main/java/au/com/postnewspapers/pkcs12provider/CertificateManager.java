package au.com.postnewspapers.pkcs12provider;

import java.io.InputStream;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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

    private CertificateManager(PKCS12DataSource fileSource, PKCS12PasswordSource pwsource, boolean caching) {
        this.passwordSource = pwsource;
        this.pkcs12DataSource = fileSource;
        pkcs12map = caching ? Collections.synchronizedMap(new HashMap<String,PKCS12Store>()) : null;
    }

    private static CertificateManager _getInstance() {
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
        }
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
    public static PKCS12Store getStoreForKey(String key) {
        return _getInstance()._getStoreForKey(key);
    }

    private PKCS12Store _getStoreForKey(String key) {
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
     * Drop the PKCS12Store associated with `key' from the cache,
     * if any such key is present in the cache. If the key is not found,
     * no action is taken.
     *
     * If caching is not enabled this is a no-op.
     *
     * @param key Identifier of store to drop from the cache
     */
    public static void dropKeyFromCache(String key) {
        _getInstance()._dropKeyFromCache(key);
    }

    private void _dropKeyFromCache(String key) {
        if (pkcs12map != null) {
            pkcs12map.remove(key);
        }
    }

    /**
     * Remove all cached PKCS12Store instances, if any.
     *
     * If caching is not enabled this is a no-op.
     */
    public static void clearCache() {
        _getInstance()._clearCache();
    }

    private void _clearCache() {
        if (pkcs12map != null) {
            pkcs12map.clear();
        }
    }
}
