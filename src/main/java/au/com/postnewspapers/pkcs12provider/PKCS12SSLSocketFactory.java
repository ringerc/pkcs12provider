package au.com.postnewspapers.pkcs12provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;

/**
 * An SSL Socket factory that uses the CertificateTrustManager credentials
 * to authenticate the remote end and to perform client certificate
 * negotiation if requested by the remote end.
 *
 * This socket factory will only connect to a service whose certificate is
 * signed by one of the certificate chain members from the user's pkcs12
 * cert. It will not talk to servers using other "well known" CA-signed certs.
 *
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public class PKCS12SSLSocketFactory extends WrappedFactory {

    // A PKCS12Store instance obtained from the certificate manager
    // for this session
    PKCS12Store pks;

    /**
     * Create a PKCS12SSLSocketFactory.
     *
     * If supplied, the argument to the factory is taken as an identifier for
     * a PKCS#12 resource, and is passed on to the PKCS12FileSource and
     * PKCS12PasswordSource to help them select appropriate credentials. It will
     * be null if no argument was supplied to the factory.
     *
     * @param arg String identifier for pkcs12 resource
     * @throws GeneralSecurityException
     */
    public PKCS12SSLSocketFactory(String arg) throws GeneralSecurityException {
        pks = CertificateManager.getStoreForKey(arg);
        SSLContext ctx = SSLContext.getInstance("TLS"); // or "SSL" ?
        ctx.init(
                new KeyManager[]{ new CMSSLKeyManager()},
                new TrustManager[]{ new CMSSLTrustManager()},
                null);
        _factory = ctx.getSocketFactory();
    }

    /**
     * This X509TrustManager implementation verifies the server against the
     * list of trusted certificates obtained from the CertificateManager.
     *
     * It does not use the system trusted certificate store.
     */
    private class CMSSLTrustManager implements X509TrustManager {

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            X509Certificate[] localCerts = pks.getUserCertificateChain();
            List<X509Certificate> validTrustCerts = new ArrayList<X509Certificate>(localCerts.length);
            for (X509Certificate localCert : localCerts) {
                try {
                    localCert.checkValidity();
                } catch (CertificateExpiredException ex) {
                    Logger.getLogger(PKCS12SSLSocketFactory.class.getName()).log(Level.SEVERE, null, ex);
                    continue;
                } catch (CertificateNotYetValidException ex) {
                    Logger.getLogger(PKCS12SSLSocketFactory.class.getName()).log(Level.SEVERE, null, ex);
                    continue;
                }
                // Make sure it's allowed to be used as a CA certificate
                if (localCert.getBasicConstraints() < 0) {
                    continue;
                }
                // Other things you might want to do here:
                //
                // - check 'getKeyUsage()' bits to determine if cert is allowed to sign certificates.
                // - check extended usage bits
                validTrustCerts.add(localCert);
            }
            return validTrustCerts.toArray(new X509Certificate[validTrustCerts.size()]);
        }

        @Override
        public void checkClientTrusted(X509Certificate[] certs, String authType) throws CertificateException {
            throw new CertificateException("Client mode not supported by trust manager");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            // Given the peer provided certificate chain, determine if we trust
            // any of them, or throw CertificateException if not.
            //
            // WARNING: Does **NOT** validate host name against server certificate Subject
            if (chain == null || chain.length == 0) {
                throw new IllegalArgumentException("Peer-provided certificate chain null or zero-length");
            }

            X509Certificate[] validTrustCerts = getAcceptedIssuers();

            // We've been passed a certificate chain. What we must first do is verify that
            // we trust one of the certificates in the chain (by making sure it's signed
            // by one of our trusted certificates). If we don't trust any of the certs
            // in the chain, we can reject the lot.
            //
            // If we trust multiple certificates we only need to establish trust
            // from the "closest" one to the peer, so we work forward in the list.
            //
            int trustedIdx = -1;
            try {
                X509Certificate lastCert = null, thisCert = null;
                for (int i = 0; i < chain.length; i++) {
                    lastCert = thisCert;
                    thisCert = chain[i];
                    // Is this cert valid? If not, the chain of trust is broken
                    // and we'll throw our toys.
                    thisCert.checkValidity();
                    // Similarly, `lastCert' must be signed by `thisCert'
                    // or `thisCert' breaks the chain of trust. This will throw
                    // unless verification passes.
                    if (lastCert != null) {
                        lastCert.verify(thisCert.getPublicKey());
                    }
                    // Cert is valid. Is it signed by somebody we trust? If not,
                    // that's no big deal, we'll just check the next certificate.
                    if (certTrustedSigner(thisCert, validTrustCerts) != null) {
                        // OK, we trust this cert, it's valid, and there's an unbroken
                        // valid chain of signatures from it to the peer cert. Guess we trust
                        // the peer.
                        trustedIdx = i;
                        break;
                    }
                }
            } catch (NoSuchAlgorithmException ex) {
                throw new CertificateException("Certificate chain validation failed", ex);
            } catch (InvalidKeyException ex) {
                throw new CertificateException("Certificate chain validation failed", ex);
            } catch (NoSuchProviderException ex) {
                throw new CertificateException("Certificate chain validation failed", ex);
            } catch (SignatureException ex) {
                throw new CertificateException("Certificate chain validation failed", ex);
            }
            if (trustedIdx == -1) {
                // We didn't find any signatures from anyone we trust in the
                // certificate chain provided by the peer. Reject it.
                throw new CertificateException("No certificate in chain signed by trusted authority");
            }
        }

        /**
         * Test `cert' against `trustedSigners' to see if any of the trusted
         * signers have signed `cert'. If so, return the certificate of the trusted
         * signer who signed `cert', or null if no trusted signatures were found on `cert'.
         *
         * @param cert certificate to check for trustworthiness
         * @param trustedSigners certificates whose signatures are trusted
         * @return trusted cert whose signature was found on `cert', or null if no trusted signatures found
         */
        private X509Certificate certTrustedSigner(X509Certificate cert, X509Certificate[] trustedSigners) {
            for (X509Certificate trustedSigner : trustedSigners) {
            try {
                cert.verify(trustedSigner.getPublicKey());
                // Verification passed, `cert' is signed by `trustedSigner'
                return trustedSigner;
            } catch (CertificateException ex) {
                continue;
            } catch (InvalidKeyException ex) {
                continue;
            } catch (NoSuchAlgorithmException ex) {
                continue;
            } catch (NoSuchProviderException ex) {
                continue;
            } catch (SignatureException ex) {
                continue;
            }
            }
            return null;
        }
    }

    /**
     * This X509KeyManager implementation obtains key and certificate material
     * from the X.509 certificate provided by the CertificateManager. It's really
     * just an adapter for the CertificateManager interface.
     */
    private class CMSSLKeyManager implements X509KeyManager {

        @Override
        public String[] getClientAliases(String string, Principal[] prncpls) {
            return new String[]{pks.getUserCertificateAlias()};
        }

        @Override
        public String chooseClientAlias(String[] strings, Principal[] prncpls, Socket socket) {
            return pks.getUserCertificateAlias();
        }

        @Override
        public String[] getServerAliases(String string, Principal[] prncpls) {
            return new String[]{pks.getUserCertificateAlias()};
        }

        @Override
        public String chooseServerAlias(String string, Principal[] prncpls, Socket socket) {
            return pks.getUserCertificateAlias();
        }

        @Override
        public X509Certificate[] getCertificateChain(String alias) {
            if (!alias.equals(pks.getUserCertificateAlias())) {
                return null;
            } else {
                return pks.getUserCertificateChain();
            }
        }

        @Override
        public PrivateKey getPrivateKey(String alias) {
            if (!alias.equals(pks.getUserCertificateAlias())) {
                return null;
            } else {
                return pks.getUserKey();
            }
        }
    }
}
