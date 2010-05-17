package au.com.postnewspapers.pkcs12provider;

import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.util.Arrays;
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

    private final CertificateFactory x509CertFactory =
            CertificateFactory.getInstance(CERT_TYPE_X509);

    private static final String
            VALIDATION_TYPE_PKIX = "PKIX",
            CERT_TYPE_X509 = "X.509",
            SSLCONTEXT_TYPE_TLS = "TLS";

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
        pks = CertificateManager.getInstance().getStoreForKey(arg);
        SSLContext ctx = SSLContext.getInstance(SSLCONTEXT_TYPE_TLS);
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

        /**
         * See CertificateManager.getTrustedCertificates
         * @return All trusted certificate
         */
        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return CertificateManager.getInstance().getTrustedCertificates(pks);
        }

        private void checkTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                CertificateManager cm = CertificateManager.getInstance();
                // We need the peer-supplied chain as a CertPath
                CertPath path = x509CertFactory.generateCertPath(Arrays.asList(chain));
                // And validate the path against our trusted certs
                CertPathValidator v = CertPathValidator.getInstance(VALIDATION_TYPE_PKIX);
                PKIXParameters params = cm.getValidatorParams(pks);
                PKIXCertPathValidatorResult validationResult = (PKIXCertPathValidatorResult) v.validate(path, params);
                // If we get any result from validation, we're ok.
                
            } catch (CertPathValidatorException ex) {
                throw new CertificateException("Failed to find valid trust for provided certificate path", ex);
            } catch (InvalidAlgorithmParameterException ex) {
                throw new CertificateException("Unable to validate trust path due to internal error", ex);
            } catch (NoSuchAlgorithmException ex) {
                throw new CertificateException("Unable to validate trust path due to internal error", ex);
            }
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            checkTrusted(chain, authType);
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            checkTrusted(chain, authType);
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
