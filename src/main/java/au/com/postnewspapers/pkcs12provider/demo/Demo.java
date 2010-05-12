package au.com.postnewspapers.pkcs12provider.demo;

import au.com.postnewspapers.pkcs12provider.CertificateManager;
import au.com.postnewspapers.pkcs12provider.PKCS12DataSource;
import au.com.postnewspapers.pkcs12provider.PKCS12PasswordSource;
import au.com.postnewspapers.pkcs12provider.PKCS12SSLSocketFactory;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.GeneralSecurityException;
import javax.net.ssl.HttpsURLConnection;

public class Demo {

    public static final String
            PKCS12_FILE_PATH = "/path/to/pkcsfile.p12",
            PKCS12_FILE_PASS = "password",
            HTTPS_HOST = "server.signed.by.same.ca.as.pkcsfile";

    public static final int HTTPS_PORT = 443;

    /**
     * Provider for PKCS12 data and passphrase when asked for them by the
     * CertificateManager.
     */
    public static class SimpleFileProvider implements PKCS12DataSource, PKCS12PasswordSource {

        @Override
        public InputStream getPKCS12Data(String arg) {
            try {
                return new FileInputStream(arg);
            } catch (FileNotFoundException ex) {
                // Generally you'd use something a bit more ... informative than wrapping with RuntimeException
                throw new RuntimeException("Failed to get pkcs12 file", ex);
            }
        }

        @Override
        public char[] getPassword(String arg) {
            return PKCS12_FILE_PASS.toCharArray();
        }

    }

    public static void main(String[] args) throws GeneralSecurityException, IOException{
        // Init the CertificateManager
        SimpleFileProvider provider = new SimpleFileProvider();
        CertificateManager.init(provider, provider, true /*cache*/);

        // Now establish a HTTPs connection to a test host we can mutually
        // authenticate with.
        URL url = new URL("https",HTTPS_HOST,HTTPS_PORT,"/");
        HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
        conn.setSSLSocketFactory(
                // The argument will be passed to SimpleFileProvider.getPKCS12Data(...)
                // where we choose to interpret it as the path to a pkcs12 file
                new PKCS12SSLSocketFactory(PKCS12_FILE_PATH)
                );
        conn.connect();
        BufferedReader is = new BufferedReader(new InputStreamReader(conn.getInputStream()));
        String line;
        while ((line = is.readLine()) != null) {
            System.out.println(line);
        }
        conn.disconnect();
    }
}