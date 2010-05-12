package au.com.postnewspapers.pkcs12provider.demo;

import au.com.postnewspapers.pkcs12provider.CertificateManager;
import au.com.postnewspapers.pkcs12provider.PKCS12ConstantPasswordSource;
import au.com.postnewspapers.pkcs12provider.PKCS12FileSource;
import au.com.postnewspapers.pkcs12provider.PKCS12SSLSocketFactory;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.GeneralSecurityException;
import javax.net.ssl.HttpsURLConnection;

public class Demo {

    public static final int HTTPS_PORT = 443;

    public static void main(String[] args) throws GeneralSecurityException, IOException{
        // Get the server, cert and password from our arguments. Typically
        // these would be obtained via the PKCS12DataSource() and PKCS12PasswordSource()
        // interface implementations, but we're going for ultra-simple here.
        if (args.length != 3) {
            System.err.println("Usage: demo https://serverurl[:port]/  path/to/cert.p12  password");
            System.exit(1);
        }
        URL url = new URL(args[0]);
        String certPath = args[1];
        char[] certPass = args[2].toCharArray();

        // Init the CertificateManager
        CertificateManager.init(
                new PKCS12FileSource(),
                /* Usually you'd provide a password prompter implementation here */
                new PKCS12ConstantPasswordSource(certPass),
                false /* don't cache loaded certs */);

        // Now establish a HTTPs connection to a test host we can mutually
        // authenticate with, override the default ssl socket factory with ours,
        // connect, print the data read, and quit.
        HttpsURLConnection conn = (HttpsURLConnection)url.openConnection();
        conn.setSSLSocketFactory(
                // The argument will be passed to PKCS12FileSource(...)
                // where it is interpreted as the path to a pkcs12 file.
                // You can interpret the arg to mean whatever you want in
                // your own provider should you implement one.
                new PKCS12SSLSocketFactory(certPath)
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