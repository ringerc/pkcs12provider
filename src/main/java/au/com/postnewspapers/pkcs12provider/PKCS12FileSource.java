package au.com.postnewspapers.pkcs12provider;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

/**
 * Basic PKCS12DataSource that reads a PKCS12 file from the
 * path provided as `arg', optionally prepending a path prefix
 * (such as a certificate folder).
 *
 * @author Craig Ringer <craig@postnewspapers.com.au>
 */
public class PKCS12FileSource implements PKCS12DataSource {

    private File pathPrefix = new File("");

    public File getPathPrefix() {
        return pathPrefix;
    }

    public void setPathPrefix(File pathPrefix) {
        this.pathPrefix = pathPrefix;
    }

    @Override
    public InputStream getPKCS12Data(String arg) {
        try {
            return new FileInputStream(arg);
        } catch (FileNotFoundException ex) {
            throw new PKCS12Error("Failed to read pkcs12 file " + arg, ex);
        }
    }

}
