

package gnu.javax.net.ssl.provider;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collections;

class testCertificate
{
  static final byte[] test_cert =
    ("-----BEGIN CERTIFICATE-----\n" +
     "MIICFTCCAX6gAwIBAgIBATANBgkqhkiG9w0BAQQFADBVMRswGQYDVQQKExJBcGFj\n" +
     "aGUgSFRUUCBTZXJ2ZXIxIjAgBgNVBAsTGUZvciB0ZXN0aW5nIHB1cnBvc2VzIG9u\n" +
     "bHkxEjAQBgNVBAMTCWxvY2FsaG9zdDAeFw0wNDA0MTMwMzM1NTJaFw0wNTA0MTMw\n" +
     "MzM1NTJaMEwxGzAZBgNVBAoTEkFwYWNoZSBIVFRQIFNlcnZlcjEZMBcGA1UECxMQ\n" +
     "VGVzdCBDZXJ0aWZpY2F0ZTESMBAGA1UEAxMJbG9jYWxob3N0MIGfMA0GCSqGSIb3\n" +
     "DQEBAQUAA4GNADCBiQKBgQCxJUcMWt9GO59u46xY/gbp0sZP6v4nbnG64as6UF9c\n" +
     "rlyKUaSToUoO0LtBT1MlZxAg+VgmrCz75clOFdzUJonj9aOMZZvkOHgVhUwuGOcO\n" +
     "1gLYa+vjhaPdbfymo5ztEbBZBZ9GsasGPX6K58GmQaUQwUtdcgE/hhnhwN+gHPBm\n" +
     "7wIDAQABMA0GCSqGSIb3DQEBBAUAA4GBADSEHkrDmCCdmtX8+9O4o4Uvb2UobeF+\n" +
     "1GspRsWBMPHUDDF1ipEHxlNp0+M9hwTqFqQwBoJJ7Kfcqz+lXd61hS0GQZJdEkzp\n" +
     "7578r/KhpXsT+fLKTBUgjrwOoHbohCqOWejV2j6lstA8P3U/vdAQuLTm0GiuIFcv\n" +
     "riDVGJJzZ2b/\n" +
     "-----END CERTIFICATE-----\n").getBytes ();

  public static void main (String[] argv) throws Throwable
  {
    final int alloc_len = 4096;
    CertificateFactory factory = CertificateFactory.getInstance ("X.509");
    X509Certificate cert = (X509Certificate)
      factory.generateCertificate (new ByteArrayInputStream (test_cert));
    ByteBuffer buffer = ByteBuffer.allocate (alloc_len);
    Handshake handshake = new Handshake (buffer);

    handshake.setType (Handshake.Type.CERTIFICATE);
    handshake.setLength (alloc_len - 4);

    Certificate _cert = (Certificate) handshake.getBody ();
    _cert.setCertificates (Collections.singletonList (cert));
    System.err.println (_cert.getCertificates ());
    System.err.println (_cert);
  }
}
