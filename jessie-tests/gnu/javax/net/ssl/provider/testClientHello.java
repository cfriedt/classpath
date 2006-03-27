

package gnu.javax.net.ssl.provider;

import java.nio.ByteBuffer;
import java.util.Arrays;

class testClientHello
{
  public static void main (String[] argv)
  {
    final int alloc_len = 4096;
    ByteBuffer buffer = ByteBuffer.allocate (alloc_len);
    Handshake handshake = new Handshake (buffer);

    handshake.setType (Handshake.Type.CLIENT_HELLO);
    handshake.setLength (alloc_len - 4);

    ClientHello hello = null;
    try
      {
        hello = (ClientHello) handshake.getBody ();
      }
    catch (Exception x)
      {
        x.printStackTrace (System.err);
        System.out.println ("FAIL: " + x);
        System.exit (1);
      }

    byte[] sessionId = new byte[32];
    for (int i = 0; i < 32; i++)
      sessionId[i] = (byte) i;

    hello.setProtocolVersion (ProtocolVersion.TLS_1);
    hello.setSessionId (sessionId);

    Random random = hello.getRandom ();
    random.setGMTUnixTime (123456);
    byte[] nonce = new byte [28];
    for (int i = 0; i < nonce.length; i++)
      nonce[i] = (byte) i;
    random.setRandomBytes (nonce);

    CipherSuiteList suites = hello.getCipherSuites ();
    suites.setSize (10);
    suites.put (0, CipherSuite.TLS_NULL_WITH_NULL_NULL);
    suites.put (1, CipherSuite.TLS_RSA_WITH_NULL_MD5);
    suites.put (2, CipherSuite.TLS_RSA_WITH_NULL_SHA);
    suites.put (3, CipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5);
    suites.put (4, CipherSuite.TLS_RSA_WITH_RC4_128_MD5);
    suites.put (5, CipherSuite.TLS_RSA_WITH_RC4_128_SHA);
    suites.put (6, CipherSuite.TLS_RSA_EXPORT_WITH_DES40_CBC_SHA);
    suites.put (7, CipherSuite.TLS_RSA_WITH_DES_CBC_SHA);
    suites.put (8, CipherSuite.TLS_RSA_WITH_3DES_EDE_CBC_SHA);
    suites.put (9, CipherSuite.TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA);

    CompressionMethodList comps = hello.getCompressionMethods ();
    comps.setSize (2);
    comps.put (0, CompressionMethod.NULL);
    comps.put (1, CompressionMethod.ZLIB);

    hello.setExtensionsLength (0);
    handshake.setLength (hello.getLength ());

    hello = (ClientHello) handshake.getBody ();
    if (!ProtocolVersion.TLS_1.equals (hello.getProtocolVersion ()))
      System.out.println ("FAIL: getProtocolVersion ()");
    if (hello.getRandom ().getGMTUnixTime () != 123456)
      System.out.println ("FAIL: getRandom ().getGMTUnixTime ()");
    if (!Arrays.equals (nonce, hello.getRandom ().getRandomBytes ()))
      System.out.println ("FAIL: getRandom ().getRandomBytes ()");

    System.err.println (handshake);
  }
}
