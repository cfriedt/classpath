

import gnu.javax.net.ssl.provider.CipherSuite;
import gnu.javax.net.ssl.provider.CipherSuiteList;
import gnu.javax.net.ssl.provider.ClientHello;
import gnu.javax.net.ssl.provider.CompressionMethod;
import gnu.javax.net.ssl.provider.CompressionMethodList;
import gnu.javax.net.ssl.provider.ProtocolVersion;
import gnu.javax.net.ssl.provider.Handshake;
import gnu.javax.net.ssl.provider.Random;

import java.nio.ByteBuffer;
import java.util.Arrays;

class testClientHello
{
  public static void main (String[] argv)
  {
    try
      {
        check ();
      }
    catch (Exception x)
      {
        System.out.println ("FAIL: caught exception " + x);
        x.printStackTrace ();
      }
  }

  static void check () throws Exception
  {
    final int alloc_len = 4096;
    ByteBuffer buffer = ByteBuffer.allocate (alloc_len);
    Handshake handshake = new Handshake (buffer);

    handshake.setType (Handshake.Type.CLIENT_HELLO);
    handshake.setLength (alloc_len - 4);

    ClientHello hello = null;
    hello = (ClientHello) handshake.body ();

    byte[] sessionId = new byte[32];
    for (int i = 0; i < 32; i++)
      sessionId[i] = (byte) i;

    hello.setVersion (ProtocolVersion.TLS_1);
    hello.setSessionId (sessionId);

    Random random = hello.random ();
    random.setGmtUnixTime (123456);
    byte[] nonce = new byte [28];
    for (int i = 0; i < nonce.length; i++)
      nonce[i] = (byte) i;
    random.setRandomBytes (nonce);

    CipherSuiteList suites = hello.cipherSuites ();
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

    CompressionMethodList comps = hello.compressionMethods ();
    comps.setSize (2);
    comps.put (0, CompressionMethod.NULL);
    comps.put (1, CompressionMethod.ZLIB);

    hello.setExtensionsLength (0);
    handshake.setLength (hello.length ());

    handshake = new Handshake (buffer);

    hello = (ClientHello) handshake.body ();
    if (ProtocolVersion.TLS_1.equals (hello.version ()))
      System.out.println ("PASS: protocolVersion ()");
    else
      System.out.println ("FAIL: protocolVersion ()");

    if (hello.random ().gmtUnixTime () == 123456)
      System.out.println ("PASS: random ().gmtUnixTime ()");
    else
      System.out.println ("FAIL: random ().gmtUnixTime ()");

    if (Arrays.equals (nonce, hello.random ().randomBytes ()))
      System.out.println ("PASS: random ().randomBytes ()");
    else
      System.out.println ("FAIL: random ().randomBytes ()");

    if (suites.equals (hello.cipherSuites ()))
      System.out.println ("PASS: cipherSuites()");
    else
      System.out.println ("FAIL: cipherSuites()");

    if (comps.equals (hello.compressionMethods ()))
      System.out.println ("PASS: compressionMethods()");
    else
      System.out.println ("FAIL: compressionMethods()");

    System.err.println (handshake);
  }
}
