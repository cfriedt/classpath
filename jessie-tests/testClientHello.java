

import gnu.javax.net.ssl.provider.CipherSuite;
import gnu.javax.net.ssl.provider.CipherSuiteList;
import gnu.javax.net.ssl.provider.ClientHello;
import gnu.javax.net.ssl.provider.CompressionMethod;
import gnu.javax.net.ssl.provider.CompressionMethodList;
import gnu.javax.net.ssl.provider.Extension;
import gnu.javax.net.ssl.provider.ExtensionList;
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

    hello.setExtensionsLength (12);
    ExtensionList exts = hello.extensions();
    // Max fragment length of 2^9-1
    exts.set (0, Extension.Type.MAX_FRAGMENT_LENGTH, 1); // 2 + 2 + 1
    exts.get (0).setValue (new byte[] { 1 });
    // Zero-length server name.
    exts.set (1, Extension.Type.SERVER_NAME, 3); // 2 + 2 + 3
    exts.get(1).setValue(new byte[3]);

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
    
    exts = hello.extensions();
    if (exts.size() == 2)
      System.out.println ("PASS: extensions().size");
    else
      System.out.println ("FAIL: extensions().size");
    if (exts.length () == 12)
      System.out.println ("PASS: extensions().length");
    else
      System.out.println ("FAIL: extensions().length");
      
    Extension e = exts.get(0);
    if (e.type() == Extension.Type.MAX_FRAGMENT_LENGTH)
      System.out.println ("PASS: get(0).type()");
    else
      System.out.println ("FAIL: get(0).type()");
    if (Arrays.equals (e.valueBytes(), new byte[] { 1 }))
      System.out.println ("PASS: get(0).value()");
    else
      System.out.println ("FAIL: get(0).value()");
    
    e = exts.get(1);
    if (e.type () == Extension.Type.SERVER_NAME)
      System.out.println ("PASS: get(1).type()");
    else
      System.out.println ("FAIL: get(1).type()");
    if (Arrays.equals(e.valueBytes(), new byte[3]))
      System.out.println ("PASS: get(1).value()");
    else
      System.out.println ("FAIL: get(1).value()");

    System.err.println (handshake);
    
    // Part 2: no extensions.
    buffer = ByteBuffer.allocate(96);
    handshake = new Handshake (buffer);

    handshake.setType (Handshake.Type.CLIENT_HELLO);
    handshake.setLength (92);

    hello = null;
    hello = (ClientHello) handshake.body ();

    sessionId = new byte[32];
    for (int i = 0; i < 32; i++)
      sessionId[i] = (byte) i;

    hello.setVersion (ProtocolVersion.TLS_1); // 2
    hello.setSessionId (sessionId);           // +33    (1 + 32)

    random = hello.random ();                 // +32
    random.setGmtUnixTime (123456);
    nonce = new byte [28];
    for (int i = 0; i < nonce.length; i++)
      nonce[i] = (byte) i;
    random.setRandomBytes (nonce);

    suites = hello.cipherSuites ();
    suites.setSize (10);                      // + 22   (2 + 2*10)
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

    comps = hello.compressionMethods ();      // + 3    (1 + 2*1)
    comps.setSize (2);
    comps.put (0, CompressionMethod.NULL);
    comps.put (1, CompressionMethod.ZLIB);
    
    handshake = new Handshake(buffer);
    hello = (ClientHello) handshake.body();
    if (hello.extensions() == null)
      System.out.println("PASS: extensions() == null");
    else
      System.out.println("FAIL: extensions() != null");
    
    System.err.println(handshake);
  }
}
