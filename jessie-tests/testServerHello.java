
import gnu.javax.net.ssl.provider.CipherSuite;
import gnu.javax.net.ssl.provider.CompressionMethod;
import gnu.javax.net.ssl.provider.Extension;
import gnu.javax.net.ssl.provider.ExtensionList;
import gnu.javax.net.ssl.provider.Handshake;
import gnu.javax.net.ssl.provider.ProtocolVersion;
import gnu.javax.net.ssl.provider.Random;
import gnu.javax.net.ssl.provider.ServerHello;
import gnu.javax.net.ssl.provider.ServerHelloBuilder;

import java.nio.ByteBuffer;
import java.util.Arrays;

class testServerHello
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

    handshake.setType (Handshake.Type.SERVER_HELLO);
    handshake.setLength (alloc_len - 4);

    ServerHelloBuilder hello = new ServerHelloBuilder();

    hello.setVersion (ProtocolVersion.TLS_1);
    Random random = hello.random ();
    random.setGmtUnixTime (123456);
    byte[] nonce = new byte[28];
    for (int i = 0; i < nonce.length; i++)
      nonce[i] = (byte) i;
    random.setRandomBytes (nonce);
    byte[] sessionId = new byte[32];
    for (int i = 0; i < sessionId.length; i++)
      sessionId[i] = (byte) i;
    hello.setSessionId (sessionId);
    hello.setCipherSuite (CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA);
    hello.setCompressionMethod (CompressionMethod.ZLIB);
    hello.setExtensionsLength (12);
    ExtensionList exts = hello.extensions();
    // Max fragment length of 2^9-1
    exts.set (0, Extension.Type.MAX_FRAGMENT_LENGTH, 1); // 2 + 2 + 1
    exts.get (0).setValue (new byte[] { 1 });
    // Zero-length server name.
    exts.set (1, Extension.Type.SERVER_NAME, 3); // 2 + 2 + 3
    exts.get(1).setValue(new byte[3]);

    handshake.setLength (hello.length ());
    handshake.bodyBuffer().put(hello.buffer());
    System.err.println (handshake);

    handshake = new Handshake (buffer);
    ServerHello hello2 = (ServerHello) handshake.body ();
    if (Arrays.equals (sessionId, hello2.sessionId ()))
      System.out.println ("PASS: sessionId");
    else
      System.out.println ("FAIL: sessionId");

    if (hello2.cipherSuite () == CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)
      System.out.println ("PASS: cipherSuite");
    else
      System.out.println ("FAIL: cipherSuite");

    if (hello2.compressionMethod () == CompressionMethod.ZLIB)
      System.out.println ("PASS: compressionMethod");
    else
      System.out.println ("FAIL: compressionMethod");
    
    exts = hello2.extensions();
    Extension e = exts.get(0);
    if (e.type() == Extension.Type.MAX_FRAGMENT_LENGTH)
      System.out.println ("PASS: extensions().get(0).type");
    else
      System.out.println ("FAIL: extensions().get(0).type");
    if (Arrays.equals(e.valueBytes(), new byte[] { 1 }))
      System.out.println ("PASS: extensions().get(0).value");
    else
      System.out.println ("FAIL: extensions().get(0).value");

    e = exts.get(1);
    if (e.type() == Extension.Type.SERVER_NAME)
      System.out.println ("PASS: extensions().get(1).type");
    else
      System.out.println ("FAIL: extensions().get(1).type");
    if (Arrays.equals(e.valueBytes(), new byte[3]))
      System.out.println ("PASS: extensions().get(1).value");
    else
      System.out.println ("FAIL: extensions().get(1).value");
 
    // Part 2: with no extensions.
    buffer = ByteBuffer.allocate (74);
    handshake = new Handshake (buffer);

    handshake.setType (Handshake.Type.SERVER_HELLO);
    handshake.setLength (70);

    hello = new ServerHelloBuilder();

    hello.setVersion (ProtocolVersion.TLS_1); // 2
    random = hello.random ();
    random.setGmtUnixTime (123456);
    nonce = new byte[28];
    for (int i = 0; i < nonce.length; i++)
      nonce[i] = (byte) i;
    random.setRandomBytes (nonce);            // + 32
    sessionId = new byte[32];
    for (int i = 0; i < sessionId.length; i++)
      sessionId[i] = (byte) i;
    hello.setSessionId (sessionId);           // + 33
    hello.setCipherSuite (CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA); // + 2
    hello.setCompressionMethod (CompressionMethod.ZLIB); // + 1
    handshake.setLength(hello.length());
    handshake.bodyBuffer().put(hello.buffer());
    
    handshake = new Handshake (buffer);
    hello2 = (ServerHello) handshake.body();
    if (hello.extensions() == null)
      System.out.println ("PASS: hello.extensions() == null");
    else
      System.out.println ("FAIL: hello.extensions() != null");
    
    System.err.println (handshake);
  }
}
