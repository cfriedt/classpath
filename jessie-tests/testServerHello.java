
import gnu.javax.net.ssl.provider.CipherSuite;
import gnu.javax.net.ssl.provider.CompressionMethod;
import gnu.javax.net.ssl.provider.Handshake;
import gnu.javax.net.ssl.provider.ProtocolVersion;
import gnu.javax.net.ssl.provider.Random;
import gnu.javax.net.ssl.provider.ServerHello;

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

    ServerHello hello = (ServerHello) handshake.body ();

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
    hello.setExtensionsLength (0);

    handshake.setLength (hello.length ());
    System.err.println (handshake);

    handshake = new Handshake (buffer);
    hello = (ServerHello) handshake.body ();
    if (Arrays.equals (sessionId, hello.sessionId ()))
      System.out.println ("PASS: sessionId");
    else
      System.out.println ("FAIL: sessionId");

    if (hello.cipherSuite () == CipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA)
      System.out.println ("PASS: cipherSuite");
    else
      System.out.println ("FAIL: cipherSuite");

    if (hello.compressionMethod () == CompressionMethod.ZLIB)
      System.out.println ("PASS: compressionMethod");
    else
      System.out.println ("FAIL: compressionMethod");
  }
}
