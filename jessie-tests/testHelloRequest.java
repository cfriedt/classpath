

import gnu.javax.net.ssl.provider.Handshake;
import gnu.javax.net.ssl.provider.HelloRequest;

import java.nio.ByteBuffer;

class testHelloRequest
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
    ByteBuffer buffer = ByteBuffer.allocate (4);
    Handshake handshake = new Handshake (buffer);
    handshake.setType (Handshake.Type.HELLO_REQUEST);
    handshake.setLength (0);
    HelloRequest body = (HelloRequest) handshake.body ();

    System.out.println ("PASS: body");

    System.err.println (handshake);
  }
}
