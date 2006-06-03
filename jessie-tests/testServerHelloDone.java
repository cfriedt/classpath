import gnu.javax.net.ssl.provider.Handshake;
import gnu.javax.net.ssl.provider.ServerHelloDone;

import java.nio.ByteBuffer;

class testServerHelloDone
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
    handshake.setType (Handshake.Type.SERVER_HELLO_DONE);
    handshake.setLength (0);
    
    // Should not throw ClassCastException
    ServerHelloDone done = (ServerHelloDone) handshake.body ();
    
    System.out.println ("PASS: body()");
    
    System.err.println (handshake);
  }
}