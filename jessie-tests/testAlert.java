

import gnu.javax.net.ssl.provider.Alert;
import java.nio.ByteBuffer;

class testAlert
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
    Alert a1 = new Alert (ByteBuffer.allocate (2));
   
    a1.setLevel (Alert.Level.WARNING);
    System.out.println ("PASS: setLevel()");
    a1.setDescription (Alert.Description.UNEXPECTED_MESSAGE);
    System.out.println ("PASS: setDescription()");

    Alert a2 = new Alert (ByteBuffer.allocate (2));

    a2.setLevel (Alert.Level.WARNING);
    System.out.println ("PASS: setLevel()");
    a2.setDescription (Alert.Description.UNEXPECTED_MESSAGE);
    System.out.println ("PASS: setDescription()");

    if (a1.equals (a2))
      System.out.println ("PASS: equals()");
    else
      System.out.println ("FAIL: equals()");

    if (a1.level () == Alert.Level.WARNING)
      System.out.println ("PASS: level");
    else
      System.out.println ("FAIL: level");

    if (a1.description () == Alert.Description.UNEXPECTED_MESSAGE)
      System.out.println ("PASS: description");
    else
      System.out.println ("FAIL: description");

    System.err.println (a1);
  }
}
