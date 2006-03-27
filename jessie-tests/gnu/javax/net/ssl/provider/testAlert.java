

package gnu.javax.net.ssl.provider;

import java.nio.ByteBuffer;

class testAlert
{
  public static void main (String[] argv)
  {
    Alert a1 = new Alert (ByteBuffer.allocate (2));
    try
      {
        a1.setLevel (Alert.Level.WARNING);
        System.out.println ("PASS: setLevel()");
        a1.setDescription (Alert.Description.UNEXPECTED_MESSAGE);
        System.out.println ("PASS: setDescription()");
      }
    catch (Throwable t)
      {
        System.out.println ("FAIL: " + t);
        t.printStackTrace ();
        System.exit (1);
      }

    Alert a2 = new Alert (ByteBuffer.allocate (2));
    try
      {
        a2.setLevel (Alert.Level.WARNING);
        System.out.println ("PASS: setLevel()");
        a2.setDescription (Alert.Description.UNEXPECTED_MESSAGE);
        System.out.println ("PASS: setDescription()");
      }
    catch (Throwable t)
      {
        System.out.println ("FAIL: " + t);
        t.printStackTrace ();
        System.exit (1);
      }

    if (a1.equals (a2))
      System.out.println ("PASS: equals()");
    else
      System.out.println ("FAIL: equals()");

    System.err.println (a1);
  }
}
