

import gnu.javax.net.ssl.provider.CipherSuite;
import gnu.javax.net.ssl.provider.CipherSuiteList;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.ByteBuffer;

class testCipherSuiteList
{
  public static void main (String[] argv) throws Exception
  {
    final int n = 8;
    ByteBuffer buffer = ByteBuffer.allocate (n * 2 + 2);
    CipherSuiteList list = new CipherSuiteList (buffer);

    list.setSize (n);
    Field[] f = CipherSuite.class.getDeclaredFields ();
    for (int i = 0, j = 0; i < f.length && j < n; i++)
      {
        if (CipherSuite.class.equals (f[i].getType ())
            && Modifier.isStatic (f[i].getModifiers ()))
          list.put (j++, (CipherSuite) f[i].get (null));
      }

    System.err.println (list);

    CipherSuiteList list2 = new CipherSuiteList (buffer);

    if (list2.equals (list))
      System.out.println ("PASS: equals()");
    else
      System.out.println ("FAIL: equals()");
  }
}
