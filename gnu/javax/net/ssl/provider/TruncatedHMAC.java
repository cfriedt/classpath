package gnu.javax.net.ssl.provider;

import gnu.javax.net.ssl.provider.Extension.Value;

/**
 * The value type for the {@link Extension.Type#TRUNCATED_HMAC} extension.
 * This extension has an empty value; this class is thusly empty.
 * 
 * @author csm
 */
public class TruncatedHMAC extends Value
{

  public int length()
  {
    return 0;
  }
  
  public String toString()
  {
    return toString(null);
  }

  public String toString(String prefix)
  {
    String s = "TruncatedHMAC;";
    if (prefix != null)
      s = prefix + s;
    return s;
  }
}
