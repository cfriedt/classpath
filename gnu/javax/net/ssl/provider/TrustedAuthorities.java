package gnu.javax.net.ssl.provider;

import gnu.java.security.x509.X500DistinguishedName;
import gnu.javax.net.ssl.provider.Extension.Value;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.ByteBuffer;
import java.util.Iterator;
import java.util.NoSuchElementException;

import javax.security.auth.x500.X500Principal;

/**
 * The trusted authorities hello extension.
 * 
 * <pre>
struct {
  TrustedAuthority trusted_authorities_list&lt;0..2^16-1&gt;;
} TrustedAuthorities;

struct {
  IdentifierType identifier_type;
  select (identifier_type) {
    case pre_agreed: struct {};
    case key_sha1_hash: SHA1Hash;
    case x509_name: DistinguishedName;
    case cert_sha1_hash: SHA1Hash;
  } identifier;
} TrustedAuthority;

enum {
  pre_agreed(0), key_sha1_hash(1), x509_name(2),
  cert_sha1_hash(3), (255)
} IdentifierType;

opaque DistinguishedName&lt;1..2^16-1&gt;;</pre>
 * 
 * @author csm
 */
public class TrustedAuthorities extends Value
  implements Iterable<TrustedAuthorities.TrustedAuthority>
{
  private final ByteBuffer buffer;

  public TrustedAuthorities(final ByteBuffer buffer)
  {
    this.buffer = buffer;
  }
  
  public int length()
  {
    return 2 + (buffer.getShort(0) & 0xFFFF);
  }
  
  public int size()
  {
    int len = buffer.getShort(0) & 0xFFFF;
    int n = 0;
    for (int i = 2; i < len; i++)
      {
        TrustedAuthority auth =
          new TrustedAuthority((ByteBuffer) buffer.duplicate().position(i));
        i += auth.length();
        n++;
      }
    return n;
  }

  public TrustedAuthority get(final int index)
  {
    int len = buffer.getShort(0) & 0xFFFF;
    int n = 0;
    int i = 2;
    while (i < len && n <= index)
      {
        TrustedAuthority auth =
          new TrustedAuthority((ByteBuffer) buffer.duplicate().position(i));
        if (n == index)
          return auth;
        i += auth.length();
        n++;
      }
    throw new IndexOutOfBoundsException();
  }
  
  public String toString()
  {
    return toString(null);
  }
  
  public String toString(String prefix)
  {
    StringWriter str = new StringWriter();
    PrintWriter out = new PrintWriter(str);
    if (prefix != null) out.print(prefix);
    out.println("struct {");
    String subprefix = "  ";
    if (prefix != null)
      subprefix = prefix + subprefix;
    for(TrustedAuthority ta : this)
      out.println(ta);
    if (prefix != null) out.print(prefix);
    out.print("} TrustedAuthorities;");
    return str.toString();
  }
  
  public Iterator<TrustedAuthority> iterator()
  {
    return new AuthoritiesIterator();
  }
  
  public class AuthoritiesIterator implements Iterator<TrustedAuthority>
  {
    private int index;
    
    public AuthoritiesIterator()
    {
      index = 0;
    }
    
    public TrustedAuthority next() throws NoSuchElementException
    {
      try
        {
          return get(index++);
        }
      catch (IndexOutOfBoundsException ioobe)
        {
          throw new NoSuchElementException();
        }
    }
    
    public boolean hasNext()
    {
      return index < size();
    }
    
    public void remove()
    {
      throw new UnsupportedOperationException();
    }
  }

  public static class TrustedAuthority implements Constructed
  {
    private final ByteBuffer buffer;
    
    public TrustedAuthority(final ByteBuffer buffer)
    {
      this.buffer = buffer;
    }
    
    public int length()
    {
      switch (type().getValue())
      {
        case 0: return 1;
        case 1:
        case 3: return 21;
        case 2: return 3 + (buffer.getShort(1) & 0xFFFF);
      }
      throw new IllegalArgumentException("unknown authority type");
    }
    
    public byte[] sha1Hash()
    {
      IdentifierType t = type();
      if (t != IdentifierType.CERT_SHA1_HASH
          && t != IdentifierType.KEY_SHA1_HASH)
        throw new IllegalArgumentException(t + " does not have a hash value");
      byte[] b = new byte[20];
      ((ByteBuffer) buffer.duplicate().position(1)).get(b);
      return b;
    }
    
    public X500Principal name()
    {
      int len = buffer.getShort(1) & 0xFFFF;
      byte[] b = new byte[len];
      ((ByteBuffer) buffer.duplicate().position(3)).get(b);
      return new X500Principal(b);
    }
    
    public IdentifierType type()
    {
      switch (buffer.get(0))
      {
        case 0: return IdentifierType.PRE_AGREED;
        case 1: return IdentifierType.KEY_SHA1_HASH;
        case 2: return IdentifierType.X509_NAME;
        case 3: return IdentifierType.CERT_SHA1_HASH;
      }
      
      throw new IllegalArgumentException("invalid IdentifierType");
    }
    
    public String toString()
    {
      return toString(null);
    }
    
    public String toString(String prefix)
    {
      StringWriter str = new StringWriter();
      PrintWriter out = new PrintWriter(str);
      if (prefix != null) out.print(prefix);
      out.println("struct {");
      if (prefix != null) out.print(prefix);
      out.print("  identifier_type = ");
      out.print(type());
      out.println(";");
      switch (type().getValue())
      {
        case 0: break;
        case 1:
        case 3:
          if (prefix != null) out.print(prefix);
          out.print("  sha1_hash = ");
          out.print(Util.toHexString(sha1Hash(), ':'));
          out.println(";");
          break;
          
        case 2:
          if (prefix != null) out.print(prefix);
          out.print("  name = ");
          out.print(name());
          out.println(";");
      }
      if (prefix != null) out.print(prefix);
      out.print("} TrustedAuthority;");
      return str.toString();
    }
  }
  
  public static enum IdentifierType
  {
    PRE_AGREED (0), KEY_SHA1_HASH (1), X509_NAME (2), CERT_SHA1_HASH (3);
    
    private final int value;
    
    private IdentifierType(final int value)
    {
      this.value = value;
    }
    
    public int getValue()
    {
      return value;
    }
  }
}
