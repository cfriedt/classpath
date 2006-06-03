/* SessionImpl.java -- concrete definition of SSLSession.
   Copyright (C) 2006  Free Software Foundation, Inc.

This file is a part of GNU Classpath.

GNU Classpath is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or (at
your option) any later version.

GNU Classpath is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU Classpath; if not, write to the Free Software
Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
USA

Linking this library statically or dynamically with other modules is
making a combined work based on this library.  Thus, the terms and
conditions of the GNU General Public License cover the whole
combination.

As a special exception, the copyright holders of this library give you
permission to link this library with independent modules to produce an
executable, regardless of the license terms of these independent
modules, and to copy and distribute the resulting executable under
terms of your choice, provided that you also meet, for each linked
independent module, the terms and conditions of the license of that
module.  An independent module is a module which is not derived from
or based on this library.  If you modify this library, you may extend
this exception to your version of the library, but you are not
obligated to do so.  If you do not wish to do so, delete this
exception statement from your version.  */


package gnu.javax.net.ssl;

import java.io.Serializable;

import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.Certificate;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;

import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.cert.X509Certificate;

/**
 * A concrete implementation of the {@link SSLSession} interface. This
 * class is provided to allow pluggable {@link SessionStore}
 * implementations.
 */
public abstract class Session implements SSLSession, Serializable
{
  protected final long creationTime;
  protected long lastAccessedTime;
  protected int applicationBufferSize;
  protected ID sessionId;
  protected Certificate[] localCerts;
  protected Certificate[] peerCerts;
  protected X509Certificate[] peerCertChain;
  protected String peerHost;
  protected int peerPort;
  protected boolean peerVerified;
  protected HashMap values;
  protected boolean valid;
  protected SecureRandom random;

  protected Session ()
  {
    creationTime = System.currentTimeMillis ();
    values = new HashMap ();
  }

  public void access ()
  {
    lastAccessedTime = System.currentTimeMillis ();
  }

  public int getApplicationBufferSize ()
  {
    return applicationBufferSize;
  }

  public String getCipherSuite ()
  {
    return null;
  }

  public long getCreationTime ()
  {
    return creationTime;
  }

  public byte[] getId ()
  {
    return sessionId.id ();
  }

  public ID id ()
  {
    return sessionId;
  }

  public long getLastAccessedTime ()
  {
    return lastAccessedTime;
  }

  public Certificate[] getLocalCertificates ()
  {
    if (localCerts == null)
      return null;
    return (Certificate[]) localCerts.clone ();
  }

  public Certificate[] getPeerCertificates () throws SSLPeerUnverifiedException
  {
    if (!peerVerified)
      throw new SSLPeerUnverifiedException ("peer not verified");
    if (peerCerts == null)
      return null;
    return (Certificate[]) peerCerts.clone ();
  }

  public X509Certificate[] getPeerCertificateChain () throws SSLPeerUnverifiedException
  {
    if (!peerVerified)
      throw new SSLPeerUnverifiedException ("peer not verified");
    if (peerCertChain == null)
      return null;
    return (X509Certificate[]) peerCertChain.clone ();
  }
  
  public String getPeerHost ()
  {
    return peerHost;
  }
  
  public int getPeerPort ()
  {
    return peerPort;
  }

  public Principal getPeerPrincipal () throws SSLPeerUnverifiedException
  {
    return null;
  }
  
  public String[] getValueNames ()
  {
    HashMap values = this.values;
    String[] s = new String[values.size ()];
    int i = 0;
    for (Iterator it = values.keySet ().iterator (); it.hasNext () && i < s.length; )
      s[i++] = (String) it.next ();
    return s;
  }
  
  public Object getValue (String name)
  {
    return values.get (name);
  }
  
  public void invalidate ()
  {
    valid = false;
  }
  
  public boolean isValid ()
  {
    return valid;
  }
  
  public void putValue (String name, Object value)
  {
    values.put (name, value);
  }
  
  public void removeValue (String name)
  {
    values.remove (name);
  }

  public abstract void prepare (char[] password);

  // Inner classes.
  // -------------------------------------------------------------------------

  /**
   * An SSL or TLS session ID.
   */
  public static final class ID implements Comparable, Serializable
  {

    // Fields.
    // -----------------------------------------------------------------------

    /** The ID itself. */
    private final byte[] id;

    // Constructor.
    // -----------------------------------------------------------------------

    /**
     * Creates a new ID.
     *
     * @param id The ID. The array is cloned.
     */
    public ID (final byte[] id)
    {
      if (id.length > 32)
        throw new IllegalArgumentException ("session ID's are limited to 32 bytes");
      this.id = (byte[]) id.clone();
    }

    // Instance methods.
    // -----------------------------------------------------------------------

    public byte[] id()
    {
      return (byte[]) id.clone();
    }

    public boolean equals(Object other)
    {
      if (!(other instanceof ID))
        return false;
      return Arrays.equals(id, ((ID) other).id);
    }

    public int hashCode()
    {
      int code = 0;
      for (int i = 0; i < id.length; i++)
        code |= (id[i] & 0xFF) << ((i & 3) << 3);
      return code;
    }

    public int compareTo(Object other)
    {
      byte[] id2 = ((ID) other).id;
      if (id.length != id2.length)
        return (id.length < id2.length) ? -1 : 1;
      for (int i = 0; i < id.length; i++)
        {
          if ((id[i] & 0xFF) < (id2[i] & 0xFF))
            return -1;
          if ((id[i] & 0xFF) > (id2[i] & 0xFF))
            return 1;
        }
      return 0;
    }

    public String toString()
    {
      StringBuffer str = new StringBuffer (3 * id.length + 1);
      for (int i = 0; i < id.length; i++)
        {
          int x = id[i] & 0xFF;
          str.append (Character.forDigit ((x >>> 4) & 0xF, 16));
          str.append (Character.forDigit (x & 0xF, 16));
          if (i != id.length - 1)
            str.append (':');
        }
      return str.toString ();
    }
  }
}