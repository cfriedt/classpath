/* CertificateRequest.java -- SSL CertificateRequest message.
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


package gnu.javax.net.ssl.provider;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringWriter;

import java.lang.reflect.Constructor;
import java.lang.reflect.Method;

import java.nio.ByteBuffer;

import java.util.LinkedList;
import java.security.Principal;

/**
 * A request by the server for a client certificate.
 *
 * <pre>
struct
{
  ClientCertificateType certificate_types&lt;1..2^8-1&gt;;
  DistinguishedName certificate_authorities&lt;3..2^16-1&gt;;
} CertificateRequest;
</pre>
 */
final class CertificateRequest implements Handshake.Body
{

  // Fields.
  // -------------------------------------------------------------------------

  private final ByteBuffer buffer;

  // Constructor.
  // -------------------------------------------------------------------------

  CertificateRequest (final ByteBuffer buffer)
  {
    this.buffer = buffer;
  }

  // Instance methods.
  // -------------------------------------------------------------------------

  public int getLength ()
  {
    int o1 = (buffer.get (0) & 0xFF) + 1;
    return o1 + (buffer.getShort (o1) & 0xFFFF) + 2;
  }

  ClientCertificateTypeList getTypes ()
  {
    return new ClientCertificateTypeList (buffer.duplicate ());
  }

  X500PrincipalList getAuthorities ()
  {
    int offset = (buffer.get (0) & 0xFF) + 1;
    return new X500PrincipalList (((ByteBuffer) buffer.position (offset)).slice ());
  }

  public String toString()
  {
    return toString (null);
  }

  public String toString (final String prefix)
  {
    StringWriter str = new StringWriter();
    PrintWriter out = new PrintWriter(str);
    String subprefix = "  ";
    if (prefix != null) subprefix = prefix + "  ";
    if (prefix != null) out.print (prefix);
    out.println("struct {");
    if (prefix != null) out.print (prefix);
    out.println ("  types =");
    out.println (getTypes ().toString (subprefix));
    if (prefix != null) out.print (prefix);
    out.println("  authorities =");
    out.println (getAuthorities ().toString (subprefix));
    if (prefix != null) out.print (prefix);
    out.print ("} CertificateRequest;");
    return str.toString();
  }

  // Inner class.
  // -------------------------------------------------------------------------

  static final class ClientCertificateType implements Enumerated
  {

    // Constants and fields.
    // -----------------------------------------------------------------------

    private static final int RSA_SIGN_VALUE     = 1;
    private static final int DSS_SIGN_VALUE     = 2;
    private static final int RSA_FIXED_DH_VALUE = 3;
    private static final int DSS_FIXED_DH_VALUE = 4;

    static final ClientCertificateType RSA_SIGN     = new ClientCertificateType (RSA_SIGN_VALUE);
    static final ClientCertificateType DSS_SIGN     = new ClientCertificateType (DSS_SIGN_VALUE);
    static final ClientCertificateType RSA_FIXED_DH = new ClientCertificateType (RSA_FIXED_DH_VALUE);
    static final ClientCertificateType DSS_FIXED_DH = new ClientCertificateType (DSS_FIXED_DH_VALUE);

    private final int value;

    // Constructor.
    // -----------------------------------------------------------------------

    private ClientCertificateType (final int value)
    {
      this.value = value;
    }

    // Class method.
    // -----------------------------------------------------------------------

    static ClientCertificateType forValue (final int value)
    {
      switch (value)
        {
        case RSA_SIGN_VALUE:     return RSA_SIGN;
        case DSS_SIGN_VALUE:     return DSS_SIGN;
        case RSA_FIXED_DH_VALUE: return RSA_FIXED_DH;
        case DSS_FIXED_DH_VALUE: return DSS_FIXED_DH;
        }
      return new ClientCertificateType (value);
    }

    // Instance methods.
    // -----------------------------------------------------------------------

    public byte[] getEncoded()
    {
      return new byte[] { (byte) value };
    }

    public int getValue()
    {
      return value;
    }

    public String toString()
    {
      switch (value)
        {
        case RSA_SIGN_VALUE:     return "rsa_sign";
        case DSS_SIGN_VALUE:     return "dss_sign";
        case RSA_FIXED_DH_VALUE: return "rsa_fixed_dh";
        case DSS_FIXED_DH_VALUE: return "dss_fixed_dh";
        default: return "unknown(" + value + ")";
        }
    }
  }
}
