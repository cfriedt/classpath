/* ServerKeyExchange.java -- SSL ServerKeyExchange message.
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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;

import java.math.BigInteger;

import java.nio.ByteBuffer;

import javax.net.ssl.SSLProtocolException;

/**
 * The server key exchange message.
 *
 * <pre>
struct
{
  select (KeyExchangeAlgorithm)
  {
    case diffie_hellman:
      ServerDHParams params;
      Signature signed_params;
    case rsa:
      ServerRSAParams params;
      Signature signed_params;
    case srp:
      ServerSRPParams params;
      Signature signed_params;
  };
} ServerKeyExchange;
</pre>
 */
public class ServerKeyExchange implements Handshake.Body
{

  private final ByteBuffer buffer;
  private final CipherSuite suite;

  public ServerKeyExchange (final ByteBuffer buffer, final CipherSuite suite)
  {
    suite.getClass ();
    this.buffer = buffer;
    this.suite = suite;
    if (!suite.isResolved ())
      throw new IllegalArgumentException ("requires resolved cipher suite");
  }

  public int length ()
  {
    if (suite.keyExchangeAlgorithm ().equals (KeyExchangeAlgorithm.NONE))
      return 0;
    return params ().length () + signature ().length ();
  }

  /**
   * Returns the server's key exchange parameters. The value returned will
   * depend on the key exchange algorithm this object was created with.
   *
   * @return The server's key exchange parameters.
   */
  public ServerKeyExchangeParams params ()
  {
    KeyExchangeAlgorithm kex = suite.keyExchangeAlgorithm ();
    if (kex.equals (KeyExchangeAlgorithm.RSA))
      return new ServerRSAParams (buffer.duplicate ());
    else if (kex.equals (KeyExchangeAlgorithm.DIFFIE_HELLMAN))
      return new ServerDHParams (buffer.duplicate ());
//     else if (kex.equals (KeyExchangeAlgorithm.SRP))
//       return new ServerSRPParams (buffer.duplicate ());
    else if (kex.equals (KeyExchangeAlgorithm.NONE))
      return null;
    throw new IllegalArgumentException ("unsupported key exchange: " + kex);
  }

  /**
   * Returns the digital signature made over the key exchange parameters.
   *
   * @return The signature.
   */
  public Signature signature ()
  {
    if (suite.keyExchangeAlgorithm ().equals (KeyExchangeAlgorithm.NONE))
      return null;
    ServerKeyExchangeParams params = params ();
    ByteBuffer sigbuf = ((ByteBuffer) buffer.position (params.length ())).slice ();
    return new Signature (sigbuf, suite.signatureAlgorithm ());
  }

  public String toString()
  {
    return toString (null);
  }

  public String toString (final String prefix)
  {
    StringWriter str = new StringWriter();
    PrintWriter out = new PrintWriter(str);
    if (prefix != null) out.print (prefix);
    out.println("struct {");
    if (prefix != null) out.print (prefix);
    out.print ("  algorithm: ");
    out.print (suite.keyExchangeAlgorithm ());
    out.println (";");
    if (!suite.keyExchangeAlgorithm ().equals (KeyExchangeAlgorithm.NONE))
      {
        if (prefix != null) out.print (prefix);
        out.println ("  parameters:");
        out.println (params ().toString (prefix != null ? prefix+"  " : "  "));
      }
    if (!suite.signatureAlgorithm ().equals (SignatureAlgorithm.ANONYMOUS))
      {
        if (prefix != null) out.print (prefix);
        out.println ("  signature:");
        out.println (signature ().toString (prefix != null ? prefix+"  " : "  "));
      }
    if (prefix != null) out.print (prefix);
    out.print ("} ServerKeyExchange;");
    return str.toString();
  }
}
