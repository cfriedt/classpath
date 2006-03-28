/* ClientKeyExchange.java -- SSL ClientKeyExchange message.
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
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;

import java.math.BigInteger;

import java.nio.ByteBuffer;

import java.security.PublicKey;
import java.security.interfaces.RSAKey;
import javax.crypto.interfaces.DHPublicKey;

/**
 * The client key exchange message.
 *
 * <pre>
struct {
  select (KeyExchangeAlgorithm) {
    case rsa: EncryptedPreMasterSecret;
    case diffie_hellman: ClientDiffieHellmanPublic;
  } exchange_keys;
} ClientKeyExchange;</pre>
 */
final class ClientKeyExchange implements Handshake.Body
{

  // Fields.
  // -------------------------------------------------------------------------

  private final ByteBuffer buffer;
  private final CipherSuite suite;

  // Constructors.
  // -------------------------------------------------------------------------

  ClientKeyExchange (final ByteBuffer buffer, final CipherSuite suite)
  {
    buffer.getClass ();
    suite.getClass ();
    this.buffer = buffer;
    this.suite = suite;
  }

  // Instance methods.
  // -------------------------------------------------------------------------

  ExchangeKeys exchangeKeys ()
  {
    KeyExchangeAlgorithm alg = suite.keyExchangeAlgorithm ();
    if (alg == KeyExchangeAlgorithm.RSA)
      return new EncryptedPreMasterSecret (buffer, suite.version ());
    else if (alg == KeyExchangeAlgorithm.DIFFIE_HELLMAN)
      return new ClientDiffieHellmanPublic (buffer);
    throw new IllegalArgumentException ("unsupported key exchange");
  }

  public int length ()
  {
    return exchangeKeys ().length ();
  }

  public String toString ()
  {
    return toString (null);
  }

  public String toString (final String prefix)
  {
    StringWriter str = new StringWriter();
    PrintWriter out = new PrintWriter(str);
    if (prefix != null)
      out.print (prefix);
    out.println("struct {");
    String subprefix = "  ";
    if (prefix != null)
      subprefix = prefix + subprefix;
    out.println (exchangeKeys ().toString (subprefix));
    if (prefix != null)
      out.print (prefix);
    out.println("} ClientKeyExchange;");
    return str.toString();
  }
}
