/* Handshake.java -- SSL Handshake message.
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
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.InputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;

import java.nio.ByteBuffer;

import java.security.PublicKey;

import java.util.ArrayList;
import java.util.Collections;

import javax.net.ssl.SSLProtocolException;

/**
 * An SSL handshake message. SSL handshake messages have the following
 * form:
 *
 * <pre>
struct
{
  HandshakeType msg_type;
  uint24        length;
  select (msg_type)
  {
    case hello_request:       HelloRequest;
    case client_hello:        ClientHello;
    case server_hello:        ServerHello;
    case certificate:         Certificate;
    case server_key_exchange: ServerKeyExchange;
    case certificate_request: CertificateRequest;
    case server_hello_done:   ServerHelloDone;
    case certificate_verify:  CertificateVerify;
    case client_key_exchange: ClientKeyExchange;
    case finished:            Finished;
  } body;
};</pre>
 */
final class Handshake implements Constructed
{

  // Fields.
  // -------------------------------------------------------------------------

  private final ByteBuffer buffer;
  private final CipherSuite suite;

  // Constructors.
  // -------------------------------------------------------------------------

  Handshake (final ByteBuffer buffer)
  {
    this (buffer, null);
  }

  Handshake (final ByteBuffer buffer, final CipherSuite suite)
  {
    this.buffer = buffer;
    this.suite = suite;
  }

  // Instance methods.
  // -------------------------------------------------------------------------

  /**
   * Returns the handshake type.
   *
   * @return The handshake type.
   */
  Type getType()
  {
    return Type.forInteger (buffer.get (0) & 0xFF);
  }

  /**
   * Returns the message length.
   *
   * @return The message length.
   */
  public int getLength ()
  {
    // Length is a uint24.
    return buffer.getInt (0) & 0xFFFFFF;
  }

  /**
   * Returns the handshake message body. Depending on the handshake
   * type, some implementation of the Body interface is returned.
   *
   * @return The handshake body.
   */
  Body getBody()
  {
    int type = buffer.get (0) & 0xFF;
    ByteBuffer bodyBuffer = getBodyBuffer ();
    switch (type)
      {
      case Type.HELLO_REQUEST_VALUE:
        return new HelloRequest ();

      case Type.CLIENT_HELLO_VALUE:
        return new ClientHello (bodyBuffer);

      case Type.SERVER_HELLO_VALUE:
        return new ServerHello (bodyBuffer);

      case Type.CERTIFICATE_VALUE:
        return new Certificate (bodyBuffer, CertificateType.X509);

      case Type.SERVER_KEY_EXCHANGE_VALUE:
        return new ServerKeyExchange (bodyBuffer, suite);

      case Type.CERTIFICATE_REQUEST_VALUE:
        return new CertificateRequest (bodyBuffer);

      case Type.SERVER_HELLO_DONE_VALUE:
        return new ServerHelloDone ();

      case Type.CERTIFICATE_VERIFY_VALUE:
        return new CertificateVerify (bodyBuffer, suite.getSignatureAlgorithm ());

      case Type.CLIENT_KEY_EXCHANGE_VALUE:
        return new ClientKeyExchange (bodyBuffer, suite);

      case Type.FINISHED_VALUE:
        return new Finished (bodyBuffer, suite.getVersion ());

      case Type.CERTIFICATE_URL_VALUE:
      case Type.CERTIFICATE_STATUS_VALUE:
        throw new UnsupportedOperationException ("FIXME");
      }
    throw new IllegalArgumentException ("unknown handshake type " + type);
  }

  /**
   * Returns a subsequence of the underlying buffer, containing only
   * the bytes that compose the handshake body.
   *
   * @return The body's byte buffer.
   */
  ByteBuffer getBodyBuffer ()
  {
    int length = getLength ();
    return ((ByteBuffer) buffer.position (4).limit (4 + length)).slice ();
  }

  /**
   * Sets the handshake body type.
   *
   * @param type The handshake type.
   */
  void setType (final Type type)
  {
    buffer.put (0, (byte) type.getValue ());
  }

  /**
   * Sets the length of the handshake body.
   *
   * @param length The handshake body length.
   * @throws java.nio.ReadOnlyBufferException If the underlying buffer
   * is not writable.
   * @throws IllegalArgumentException of <code>length</code> is not
   * between 0 and 16777215, inclusive.
   */
  void setLength (final int length)
  {
    if (length < 0 || length > 0xFFFFFF)
      throw new IllegalArgumentException ("length " + length + " out of range;"
                                          + " must be between 0 and 16777215");
    buffer.put (1, (byte) (length >>> 16));
    buffer.put (2, (byte) (length >>>  8));
    buffer.put (3, (byte)  length);
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
    out.print ("  type: ");
    out.print (getType ());
    out.println (";");
    Body body = getBody ();
    out.println (body.toString (prefix != null ? (prefix + "  ") : "  "));
    if (prefix != null) out.print (prefix);
    out.print ("} Handshake;");
    return str.toString();
  }

  // Inner class.
  // -------------------------------------------------------------------------

  static interface Body extends Constructed
  {
    int getLength ();

    String toString (String prefix);
  }

  static class Type implements Enumerated
  {

    // Constants and fields.
    // -----------------------------------------------------------------------

    private static final int
      HELLO_REQUEST_VALUE       =  0,
      CLIENT_HELLO_VALUE        =  1,
      SERVER_HELLO_VALUE        =  2,
      CERTIFICATE_VALUE         = 11,
      SERVER_KEY_EXCHANGE_VALUE = 12,
      CERTIFICATE_REQUEST_VALUE = 13,
      SERVER_HELLO_DONE_VALUE   = 14,
      CERTIFICATE_VERIFY_VALUE  = 15,
      CLIENT_KEY_EXCHANGE_VALUE = 16,
      FINISHED_VALUE            = 20,
      CERTIFICATE_URL_VALUE     = 21,
      CERTIFICATE_STATUS_VALUE  = 22;

    static final Type
      HELLO_REQUEST       = new Type (HELLO_REQUEST_VALUE),
      CLIENT_HELLO        = new Type (CLIENT_HELLO_VALUE),
      SERVER_HELLO        = new Type (SERVER_HELLO_VALUE),
      CERTIFICATE         = new Type (CERTIFICATE_VALUE),
      SERVER_KEY_EXCHANGE = new Type (SERVER_KEY_EXCHANGE_VALUE),
      CERTIFICATE_REQUEST = new Type (CERTIFICATE_REQUEST_VALUE),
      SERVER_HELLO_DONE   = new Type (SERVER_HELLO_DONE_VALUE),
      CERTIFICATE_VERIFY  = new Type (CERTIFICATE_VERIFY_VALUE),
      CLIENT_KEY_EXCHANGE = new Type (CLIENT_KEY_EXCHANGE_VALUE),
      FINISHED            = new Type (FINISHED_VALUE),
      CERTIFICATE_URL     = new Type (CERTIFICATE_URL_VALUE),
      CERTIFICATE_STATUS  = new Type (CERTIFICATE_STATUS_VALUE);

    private final int value;

    // Constructor.
    // -----------------------------------------------------------------------

    private Type(int value)
    {
      this.value = value;
    }

    // Class methods.
    // -----------------------------------------------------------------------

    static Type forInteger (final int value)
    {
      switch (value & 0xFF)
        {
        case HELLO_REQUEST_VALUE:       return HELLO_REQUEST;
        case CLIENT_HELLO_VALUE:        return CLIENT_HELLO;
        case SERVER_HELLO_VALUE:        return SERVER_HELLO;
        case CERTIFICATE_VALUE:         return CERTIFICATE;
        case SERVER_KEY_EXCHANGE_VALUE: return SERVER_KEY_EXCHANGE;
        case CERTIFICATE_REQUEST_VALUE: return CERTIFICATE_REQUEST;
        case SERVER_HELLO_DONE_VALUE:   return SERVER_HELLO_DONE;
        case CERTIFICATE_VERIFY_VALUE:  return CERTIFICATE_VERIFY;
        case CLIENT_KEY_EXCHANGE_VALUE: return CLIENT_KEY_EXCHANGE;
        case FINISHED_VALUE:            return FINISHED;
        case CERTIFICATE_URL_VALUE:     return CERTIFICATE_URL;
        case CERTIFICATE_STATUS_VALUE:  return CERTIFICATE_STATUS;
        default: throw new IllegalArgumentException ("unsupported value type " + value);
        }
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

    public boolean equals (Object o)
    {
      if (!(o instanceof Type))
        return false;
      return ((Type) o).value == value;
    }

    public int hashCode ()
    {
      return value;
    }

    public String toString()
    {
      switch (value)
        {
        case HELLO_REQUEST_VALUE:       return "hello_request";
        case CLIENT_HELLO_VALUE:        return "client_hello";
        case SERVER_HELLO_VALUE:        return "server_hello";
        case CERTIFICATE_VALUE:         return "certificate";
        case SERVER_KEY_EXCHANGE_VALUE: return "server_key_exchange";
        case CERTIFICATE_REQUEST_VALUE: return "certificate_request";
        case SERVER_HELLO_DONE_VALUE:   return "server_hello_done";
        case CERTIFICATE_VERIFY_VALUE:  return "certificate_verify";
        case CLIENT_KEY_EXCHANGE_VALUE: return "client_key_exchange";
        case FINISHED_VALUE:            return "finished";
        case CERTIFICATE_URL_VALUE:     return "certificate_url";
        case CERTIFICATE_STATUS_VALUE:  return "certificate_status";
        default: return "unknown(" + value + ")";
        }
    }
  }
}
