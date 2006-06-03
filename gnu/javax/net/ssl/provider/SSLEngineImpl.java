/* SSLEngineImpl.java -- implementation of SSLEngine.
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

import gnu.classpath.debug.Component;
import gnu.classpath.debug.SystemLogger;

import gnu.javax.net.ssl.Session;
import gnu.javax.net.ssl.SSLRecordHandler;

import java.nio.ByteBuffer;

import java.util.List;
import java.util.logging.Logger;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

abstract // XXX
class SSLEngineImpl extends SSLEngine
{
  private SSLRecordHandler[] handlers;
//  private SecurityParameters params;
  private static final Logger logger = SystemLogger.SYSTEM;
  private SessionImpl session;
  private InputSecurityParameters insec;
  private OutputSecurityParameters outsec;
  private boolean closed;

  /**
   * We can receive any message chunked across multiple records,
   * including alerts, even though all alert messages are only two
   * bytes long. Handshake messages are de-chunked in the handshake
   * handler, change-cipher-spec messages are always empty, and we
   * don't care about chunking of application messages.
   *
   * This buffer will hold the incomplete alert that we receive, if
   * any.
   */
  private final ByteBuffer alertBuffer;

  private int mode;
  private static final int MODE_NONE = 0, MODE_SERVER = 1, MODE_CLIENT = 2;

  SSLEngineImpl (SessionImpl session)
  {
    handlers = new SSLRecordHandler[256];
    insec = new InputSecurityParameters (null, null, null,
                                         CipherSuite.SSL_NULL_WITH_NULL_NULL);
    outsec = new OutputSecurityParameters (null, null, null,
                                           CipherSuite.SSL_NULL_WITH_NULL_NULL);
    alertBuffer = ByteBuffer.wrap (new byte[2]);
    this.session = session;
    mode = MODE_NONE;
  }

  public void registerHandler (final ContentType type,
                               SSLRecordHandler handler)
    throws SSLException
  {
    if (type.equals (ContentType.CHANGE_CIPHER_SPEC)
        || type.equals (ContentType.ALERT)
        || type.equals (ContentType.HANDSHAKE)
        || type.equals (ContentType.APPLICATION_DATA))
      throw new SSLException ("can't override handler for content type " + type);
    int i = type.getValue ();
    if (i < 0 || i > 255)
      throw new SSLException ("illegal content type: " + type);
    handlers[i] = handler;
  }

  public void beginHandshake ()
  {
    switch (mode)
      {
      case MODE_SERVER:
        break;
      case MODE_CLIENT:
        break;
      case MODE_NONE:
        throw new IllegalStateException ("setUseClientMode was never called");
      }
  }

  public boolean getUseClientMode ()
  {
    return (mode == MODE_CLIENT);
  }

  public void setUseClientMode (final boolean clientMode)
  {
    if (clientMode)
      mode = MODE_CLIENT;
    else
      mode = MODE_SERVER;
  }

  public SSLEngineResult unwrap (final ByteBuffer source,
                                 final ByteBuffer[] sinks,
                                 final int offset, final int length)
    throws SSLException
  {
    if (mode == MODE_NONE)
      throw new IllegalStateException ("setUseClientMode was never called");

    Record r = new Record (source.slice ());
    ContentType type = r.contentType ();

    // XXX: messages may be chunked across multiple records; does this
    // include the SSLv2 message? I don't think it does, but we should
    // make sure.
    if (!getUseClientMode () && type == ContentType.CLIENT_HELLO_V2)
      {
        if (!insec.cipherSuite ().equals (CipherSuite.SSL_NULL_WITH_NULL_NULL))
          throw new SSLException ("received SSLv2 client hello in encrypted session; this is invalid.");
        logger.log (Component.SSL_RECORD_LAYER, "converting SSLv2 client hello to version 3 hello");
        ClientHelloV2 v2 = new ClientHelloV2 (source.slice ());
        List suites = v2.cipherSpecs ();

        // For the length of the "fake" v3 hello we need:
        //   1   for the content type
        //   2   for the protocol version
        //   2   for the record length
        //   2   for the client version
        //  32   for the random value
        //  33   for the session ID
        //   2   for the cipher suites length
        // 2*n   for the n cipher suites
        //   2   for the singleton compression method list, with length
        int len = 76 + 2 * suites.size ();
        ByteBuffer buf = ByteBuffer.allocate (len);
        Record record = new Record (buf);
        record.setContentType (ContentType.HANDSHAKE);
        record.setVersion (v2.version ());
        record.setLength (len - 5);

        Handshake handshake = new Handshake (record.fragment ());
        handshake.setType (Handshake.Type.CLIENT_HELLO);
        handshake.setLength (len - 9);

        ClientHello hello = (ClientHello) handshake.body ();
        hello.setVersion (v2.version ());

        Random random = hello.random ();
        byte[] challenge = v2.challenge ();
        if (challenge.length < 32)
          {
            byte[] b = new byte[32];
            System.arraycopy(challenge, 0, b, b.length - challenge.length,
                             challenge.length);
            challenge = b;
          }
        random.setGmtUnixTime ((challenge[0] & 0xFF) << 24 | (challenge[1] & 0xFF) << 16
                               | (challenge[2] & 0xFF) <<  8 | (challenge[3] & 0xFF));
        random.setRandomBytes (challenge, 4);

        byte[] sessionId = v2.sessionId ();
        hello.setSessionId (sessionId, 0, sessionId.length);

        CipherSuiteList mySuites = hello.cipherSuites ();
        mySuites.setSize (2 * suites.size ());
        for (int i = 0; i < suites.size (); i++)
          mySuites.put (i, (CipherSuite) suites.get (i));

        CompressionMethodList comps = hello.compressionMethods ();
        comps.setSize (1);
        comps.put (0, CompressionMethod.NULL);

        r = record;
      }

    logger.log (Component.SSL_RECORD_LAYER, "read record {0}", r);
    ByteBuffer msg = ByteBuffer.allocate (r.length ());

    try
      {
        insec.decrypt (r, msg);
      }
    catch (Exception x) { /* XXX */ }

    SSLEngineResult result = null;
    if (type == ContentType.CHANGE_CIPHER_SPEC)
      {
        if (r.length () == 0)
          result = new SSLEngineResult (SSLEngineResult.Status.OK,
                                        SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                                        0, 0);
        else
          {
            byte b = r.fragment ().get ();
            if (b != 1)
              throw new SSLException ("unknown ChangeCipherSpec value: " + (b & 0xFF));
            InputSecurityParameters params = null; //handshake.inputSecurityParameters ();
            logger.log (Component.SSL_RECORD_LAYER,
                        "switching to input security parameters {0}",
                        params.cipherSuite ());
            insec = params;
            result = new SSLEngineResult (SSLEngineResult.Status.OK,
                                          SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                          0, 0); // XXXX
          }
      }
    else if (type == ContentType.ALERT)
      {
        ByteBuffer b = r.fragment ();
        int len = 0;
        if (alertBuffer.position () > 0)
          {
            alertBuffer.put (b.get ());
            len = 1;
          }
        len += b.remaining () / 2;
        Alert[] alerts = new Alert[len];
        int i = 0;
        if (alertBuffer.position () > 0)
          {
            alertBuffer.flip ();
            alerts[0] = new Alert (alertBuffer);
            i++;
          }
        while (i < alerts.length)
          {
            alerts[i++] = new Alert (b.duplicate ());
            b.position (b.position () + 2);
          }

        for (i = 0; i < alerts.length; i++)
          {
            if (alerts[i].level () == Alert.Level.FATAL)
              throw new AlertException (alerts[i]);
            logger.log (java.util.logging.Level.WARNING, "received alert: {0}", alerts[i]);
            if (alerts[i].description () == Alert.Description.CLOSE_NOTIFY)
              closed = true;
          }

        if (b.hasRemaining ())
          alertBuffer.position (0).limit (2);

        result = new SSLEngineResult (closed ? SSLEngineResult.Status.CLOSED
                                      : SSLEngineResult.Status.OK,
                                      SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                      r.length (), 0);
      }
    else if (type == ContentType.HANDSHAKE)
      {
      }
    else if (type == ContentType.APPLICATION_DATA)
      {
        int len = r.length ();
        int outlen = 0;
        for (int i = offset; i < length; i++)
          outlen += sinks[i].remaining ();
        if (len > outlen)
          return new SSLEngineResult (SSLEngineResult.Status.BUFFER_OVERFLOW,
                                      SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                      0, 0);

        ByteBuffer b = r.fragment ();
        int i = offset;
//        while (b.hasRemaining ())
      }
    else
      {
        SSLRecordHandler handler = handlers[type.getValue ()];
        if (handler != null)
          {
//            handler.handle (r.fragment ());
            result = new SSLEngineResult (SSLEngineResult.Status.OK,
                                          SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                          r.length (), 0);
          }
        else
          throw new SSLException ("unknown content type: " + type);
      }

    return result;
  }

  public SSLEngineResult wrap (ByteBuffer[] sources, int offset, int length,
                               ByteBuffer sink)
  {
    return null; // XXX
  }

  // Package-private methods.

  SessionImpl session ()
  {
    return session;
  }
}