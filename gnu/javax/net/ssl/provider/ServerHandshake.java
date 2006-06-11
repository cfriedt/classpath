/* ServerHandshake.java -- the server-side handshake.
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

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import java.util.HashSet;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;

class ServerHandshake extends AbstractHandshake
{
  // State masks.
  static final int READ_MASK = 1 << 8;
  static final int WRITE_MASK = 1 << 9;

  // State values.
  static final int WRITE_HELLO_REQUEST = WRITE_MASK | 1;
  static final int READ_CLIENT_HELLO = READ_MASK | 2;
  static final int WRITE_SERVER_HELLO = WRITE_MASK | 3;
  static final int DONE = -1;

  private int state;

  private final SSLEngineImpl engine;

  /* Handshake result fields. */
  private ProtocolVersion version;
  private CipherSuite suite;
  private CompressionMethod compression;
  private Random clientRandom;
  private Random serverRandom;

  ServerHandshake (boolean writeHelloRequest, final SSLEngineImpl engine)
  {
    if (writeHelloRequest)
      state = WRITE_HELLO_REQUEST;
    else
      state = READ_CLIENT_HELLO;
    this.engine = engine;
    handshakeOffset = 0;
  }

  private static boolean isWriteState (int state)
  {
    return (state & WRITE_MASK) == WRITE_MASK;
  }

  private static boolean isReadState (final int state)
  {
    return (state & READ_MASK) == READ_MASK;
  }

  /**
   * Choose the protocol version. Here we choose the largest protocol
   * version we support that is not greater than the client's
   * requested version.
   */
  private static ProtocolVersion chooseProtocol (final ProtocolVersion clientVersion,
                                                 final String[] enabledVersions)
    throws SSLException
  {
    ProtocolVersion version = null;
    for (int i = 0; i < enabledVersions.length; i++)
      {
        ProtocolVersion v = ProtocolVersion.forName (enabledVersions[i]);
        if (v.compareTo (clientVersion) <= 0)
          {
            if (version == null
                || v.compareTo (version) > 0)
              version = v;
          }
      }

    // The client requested a protocol version too old, or no protocol
    // versions are enabled.
    if (version == null)
      throw new SSLException ("no acceptable protocol version available");
    return version;
  }

  /**
   * Choose the first cipher suite in the client's requested list that
   * we have enabled.
   */
  private static CipherSuite chooseSuite (final CipherSuiteList clientSuites,
                                          final String[] enabledSuites,
                                          final ProtocolVersion version)
    throws SSLException
  {
    HashSet<CipherSuite> suites = new HashSet<CipherSuite> (enabledSuites.length);
    for (String s : enabledSuites)
      {
        CipherSuite suite = CipherSuite.forName (s);
        if (suite != null)
          {
            suite = suite.resolve (version);
            suites.add (suite);
          }
      }
    for (CipherSuite suite : clientSuites)
      {
        if (suites.contains (suite))
          return suite.resolve (version);
      }
    throw new AlertException (new Alert (Alert.Level.FATAL,
                                         Alert.Description.INSUFFICIENT_SECURITY));
  }

  /**
   * Choose a compression method that we support, among the client's
   * requested compression methods. We prefer ZLIB over NONE in this
   * implementation.
   *
   * XXX Maybe consider implementing lzo (GNUTLS supports that).
   * XXX Maybe add way to disable zlib support, through properties.
   */
  private static CompressionMethod chooseCompression (final CompressionMethodList comps)
    throws SSLException
  {
    // Scan for ZLIB first.
    for (CompressionMethod cm : comps)
      {
        if (cm.equals (CompressionMethod.ZLIB))
          return CompressionMethod.ZLIB;
      }
    for (CompressionMethod cm : comps)
      {
        if (cm.equals (CompressionMethod.NULL))
          return CompressionMethod.NULL;
      }

    throw new SSLException ("no supported compression method");
  }

  public SSLEngineResult handleInput (Record record) throws SSLException
  {
    if (state == DONE)
      return new SSLEngineResult (SSLEngineResult.Status.OK,
                                  SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING,
                                  0, 0);

    if (!isReadState (state) && isWriteState (state))
      return new SSLEngineResult (SSLEngineResult.Status.OK,
                                  SSLEngineResult.HandshakeStatus.NEED_WRAP,
                                  0, 0);

    // If we don't have a message already waiting...
    if (!hasMessage())
      {
        // Try to read another...
        if (!pollHandshake (record))
          {
            // If we have some more data, but not a full handshake
            // message, return, asking for more.
            return new SSLEngineResult (SSLEngineResult.Status.OK,
                                        SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                                        record.length () + 5, 0);
          }

        // Otherwise, we've got something to process.
      }

    SSLEngineResult.HandshakeStatus status = null;

    while (hasMessage ())
      {
        // Copy the current buffer, and prepare it for reading.
        ByteBuffer buffer = handshakeBuffer.duplicate ();
        buffer.flip ();
        buffer.position (handshakeOffset);
        Handshake handshake = new Handshake (buffer.slice ());

        switch (state)
          {
          case READ_CLIENT_HELLO:
            if (handshake.type () != Handshake.Type.CLIENT_HELLO)
              throw new SSLException ("expecting client hello");
            // FIXME: we need to ask the caller to call `wrap,' so we can
            // push an SSL error alert to the remote side. Then, we can
            // defer throwing the exception until then.

            {
              ClientHello hello = (ClientHello) handshake.body ();
              version = chooseProtocol (hello.version (),
                                        engine.getEnabledProtocols ());
              suite = chooseSuite (hello.cipherSuites (),
                                   engine.getEnabledCipherSuites (), version);
              compression = chooseCompression (hello.compressionMethods ());
              clientRandom = hello.random ().copy ();
              byte[] sessionId = hello.sessionId ();
              status = SSLEngineResult.HandshakeStatus.NEED_WRAP;
              state = WRITE_SERVER_HELLO;
            }
          }

        handshakeOffset += handshake.length ();
      }

    return new SSLEngineResult (SSLEngineResult.Status.OK, status,
                                record.length () + 5, 0);
  }

  public SSLEngineResult handleOutput (Record rec) throws SSLException
  {
    if (!isWriteState (state))
      {
        return new SSLEngineResult (SSLEngineResult.Status.OK,
                                    SSLEngineResult.HandshakeStatus.NEED_UNWRAP,
                                    0, 0);
      }
    ByteBuffer out = rec.fragment();
    int offset = out.position ();
    int pushed = 0;
    push_messages: while (true)
      {
        Record outRecord = new Record (((ByteBuffer) out.position (offset)).slice ());
        outRecord.setContentType (ContentType.HANDSHAKE);
        outRecord.setVersion (version);
        outRecord.setLength (out.remaining ());

        Handshake handshake = new Handshake (outRecord.fragment ());
        boolean pushed_message = false;

        try
          {
            switch (state)
              {
              case WRITE_SERVER_HELLO:
                {
                  handshake.setType (Handshake.Type.SERVER_HELLO);
                  ServerHello hello = (ServerHello) handshake.body ();
                  hello.setVersion (version);
                  hello.setCipherSuite (suite);
                  Random r = hello.random ();
                  r.setGmtUnixTime ((int) (System.currentTimeMillis () / 1000));
                  byte[] nonce = new byte[28];
                  engine.session ().random ().nextBytes (nonce);
                  r.setRandomBytes (nonce);
                  serverRandom = r.copy ();
                  
                }
              }
          }
        catch (BufferOverflowException bfe)
          {
            if (!pushed_message)
              {
                return new SSLEngineResult (SSLEngineResult.Status.BUFFER_OVERFLOW,
                                            SSLEngineResult.HandshakeStatus.NEED_WRAP,
                                            0, pushed);
              }
          }
      }
  }
}