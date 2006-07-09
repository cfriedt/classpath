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

import static gnu.javax.net.ssl.provider.Extension.Type.*;
import static gnu.javax.net.ssl.provider.KeyExchangeAlgorithm.*;
import static gnu.javax.net.ssl.provider.ServerHandshake.State.*;
import static gnu.javax.net.ssl.provider.SignatureAlgorithm.*;
import static gnu.javax.net.ssl.provider.Handshake.Type.*;

import gnu.classpath.Configuration;
import gnu.classpath.debug.Component;
import gnu.java.security.action.GetSecurityPropertyAction;
import gnu.javax.crypto.key.dh.GnuDHPublicKey;
import gnu.javax.net.ssl.AbstractSessionContext;
import gnu.javax.net.ssl.Session;
import gnu.javax.net.ssl.Session.ID;
import gnu.javax.net.ssl.provider.CertificateRequest.ClientCertificateType;
import gnu.javax.net.ssl.provider.ServerNameList.ServerName;

import java.nio.BufferOverflowException;
import java.nio.ByteBuffer;

import java.security.AccessController;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.logging.Level;
import java.util.zip.Deflater;
import java.util.zip.Inflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSessionContext;
import javax.net.ssl.X509ExtendedKeyManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.SSLEngineResult.HandshakeStatus;
import javax.security.auth.x500.X500Principal;

class ServerHandshake extends AbstractHandshake
{  
  /**
   * Handshake state enumeration.
   */
  static enum State
  {
    WRITE_HELLO_REQUEST (true, false),
    WRITE_SERVER_HELLO (true, false),
    WRITE_CERTIFICATE (true, false),
    WRITE_SERVER_KEY_EXCHANGE (true, false),
    WRITE_CERTIFICATE_REQUEST (true, false),
    WRITE_SERVER_HELLO_DONE (true, false),
    WRITE_FINISHED (true, false),
    READ_CLIENT_HELLO (false, true),
    READ_CERTIFICATE (false, true),
    READ_CLIENT_KEY_EXCHANGE (false, true),
    READ_CERTIFICATE_VERIFY (false, true),
    READ_FINISHED (false, true),
    DONE (false, false);
    
    private final boolean isWriteState;
    private final boolean isReadState;
    
    private State(final boolean isWriteState, final boolean isReadState)
    {
      this.isWriteState = isWriteState;
      this.isReadState = isReadState;
    }
    
    boolean isReadState()
    {
      return isReadState;
    }
    
    boolean isWriteState()
    {
      return isWriteState;
    }
  }

  private State state;

  private final SSLEngineImpl engine;

  /* Handshake result fields. */
  private CompressionMethod compression;
  private Random clientRandom;
  private Random serverRandom;
  private ByteBuffer outBuffer;
  private boolean clientHadExtensions = false;
  private boolean continuedSession = false;
  private ServerNameList requestedNames = null;
  private String keyAlias = null;
  private X509Certificate clientCert = null;
  private X509Certificate localCert = null;
  private boolean helloV2 = false;
  
  /**
   * We remember this to ensure that we use a different one if the client's
   * session ID happens to be the same as our random one (this is possible,
   * if the random we're initialized with is predictable).
   */
  private Session.ID clientSessionID;

  private InputSecurityParameters inParams;
  private OutputSecurityParameters outParams;
  
  private KeyAgreement keyAgreement;
  private KeyPair dhPair;

  ServerHandshake (boolean writeHelloRequest, final SSLEngineImpl engine)
    throws NoSuchAlgorithmException
  {
    if (writeHelloRequest)
      state = WRITE_HELLO_REQUEST;
    else
      state = READ_CLIENT_HELLO;
    this.engine = engine;
    handshakeOffset = 0;
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
  private CipherSuite chooseSuite (final CipherSuiteList clientSuites,
                                   final String[] enabledSuites,
                                   final ProtocolVersion version)
    throws SSLException
  {
    // Figure out which SignatureAlgorithms we can support.
    HashSet<SignatureAlgorithm> sigs = new HashSet<SignatureAlgorithm>(2);
    X509ExtendedKeyManager km = engine.contextImpl.keyManager;
    if (km.getServerAliases(SignatureAlgorithm.DSA.name(), null).length != 0)
      sigs.add(SignatureAlgorithm.DSA);
    if (km.getServerAliases(SignatureAlgorithm.RSA.name(), null).length != 0)
      sigs.add(SignatureAlgorithm.RSA);
    
    if (Debug.DEBUG)
      logger.logv(Component.SSL_HANDSHAKE, "we have certs for signature algorithms {0}", sigs);
    
    HashSet<CipherSuite> suites = new HashSet<CipherSuite>(enabledSuites.length);
    for (String s : enabledSuites)
      {
        CipherSuite suite = CipherSuite.forName(s);
        if (suite != null && sigs.contains(suite.signatureAlgorithm()))
          suites.add (suite);
      }
    for (CipherSuite suite : clientSuites)
      {
        if (suites.contains (suite))
          return suite.resolve();
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
    GetSecurityPropertyAction gspa
      = new GetSecurityPropertyAction("jessie.enable.compression");
    String enable = AccessController.doPrivileged(gspa);
    // Scan for ZLIB first.
    if (Boolean.valueOf(enable))
      {
        for (CompressionMethod cm : comps)
          {
            if (cm.equals (CompressionMethod.ZLIB))
              return CompressionMethod.ZLIB;
          }
      }
    for (CompressionMethod cm : comps)
      {
        if (cm.equals (CompressionMethod.NULL))
          return CompressionMethod.NULL;
      }

    throw new SSLException ("no supported compression method");
  }
  
  protected @Override boolean doHash()
  {
    boolean b = helloV2;
    helloV2 = false;
    return (state != WRITE_HELLO_REQUEST) && !b;
  }

  public @Override HandshakeStatus implHandleInput()
    throws SSLException
  {    
    if (state == DONE)
      return HandshakeStatus.FINISHED;

    if (state.isWriteState()
        || (outBuffer != null && outBuffer.hasRemaining()))
      return HandshakeStatus.NEED_WRAP;

    // Copy the current buffer, and prepare it for reading.
    ByteBuffer buffer = handshakeBuffer.duplicate ();
    buffer.flip();
    buffer.position(handshakeOffset);
    Handshake handshake = new Handshake(buffer.slice(),
                                        engine.session().suite,
                                        engine.session().version);
        
    if (Debug.DEBUG)
      logger.logv(Component.SSL_HANDSHAKE, "processing in state {0}:\n{1}",
                  state, handshake);

    switch (state)
      {
        // Client Hello.
        //
        // This message is sent by the client to initiate a new handshake.
        // On a new connection, it is the first handshake message sent.
        //
        // The state of the handshake, after this message is processed,
        // will have a protocol version, cipher suite, compression method,
        // session ID, and various extensions (that the server also
        // supports).
        case READ_CLIENT_HELLO:
          if (handshake.type () != CLIENT_HELLO)
            throw new SSLException ("expecting client hello");
          // XXX throw better exception.

          {
            ClientHello hello = (ClientHello) handshake.body ();
            engine.session().version
              = chooseProtocol (hello.version (),
                                engine.getEnabledProtocols ());
            engine.session().suite =
              chooseSuite (hello.cipherSuites (),
                           engine.getEnabledCipherSuites (),
                           engine.session().version);
            compression = chooseCompression (hello.compressionMethods ());
            if (Debug.DEBUG)
              logger.logv(Component.SSL_HANDSHAKE,
                          "chose version:{0} suite:{1} compression:{2}",
                          engine.session().version, engine.session().suite,
                          compression);
            clientRandom = hello.random().copy();
            byte[] sessionId = hello.sessionId();
            if (hello.hasExtensions())
              {
                ExtensionList exts = hello.extensions();
                clientHadExtensions = exts.size() > 0;
                for (Extension e : hello.extensions())
                  {
                    Extension.Type type = e.type();
                    if (type == null)
                      continue;
                    switch (type)
                    {
                    case TRUNCATED_HMAC:
                      engine.session().setTruncatedMac(true);
                      break;

                    case MAX_FRAGMENT_LENGTH:
                      MaxFragmentLength len = (MaxFragmentLength) e.value();
                      engine.session().maxLength = len;
                      engine.session().setApplicationBufferSize(len.maxLength());
                      break;
                      
                    case SERVER_NAME:
                      requestedNames = (ServerNameList) e.value();
                      List<String> names
                        = new ArrayList<String>(requestedNames.size());
                      for (ServerNameList.ServerName name : requestedNames)
                        names.add(name.name());
                      engine.session().putValue("gnu.javax.net.ssl.RequestedServerNames", names);
                      break;

                    default:
                      logger.log(Level.INFO, "skipping unsupported extension {0}", e);
                    }
                  }
              }
            AbstractSessionContext sessions = (AbstractSessionContext)
              engine.contextImpl.engineGetServerSessionContext();
            SSLSession s = sessions.getSession(sessionId);
            if (Debug.DEBUG)
              logger.logv(Component.SSL_HANDSHAKE, "looked up saved session {0}", s);
            if (s != null && s.isValid() && (s instanceof SessionImpl))
              {
                engine.setSession((SessionImpl) s);
                continuedSession = true;
              }
            else
              {
                // We *may* wind up with a badly seeded PRNG, and emit the
                // same session ID over and over (this did happen to me,
                // so we add this sanity check just in case).
                if (engine.session().id().equals(new Session.ID(sessionId)))
                  {
                    byte[] newId = new byte[32];
                    engine.session().random().nextBytes(newId);
                    engine.session().setId(new Session.ID(newId));
                  }
                sessions.put(engine.session());
              }
            state = WRITE_SERVER_HELLO;
          }
          break;

        // Certificate.
        //
        // This message is sent by the client if the server had previously
        // requested that the client authenticate itself with a certificate,
        // and if the client has an appropriate certificate available.
        //
        // Processing this message will save the client's certificate,
        // rejecting it if the certificate is not trusted, in preparation
        // for the certificate verify message that will follow.
        case READ_CERTIFICATE:
          {
            if (handshake.type() != CERTIFICATE)
              {
                if (engine.getNeedClientAuth()) // XXX throw better exception.
                  throw new SSLException("client auth required");
                state = READ_CLIENT_KEY_EXCHANGE;
                return HandshakeStatus.NEED_UNWRAP;
              }
            
            Certificate cert = (Certificate) handshake.body();
            try
              {
                engine.session().setPeerVerified(false);
                X509Certificate[] chain
                  = cert.certificates().toArray(new X509Certificate[0]);
                if (chain.length == 0)
                  throw new CertificateException("no certificates in chain");
                X509TrustManager tm = engine.contextImpl.trustManager;
                tm.checkClientTrusted(chain, null);
                engine.session().setPeerCertificates(chain);
                clientCert = chain[0];
                // Delay setting 'peerVerified' until CertificateVerify.
              }
            catch (CertificateException ce)
              {
                if (engine.getNeedClientAuth())
                  {
                    SSLPeerUnverifiedException x
                      = new SSLPeerUnverifiedException("client certificates could not be verified");
                    x.initCause(ce);
                    throw x;
                  }
              }
            catch (NoSuchAlgorithmException nsae)
              {
                throw new SSLException(nsae);
              }
            state = READ_CLIENT_KEY_EXCHANGE;
          }
          break;

        // Client Key Exchange.
        //
        // The client's key exchange. This message is sent either following
        // the certificate message, or if no certificate is available or
        // requested, following the server's hello done message.
        //
        // After receipt of this message, the session keys for this
        // session will have been created.
        case READ_CLIENT_KEY_EXCHANGE:
          {
            if (handshake.type() != CLIENT_KEY_EXCHANGE)
              throw new SSLException("expecting client key exchange");
            ClientKeyExchange kex = (ClientKeyExchange) handshake.body();
            
            if (engine.session().suite.keyExchangeAlgorithm() ==
                KeyExchangeAlgorithm.DIFFIE_HELLMAN)
              {
                ClientDiffieHellmanPublic pub = (ClientDiffieHellmanPublic)
                  kex.exchangeKeys();
                DHPublicKey myKey = (DHPublicKey) dhPair.getPublic();
                DHPublicKey clientKey =
                  new GnuDHPublicKey(null, myKey.getParams().getP(),
                                     myKey.getParams().getG(),
                                     pub.publicValue());
                diffieHellmanPhase2(clientKey);
              }
            if (engine.session().suite.keyExchangeAlgorithm() ==
                KeyExchangeAlgorithm.RSA)
              {
                EncryptedPreMasterSecret secret = (EncryptedPreMasterSecret)
                  kex.exchangeKeys();
                Cipher rsa = null;
                try
                  {
                    rsa = Cipher.getInstance("RSA");
                    rsa.init(Cipher.DECRYPT_MODE, localCert);
                  }
                catch (InvalidKeyException ike)
                  {
                    throw new SSLException(ike);
                  }
                catch (NoSuchAlgorithmException nsae)
                  {
                    throw new SSLException(nsae);
                  }
                catch (NoSuchPaddingException nspe)
                  {
                    // Shouldn't happen; RSA only has one padding here.
                    throw new SSLException(nspe);
                  }
                
                try
                  {
                    preMasterSecret = rsa.doFinal(secret.encryptedSecret());
                  }
                catch (BadPaddingException bpe)
                  {
                    throw new SSLException(bpe);
                  }
                catch (IllegalBlockSizeException ibse)
                  {
                    throw new SSLException(ibse);
                  }
              }
            // XXX SRP
            
            // Generate the master keys.
            generateMasterSecret(clientRandom, serverRandom, engine.session());
            
            // Initialize our security parameters.
            byte[][] keys = generateKeys(clientRandom, serverRandom,
                                         engine.session());
            try
              {
                CipherSuite s = engine.session().suite;
                Cipher inCipher = s.cipher();
                Mac inMac = s.mac(engine.session().version);
                Inflater inflater = (compression == CompressionMethod.ZLIB
                                     ? new Inflater() : null); 
                inCipher.init(Cipher.DECRYPT_MODE,
                              new SecretKeySpec(keys[2],
                                                s.cipherAlgorithm().toString()),
                              new IvParameterSpec(keys[4]));
                inMac.init(new SecretKeySpec(keys[0],
                                             inMac.getAlgorithm()));
                inParams = new InputSecurityParameters(inCipher, inMac,
                                                       inflater,
                                                       engine.session(), s);
                
                Cipher outCipher = s.cipher();
                Mac outMac = s.mac(engine.session().version);
                Deflater deflater = (compression == CompressionMethod.ZLIB
                                     ? new Deflater() : null);
                outCipher.init(Cipher.ENCRYPT_MODE,
                               new SecretKeySpec(keys[3],
                                                 s.cipherAlgorithm().toString()),
                               new IvParameterSpec(keys[5]));
                outMac.init(new SecretKeySpec(keys[1],
                                              outMac.getAlgorithm()));
                outParams = new OutputSecurityParameters(outCipher, outMac,
                                                         deflater,
                                                         engine.session(), s);
              }
            catch (InvalidAlgorithmParameterException iape)
              {
                throw new SSLException(iape);
              }
            catch (InvalidKeyException ike)
              {
                throw new SSLException(ike);
              }
            catch (NoSuchAlgorithmException nsae)
              {
                throw new SSLException(nsae);
              }
            catch (NoSuchPaddingException nspe)
              {
                throw new SSLException(nspe);
              }
            
            if (clientCert != null)
              state = READ_CERTIFICATE_VERIFY;
            else
              {
                if (continuedSession)
                  {
                    engine.changeCipherSpec();
                    state = WRITE_FINISHED;
                  }
                else
                  state = READ_FINISHED;
              }
          }
          break;

        // Certificate Verify.
        //
        // This message is sent following the client key exchange message,
        // but only when the client included its certificate in a previous
        // message.
        //
        // After receipt of this message, the client's certificate (and,
        // to a degree, the client's identity) will have been verified.
        case READ_CERTIFICATE_VERIFY:
          {
            if (handshake.type() != CERTIFICATE_VERIFY)
              throw new SSLException("expecting certificate verify message");
            
            CertificateVerify verify = (CertificateVerify) handshake.body();
            try
              {
                verifyClient(verify.signature());
                engine.session().setPeerVerified(true);
              }
            catch (SignatureException se)
              {
                if (engine.getNeedClientAuth())
                  throw new SSLException("client auth failed", se);
              }
            if (continuedSession)
              {
                engine.changeCipherSpec();
                state = WRITE_FINISHED;
              }
            else
              state = READ_FINISHED;
          }
          break;
          
        // Finished.
        //
        // This message is sent immediately following the change cipher
        // spec message (which is sent outside of the handshake layer).
        // After receipt of this message, the session keys for the client
        // side will have been verified (this is the first message the
        // client sends encrypted and authenticated with the newly
        // negotiated keys).
        //
        // In the case of a continued session, the client sends its
        // finished message first. Otherwise, the server will send its
        // finished message first.
        case READ_FINISHED:
          {
            if (handshake.type() != FINISHED)
              {
                throw new SSLException("expecting FINISHED message");
              }
            
            Finished clientFinished = (Finished) handshake.body();
            
            MessageDigest md5copy = null;
            MessageDigest shacopy = null;
            try
              {
                md5copy = (MessageDigest) md5.clone();
                shacopy = (MessageDigest) sha.clone();
              }
            catch (CloneNotSupportedException cnse)
              {
                // We're improperly configured to use a non-cloneable
                // md5/sha-1, OR there's a runtime bug.
                throw new SSLException(cnse);
              }
            Finished serverFinished =
              new Finished(generateFinished(md5copy, shacopy,
                                            true, engine.session()),
                                            engine.session().version);

            if (Debug.DEBUG)
              logger.log(Component.SSL_HANDSHAKE, "server finished: {0}",
                         serverFinished);
            
            if (engine.session().version == ProtocolVersion.SSL_3)
              {
                if (!Arrays.equals(clientFinished.md5Hash(),
                                   serverFinished.md5Hash())
                    || !Arrays.equals(clientFinished.shaHash(),
                                      serverFinished.shaHash()))
                  {
                    engine.session().invalidate();
                    throw new SSLException("session verify failed");
                  }
              }
            else
              {
                if (!Arrays.equals(clientFinished.verifyData(),
                                   serverFinished.verifyData()))
                  {
                    engine.session().invalidate();
                    throw new SSLException("session verify failed");
                  }
              }
            
            if (continuedSession)
              state = DONE;
            else
              {
                engine.changeCipherSpec();
                state = WRITE_FINISHED;
              }
          }
          break;
      }

    handshakeOffset += handshake.length() + 4;

    if (state.isReadState())
      return HandshakeStatus.NEED_UNWRAP;
    if (state.isWriteState())
      return HandshakeStatus.NEED_WRAP;

    return HandshakeStatus.FINISHED; // XXX ???
  }

  public @Override HandshakeStatus implHandleOutput (ByteBuffer fragment)
    throws SSLException
  {
    if (Debug.DEBUG)
      logger.logv(Component.SSL_HANDSHAKE,
                  "handle output state: {0}; output fragment: {1}",
                  state, fragment);
    
    // Drain the output buffer, if it needs it.
    if (outBuffer != null && outBuffer.hasRemaining())
      {
        int l = Math.min(fragment.remaining(), outBuffer.remaining());
        fragment.put((ByteBuffer) outBuffer.duplicate().limit(outBuffer.position() + l));
        outBuffer.position(outBuffer.position() + l);
      }
    
    if (!fragment.hasRemaining())
      {
        if (state.isWriteState() || outBuffer.hasRemaining())
          return HandshakeStatus.NEED_WRAP;
        else
          return HandshakeStatus.NEED_UNWRAP;
      }
    
    // XXX what we need to do here is generate a "stream" of handshake
    // messages, and insert them into fragment amounts that we have available.
    // A handshake message can span multiple records, and we can put
    // multiple records into a single record.
    //
    // So, we can have one of two states:
    //
    // 1) We have enough space in the record we are creating to push out
    //    everything we need to on this round. This is easy; we just
    //    repeatedly fill in these messages in the buffer, so we get something
    //    that looks like this:
    //                 ________________________________
    //       records: |________________________________|
    //    handshakes: |______|__|__________|
    //
    // 2) We can put part of one handshake message in the current record,
    //    but we must put the rest of it in the following record, or possibly
    //    more than one following record. So here, we'd see this:
    //
    //                 ________________________
    //       records: |_______|_______|________|
    //    handshakes: |____|_______|_________|
    //
    // We *could* make this a lot easier by just only ever emitting one
    // record per call, but then we would waste potentially a lot of space
    // and waste a lot of TCP packets by doing it the simple way. What
    // we desire here is that we *maximize* our usage of the resources
    // given to us, and to use as much space in the present fragment as
    // we can.
    //
    // Note that we pretty much have to support this, anyway, because SSL
    // provides no guarantees that the record size is large enough to
    // admit *even one* handshake message. Also, callers could call on us
    // with a short buffer, even though they aren't supposed to.
    //
    // This is somewhat complicated by the fact that we don't know, a priori,
    // how large a handshake message will be until we've built it, and our
    // design builds the message around the byte buffer.
    //
    // Some ways to handle this:
    //
    //  1. Write our outgoing handshake messages to a private buffer,
    //     big enough per message (and, if we run out of space, resize that
    //     buffer) and push (possibly part of) this buffer out to the
    //     outgoing buffer. This isn't that great because we'd need to
    //     store and copy things unnecessarily.
    //
    //  2. Build outgoing handshake objects “virtually,” that is, store them
    //     as collections of objects, then compute the length, and then write
    //     them to a buffer, instead of making the objects views on
    //     ByteBuffers for both input and output. This would complicate the
    //     protocol objects a bit (although, it would amount to doing
    //     separation between client objects and server objects, which is
    //     pretty OK), and we still need to figure out how exactly to chunk
    //     those objects across record boundaries.
    //
    //  3. Try to build these objects on the buffer we’re given, but detect
    //     when we run out of space in the output buffer, and split the
    //     overflow message. This sounds like the best, but also probably
    //     the hardest to code.
output_loop:
    while (fragment.remaining() >= 4 && state.isWriteState())
      {
        switch (state)
          {
            // Hello Request.
            //
            // This message is sent by the server to initiate a new
            // handshake, to establish new session keys.
            case WRITE_HELLO_REQUEST:
            {
              Handshake handshake = new Handshake(fragment);
              handshake.setType(Handshake.Type.HELLO_REQUEST);
              handshake.setLength(0);
              fragment.position(fragment.position() + 4);
              if (Debug.DEBUG)
                logger.log(Component.SSL_HANDSHAKE, "{0}", handshake);
              state = READ_CLIENT_HELLO;
            }
            break output_loop; // XXX temporary
            
            // Server Hello.
            //
            // This message is sent immediately following the client hello.
            // It informs the client of the cipher suite, compression method,
            // session ID (which may have been a continued session), and any
            // supported extensions.
            case WRITE_SERVER_HELLO:
            {
              ServerHelloBuilder hello = new ServerHelloBuilder();
              hello.setVersion (engine.session().version);
              Random r = hello.random();
              r.setGmtUnixTime ((int) (System.currentTimeMillis() / 1000));
              byte[] nonce = new byte[28];
              engine.session().random().nextBytes(nonce);
              r.setRandomBytes(nonce);
              serverRandom = r.copy ();
              hello.setSessionId(engine.session().getId());
              hello.setCipherSuite (engine.session().suite);
              hello.setCompressionMethod(compression);
              if (clientHadExtensions)
                {
                  // XXX figure this out.
                }
              else // Don't send any extensions.
                hello.setDisableExtensions(true);
              
              if (Debug.DEBUG)
                logger.log(Component.SSL_HANDSHAKE, "{0}", hello);

              int typeLen = ((Handshake.Type.SERVER_HELLO.getValue() << 24)
                  | (hello.length() & 0xFFFFFF));
              fragment.putInt(typeLen);

              outBuffer = hello.buffer();
              int l = Math.min(fragment.remaining(), outBuffer.remaining());
              fragment.put((ByteBuffer) outBuffer.duplicate().limit(outBuffer.position() + l));
              outBuffer.position(outBuffer.position() + l);

              if (continuedSession)
                {
                  engine.changeCipherSpec();
                  state = WRITE_FINISHED;
                }
              else
                state = WRITE_CERTIFICATE;
            }
            break output_loop; // XXX temporary

            // Certificate.
            //
            // This message is sent immediately following the server hello,
            // IF the cipher suite chosen requires that the server identify
            // itself (usually, servers must authenticate).
            case WRITE_CERTIFICATE:
            {
              if (engine.session().suite.keyExchangeAlgorithm() == null)
                {
                  state = WRITE_SERVER_KEY_EXCHANGE;
                  break;
                }
              String sigAlg = null;
              switch (engine.session().suite.keyExchangeAlgorithm())
                {
                  case NONE:
                    break;

                  case RSA:
                    sigAlg = "RSA";
                    break;

                  case DIFFIE_HELLMAN:
                    if (engine.session().suite.isEphemeralDH())
                      sigAlg = "DHE_";
                    else
                      sigAlg = "DH_";
                    switch (engine.session().suite.signatureAlgorithm())
                      {
                        case RSA:
                          sigAlg += "RSA";
                          break;

                        case DSA:
                          sigAlg += "DSS";
                          break;
                      }

                  case SRP:
                    switch (engine.session().suite.signatureAlgorithm())
                      {
                        case RSA:
                          sigAlg = "SRP_RSA";
                          break;

                        case DSA:
                          sigAlg = "SRP_DSS";
                          break;
                      }
                }
              X509ExtendedKeyManager km = engine.contextImpl.keyManager;
              Principal[] issuers = null; // XXX use TrustedAuthorities extension.
              keyAlias = km.chooseEngineServerAlias(sigAlg, issuers, engine);
              X509Certificate[] chain = km.getCertificateChain(keyAlias);

              CertificateBuilder cert = new CertificateBuilder(CertificateType.X509);
              try
                {
                  cert.setCertificates(Arrays.asList(chain));
                }
              catch (CertificateException ce)
                {
                  throw new SSLException(ce);
                }
              engine.session().setLocalCertificates(chain);
              localCert = chain[0];

              if (Debug.DEBUG)
                {
                  logger.logv(Component.SSL_HANDSHAKE, "my cert:\n{0}", localCert);
                  logger.logv(Component.SSL_HANDSHAKE, "{0}", cert);
                }
              
              int typeLen = ((CERTIFICATE.getValue() << 24)
                             | (cert.length() & 0xFFFFFF));
              fragment.putInt(typeLen);

              outBuffer = cert.buffer();
              final int l = Math.min(fragment.remaining(), outBuffer.remaining());
              fragment.put((ByteBuffer) outBuffer.duplicate().limit(outBuffer.position() + l));
              outBuffer.position(outBuffer.position() + l);

              state = WRITE_SERVER_KEY_EXCHANGE;
            }
            break output_loop; // XXX temporary

            // Server key exchange.
            //
            // This message is sent, following the certificate if sent,
            // otherwise following the server hello, IF the chosen cipher
            // suite requires that the server send explicit key exchange
            // parameters (that is, if the key exchange parameters are not
            // implicit in the server's certificate).
            case WRITE_SERVER_KEY_EXCHANGE:
            {
              KeyExchangeAlgorithm kex = engine.session().suite.keyExchangeAlgorithm();
              
              if (kex == KeyExchangeAlgorithm.DIFFIE_HELLMAN)
                {
                  genDiffieHellman();
                  initDiffieHellman((DHPrivateKey) dhPair.getPrivate(),
                                    engine.session().random());
                }
              // XXX handle SRP
              
              if (kex != KeyExchangeAlgorithm.NONE
                  && kex != KeyExchangeAlgorithm.RSA
                  && engine.session().suite.isEphemeralDH())
                {
                  // This key exchange requires server params; construct them.
                  ByteBuffer paramBuffer = null;
                  
                  if (kex == KeyExchangeAlgorithm.DIFFIE_HELLMAN)
                    {
                      DHPublicKey pubKey = (DHPublicKey) dhPair.getPublic();
                      ServerDHParams params =
                        new ServerDHParams(pubKey.getParams().getP(),
                                           pubKey.getParams().getG(),
                                           pubKey.getY());
                      paramBuffer = params.buffer();
                      if (Debug.DEBUG)
                        logger.logv(Component.SSL_HANDSHAKE, "server DH params:\n{0}",
                                    Util.hexDump(paramBuffer));
                    }
                  // XXX handle SRP
                  
                  ByteBuffer sigBuffer = signParams(paramBuffer.duplicate());
                  ServerKeyExchangeBuilder ske
                    = new ServerKeyExchangeBuilder(engine.session().suite);
                  ske.setParams(paramBuffer);
                  ske.setSignature(sigBuffer);
                  
                  if (Debug.DEBUG)
                    logger.log(Component.SSL_HANDSHAKE, "{0}", ske);
                  
                  outBuffer = ske.buffer();
                  int l = Math.min(fragment.remaining(), outBuffer.remaining());
                  fragment.putInt((SERVER_KEY_EXCHANGE.getValue() << 24)
                                  | (ske.length() & 0xFFFFFF));
                  fragment.put((ByteBuffer) outBuffer.duplicate().limit(outBuffer.position() + l));
                  outBuffer.position(outBuffer.position() + l);
                }
              
              if (engine.getWantClientAuth() || engine.getNeedClientAuth())
                state = WRITE_CERTIFICATE_REQUEST;
              else
                state = WRITE_SERVER_HELLO_DONE;
            }
            break output_loop; // XXX temporary

            // Certificate Request.
            //
            // This message is sent when the server desires or requires
            // client authentication with a certificate; if it is sent, it
            // will be sent just after the Certificate or Server Key
            // Exchange messages, whichever is sent. If neither of the
            // above are sent, it will be the message that follows the
            // server hello.
            case WRITE_CERTIFICATE_REQUEST:
            {
              CertificateRequestBuilder req = new CertificateRequestBuilder();
              
              List<ClientCertificateType> types
                = new ArrayList<ClientCertificateType>(4);
              types.add(ClientCertificateType.RSA_SIGN);
              types.add(ClientCertificateType.RSA_FIXED_DH);
              types.add(ClientCertificateType.DSS_SIGN);
              types.add(ClientCertificateType.DSS_FIXED_DH);
              req.setTypes(types);
              
              X509Certificate[] anchors
                = engine.contextImpl.trustManager.getAcceptedIssuers();
              List<X500Principal> issuers
                = new ArrayList<X500Principal>(anchors.length);
              for (X509Certificate cert : anchors)
                issuers.add(cert.getIssuerX500Principal());
              req.setAuthorities(issuers);
              
              if (Debug.DEBUG)
                logger.log(Component.SSL_HANDSHAKE, "{0}", req);
              
              fragment.putInt((CERTIFICATE_REQUEST.getValue() << 24)
                              | (req.length() & 0xFFFFFF));
              
              outBuffer = req.buffer();
              int l = Math.min(outBuffer.remaining(), fragment.remaining());
              fragment.put((ByteBuffer) outBuffer.duplicate().limit(outBuffer.position() + l));
              outBuffer.position(outBuffer.position() + l);
              
              state = WRITE_SERVER_HELLO_DONE;
            }
            break output_loop; // XXX temporary

            // Server Hello Done.
            //
            // This message is always sent by the server, to terminate its
            // side of the handshake. Since the server's handshake message
            // may comprise multiple, optional messages, this sentinel
            // message lets the client know when the server's message stream
            // is complete.
            case WRITE_SERVER_HELLO_DONE:
            {
              // ServerHelloDone is zero-length; just put in the type
              // field.
              fragment.putInt(SERVER_HELLO_DONE.getValue() << 24);
              if (Debug.DEBUG)
                logger.logv(Component.SSL_HANDSHAKE, "writing ServerHelloDone");
              state = READ_CERTIFICATE;
            }
            break output_loop; // XXX temporary
            
            // Finished.
            //
            // This is always sent by the server to verify the keys that the
            // server will use to encrypt and authenticate. In a full
            // handshake, this message will be sent after the client's
            // finished message; in an abbreviated handshake (with a continued
            // session) the server sends its finished message first.
            //
            // This message follows the change cipher spec message, which is
            // sent out-of-band in a different SSL content-type.
            //
            // This is the first message that the server will send encrypted
            // and authenticated with the newly negotiated session keys.
            case WRITE_FINISHED:
            {
              MessageDigest md5copy = null;
              MessageDigest shacopy = null;
              try
                {
                  md5copy = (MessageDigest) md5.clone();
                  shacopy = (MessageDigest) sha.clone();
                }
              catch (CloneNotSupportedException cnse)
                {
                  // We're improperly configured to use a non-cloneable
                  // md5/sha-1, OR there's a runtime bug.
                  throw new SSLException(cnse);
                }
              outBuffer
                = generateFinished(md5copy, shacopy, false,
                                   engine.session());
              
              fragment.putInt((FINISHED.getValue() << 24)
                              | outBuffer.remaining() & 0xFFFFFF);
              
              int l = Math.min(outBuffer.remaining(), fragment.remaining());
              fragment.put((ByteBuffer) outBuffer.duplicate().limit(outBuffer.position() + l));
              outBuffer.position(outBuffer.position() + l);

              if (continuedSession)
                state = READ_FINISHED;
              else
                state = DONE;
            }
            break;
          }
      }
    if (state.isWriteState() || outBuffer.hasRemaining())
      return HandshakeStatus.NEED_WRAP;
    if (state.isReadState())
      return HandshakeStatus.NEED_UNWRAP;
    
    return HandshakeStatus.FINISHED;
  }
  
  @Override HandshakeStatus status()
  {
    if (state.isReadState())
      return HandshakeStatus.NEED_UNWRAP;
    if (state.isWriteState())
      return HandshakeStatus.NEED_WRAP;
    
    return HandshakeStatus.FINISHED;
  }
  
  @Override InputSecurityParameters getInputParams() throws SSLException
  {
    if (inParams == null)
      throw new SSLException("premature usage of input security parameters");
    return inParams;
  }
  
  @Override OutputSecurityParameters getOutputParams() throws SSLException
  {
    if (outParams == null)
      throw new SSLException("premature usage of output security parameters");
    return outParams;
  }
  
  @Override void handleV2Hello(ByteBuffer hello)
  {
    int len = hello.getShort(0) & 0x7FFF;
    md5.update((ByteBuffer) hello.duplicate().position(2).limit(len+2));
    sha.update((ByteBuffer) hello.duplicate().position(2).limit(len+2));
    helloV2 = true;
  }
  
  /**
   * Generate, or fetch from our certificate, the Diffie-Hellman exchange
   * parameters.
   * 
   * @throws SSLException
   */
  private void genDiffieHellman() throws SSLException
  {
    try
      {
        // XXX generating a DH key, especially given a large prime, can
        // take a while. We should perhaps look into making this a delegated
        // task, so we don't block other connections when generating keys.
        //
        // Also, I should investigate whether or not these DH parameters are
        // "secure" or not; I mean, I'm not really worried, because SSH uses
        // similar static parameters, but this *could* be a potential hole.
        if (engine.session().suite.isEphemeralDH())
          {
            KeyPairGenerator dhGen = KeyPairGenerator.getInstance("DH");
            DHParameterSpec dhparams = DiffieHellman.getParams().getParams();
            dhGen.initialize(dhparams, engine.session().random());
            dhPair = dhGen.generateKeyPair();
          }
        else
          {
            X509Certificate cert = (X509Certificate)
              engine.session().getLocalCertificates()[0];
            PrivateKey key = engine.contextImpl.keyManager.getPrivateKey(keyAlias);
            dhPair = new KeyPair(cert.getPublicKey(), key);
          }

        if (Debug.DEBUG_KEY_EXCHANGE)
          logger.logv(Component.SSL_KEY_EXCHANGE,
                      "Diffie-Hellman public:{0} private:{1}",
                      dhPair.getPublic(), dhPair.getPrivate());
      }
    catch (InvalidAlgorithmParameterException iape)
      {
        throw new SSLException(iape);
      }
    catch (NoSuchAlgorithmException nsae)
      {
        throw new SSLException(nsae);
      }
  }
  
  private ByteBuffer signParams(ByteBuffer serverParams) throws SSLException
  {
    try
      {
        SignatureAlgorithm alg = engine.session().suite.signatureAlgorithm();
        java.security.Signature sig
          = java.security.Signature.getInstance(alg.algorithm());
        PrivateKey key = engine.contextImpl.keyManager.getPrivateKey(keyAlias);
        if (Debug.DEBUG_KEY_EXCHANGE)
          logger.logv(Component.SSL_HANDSHAKE, "server key: {0}", key);
        sig.initSign(key);
        sig.update(clientRandom.buffer());
        sig.update(serverRandom.buffer());
        sig.update(serverParams);
        byte[] sigVal = sig.sign();
        Signature signature = new Signature(sigVal, engine.session().suite.signatureAlgorithm());
        return signature.buffer();
      }
    catch (NoSuchAlgorithmException nsae)
      {
        throw new SSLException(nsae);
      }
    catch (InvalidKeyException ike)
      {
        throw new SSLException(ike);
      }
    catch (SignatureException se)
      {
        throw new SSLException(se);
      }
  }
  
  private void verifyClient(byte[] sigValue) throws SSLException, SignatureException
  {
    MessageDigest md5copy = null;
    MessageDigest shacopy = null;
    try
      {
        md5copy = (MessageDigest) md5.clone();
        shacopy = (MessageDigest) sha.clone();
      }
    catch (CloneNotSupportedException cnse)
      {
        // Mis-configured with non-cloneable digests.
        throw new SSLException(cnse);
      }
    byte[] toSign = null;
    if (engine.session().version == ProtocolVersion.SSL_3)
      toSign = genV3CertificateVerify(md5copy, shacopy, engine.session());
    else
      {
        if (engine.session().suite.signatureAlgorithm() == SignatureAlgorithm.RSA)
          toSign = Util.concat(md5copy.digest(), shacopy.digest());
        else
          toSign = shacopy.digest();
      }
    
    try
      {
        java.security.Signature sig = java.security.Signature.getInstance(engine.session().suite.signatureAlgorithm().toString());
        sig.initVerify(clientCert);
        sig.update(toSign);
        sig.verify(sigValue);
      }
    catch (InvalidKeyException ike)
      {
        throw new SSLException(ike);
      }
    catch (NoSuchAlgorithmException nsae)
      {
        throw new SSLException(nsae);
      }
  }
}