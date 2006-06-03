/* SecurityParameters.java -- SSL security parameters.
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

import java.nio.ByteBuffer;

import java.util.Arrays;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

import javax.net.ssl.SSLException;

class InputSecurityParameters
{
  private final Cipher cipher;
  private final Mac mac;
  private final Inflater inflater;
  private final CipherSuite suite;
  private long sequence;

  InputSecurityParameters (final Cipher cipher, final Mac mac,
                           final Inflater inflater, final CipherSuite suite)
  {
    this.cipher = cipher;
    this.mac = mac;
    this.inflater = inflater;
    this.suite = suite;
    sequence = 0;
  }

  void decrypt (Record record, ByteBuffer output)
    throws BadPaddingException, DataFormatException, IllegalBlockSizeException,
           MacException, SSLException, ShortBufferException
  {
    ByteBuffer fragment;
    if (cipher != null)
      {
        ByteBuffer input = record.fragment ();
        fragment = ByteBuffer.allocate (input.limit ());
        cipher.doFinal (input, fragment);
      }
    else
      fragment = record.fragment ();

    int maclen = 0;
    if (mac != null)
      maclen = mac.getMacLength ();
    CipheredStruct plaintext;

    // We delay throwing an error for bad padding bytes until after we
    // verify the MAC; this helps avoid timing attacks.
    boolean badPadding = false;

    if (suite.isStreamCipher ())
      plaintext = new GenericStreamCipher (fragment, maclen);
    else
      {
        plaintext = new GenericBlockCipher (fragment, maclen);
        int padlen = ((GenericBlockCipher) plaintext).paddingLength ();

        if (record.version () == ProtocolVersion.SSL_3)
          {
            // In SSLv3, the padding length must not be larger than
            // the cipher's block size.
            if (padlen > cipher.getBlockSize ())
              badPadding = true;
          }
        else if (record.version () == ProtocolVersion.TLS_1)
          {
            // In TLSv1, the padding must be `padlen' copies of the
            // value `padlen'.
            byte[] pad = ((GenericBlockCipher) plaintext).padding ();
            for (int i = 0; i < pad.length; i++)
              if ((pad[i] & 0xFF) != padlen)
                badPadding = true;
          }
      }

    // Compute and check the MAC.
    if (mac != null)
      {
        mac.update ((byte) (sequence >>> 56));
        mac.update ((byte) (sequence >>> 48));
        mac.update ((byte) (sequence >>> 40));
        mac.update ((byte) (sequence >>> 32));
        mac.update ((byte) (sequence >>> 24));
        mac.update ((byte) (sequence >>> 16));
        mac.update ((byte) (sequence >>>  8));
        mac.update ((byte)  sequence);
        mac.update ((byte) record.getContentType ().getValue ());
        ProtocolVersion version = record.version ();
        if (version != ProtocolVersion.SSL_3)
          {
            mac.update ((byte) version.major ());
            mac.update ((byte) version.minor ());
          }
        mac.update ((byte) (plaintext.contentLength () >>> 8));
        mac.update ((byte)  plaintext.contentLength ());
        mac.update (plaintext.content ());
        byte[] mac1 = mac.doFinal ();
        byte[] mac2 = plaintext.mac ();
        if (!Arrays.equals (mac1, mac2))
          badPadding = true;
      }

    // We always say "bad MAC" and not "bad padding," because saying
    // the latter will leak information to an attacker.
    if (badPadding)
      throw new MacException ();

    // Inflate the compressed bytes.
    if (inflater != null)
      {
        byte[] inbuffer = new byte[4096];
        byte[] outbuffer = new byte[4096];
        boolean done = false;
        fragment.position (0);
        while (!done)
          {
            int l;
            if (inflater.needsInput ())
              {
                l = Math.min (inbuffer.length, fragment.remaining ());
                fragment.get (inbuffer, 0, l);
                inflater.setInput (inbuffer);
              }

            l = inflater.inflate (outbuffer);
            output.put (outbuffer, 0, l);
            done = !fragment.hasRemaining () && inflater.finished ();
          }
      }
    else
      output.put (plaintext.content ());

    sequence++;
  }
  
  CipherSuite cipherSuite ()
  {
    return suite;
  }
}
