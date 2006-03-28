/* OutputSecurityParameters.java -- 
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

import java.util.zip.DataFormatException;
import java.util.zip.Deflater;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

class OutputSecurityParameters
{
  private final Cipher cipher;
  private final Mac mac;
  private final Deflater deflater;
  private final CipherSuite suite;
  private long sequence;

  OutputSecurityParameters (final Cipher cipher, final Mac mac,
                            final Deflater deflater, final CipherSuite suite)
  {
    this.cipher = cipher;
    this.mac = mac;
    this.deflater = deflater;
    this.suite = suite;
    sequence = 0;
  }

  /**
   * Encrypt a record, storing the result in the given output buffer.
   *
   * @return The number of bytes stored into `output;' that is, the
   * size of the encrypted fragment, plus the encoding for the record.
   */
  int encrypt (final Record record, final ByteBuffer output)
    throws DataFormatException, IllegalBlockSizeException, ShortBufferException
  {
    int macLen = 0;
    if (mac != null)
      macLen = mac.getMacLength ();

    int padLen = 0;
    if (!suite.isStreamCipher ())
      {
        padLen = (cipher.getBlockSize() -
                  ((record.length () + macLen + 1) % cipher.getBlockSize()));
        // For TLSv1 or later, we can use a random amout of padding.
//         if (version != ProtocolVersion.SSL_3 && session.random != null)
//           {
//             padLen += (Math.abs(session.random.nextInt ()) & 7) *
//               outCipher.currentBlockSize();
//             while (padLen > 255)
//               padLen -= outCipher.currentBlockSize();
//           }
      }

    int fragmentLength = 0;
    ByteBuffer fragment = null;
    // Compress the content, if needed.
    if (deflater != null)
      {
        ByteBuffer in = record.fragment ();
        fragment = ByteBuffer.allocate (record.length () + macLen + padLen + 1024);
        byte[] inbuf = new byte[4096];
        byte[] outbuf = new byte[4096];

        in.position (0);
        while (in.hasRemaining ())
          {
            int l = Math.min (in.remaining (), inbuf.length);
            in.get (inbuf, 0, l);
            deflater.setInput (inbuf, 0, l);
            if (!in.hasRemaining ())
              deflater.finish ();
            l = deflater.deflate (outbuf);
            fragment.put (outbuf, 0, l);
          }
        fragmentLength = deflater.getTotalOut () + macLen + padLen;
        fragment = ((ByteBuffer) fragment.position (0).limit (fragmentLength)).slice ();
      }
    else
      {
        fragmentLength = record.length () + macLen + padLen;
        fragment = ByteBuffer.allocate (fragmentLength);
        fragment.put (record.fragment ());
      }

    CipheredStruct plaintext = null;
    if (suite.isStreamCipher ())
      plaintext = new GenericStreamCipher (fragment, fragmentLength - macLen - padLen,
                                           macLen);
    else
      plaintext = new GenericBlockCipher (fragment, fragmentLength - macLen - padLen,
                                          macLen);

    // If there is a MAC, compute it.
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
        mac.update ((byte) record.contentType ().getValue ());
        ProtocolVersion version = record.version ();
        if (version != ProtocolVersion.SSL_3)
          {
            mac.update ((byte) version.major ());
            mac.update ((byte) version.minor ());
          }
        mac.update ((byte) (plaintext.contentLength () >>> 8));
        mac.update ((byte)  plaintext.contentLength ());
        mac.update (plaintext.content ());
        plaintext.setMac (mac.doFinal (), 0);
      }

    Record outrecord = new Record (output);
    outrecord.setContentType (record.contentType ());
    outrecord.setVersion (record.version ());
    outrecord.setLength (fragmentLength);

    if (cipher != null)
      {
        if (padLen > 0)
          {
            int x = padLen - 1;
            byte[] padding = new byte[x];
            for (int i = 0; i < padding.length; i++)
              padding[i] = (byte) x;
            ((GenericBlockCipher) plaintext).setPaddingLength (x);
            ((GenericBlockCipher) plaintext).setPadding (padding);
          }

        try
          {
            cipher.doFinal (fragment, outrecord.fragment ());
          }
        catch (BadPaddingException bpe)
          {
            throw new RuntimeException ("caught BadPaddingException; this should not happen", bpe);
          }
      }
    else
      outrecord.fragment ().put (fragment);

    sequence++;

    return fragmentLength + 5;
  }
}