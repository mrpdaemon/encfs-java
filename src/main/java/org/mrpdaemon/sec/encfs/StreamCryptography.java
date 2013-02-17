package org.mrpdaemon.sec.encfs;

import javax.crypto.Cipher;

/**
 * User: lars
 */
public class StreamCryptography {

  public static Cipher newStreamCipher() throws EncFSUnsupportedException {
    return EncFSCrypto.getCipher(EncFSCrypto.STREAM_CIPHER);
  }

}
