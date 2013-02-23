package org.mrpdaemon.sec.encfs;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;

class BlockCryptography {

  public static Cipher newBlockCipher() throws EncFSUnsupportedException {
    return EncFSCrypto.getCipher(EncFSCrypto.BLOCK_CIPHER);
  }

  private static byte[] blockOperation(EncFSVolume volume, byte[] ivSeed, byte[] data, int opMode) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    Cipher cipher = volume.getBlockCipher();
    EncFSCrypto.cipherInit(volume, opMode, cipher, ivSeed);
    return cipher.doFinal(data);
  }

  public static byte[] blockDecode(EncFSVolume volume, byte[] ivSeed, byte[] data) throws InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
    return blockOperation(volume, ivSeed, data, Cipher.DECRYPT_MODE);
  }

  public static byte[] blockEncode(EncFSVolume volume, byte[] ivSeed, byte[] data) throws IllegalBlockSizeException, InvalidAlgorithmParameterException, BadPaddingException {
    return blockOperation(volume, ivSeed, data, Cipher.ENCRYPT_MODE);
  }
}
