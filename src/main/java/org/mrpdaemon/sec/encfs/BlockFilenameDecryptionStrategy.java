package org.mrpdaemon.sec.encfs;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

public class BlockFilenameDecryptionStrategy extends NotNullFilenameDecryptionStrategy {

  public BlockFilenameDecryptionStrategy(EncFSVolume volume, String volumePath) {
    super(volume, volumePath, EncFSAlgorithm.BLOCK);
  }

  protected byte[] decryptConcrete(EncFSVolume volume, byte[] chainIv, byte[] macBytes, byte[] encFileName, byte[] fileIv) throws EncFSCorruptDataException {
    try {
      return BlockCryptography.blockDecode(volume, fileIv, encFileName);
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSCorruptDataException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    }
  }

  public String decryptPost(byte[] fileName) {
    // For the block cipher remove padding before returning the result
    int padLen = fileName[fileName.length - 1];

    return new String(Arrays.copyOfRange(fileName, 0, fileName.length - padLen));
  }
}
