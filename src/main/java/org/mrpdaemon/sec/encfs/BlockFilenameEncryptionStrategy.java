package org.mrpdaemon.sec.encfs;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

public class BlockFilenameEncryptionStrategy extends NotNullFilenameEncryptionStrategy {

  public BlockFilenameEncryptionStrategy(EncFSVolume volume, String volumePath) {
    super(volume, volumePath, EncFSAlgorithm.BLOCK);
  }

  @Override
  protected byte[] encryptConcrete(EncFSVolume volume, byte[] paddedDecFileName, byte[] fileIv) throws EncFSCorruptDataException {
    try {
      return BlockCryptography.blockEncode(volume, fileIv, paddedDecFileName);
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSCorruptDataException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    }
  }

  protected byte[] getPaddedDecFilename(byte[] decFileName) {
    // Pad to the nearest 16 bytes, add a full block if needed
    int padBytesSize = 16;
    int padLen = padBytesSize - (decFileName.length % padBytesSize);
    if (padLen == 0) {
      padLen = padBytesSize;
    }
    byte[] paddedDecFileName = Arrays.copyOf(decFileName, decFileName.length + padLen);
    Arrays.fill(paddedDecFileName, decFileName.length, paddedDecFileName.length, (byte) padLen);
    return paddedDecFileName;
  }
}
