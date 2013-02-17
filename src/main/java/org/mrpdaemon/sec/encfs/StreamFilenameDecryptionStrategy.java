package org.mrpdaemon.sec.encfs;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;

public class StreamFilenameDecryptionStrategy extends NotNullFilenameDecryptionStrategy {

  public StreamFilenameDecryptionStrategy(EncFSVolume volume, String volumePath) {
    super(volume, volumePath, EncFSAlgorithm.STREAM);
  }

  protected byte[] decryptConcrete(EncFSVolume volume, byte[] chainIv, byte[] macBytes, byte[] encFileName, byte[] fileIv) throws EncFSCorruptDataException {
    try {
      return EncFSCrypto.streamDecode(volume, fileIv, encFileName);
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSCorruptDataException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    } catch (EncFSUnsupportedException e) {
      throw new EncFSCorruptDataException(e);
    }
  }

  public String decryptPost(byte[] fileName) {
    return new String(fileName);
  }
}
