package org.mrpdaemon.sec.encfs;

import java.util.Arrays;

public abstract class NotNullFilenameDecryptionStrategy extends FilenameDecryptionStrategy {

  public NotNullFilenameDecryptionStrategy(EncFSVolume volume, String volumePath, EncFSAlgorithm algorithm) {
    super(volume, volumePath, algorithm);
  }

  protected abstract byte[] decryptConcrete(EncFSVolume volume, byte[] encFileName, byte[] fileIv) throws EncFSCorruptDataException;

  protected String decryptImpl(String fileName) throws EncFSCorruptDataException, EncFSChecksumException {
    EncFSVolume volume = getVolume();
    String volumePath = getVolumePath();
    EncFSConfig config = volume.getVolumeConfiguration();

    byte[] chainIv = EncFSCrypto.computeChainedIVInCase(volume, volumePath, config);
    byte[] base256FileName = EncFSBase64.decodeEncfs(fileName.getBytes());
    byte[] macBytes = EncFSCrypto.getMacBytes(base256FileName);
    byte[] encFileName = Arrays.copyOfRange(base256FileName, 2, base256FileName.length);
    byte[] fileIv = EncFSCrypto.computeFileIV(chainIv, macBytes);

    byte[] decFileName = decryptConcrete(volume, encFileName, fileIv);

    verifyDecryptionWorked(volume, chainIv, base256FileName, decFileName);

    return decryptPost(decFileName);
  }

  protected abstract String decryptPost(byte[] fileName);

  private void verifyDecryptionWorked(EncFSVolume volume, byte[] chainIv, byte[] base256FileName, byte[] decFileName) throws EncFSChecksumException {
    // Verify decryption worked
    // current versions store the checksum at the beginning (encfs 0.x
    // stored checksums at the end)
    byte[] mac16;
    if (volume.getVolumeConfiguration().isChainedNameIV()) {
      mac16 = EncFSCrypto.mac16(volume.getVolumeMAC(), decFileName, chainIv);
    } else {
      mac16 = EncFSCrypto.mac16(volume.getVolumeMAC(), decFileName);
    }

    byte[] expectedMac = Arrays.copyOfRange(base256FileName, 0, 2);
    if (!Arrays.equals(mac16, expectedMac)) {
      throw new EncFSChecksumException("Mismatch in file name checksum");
    }
  }
}
