package org.mrpdaemon.sec.encfs;

import java.util.Arrays;

/**
 * User: lars
 */
public abstract class NotNullFilenameDecryptionStrategy extends FilenameDecryptionStrategy {

  public NotNullFilenameDecryptionStrategy(EncFSVolume volume, String volumePath, EncFSAlgorithm algorithm) {
    super(volume, volumePath, algorithm);
  }

  protected abstract byte[] decryptConcrete(EncFSVolume volume, byte[] chainIv, byte[] macBytes, byte[] encFileName, byte[] fileIv) throws EncFSCorruptDataException;

  protected String decryptImpl(String fileName) throws EncFSCorruptDataException, EncFSChecksumException {
    EncFSVolume volume = getVolume();
    String volumePath = getVolumePath();
    EncFSConfig config = volume.getVolumeConfiguration();

    byte[] chainIv = computeChainedIVInCase(volume, volumePath, config);
    byte[] base256FileName = EncFSBase64.decodeEncfs(fileName.getBytes());
    byte[] macBytes = getMacBytes(base256FileName);
    byte[] encFileName = Arrays.copyOfRange(base256FileName, 2, base256FileName.length);
    byte[] fileIv = computeFileIV(chainIv, macBytes);

    byte[] decFileName = decryptConcrete(volume, chainIv, macBytes, encFileName, fileIv);

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

  protected byte[] computeFileIV(byte[] chainIv, byte[] macBytes) {
    byte[] fileIv = new byte[8];
    for (int i = 0; i < 8; i++) {
      fileIv[i] = (byte) (macBytes[i] ^ chainIv[i]);
    }
    return fileIv;
  }

  private byte[] getMacBytes(byte[] base256FileName) {
    // TODO: make sure its multiple of 16
    byte[] macBytes = new byte[8];
    macBytes[6] = base256FileName[0];
    macBytes[7] = base256FileName[1];
    return macBytes;
  }

  protected byte[] computeChainedIVInCase(EncFSVolume volume, String volumePath, EncFSConfig config) {
    // Chained IV computation
    byte[] chainIv = new byte[8];
    if (config.isChainedNameIV()) {
      chainIv = EncFSCrypto.computeChainIv(volume, volumePath);
    }
    return chainIv;
  }
}
