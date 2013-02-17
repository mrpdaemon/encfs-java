package org.mrpdaemon.sec.encfs;

import java.util.Arrays;

public abstract class NotNullFilenameEncryptionStrategy extends FilenameEncryptionStrategy {

  NotNullFilenameEncryptionStrategy(EncFSVolume volume, String volumePath, EncFSAlgorithm algorithm) {
    super(volume, volumePath, algorithm);
  }

  protected abstract byte[] encryptConcrete(EncFSVolume volume, byte[] paddedDecFileName, byte[] fileIv) throws EncFSCorruptDataException;

  protected String encryptImpl(String fileName) throws EncFSCorruptDataException {
    EncFSVolume volume = getVolume();
    String volumePath = getVolumePath();
    EncFSConfig config = volume.getVolumeConfiguration();

    byte[] decFileName = fileName.getBytes();
    byte[] paddedDecFileName = getPaddedDecFilename(decFileName);
    byte[] chainIv = EncFSCrypto.computeChainedIVInCase(volume, volumePath, config);
    byte[] mac16 = getMac16(volume, paddedDecFileName, chainIv);
    byte[] macBytes = EncFSCrypto.getMacBytes(mac16);
    byte[] fileIv = EncFSCrypto.computeFileIV(chainIv, macBytes);

    byte[] encFileName = encryptConcrete(volume, paddedDecFileName, fileIv);

    return getBase256Filename(mac16, encFileName);
  }

  private String getBase256Filename(byte[] mac16, byte[] encFileName) {
    // current versions store the checksum at the beginning (encfs 0.x
    // stored checksums at the end)

    byte[] base256FileName = new byte[encFileName.length + 2];
    base256FileName[0] = mac16[0];
    base256FileName[1] = mac16[1];
    System.arraycopy(encFileName, 0, base256FileName, 2, encFileName.length);

    byte[] fileNameOutput = EncFSBase64.encodeEncfs(base256FileName);

    return new String(fileNameOutput);
  }

  private byte[] getMac16(EncFSVolume volume, byte[] paddedDecFileName, byte[] chainIv) {
    if (volume.getVolumeConfiguration().isChainedNameIV()) {
      return EncFSCrypto.mac16(volume.getVolumeMAC(), paddedDecFileName, Arrays.copyOf(chainIv, chainIv.length));
    } else {
      return EncFSCrypto.mac16(volume.getVolumeMAC(), paddedDecFileName);
    }
  }

  protected abstract byte[] getPaddedDecFilename(byte[] decFileName);

}
