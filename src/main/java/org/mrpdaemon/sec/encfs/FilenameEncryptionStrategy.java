package org.mrpdaemon.sec.encfs;

/**
 * User: lars
 */
abstract class FilenameEncryptionStrategy {

  private final EncFSVolume volume;
  private final String volumePath;
  private final EncFSAlgorithm algorithm;

  String getVolumePath() {
    return volumePath;
  }

  EncFSVolume getVolume() {
    return volume;
  }

  FilenameEncryptionStrategy(EncFSVolume volume, String volumePath, EncFSAlgorithm algorithm) {
    this.volume = volume;
    this.volumePath = volumePath;
    this.algorithm = algorithm;
  }

  protected abstract String encryptImpl(String fileName) throws EncFSCorruptDataException;

  public String encrypt(String filename) throws EncFSCorruptDataException {
    if (volume.getVolumeConfiguration().getAlgorithm() != algorithm) {
      throw new IllegalStateException("only accessable when algorithm is " + algorithm);
    }

    return encryptImpl(filename);
  }
}
