package org.mrpdaemon.sec.encfs;

public final class EncFSConfigFactory {

  public static EncFSConfig createDefault() {
    EncFSConfig config = new EncFSConfig();
    config.setAlgorithm(EncFSAlgorithm.BLOCK);
    config.setVolumeKeySizeInBits(192);
    config.setEncryptedFileBlockSizeInBytes(1024);
    config.setUseUniqueIV(true);
    config.setChainedNameIV(true);
    config.setHolesAllowedInFiles(true);
    config.setIterationForPasswordKeyDerivationCount(5000);
    config.setNumberOfMACBytesForEachFileBlock(0);
    config.setNumberOfRandomBytesInEachMACHeader(0);
    config.setSupportedExternalIVChaining(false);
    return config;
  }
}
