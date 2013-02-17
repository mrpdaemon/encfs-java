package org.mrpdaemon.sec.encfs;

import java.io.File;
import java.io.IOException;

/**
 * User: lars
 */
public final class EncFSVolumeBuilder {

  public static class FileProviderBuilder {

    private final EncFSVolume volume;

    public FileProviderBuilder(EncFSVolume volume, String rootPath) {
      this(volume, new EncFSLocalFileProvider(new File(rootPath)));
    }

    public FileProviderBuilder(EncFSVolume volume, EncFSFileProvider fileProvider) {
      this.volume = volume;
      volume.setFileProvider(fileProvider);
    }

    public ConfigBuilder withConfig(EncFSConfig config) {
      return new ConfigBuilder(volume, config);
    }

    public Pbkdf2ProviderBuilder withPbkdf2Provider(EncFSPBKDF2Provider pbkdf2Provider) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException {
      return new ConfigBuilder(volume).withPbkdf2Provider(pbkdf2Provider);
    }

    public EncFSVolume withPassword(String password) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSCorruptDataException, EncFSInvalidPasswordException {
      return withPbkdf2Provider(null).withPassword(password);
    }

    public EncFSVolume withDerivedPassword(byte[] derivedPassword) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSCorruptDataException, EncFSInvalidPasswordException {
      return withPbkdf2Provider(null).withDerivedPassword(derivedPassword);
    }
  }

  public static class ConfigBuilder {

    private final EncFSVolume volume;

    public ConfigBuilder(EncFSVolume volume, EncFSConfig volumeConfiguration) {
      this.volume = volume;
      volume.setVolumeConfiguration(volumeConfiguration);
    }

    public ConfigBuilder(EncFSVolume volume) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException {
      this.volume = volume;
      EncFSFileProvider fileProvider = volume.getFileProvider();
      EncFSConfig volumeConfiguration = EncFSConfigParser.parseConfig(fileProvider, EncFSVolume.CONFIG_FILE_NAME);
      volume.setVolumeConfiguration(volumeConfiguration);
    }

    public Pbkdf2ProviderBuilder withPbkdf2Provider(EncFSPBKDF2Provider provider) {
      return new Pbkdf2ProviderBuilder(volume, provider);
    }

    public EncFSVolume withPassword(String password) throws EncFSCorruptDataException, EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSUnsupportedException, IOException {
      return withPbkdf2Provider(null).withPassword(password);
    }
  }

  public static class Pbkdf2ProviderBuilder {

    private final EncFSVolume volume;
    private final EncFSPBKDF2Provider provider;

    public Pbkdf2ProviderBuilder(EncFSVolume volume, EncFSPBKDF2Provider provider) {
      this.volume = volume;
      this.provider = provider;
    }

    public EncFSVolume withPassword(String password) throws EncFSInvalidConfigException, EncFSUnsupportedException, EncFSCorruptDataException, IOException, EncFSInvalidPasswordException {
      EncFSConfig config = volume.getVolumeConfiguration();
      byte[] derivedPassword = EncFSCrypto.derivePasswordKey(config, password, provider);
      return withDerivedPassword(derivedPassword);
    }

    public EncFSVolume withDerivedPassword(byte[] derivedPassword) throws EncFSCorruptDataException, EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSUnsupportedException, IOException {
      return new PasswordBuilder(volume, derivedPassword).build();
    }
  }

  public static class PasswordBuilder {

    private final EncFSVolume volume;

    public PasswordBuilder(EncFSVolume volume, byte[] derivedPassword) {
      this.volume = volume;
      volume.setPasswordBasedVolumeKey(derivedPassword);
    }

    public EncFSVolume build() throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSInvalidPasswordException, EncFSCorruptDataException {
      volume.readConfigAndInitializeVolume();
      return volume;
    }
  }

  public FileProviderBuilder withRootPath(String rootPath) {
    return new FileProviderBuilder(new EncFSVolume(), rootPath);
  }

  public FileProviderBuilder withFileProvider(EncFSFileProvider fileProvider) {
    return new FileProviderBuilder(new EncFSVolume(), fileProvider);
  }
}
