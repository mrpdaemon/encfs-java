package org.mrpdaemon.sec.encfs;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

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

    public PasswordBuilder withPassword(String password) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSCorruptDataException, EncFSInvalidPasswordException {
      return withPbkdf2Provider(null).withPassword(password);
    }

    public PasswordBuilder withDerivedPassword(byte[] derivedPassword) throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSCorruptDataException, EncFSInvalidPasswordException {
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

    public PasswordBuilder withPassword(String password) throws EncFSCorruptDataException, EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSUnsupportedException, IOException {
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

    public PasswordBuilder withPassword(String password) throws EncFSInvalidConfigException, EncFSUnsupportedException, EncFSCorruptDataException, IOException, EncFSInvalidPasswordException {
      return new PasswordBuilder(volume, password, provider);
    }

    public PasswordBuilder withDerivedPassword(byte[] derivedPassword) throws EncFSCorruptDataException, EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSUnsupportedException, IOException {
      return new PasswordBuilder(volume, derivedPassword);
    }
  }

  public static class PasswordBuilder {

    private final EncFSVolume volume;
    private final EncFSPBKDF2Provider provider;
    private final String password;

    public PasswordBuilder(EncFSVolume volume, byte[] derivedPassword) {
      this.volume = volume;
      this.provider = null;
      this.password = null;
      volume.setPasswordBasedVolumeKey(derivedPassword);

    }

    public PasswordBuilder(EncFSVolume volume, String password, EncFSPBKDF2Provider provider) {
      this.volume = volume;
      this.password = password;
      this.provider = provider;
    }

    public EncFSVolume access() throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSInvalidPasswordException, EncFSCorruptDataException {
      EncFSConfig config = volume.getVolumeConfiguration();
      if (password != null) {
        byte[] derivedPassword = VolumeKey.derivePasswordKey(config, password, provider);
        volume.setPasswordBasedVolumeKey(derivedPassword);
      }
      volume.readConfigAndInitializeVolume();
      return volume;
    }

    public void create() throws EncFSUnsupportedException, IOException, EncFSInvalidConfigException, EncFSInvalidPasswordException, EncFSCorruptDataException {
      EncFSConfig config = volume.getVolumeConfiguration();
      EncFSFileProvider fileProvider = volume.getFileProvider();

      // Create a random volume VolumeCryptKey + IV pair
      byte[] randVolKey = new byte[config.getVolumeKeySizeInBits() / 8 + EncFSVolume.IV_LENGTH_IN_BYTES];
      new SecureRandom().nextBytes(randVolKey);

      VolumeKey.encodeVolumeKey(config, password, randVolKey, provider);
      EncFSConfigWriter.writeConfig(fileProvider, config, password);
    }
  }

  public FileProviderBuilder withRootPath(String rootPath) {
    return new FileProviderBuilder(new EncFSVolume(), rootPath);
  }

  public FileProviderBuilder withFileProvider(EncFSFileProvider fileProvider) {
    return new FileProviderBuilder(new EncFSVolume(), fileProvider);
  }
}
