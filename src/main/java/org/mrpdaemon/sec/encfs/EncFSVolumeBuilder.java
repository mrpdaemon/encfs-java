/*
 * EncFS Java Library
 * Copyright (C) 2013 encfs-java authors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 */
package org.mrpdaemon.sec.encfs;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * Class for building EncFSVolume objects and writing new volume files to file
 * providers.
 * 
 * Usage (in order):
 * 
 * [Required] .withFileProvider(provider) OR .withRootPath(rootPath)
 * 
 * [Optional] .withConfig(config) AND/OR .withPbkdfProvider(pbkdf2provider)
 * 
 * [Required] .withPassword(password)
 * 
 * 
 * Volume building methods: <br>
 * .writeVolumeConfig() - Write volume configuration file to the file provider <br>
 * .buildVolume() - Return an EncFSVolume
 */
public final class EncFSVolumeBuilder {

	public static class FileProviderBuilder {

		private final EncFSVolume volume;

		public FileProviderBuilder(EncFSVolume volume, String rootPath) {
			this(volume, new EncFSLocalFileProvider(new File(rootPath)));
		}

		public FileProviderBuilder(EncFSVolume volume,
				EncFSFileProvider fileProvider) {
			this.volume = volume;
			volume.setFileProvider(fileProvider);
		}

		public ConfigBuilder withConfig(EncFSConfig config) {
			return new ConfigBuilder(volume, config);
		}

		public Pbkdf2ProviderBuilder withPbkdf2Provider(
				EncFSPBKDF2Provider pbkdf2Provider)
				throws EncFSUnsupportedException, IOException,
				EncFSInvalidConfigException {
			return new ConfigBuilder(volume).withPbkdf2Provider(pbkdf2Provider);
		}

		public PasswordBuilder withPassword(String password)
				throws EncFSUnsupportedException, IOException,
				EncFSInvalidConfigException, EncFSCorruptDataException,
				EncFSInvalidPasswordException {
			return withPbkdf2Provider(null).withPassword(password);
		}

		public PasswordBuilder withDerivedKeyData(byte[] derivedKeyData)
				throws EncFSUnsupportedException, IOException,
				EncFSInvalidConfigException, EncFSCorruptDataException,
				EncFSInvalidPasswordException {
			return withPbkdf2Provider(null).withDerivedKeyData(derivedKeyData);
		}
	}

	public static class ConfigBuilder {

		private final EncFSVolume volume;

		public ConfigBuilder(EncFSVolume volume, EncFSConfig config) {
			this.volume = volume;
			volume.setVolumeConfig(config);
		}

		public ConfigBuilder(EncFSVolume volume)
				throws EncFSUnsupportedException, IOException,
				EncFSInvalidConfigException {
			this.volume = volume;
			EncFSFileProvider fileProvider = volume.getFileProvider();
			EncFSConfig volumeConfiguration = EncFSConfigParser.parseConfig(
					fileProvider, EncFSVolume.CONFIG_FILE_NAME);
			volume.setVolumeConfig(volumeConfiguration);
		}

		public Pbkdf2ProviderBuilder withPbkdf2Provider(
				EncFSPBKDF2Provider provider) {
			return new Pbkdf2ProviderBuilder(volume, provider);
		}

		public PasswordBuilder withPassword(String password)
				throws EncFSCorruptDataException,
				EncFSInvalidPasswordException, EncFSInvalidConfigException,
				EncFSUnsupportedException, IOException {
			return withPbkdf2Provider(null).withPassword(password);
		}

		public PasswordBuilder withDerivedKeyData(byte[] derivedKeyData)
				throws EncFSUnsupportedException, IOException,
				EncFSInvalidConfigException, EncFSCorruptDataException,
				EncFSInvalidPasswordException {
			return withPbkdf2Provider(null).withDerivedKeyData(derivedKeyData);
		}
	}

	public static class Pbkdf2ProviderBuilder {

		private final EncFSVolume volume;
		private final EncFSPBKDF2Provider provider;

		public Pbkdf2ProviderBuilder(EncFSVolume volume,
				EncFSPBKDF2Provider provider) {
			this.volume = volume;
			this.provider = provider;
		}

		public PasswordBuilder withPassword(String password) {
			return new PasswordBuilder(volume, password, provider);
		}

		public PasswordBuilder withDerivedKeyData(byte[] derivedKeyData) {
			return new PasswordBuilder(volume, derivedKeyData);
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
			volume.setDerivedKeyData(derivedPassword);

		}

		public PasswordBuilder(EncFSVolume volume, String password,
				EncFSPBKDF2Provider provider) {
			this.volume = volume;
			this.password = password;
			this.provider = provider;
		}

		/**
		 * Creates a new object representing an existing EncFS volume
		 * 
		 * @throws EncFSInvalidPasswordException
		 *             Given password is incorrect
		 * @throws EncFSCorruptDataException
		 *             Corrupt data detected (checksum error)
		 * @throws EncFSInvalidConfigException
		 *             Configuration file format not recognized
		 * @throws EncFSUnsupportedException
		 *             Unsupported EncFS version or options
		 * @throws IOException
		 *             File provider returned I/O error
		 */
		public EncFSVolume buildVolume() throws EncFSUnsupportedException,
				IOException, EncFSInvalidConfigException,
				EncFSInvalidPasswordException, EncFSCorruptDataException {
			EncFSConfig config = volume.getConfig();
			if (password != null) {
				byte[] derivedKeyData = VolumeKey.deriveKeyDataFromPassword(
						config, password, provider);
				volume.setDerivedKeyData(derivedKeyData);
			}
			volume.readConfigAndInitVolume();
			return volume;
		}

		/**
		 * Writes EncFS volume configuration to the file provider
		 * 
		 * @throws EncFSInvalidPasswordException
		 *             Given password is incorrect
		 * @throws EncFSCorruptDataException
		 *             Corrupt data detected (checksum error)
		 * @throws EncFSInvalidConfigException
		 *             Configuration file format not recognized
		 * @throws EncFSUnsupportedException
		 *             Unsupported EncFS version or options
		 * @throws IOException
		 *             File provider returned I/O error
		 */
		public void writeVolumeConfig() throws EncFSUnsupportedException,
				IOException, EncFSInvalidConfigException,
				EncFSCorruptDataException {
			EncFSConfig config = volume.getConfig();
			EncFSFileProvider fileProvider = volume.getFileProvider();

			// Create a random volume VolumeCryptKey + IV pair
			byte[] randVolKey = new byte[config.getVolumeKeySizeInBits() / 8
					+ EncFSVolume.IV_LENGTH_IN_BYTES];
			new SecureRandom().nextBytes(randVolKey);

			VolumeKey.encodeVolumeKey(config, password, randVolKey, provider);
			EncFSConfigWriter.writeConfig(fileProvider, config);
		}
	}

	public FileProviderBuilder withRootPath(String rootPath) {
		return new FileProviderBuilder(new EncFSVolume(), rootPath);
	}

	public FileProviderBuilder withFileProvider(EncFSFileProvider fileProvider) {
		return new FileProviderBuilder(new EncFSVolume(), fileProvider);
	}
}
