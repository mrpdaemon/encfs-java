/*
 * EncFS Java Library
 * Copyright (C) 2011-2012 Mark R. Pariente
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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Properties;

/**
 * Writer methods that write an EncFSConfig into a file
 */
public class EncFSConfigWriter {

	// Version to use if the properties file can't be read
	private static final String ENCFS_JAVA_LIB_VERSION_DEV = "dev";

	// Property file
	private static final String ENCFS_JAVA_LIB_PROPERTY_FILE = "library.properties";

	// Property key for version
	private static final String ENCFS_JAVA_LIB_VERSION_KEY = "library.version";

	// Retrieve library version
	private static String getLibraryVersion() {
		Properties prop = new Properties();
		InputStream in = EncFSConfigWriter.class
				.getResourceAsStream(ENCFS_JAVA_LIB_PROPERTY_FILE);

		if (in != null) {
			try {
				prop.load(in);
				String version = prop.getProperty(ENCFS_JAVA_LIB_VERSION_KEY);
				if (version != null) {
					return version;
				} else {
					return ENCFS_JAVA_LIB_VERSION_DEV;
				}
			} catch (IOException e) {
				return ENCFS_JAVA_LIB_VERSION_DEV;
			}
		} else {
			return ENCFS_JAVA_LIB_VERSION_DEV;
		}
	}

	// Create config file contents from a given EncFSConfig / password
	private static String createConfigFileContents(EncFSConfig config) {
		// XXX: This implementation is pretty horrible, but it works :)
		String result = "";

		result += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
		result += "<!DOCTYPE boost_serialization>\n";
		result += "<boost_serialization signature=\"serialization::archive\" version=\"9\">\n";
		result += " <cfg class_id=\"0\" tracking_level=\"0\" version=\"20\">\n";
		result += "\t<version>20100713</version>\n";
		result += "\t<creator>encfs-java " + getLibraryVersion()
				+ "</creator>\n";
		result += "\t<cipherAlg class_id=\"1\" tracking_level=\"0\" version=\"0\">\n";
		result += "\t\t<name>ssl/aes</name>\n";
		result += "\t\t<major>3</major>\n";
		result += "\t\t<minor>0</minor>\n";
		result += "\t</cipherAlg>\n";

		result += "\t<nameAlg>\n";

		EncFSFilenameEncryptionAlgorithm algorithm = config
				.getFilenameAlgorithm();
		result += "\t\t<name>" + algorithm.getIdentifier() + "</name>\n";
		result += "\t\t<major>" + algorithm.getMajor() + "</major>\n";
		result += "\t\t<minor>" + algorithm.getMinor() + "</minor>\n";

		result += "\t</nameAlg>\n";

		result += "\t<keySize>"
				+ Integer.toString(config.getVolumeKeySizeInBits())
				+ "</keySize>\n";

		result += "\t<blockSize>"
				+ Integer.toString(config.getEncryptedFileBlockSizeInBytes())
				+ "</blockSize>\n";

		result += "\t<uniqueIV>" + (config.isUseUniqueIV() ? "1" : "0")
				+ "</uniqueIV>\n";

		result += "\t<chainedNameIV>" + (config.isChainedNameIV() ? "1" : "0")
				+ "</chainedNameIV>\n";

		result += "\t<externalIVChaining>"
				+ (config.isSupportedExternalIVChaining() ? "1" : "0")
				+ "</externalIVChaining>\n";

		result += "\t<blockMACBytes>"
				+ Integer
						.toString(config.getNumberOfMACBytesForEachFileBlock())
				+ "</blockMACBytes>\n";
		result += "\t<blockMACRandBytes>"
				+ Integer.toString(config
						.getNumberOfRandomBytesInEachMACHeader())
				+ "</blockMACRandBytes>\n";

		result += "\t<allowHoles>"
				+ (config.isHolesAllowedInFiles() ? "1" : "0")
				+ "</allowHoles>\n";

		result += "\t<encodedKeySize>"
				+ Integer.toString(config.getEncodedKeyLengthInBytes())
				+ "</encodedKeySize>\n";
		result += "\t<encodedKeyData>" + config.getBase64EncodedVolumeKey()
				+ "\n</encodedKeyData>\n";

		result += "\t<saltLen>" + Integer.toString(config.getSaltLengthBytes())
				+ "</saltLen>\n";
		result += "\t<saltData>" + config.getBase64Salt() + "\n</saltData>\n";

		result += "\t<kdfIterations>"
				+ Integer.toString(config
						.getIterationForPasswordKeyDerivationCount())
				+ "</kdfIterations>\n";

		// XXX: We don't support custom KDF durations
		result += "\t<desiredKDFDuration>500</desiredKDFDuration>\n";

		result += "  </cfg>\n";
		result += "</boost_serialization>\n";

		return result;
	}

	/**
	 * Create a configuration file from the given EncFSConfig and write it to
	 * the root directory of the given EncFSFileProvider
	 */
	public static void writeConfig(EncFSFileProvider fileProvider,
			EncFSConfig config) throws EncFSUnsupportedException, IOException {
		String configFileName = fileProvider.getFilesystemRootPath()
				+ EncFSVolume.CONFIG_FILE_NAME;

		if (fileProvider.exists(configFileName)) {
			throw new EncFSUnsupportedException("Config file already exists");
		}

		String configFileContents = createConfigFileContents(config);

		OutputStream os = fileProvider.openOutputStream(configFileName,
				configFileContents.length());

		os.write(configFileContents.getBytes());
		os.close();
	}
}
