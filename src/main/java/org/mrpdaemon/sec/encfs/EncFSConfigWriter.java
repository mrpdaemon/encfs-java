package org.mrpdaemon.sec.encfs;

import java.io.IOException;
import java.io.OutputStream;

public class EncFSConfigWriter {

	private static String createConfigFileContents(EncFSConfig config, String password) {
		// XXX: This implementation is pretty horrible, but it works :)
		String result = "";

		result += "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?>\n";
		result += "<!DOCTYPE boost_serialization>\n";
		result += "<boost_serialization signature=\"serialization::archive\" version=\"9\">\n";
		result += " <cfg class_id=\"0\" tracking_level=\"0\" version=\"20\">\n";
		result += "\t<version>20100713</version>\n";
		result += "\t<creator>encfs-java 0.1</creator>\n";
		result += "\t<cipherAlg class_id=\"1\" tracking_level=\"0\" version=\"0\">\n";
		result += "\t\t<name>ssl/aes</name>\n";
		result += "\t\t<major>3</major>\n";
		result += "\t\t<minor>0</minor>\n";
		result += "\t</cipherAlg>\n";

		result += "\t<nameAlg>\n";
		if (config.getNameAlgorithm() == EncFSConfig.ENCFS_CONFIG_NAME_ALG_BLOCK) {
			result += "\t\t<name>nameio/block</name>\n";
			result += "\t\t<major>3</major>\n";
			result += "\t\t<minor>0</minor>\n";
		} else {
			assert (config.getNameAlgorithm() == EncFSConfig.ENCFS_CONFIG_NAME_ALG_STREAM);
			result += "\t\t<name>nameio/stream</name>\n";
			result += "\t\t<major>2</major>\n";
			result += "\t\t<minor>1</minor>\n";
		}
		result += "\t</nameAlg>\n";

		result += "\t<keySize>" + Integer.toString(config.getVolumeKeySize()) + "</keySize>\n";

		result += "\t<blockSize>" + Integer.toString(config.getBlockSize()) + "</blockSize>\n";

		result += "\t<uniqueIV>" + (config.isUniqueIV() == true ? "1" : "0") + "</uniqueIV>\n";

		result += "\t<chainedNameIV>" + (config.isChainedNameIV() == true ? "1" : "0") + "</chainedNameIV>\n";

		// XXX: We don't support external IV chaining yet
		result += "\t<externalIVChaining>0</externalIVChaining>\n";

		// XXX: We don't properly support holes in files either
		result += "\t<blockMACBytes>0</blockMACBytes>\n";
		result += "\t<blockMACRandBytes>0</blockMACRandBytes>\n";
		result += "\t<allowHoles>" + (config.isHolesAllowed() == true ? "1" : "0") + "</allowHoles>\n";

		result += "\t<encodedKeySize>" + Integer.toString(config.getEncodedKeyLength()) + "</encodedKeySize>\n";
		result += "\t<encodedKeyData>" + config.getEncodedKeyStr() + "\n</encodedKeyData>\n";

		result += "\t<saltLen>" + Integer.toString(config.getSaltLength()) + "</saltLen>\n";
		result += "\t<saltData>" + config.getSaltStr() + "\n</saltData>\n";

		result += "\t<kdfIterations>" + Integer.toString(config.getIterationCount()) + "</kdfIterations>\n";

		// XXX: We don't support custom KDF durations
		result += "\t<desiredKDFDuration>500</desiredKDFDuration>\n";

		result += "  </cfg>\n";
		result += "</boost_serialization>\n";

		return result;
	}

	public static void writeConfig(EncFSFileProvider fileProvider, EncFSConfig config, String password)
			throws EncFSUnsupportedException, IOException {
		String configFileName = "/" + EncFSVolume.ENCFS_VOLUME_CONFIG_FILE_NAME;

		if (fileProvider.exists(configFileName)) {
			throw new EncFSUnsupportedException("Config file already exists");
		}

		OutputStream os = fileProvider.openOutputStream(configFileName);

		String configFileContents = createConfigFileContents(config, password);

		os.write(configFileContents.getBytes());
		os.close();
	}
}