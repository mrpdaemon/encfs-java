package org.mrpdaemon.sec.encfs;

/**
 * User: lars
 */
abstract class FilenameDecryptionStrategy {

	private final EncFSVolume volume;
	private final String volumePath;
	private final EncFSFilenameEncryptionAlgorithm algorithm;

	String getVolumePath() {
		return volumePath;
	}

	EncFSVolume getVolume() {
		return volume;
	}

	FilenameDecryptionStrategy(EncFSVolume volume, String volumePath,
			EncFSFilenameEncryptionAlgorithm algorithm) {
		this.volume = volume;
		this.volumePath = volumePath;
		this.algorithm = algorithm;
	}

	protected abstract String decryptImpl(String fileName)
			throws EncFSCorruptDataException, EncFSChecksumException;

	public String decrypt(String filename) throws EncFSChecksumException,
			EncFSCorruptDataException {
		if (volume.getConfig().getAlgorithm() != algorithm) {
			throw new IllegalStateException(
					"only accessable when algorithm is " + algorithm);
		}

		return decryptImpl(filename);
	}
}
