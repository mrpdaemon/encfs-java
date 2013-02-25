package org.mrpdaemon.sec.encfs;

public class NullFilenameEncryptionStrategy extends FilenameEncryptionStrategy {

	public NullFilenameEncryptionStrategy(EncFSVolume volume, String volumePath) {
		super(volume, volumePath, EncFSFilenameEncryptionAlgorithm.NULL);
	}

	@Override
	protected String encryptImpl(String fileName) {
		return fileName;
	}
}
