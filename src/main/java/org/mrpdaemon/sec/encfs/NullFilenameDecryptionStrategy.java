package org.mrpdaemon.sec.encfs;

public class NullFilenameDecryptionStrategy extends FilenameDecryptionStrategy {

	public NullFilenameDecryptionStrategy(EncFSVolume volume, String volumePath) {
		super(volume, volumePath, EncFSAlgorithm.NULL);
	}

	@Override
	protected String decryptImpl(String fileName)
			throws EncFSCorruptDataException, EncFSChecksumException {
		EncFSFile rootDir = getVolume().getRootDir();
		// Filter out config file
		if (getVolumePath().equals(rootDir.getPath())
				&& fileName.equals(EncFSVolume.CONFIG_FILE_NAME)) {
			return null;
		}
		return fileName;
	}
}
