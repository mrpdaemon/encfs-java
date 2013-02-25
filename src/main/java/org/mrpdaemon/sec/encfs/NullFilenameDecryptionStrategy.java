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

// Class implementing the NULL decryption strategy
public class NullFilenameDecryptionStrategy extends FilenameDecryptionStrategy {

	public NullFilenameDecryptionStrategy(EncFSVolume volume, String volumePath) {
		super(volume, volumePath, EncFSFilenameEncryptionAlgorithm.NULL);
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
