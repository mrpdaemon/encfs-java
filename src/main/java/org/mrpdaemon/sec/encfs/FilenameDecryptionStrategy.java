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

// Common class for all filename decryption strategies
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

	// Decryption implementation to be provided by subclass
	protected abstract String decryptImpl(String fileName)
			throws EncFSCorruptDataException, EncFSChecksumException;

	// Decrypt the given filename
	public String decrypt(String filename) throws EncFSChecksumException,
			EncFSCorruptDataException {
		if (volume.getConfig().getFilenameAlgorithm() != algorithm) {
			throw new IllegalStateException(
					"only accessable when algorithm is " + algorithm);
		}

		return decryptImpl(filename);
	}
}
