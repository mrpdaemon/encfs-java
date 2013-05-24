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

import java.util.Arrays;

// Common class for filename decryption strategies
abstract class BasicFilenameDecryptionStrategy extends
		FilenameDecryptionStrategy {

	BasicFilenameDecryptionStrategy(EncFSVolume volume, String volumePath,
			EncFSFilenameEncryptionAlgorithm algorithm) {
		super(volume, volumePath, algorithm);
	}

	// Actual decryption to be implemented by the subclass
	protected abstract byte[] decryptConcrete(EncFSVolume volume,
			byte[] encFileName, byte[] fileIv) throws EncFSCorruptDataException;

	// Filename decryption implementation
	protected String decryptImpl(String fileName)
			throws EncFSCorruptDataException, EncFSChecksumException {
		EncFSVolume volume = getVolume();
		String volumePath = getVolumePath();
		EncFSConfig config = volume.getConfig();

		byte[] chainIv = EncFSCrypto.computeChainedIV(volume, volumePath,
				config);
		byte[] base256FileName = EncFSBase64.decodeEncfs(fileName.getBytes());
		byte[] macBytes;

		try {
			macBytes = EncFSCrypto.getMacBytes(base256FileName);
		} catch (ArrayIndexOutOfBoundsException e) {
			/*
			 * It's possible for fileName to be malformed so as to make
			 * base256FileName shorter than 2 bytes. In this case, getMacBytes()
			 * will throw an exception.
			 */
			throw new EncFSCorruptDataException(e);
		}

		byte[] encFileName = Arrays.copyOfRange(base256FileName, 2,
				base256FileName.length);
		byte[] fileIv = EncFSCrypto.computeFileIV(chainIv, macBytes);

		byte[] decFileName = decryptConcrete(volume, encFileName, fileIv);

		verifyDecryptionWorked(volume, chainIv, base256FileName, decFileName);

		return decryptPost(decFileName);
	}

	// Post decrpytion hook for subclasses
	protected abstract String decryptPost(byte[] fileName);

	// Verify that the decryption worked
	private void verifyDecryptionWorked(EncFSVolume volume, byte[] chainIv,
			byte[] base256FileName, byte[] decFileName)
			throws EncFSChecksumException {
		// Verify decryption worked
		// current versions store the checksum at the beginning (encfs 0.x
		// stored checksums at the end)
		byte[] mac16;
		if (volume.getConfig().isChainedNameIV()) {
			mac16 = EncFSCrypto.mac16(volume.getMAC(), decFileName, chainIv);
		} else {
			mac16 = EncFSCrypto.mac16(volume.getMAC(), decFileName);
		}

		byte[] expectedMac = Arrays.copyOfRange(base256FileName, 0, 2);
		if (!Arrays.equals(mac16, expectedMac)) {
			throw new EncFSChecksumException("Mismatch in file name checksum");
		}
	}
}
