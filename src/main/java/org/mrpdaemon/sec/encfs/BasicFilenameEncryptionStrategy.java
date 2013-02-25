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

// Common class for filename encryption strategies
abstract class BasicFilenameEncryptionStrategy extends
		FilenameEncryptionStrategy {

	BasicFilenameEncryptionStrategy(EncFSVolume volume, String volumePath,
			EncFSFilenameEncryptionAlgorithm algorithm) {
		super(volume, volumePath, algorithm);
	}

	// Actual encryption to be implemented by the subclass
	protected abstract byte[] encryptConcrete(EncFSVolume volume,
			byte[] paddedDecFileName, byte[] fileIv)
			throws EncFSCorruptDataException;

	// Filename encryption implementation
	protected String encryptImpl(String fileName)
			throws EncFSCorruptDataException {
		EncFSVolume volume = getVolume();
		String volumePath = getVolumePath();
		EncFSConfig config = volume.getConfig();

		byte[] decFileName = fileName.getBytes();
		byte[] paddedDecFileName = getPaddedDecFilename(decFileName);
		byte[] chainIv = EncFSCrypto.computeChainedIV(volume, volumePath,
				config);
		byte[] mac16 = getMac16(volume, paddedDecFileName, chainIv);
		byte[] macBytes = EncFSCrypto.getMacBytes(mac16);
		byte[] fileIv = EncFSCrypto.computeFileIV(chainIv, macBytes);

		byte[] encFileName = encryptConcrete(volume, paddedDecFileName, fileIv);

		return getBase256Filename(mac16, encFileName);
	}

	// Filename padding implementation hook for subclasses
	protected abstract byte[] getPaddedDecFilename(byte[] decFileName);

	// Returns the base 256 filename for the given encrypted filename
	private String getBase256Filename(byte[] mac16, byte[] encFileName) {
		// current versions store the checksum at the beginning (encfs 0.x
		// stored checksums at the end)

		byte[] base256FileName = new byte[encFileName.length + 2];
		base256FileName[0] = mac16[0];
		base256FileName[1] = mac16[1];
		System.arraycopy(encFileName, 0, base256FileName, 2, encFileName.length);

		byte[] fileNameOutput = EncFSBase64.encodeEncfs(base256FileName);

		return new String(fileNameOutput);
	}

	// Returns the mac16 of the given file name
	private byte[] getMac16(EncFSVolume volume, byte[] paddedDecFileName,
			byte[] chainIv) {
		if (volume.getConfig().isChainedNameIV()) {
			return EncFSCrypto.mac16(volume.getMAC(), paddedDecFileName,
					Arrays.copyOf(chainIv, chainIv.length));
		} else {
			return EncFSCrypto.mac16(volume.getMAC(), paddedDecFileName);
		}
	}

}
