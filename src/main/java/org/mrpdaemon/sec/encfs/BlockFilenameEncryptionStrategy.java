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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

// Implementation of block filename encryption strategy
class BlockFilenameEncryptionStrategy extends BasicFilenameEncryptionStrategy {

	BlockFilenameEncryptionStrategy(EncFSVolume volume, String volumePath) {
		super(volume, volumePath, EncFSFilenameEncryptionAlgorithm.BLOCK);
	}

	// Block encryption
	@Override
	protected byte[] encryptConcrete(EncFSVolume volume,
			byte[] paddedDecFileName, byte[] fileIv)
			throws EncFSCorruptDataException {
		try {
			return BlockCrypto.blockEncrypt(volume, fileIv, paddedDecFileName);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e);
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e);
		}
	}

	// Padding implementation
	protected byte[] getPaddedDecFilename(byte[] decFileName) {
		// Pad to the nearest 16 bytes, add a full block if needed
		int padBytesSize = 16;
		int padLen = padBytesSize - (decFileName.length % padBytesSize);
		if (padLen == 0) {
			padLen = padBytesSize;
		}
		byte[] paddedDecFileName = Arrays.copyOf(decFileName,
				decFileName.length + padLen);
		Arrays.fill(paddedDecFileName, decFileName.length,
				paddedDecFileName.length, (byte) padLen);
		return paddedDecFileName;
	}
}
