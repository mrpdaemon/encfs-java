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
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;

class BlockCryptography {

	public static Cipher newBlockCipher() throws EncFSUnsupportedException {
		return EncFSCrypto.getCipher(EncFSCrypto.BLOCK_CIPHER);
	}

	private static byte[] blockOperation(EncFSVolume volume, byte[] ivSeed,
			byte[] data, int opMode) throws InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = volume.getBlockCipher();
		EncFSCrypto.cipherInit(volume, opMode, cipher, ivSeed);
		return cipher.doFinal(data);
	}

	public static byte[] blockDecode(EncFSVolume volume, byte[] ivSeed,
			byte[] data) throws InvalidAlgorithmParameterException,
			IllegalBlockSizeException, BadPaddingException {
		return blockOperation(volume, ivSeed, data, Cipher.DECRYPT_MODE);
	}

	public static byte[] blockEncode(EncFSVolume volume, byte[] ivSeed,
			byte[] data) throws IllegalBlockSizeException,
			InvalidAlgorithmParameterException, BadPaddingException {
		return blockOperation(volume, ivSeed, data, Cipher.ENCRYPT_MODE);
	}
}
