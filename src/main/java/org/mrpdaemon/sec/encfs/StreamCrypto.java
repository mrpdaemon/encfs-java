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
import javax.crypto.Mac;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.util.Arrays;
import java.util.StringTokenizer;

// Static methods for stream cryptography
public class StreamCrypto {

	// Returns a stream cipher
	public static Cipher newStreamCipher() throws EncFSUnsupportedException {
		return EncFSCrypto.getCipher(EncFSCrypto.STREAM_CIPHER);
	}

	// Stream decryption implementation
	private static byte[] streamDecrypt(Cipher cipher, Mac mac, Key key,
			byte[] iv, byte[] ivSeed, byte[] data, int offset, int len)
			throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// First round uses IV seed + 1 for IV generation
		byte[] ivSeedPlusOne = EncFSCrypto.incrementIvSeedByOne(ivSeed);

		EncFSCrypto.cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv,
				ivSeedPlusOne);
		byte[] firstDecResult = cipher.doFinal(data, offset, len);

		EncFSCrypto.unshuffleBytes(firstDecResult);

		byte[] flipBytesResult = EncFSCrypto.flipBytes(firstDecResult);

		// Second round of decryption with IV seed itself used for IV generation
		EncFSCrypto.cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv,
				ivSeed);
		byte[] result = cipher.doFinal(flipBytesResult);

		EncFSCrypto.unshuffleBytes(result);

		return result;
	}

	// Stream decryption implementation
	static byte[] streamDecrypt(Cipher cipher, Mac mac, Key key, byte[] iv,
			byte[] ivSeed, byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamDecrypt(cipher, mac, key, iv, ivSeed, data, 0, data.length);
	}

	// Stream decryption implementation
	public static byte[] streamDecrypt(EncFSVolume volume, byte[] ivSeed,
			byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		Cipher streamCipher = volume.getStreamCipher();
		return streamDecrypt(streamCipher, volume.getMAC(), volume.getKey(),
				volume.getIV(), ivSeed, data);
	}

	// Stream decryption implementation
	public static byte[] streamDecrypt(EncFSVolume volume, byte[] ivSeed,
			byte[] data, int offset, int len) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamDecrypt(volume.getStreamCipher(), volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data, offset, len);
	}

	// Stream encryption implementation
	private static byte[] streamEncrypt(Cipher cipher, Mac mac, Key key,
			byte[] iv, byte[] ivSeed, byte[] data, int offset, int len)
			throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// First round uses IV seed + 1 for IV generation
		byte[] ivSeedPlusOne = EncFSCrypto.incrementIvSeedByOne(ivSeed);

		byte[] encBuf = Arrays.copyOfRange(data, offset, offset + len);
		EncFSCrypto.shuffleBytes(encBuf);

		EncFSCrypto.cipherInit(key, mac, Cipher.ENCRYPT_MODE, cipher, iv,
				ivSeed);
		byte[] firstEncResult = cipher.doFinal(encBuf);

		byte[] flipBytesResult = EncFSCrypto.flipBytes(firstEncResult);

		EncFSCrypto.shuffleBytes(flipBytesResult);

		// Second round of encryption with IV seed itself used for IV generation
		EncFSCrypto.cipherInit(key, mac, Cipher.ENCRYPT_MODE, cipher, iv,
				ivSeedPlusOne);

		return cipher.doFinal(flipBytesResult);
	}

	// Stream encryption implementation
	static byte[] streamEncrypt(Cipher cipher, Mac mac, Key key, byte[] iv,
			byte[] ivSeed, byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamEncrypt(cipher, mac, key, iv, ivSeed, data, 0, data.length);
	}

	// Stream encryption implementation
	public static byte[] streamEncrypt(EncFSVolume volume, byte[] ivSeed,
			byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamEncrypt(volume.getStreamCipher(), volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data);
	}

	// Stream encryption implementation
	public static byte[] streamEncrypt(EncFSVolume volume, byte[] ivSeed,
			byte[] data, int offset, int len) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamEncrypt(volume.getStreamCipher(), volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data, offset, len);
	}

	/**
	 * Compute chain IV for the given volume path
	 * 
	 * @param volume
	 *            Volume to compute chain IV for
	 * @param volumePath
	 *            Volume path to compute chain IV for
	 * @return Computed chain IV
	 */
	public static byte[] computeChainIv(EncFSVolume volume, String volumePath) {
		byte[] chainIv = new byte[8];
		StringTokenizer st = new StringTokenizer(volumePath,
				EncFSVolume.PATH_SEPARATOR);
		while (st.hasMoreTokens()) {
			String curPath = st.nextToken();
			if ((curPath.length() > 0)
					&& (!curPath.equals(EncFSVolume.PATH_SEPARATOR))) {
				byte[] encodeBytes;
				if (volume.getConfig().getFilenameAlgorithm() == EncFSFilenameEncryptionAlgorithm.BLOCK) {
					encodeBytes = EncFSCrypto
							.getBytesForBlockAlgorithm(curPath);
				} else {
					encodeBytes = curPath.getBytes();
				}

				// Update chain IV
				EncFSCrypto.mac64(volume.getMAC(), encodeBytes, chainIv);
			}
		}

		return chainIv;
	}
}
