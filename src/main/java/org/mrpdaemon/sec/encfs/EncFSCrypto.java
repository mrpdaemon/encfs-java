/*
 * EncFS Java Library
 * Copyright (C) 2011 Mark R. Pariente
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

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * Class containing static methods implementing crypto functionality for the
 * rest of the library
 */
public final class EncFSCrypto {
	public final static String STREAM_CIPHER = "AES/CFB/NoPadding";
	public final static String BLOCK_CIPHER = "AES/CBC/NoPadding";

	public EncFSCrypto() {
	}

	// Create a new Mac object for the given key.
	static Mac newMac(Key key) throws InvalidKeyException,
			EncFSUnsupportedException {
		Mac hmac;
		try {
			hmac = Mac.getInstance("HmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new EncFSUnsupportedException(e);
		}
		SecretKeySpec hmacKey = new SecretKeySpec(key.getEncoded(), "HmacSHA1");
		hmac.init(hmacKey);
		return hmac;
	}

	// Creates a new AES key with the given key bytes.
	static Key newKey(byte[] keyBytes) {
		return new SecretKeySpec(keyBytes, "AES");
	}

	// Return a a cipher with the given specification
	static Cipher getCipher(String cipherSpec) throws EncFSUnsupportedException {
		try {
			return Cipher.getInstance(cipherSpec);
		} catch (NoSuchAlgorithmException e) {
			throw new EncFSUnsupportedException(e);
		} catch (NoSuchPaddingException e) {
			throw new EncFSUnsupportedException(e);
		}
	}

	// Returns an IvParameterSpec for the given iv/seed
	private static IvParameterSpec newIvSpec(Mac mac, byte[] iv, byte[] ivSeed) {

		// TODO: Verify input byte[] lengths, raise Exception on bad ivSeed
		// length

		byte[] concat = new byte[EncFSVolume.IV_LENGTH_IN_BYTES + 8];
		System.arraycopy(iv, 0, concat, 0, EncFSVolume.IV_LENGTH_IN_BYTES);

		if (ivSeed.length == 4) {
			// Concat 4 bytes of IV seed and 4 bytes of 0
			for (int i = EncFSVolume.IV_LENGTH_IN_BYTES; i < EncFSVolume.IV_LENGTH_IN_BYTES + 4; i++)
				concat[i] = ivSeed[EncFSVolume.IV_LENGTH_IN_BYTES + 3 - i];
			for (int i = EncFSVolume.IV_LENGTH_IN_BYTES + 4; i < EncFSVolume.IV_LENGTH_IN_BYTES + 8; i++)
				concat[i] = 0;
		} else {
			// Use 8 bytes from IV seed
			for (int i = EncFSVolume.IV_LENGTH_IN_BYTES; i < EncFSVolume.IV_LENGTH_IN_BYTES + 8; i++)
				concat[i] = ivSeed[EncFSVolume.IV_LENGTH_IN_BYTES + 7 - i];
		}

		// Take first 16 bytes of the SHA-1 output (20 bytes)
		byte[] ivResult = Arrays.copyOfRange(mac.doFinal(concat), 0,
				EncFSVolume.IV_LENGTH_IN_BYTES);

		return new IvParameterSpec(ivResult);
	}

	// Initialize the given cipher in the requested mode
	static void cipherInit(Key key, Mac mac, int opMode, Cipher cipher,
			byte[] iv, byte[] ivSeed) throws InvalidAlgorithmParameterException {
		try {
			cipher.init(opMode, key, newIvSpec(mac, iv, ivSeed));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	// Initialize the given cipher for a volume with the given parameters
	static void cipherInit(EncFSVolume volume, int opMode, Cipher cipher,
			byte[] ivSeed) throws InvalidAlgorithmParameterException {
		cipherInit(volume.getKey(), volume.getMAC(), opMode, cipher,
				volume.getIV(), ivSeed);
	}

	// Encrypt the key data
	static byte[] encryptKeyData(byte[] volKeyData, byte[] passIvData,
			Key passKey, Mac mac, byte[] mac32)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException {
		byte[] cipherVolKeyData;
		try {
			cipherVolKeyData = StreamCrypto.streamEncrypt(
					StreamCrypto.newStreamCipher(), mac, passKey, passIvData,
					mac32, volKeyData);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSInvalidConfigException(e);
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e);
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e);
		}
		return cipherVolKeyData;
	}

	// Block encoding helper to do padding
	static byte[] getBytesForBlockAlgorithm(String curPath) {
		byte[] encodeBytes;// Only pad for block mode
		int padLen = 16 - (curPath.length() % 16);
		if (padLen == 0) {
			padLen = 16;
		}
		encodeBytes = new byte[curPath.length() + padLen];

		for (int i = 0; i < curPath.length(); i++) {
			encodeBytes[i] = curPath.getBytes()[i];
		}

		// Pad to the nearest 16 bytes, add a full block if needed
		for (int i = 0; i < padLen; i++) {
			encodeBytes[curPath.length() + i] = (byte) padLen;
		}
		return encodeBytes;
	}

	/**
	 * Decode the given fileName under the given volume and volume path
	 * 
	 * @param volume
	 *            Volume hosting the file
	 * @param fileName
	 *            Encrypted file name
	 * @param volumePath
	 *            Cleartext path of the file in the volume
	 * 
	 * @return Decrypted file name
	 * 
	 * @throws EncFSCorruptDataException
	 *             Corrupt data in input name
	 * @throws EncFSChecksumException
	 *             File checksum mismatch
	 */
	public static String decodeName(EncFSVolume volume, String fileName,
			String volumePath) throws EncFSCorruptDataException,
			EncFSChecksumException {

		EncFSFilenameEncryptionAlgorithm algorithm = volume.getConfig()
				.getFilenameAlgorithm();
		switch (algorithm) {
		case NULL:
			return new NullFilenameDecryptionStrategy(volume, volumePath)
					.decrypt(fileName);
		case BLOCK:
			return new BlockFilenameDecryptionStrategy(volume, volumePath)
					.decrypt(fileName);
		case STREAM:
			return new StreamFilenameDecryptionStrategy(volume, volumePath)
					.decrypt(fileName);
		default:
			throw new IllegalStateException("not implemented:" + algorithm);
		}
	}

	/**
	 * Encode the given fileName under the given volume and volume path
	 * 
	 * @param volume
	 *            Volume hosting the file
	 * @param fileName
	 *            Cleartext file name
	 * @param volumePath
	 *            Cleartext path of the file in the volume
	 * 
	 * @return Encrypted file name
	 * 
	 * @throws EncFSCorruptDataException
	 *             Corrupt data in config file
	 */
	public static String encodeName(EncFSVolume volume, String fileName,
			String volumePath) throws EncFSCorruptDataException {

		EncFSFilenameEncryptionAlgorithm algorithm = volume.getConfig()
				.getFilenameAlgorithm();
		switch (algorithm) {
		case NULL:
			return new NullFilenameEncryptionStrategy(volume, volumePath)
					.encrypt(fileName);
		case BLOCK:
			return new BlockFilenameEncryptionStrategy(volume, volumePath)
					.encrypt(fileName);
		case STREAM:
			return new StreamFilenameEncryptionStrategy(volume, volumePath)
					.encrypt(fileName);
		default:
			throw new IllegalStateException("not implemented:" + algorithm);
		}
	}

	/**
	 * Encode a given path under the given volume and volume path
	 * 
	 * @param volume
	 *            Volume hosting the path
	 * @param pathName
	 *            Cleartext name of the path to encode (relative to volumePath)
	 * @param volumePath
	 *            Cleartext volume path containing the path to encode
	 * @return Encrypted path
	 */
	public static String encodePath(EncFSVolume volume, String pathName,
			String volumePath) throws EncFSCorruptDataException {
		String[] pathParts = pathName.split(EncFSVolume.PATH_SEPARATOR);
		String tmpVolumePath = volumePath;
		String result = "";
		if (pathName.startsWith(EncFSVolume.PATH_SEPARATOR)) {
			result += EncFSVolume.PATH_SEPARATOR;
		}

		for (String pathPart : pathParts) {
			// Check that we have a valid pathPart (to handle cases of // in the
			// path)
			if (pathPart.length() > 0) {
				String toEncFileName = EncFSCrypto.encodeName(volume, pathPart,
						tmpVolumePath);

				if (result.length() > 0
						&& !result.endsWith(EncFSVolume.PATH_SEPARATOR)) {
					result += EncFSVolume.PATH_SEPARATOR;
				}

				result += toEncFileName;

				if (!tmpVolumePath.endsWith(EncFSVolume.PATH_SEPARATOR)) {
					tmpVolumePath += EncFSVolume.PATH_SEPARATOR;
				}
				tmpVolumePath += pathPart;
			}
		}

		return result;
	}

	// Compute 64-bit MAC over the given input bytes
	static byte[] mac64(Mac mac, byte[] input, int inputOffset) {
		return mac64(mac, input, inputOffset, input.length - inputOffset);
	}

	// Compute 64-bit MAC over the given input bytes
	static byte[] mac64(Mac mac, byte[] input, int inputOffset, int inputLen) {
		mac.reset();
		mac.update(input, inputOffset, inputLen);
		byte[] macResult = mac.doFinal();
		byte[] mac64 = new byte[8];
		for (int i = 0; i < 19; i++)
			// Note the 19 not 20
			mac64[i % 8] ^= macResult[i];

		return mac64;
	}

	// Compute 64-bit MAC
	private static byte[] mac64(Mac mac, byte[] input) {

		byte[] macResult = mac.doFinal(input);
		byte[] mac64 = new byte[8];
		for (int i = 0; i < 19; i++)
			// Note the 19 not 20
			mac64[i % 8] ^= macResult[i];

		return mac64;
	}

	// Compute 32-bit MAC
	private static byte[] mac32(Mac mac, byte[] input) {
		byte[] mac64 = mac64(mac, input);
		byte[] mac32 = new byte[4];
		mac32[0] = (byte) (mac64[4] ^ mac64[0]);
		mac32[1] = (byte) (mac64[5] ^ mac64[1]);
		mac32[2] = (byte) (mac64[6] ^ mac64[2]);
		mac32[3] = (byte) (mac64[7] ^ mac64[3]);

		return mac32;
	}

	// Compute 16-bit MAC
	static byte[] mac16(Mac mac, byte[] input) {
		byte[] mac32 = mac32(mac, input);
		byte[] mac16 = new byte[2];
		mac16[0] = (byte) (mac32[2] ^ mac32[0]);
		mac16[1] = (byte) (mac32[3] ^ mac32[1]);

		return mac16;
	}

	// Compute 64-bit MAC and update chainedIv
	static byte[] mac64(Mac mac, byte[] input, byte[] chainedIv) {
		byte[] concat = new byte[input.length + chainedIv.length];
		System.arraycopy(input, 0, concat, 0, input.length);
		for (int i = input.length; i < input.length + chainedIv.length; i++) {
			concat[i] = chainedIv[7 - (i - input.length)];
		}
		byte[] macResult = mac.doFinal(concat);
		byte[] mac64 = new byte[8];
		for (int i = 0; i < 19; i++)
			// Note the 19 not 20
			mac64[i % 8] ^= macResult[i];

		if (chainedIv.length > 0) {
			// Propagate the result as the new chained IV
			System.arraycopy(mac64, 0, chainedIv, 0, 8);
		}

		return mac64;
	}

	// Compute 32-bit MAC and update chainedIv
	static byte[] mac32(Mac mac, byte[] input, byte[] chainedIv) {
		byte[] mac64 = mac64(mac, input, chainedIv);
		byte[] mac32 = new byte[4];
		mac32[0] = (byte) (mac64[4] ^ mac64[0]);
		mac32[1] = (byte) (mac64[5] ^ mac64[1]);
		mac32[2] = (byte) (mac64[6] ^ mac64[2]);
		mac32[3] = (byte) (mac64[7] ^ mac64[3]);

		return mac32;
	}

	// Compute 16-bit MAC and update chainedIv
	static byte[] mac16(Mac mac, byte[] input, byte[] chainedIv) {
		byte[] mac32 = mac32(mac, input, chainedIv);
		byte[] mac16 = new byte[2];
		mac16[0] = (byte) (mac32[2] ^ mac32[0]);
		mac16[1] = (byte) (mac32[3] ^ mac32[1]);

		return mac16;
	}

	// Reverse the "shuffle bytes" transformation
	static void unshuffleBytes(byte[] input) {
		for (int i = (input.length - 1); i > 0; i--) {
			// Note size - 1
			input[i] ^= input[i - 1];
		}
	}

	// Apply the "shuffle bytes" transformation
	static void shuffleBytes(byte[] buf) {
		int size = buf.length;
		for (int i = 0; i < size - 1; ++i) {
			buf[i + 1] ^= buf[i];
		}
	}

	// Flip the given byte input stream
	static byte[] flipBytes(byte[] input) {
		byte[] result = new byte[input.length];

		int offset = 0;
		int bytesLeft = input.length;

		while (bytesLeft > 0) {
			// TODO: 64 should be defined?
			int toFlip = Math.min(64, bytesLeft);

			for (int i = 0; i < toFlip; i++)
				result[offset + i] = input[offset + toFlip - i - 1];

			bytesLeft -= toFlip;
			offset += toFlip;
		}

		return result;
	}

	// Increment the given IV seed by one
	static byte[] incrementIvSeedByOne(byte[] ivSeed)
			throws EncFSUnsupportedException {
		if (ivSeed.length == 4) {
			return EncFSUtil.convertIntToByteArrayBigEndian(EncFSUtil
					.convertBigEndianByteArrayToInt(ivSeed) + 1);
		} else if (ivSeed.length == 8) {
			return EncFSUtil.convertLongToByteArrayBigEndian(EncFSUtil
					.convertByteArrayToLong(ivSeed) + 1);
		} else {
			throw new EncFSUnsupportedException("Unsupported IV length");
		}
	}

	// Compute file IV
	static byte[] computeFileIV(byte[] chainIv, byte[] macBytes) {
		byte[] fileIv = new byte[8];
		for (int i = 0; i < 8; i++) {
			fileIv[i] = (byte) (macBytes[i] ^ chainIv[i]);
		}
		return fileIv;
	}

	// Return first two bytes of a given 8 byte sequence
	static byte[] getMacBytes(byte[] bytes) {
		// TODO: make sure its multiple of 16
		byte[] macBytes = new byte[8];
		macBytes[6] = bytes[0];
		macBytes[7] = bytes[1];
		return macBytes;
	}

	// Compute chained IV
	static byte[] computeChainedIV(EncFSVolume volume, String volumePath,
			EncFSConfig config) {
		// Chained IV computation
		byte[] chainIv = new byte[8];
		if (config.isChainedNameIV()) {
			chainIv = StreamCrypto.computeChainIv(volume, volumePath);
		}
		return chainIv;
	}
}
