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

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

// Class containing static methods implementing volume key functionality
class VolumeKey {

	// Derive volume key for the given config and password-based key/IV data
	private static byte[] encryptVolumeKey(EncFSConfig config,
			byte[] pbkdf2Data, byte[] volKeyData)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException {
		// Prepare key/IV for decryption
		int keySizeInBytes = config.getVolumeKeySizeInBits() / 8;
		byte[] passKeyData = Arrays.copyOfRange(pbkdf2Data, 0, keySizeInBytes);
		byte[] passIvData = Arrays.copyOfRange(pbkdf2Data, keySizeInBytes,
				keySizeInBytes + EncFSVolume.IV_LENGTH_IN_BYTES);

		Key passKey = EncFSCrypto.newKey(passKeyData);

		// Encrypt the volume key data
		Mac mac = encryptVolumeKeyData(passKey);

		// Calculate MAC for the key
		byte[] mac32 = EncFSCrypto.mac32(mac, volKeyData, new byte[0]);
		byte[] cipherVolKeyData = EncFSCrypto.encryptKeyData(volKeyData,
				passIvData, passKey, mac, mac32);

		// Combine MAC with key data
		byte[] result = new byte[mac32.length + cipherVolKeyData.length];

		System.arraycopy(mac32, 0, result, 0, mac32.length);
		System.arraycopy(cipherVolKeyData, 0, result, mac32.length,
				cipherVolKeyData.length);

		return result;
	}

	private static Mac encryptVolumeKeyData(Key passKey)
			throws EncFSUnsupportedException, EncFSInvalidConfigException {
		Mac mac;
		try {
			mac = EncFSCrypto.newMac(passKey);
		} catch (InvalidKeyException e) {
			throw new EncFSInvalidConfigException(e);
		}
		return mac;
	}

	// Derive volume key for the given config and password-based key/IV data
	protected static byte[] decryptVolumeKey(EncFSConfig config,
			byte[] pbkdf2Data) throws EncFSChecksumException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException {
		// Decode Base64 encoded ciphertext data
		// TODO: validate key/IV lengths
		byte[] cipherVolKeyData;
		try {
			cipherVolKeyData = EncFSBase64.decode(config
					.getBase64EncodedVolumeKey());
		} catch (IOException e) {
			throw new EncFSInvalidConfigException("Corrupt key data in config");
		}

		byte[] encryptedVolKey = Arrays.copyOfRange(cipherVolKeyData, 4,
				cipherVolKeyData.length);

		// Prepare key/IV for decryption
		int keySizeInBytes = config.getVolumeKeySizeInBits() / 8;
		byte[] passKeyData = Arrays.copyOfRange(pbkdf2Data, 0, keySizeInBytes);
		byte[] passIvData = Arrays.copyOfRange(pbkdf2Data, keySizeInBytes,
				keySizeInBytes + EncFSVolume.IV_LENGTH_IN_BYTES);

		Key passKey = EncFSCrypto.newKey(passKeyData);
		byte[] ivSeed = Arrays.copyOfRange(cipherVolKeyData, 0, 4);

		// Decrypt the volume key data
		Mac mac = encryptVolumeKeyData(passKey);
		byte[] clearVolKeyData = decryptVolumeKeyData(encryptedVolKey,
				passIvData, passKey, ivSeed, mac);

		// Perform checksum computation
		byte[] mac32 = EncFSCrypto.mac32(mac, clearVolKeyData, new byte[0]);

		if (!Arrays.equals(ivSeed, mac32)) {
			throw new EncFSChecksumException("Volume key checksum mismatch");
		}

		return clearVolKeyData;
	}

	// Decrypt volume key data
	private static byte[] decryptVolumeKeyData(byte[] encryptedVolKey,
			byte[] passIvData, Key passKey, byte[] ivSeed, Mac mac)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException {
		byte[] clearVolKeyData;
		try {
			clearVolKeyData = StreamCrypto.streamDecrypt(
					StreamCrypto.newStreamCipher(), mac, passKey, passIvData,
					ivSeed, encryptedVolKey);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSInvalidConfigException(e);
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e);
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e);
		}
		return clearVolKeyData;
	}

	// Derive password-based key from input/config parameters using PBKDF2
	protected static byte[] deriveKeyDataFromPassword(EncFSConfig config,
			String password, EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSInvalidConfigException, EncFSUnsupportedException {
		// Decode base 64 salt data
		byte[] cipherSaltData;
		try {
			cipherSaltData = EncFSBase64.decode(config.getBase64Salt());
		} catch (IOException e) {
			throw new EncFSInvalidConfigException("Corrupt salt data in config");
		}

		if (pbkdf2Provider == null) {
			// Execute PBKDF2 to derive key data from the password
			SecretKeyFactory f;
			try {
				f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
			} catch (NoSuchAlgorithmException e) {
				throw new EncFSUnsupportedException(e);
			}
			KeySpec ks = new PBEKeySpec(password.toCharArray(), cipherSaltData,
					config.getIterationForPasswordKeyDerivationCount(),
					config.getVolumeKeySizeInBits()
							+ EncFSVolume.IV_LENGTH_IN_BYTES * 8);
			SecretKey pbkdf2Key;
			try {
				pbkdf2Key = f.generateSecret(ks);
			} catch (InvalidKeySpecException e) {
				throw new EncFSInvalidConfigException(e);
			}

			return pbkdf2Key.getEncoded();
		} else {
			return pbkdf2Provider.doPBKDF2(password.length(), password,
					cipherSaltData.length, cipherSaltData,
					config.getIterationForPasswordKeyDerivationCount(),
					(config.getVolumeKeySizeInBits() / 8)
							+ EncFSVolume.IV_LENGTH_IN_BYTES);
		}
	}

	// Encodes the given volume key using the supplied password parameters
	protected static void encodeVolumeKey(EncFSConfig config, String password,
			byte[] volKey, EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSInvalidConfigException, EncFSUnsupportedException,
			EncFSCorruptDataException {
		SecureRandom random = new SecureRandom();
		config.setSaltLengthBytes(20);

		// Generate random salt
		byte[] salt = new byte[20];
		random.nextBytes(salt);
		config.setBase64Salt(EncFSBase64.encodeBytes(salt));

		// Get password key data
		byte[] pbkdf2Data = deriveKeyDataFromPassword(config, password,
				pbkdf2Provider);

		// Encode volume key
		byte[] encodedVolKey = encryptVolumeKey(config, pbkdf2Data, volKey);

		config.setEncodedKeyLengthInBytes(encodedVolKey.length);
		config.setBase64EncodedVolumeKey(EncFSBase64.encodeBytes(encodedVolKey));
	}
}
