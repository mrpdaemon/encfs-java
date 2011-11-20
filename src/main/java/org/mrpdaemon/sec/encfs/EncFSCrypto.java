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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class EncFSCrypto {

	/**
	 * Create a new Mac object for the given key.
	 * 
	 * @param key  Key to create a new Mac for.
	 * @return     New Mac object.
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws EncFSUnsupportedException 
	 * @throws Exception
	 */
	public static Mac newMac(Key key) throws InvalidKeyException,
	                                         EncFSUnsupportedException {
		Mac hmac;
		try {
			hmac = Mac.getInstance("HmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new EncFSUnsupportedException(e.getMessage());
		}
		SecretKeySpec hmacKey = new SecretKeySpec(key.getEncoded(),"HmacSHA1");
		hmac.init(hmacKey);
		return hmac;
	}
	
	/**
	 * Creates a new AES key with the given key bytes.
	 * 
	 * @param keyBytes  Key data.
	 * @return          New AES key.
	 */
	public static Key newKey(byte[] keyBytes) {
		return new SecretKeySpec(keyBytes, "AES");
	}
	
	/**
	 * Returns a new stream cipher with AES/CFB/NoPadding.
	 * 
	 * @return  A new Cipher object.
	 * @throws EncFSUnsupportedException 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Cipher newStreamCipher() throws EncFSUnsupportedException {
		Cipher result = null;
		try {
			result = Cipher.getInstance("AES/CFB/NoPadding");
		} catch (NoSuchAlgorithmException e) {
			throw new EncFSUnsupportedException(e.getMessage());
		} catch (NoSuchPaddingException e) {
			throw new EncFSUnsupportedException(e.getMessage());
		}
		return result;
	}
	
	/**
	 * Returns a new block cipher with AES/CBC/NoPadding.
	 * 
	 * @return  A new Cipher object.
	 * @throws EncFSUnsupportedException 
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	public static Cipher newBlockCipher() throws EncFSUnsupportedException {
		Cipher result = null;
		try {
			result = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException e) {
			throw new EncFSUnsupportedException(e.getMessage());
		} catch (NoSuchPaddingException e) {
			throw new EncFSUnsupportedException(e.getMessage());
		}
		return result;
	}

	private static void cipherInit(Key key, Mac mac, int opMode,
			Cipher cipher, byte[] iv, byte[] ivSeed)
					throws InvalidAlgorithmParameterException
	{
		try {
			cipher.init(opMode, key, newIvSpec(mac, iv, ivSeed));
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
	}

	public static void cipherInit(EncFSVolume volume, int opMode,
			Cipher cipher, byte[] ivSeed)
					throws InvalidAlgorithmParameterException
	{
		cipherInit(volume.getKey(), volume.getMac(), opMode, cipher,
				volume.getIV(), ivSeed);
	}

	public static byte[] mac64(Mac mac, byte[] input, byte[] chainedIv) {
		byte[] concat = new byte[input.length + chainedIv.length];
		for (int i = 0; i < input.length; i++) {
			concat[i] = input[i];
		}
		for (int i = input.length; i < input.length + chainedIv.length; i++) {
			concat[i] = chainedIv[7 - (i - input.length)];
		}
		byte[] macResult = mac.doFinal(concat);
		byte[] mac64 = new byte[8];
		for (int i = 0; i < 19; i++) // Note the 19 not 20
			mac64[i % 8] ^= macResult[i];

		if (chainedIv.length > 0) {
			// Propagate the result as the new chained IV
			for (int i = 0; i < 8; i++) {
				chainedIv[i] = mac64[i];
			}
		}

		return mac64;
	}

	public static byte[] mac32(Mac mac, byte[] input, byte[] chainedIv) {
		byte[] mac64 = mac64(mac, input, chainedIv);
		byte[] mac32 = new byte[4];
	    mac32[0] = (byte) (mac64[4] ^ mac64[0]);
	    mac32[1] = (byte) (mac64[5] ^ mac64[1]);
	    mac32[2] = (byte) (mac64[6] ^ mac64[2]);
	    mac32[3] = (byte) (mac64[7] ^ mac64[3]);

	    return mac32;
	}

	public static byte[] mac16(Mac mac, byte[] input, byte[] chainedIv) {
		byte[] mac32 = mac32(mac, input, chainedIv);
		byte[] mac16 = new byte[2];
	    mac16[0] = (byte) (mac32[2] ^ mac32[0]);
	    mac16[1] = (byte) (mac32[3] ^ mac32[1]);
	    
	    return mac16;
	}

	private static void unshuffleBytes(byte[] input) {
		for (int i = (input.length - 1); i > 0; i--) // Note size - 1
			input[i] ^= input[i - 1];
	}

	private static byte[] flipBytes(byte[] input) {
		byte[] result = new byte[input.length];

		int offset = 0;
		int bytesLeft = input.length;
		
		while (bytesLeft > 0) {
			//TODO: 64 should be defined?
			int toFlip = Math.min(64, bytesLeft);

			for (int i = 0; i < toFlip; i++)
				result[offset + i] = input[offset + toFlip - i - 1];
			
			bytesLeft -= toFlip;
			offset += toFlip;
		}

		return result;
	}
	
	private static byte[] streamDecode(Cipher cipher, Mac mac, Key key,
			byte[] iv, byte[] ivSeed, byte[] data)
					throws EncFSUnsupportedException,
					InvalidAlgorithmParameterException,
					IllegalBlockSizeException, BadPaddingException
		{
		// First round uses IV seed + 1 for IV generation
		byte[] ivSeedPlusOne = null;

		if (ivSeed.length == 4) {
			ivSeedPlusOne = EncFSUtil.intToByteArray(
					            EncFSUtil.byteArrayToInt(ivSeed) + 1);
		} else if (ivSeed.length == 8) {
			ivSeedPlusOne = EncFSUtil.longToByteArray(
					            EncFSUtil.byteArrayToLong(ivSeed) + 1);
		} else {
			throw new EncFSUnsupportedException("Unsupported IV length");
		}

		cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv, ivSeedPlusOne);
		byte[] firstDecResult = cipher.doFinal(data);

		unshuffleBytes(firstDecResult);

		byte[] flipBytesResult = flipBytes(firstDecResult);

		// Second round of decryption with IV seed itself used for IV generation
		cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv, ivSeed);
		byte[] result = cipher.doFinal(flipBytesResult);

		unshuffleBytes(result);

		return result;
	}
	
	public static byte[] streamDecode(EncFSVolume volume, byte[] ivSeed, byte[] data)
			throws EncFSUnsupportedException, InvalidAlgorithmParameterException,
			       IllegalBlockSizeException, BadPaddingException
	{
			return streamDecode(volume.getStreamCipher(),
					volume.getMac(), volume.getKey(), volume.getIV(), ivSeed,
					data);
	}
	
	public static byte[] blockDecode(EncFSVolume volume, byte[] ivSeed, byte[] data)
			throws InvalidAlgorithmParameterException, IllegalBlockSizeException,
			       BadPaddingException
	{
		if (data.length != volume.getConfig().getBlockSize()) {
			throw new IllegalBlockSizeException();
		}
		Cipher cipher = volume.getBlockCipher();
		cipherInit(volume, Cipher.DECRYPT_MODE, cipher, ivSeed);
		byte[] result = cipher.doFinal(data);
		return result;
	}
	
	public static byte[] deriveVolumeKey(EncFSConfig config, String password)
			throws EncFSChecksumException,
			       EncFSInvalidConfigException,
			       EncFSCorruptDataException,
			       EncFSUnsupportedException
	{
		// Decode Base64 encoded salt/ciphertext data
		//TODO: validate key/IV lengths
		
		byte[] cipherSaltData;
		try {
			cipherSaltData = EncFSBase64.decode(config.getSaltStr());
		} catch (IOException e) {
			throw new EncFSInvalidConfigException("Corrupt salt data in config");
		}
		byte[] cipherVolKeyData;
		try {
			cipherVolKeyData = EncFSBase64.decode(config.getEncodedKeyStr());
		} catch (IOException e) {
			throw new EncFSInvalidConfigException("Corrupt key data in config");
		}

		byte[] encryptedVolKey = Arrays.copyOfRange(cipherVolKeyData, 4,
				                                    cipherVolKeyData.length);

		// Execute PBKDF2 to derive key data from the password
		SecretKeyFactory f;
		try {
			f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
		} catch (NoSuchAlgorithmException e) {
			throw new EncFSUnsupportedException(e.getMessage());
		}
		KeySpec ks = new PBEKeySpec(password.toCharArray(),
				                    cipherSaltData,
				                    config.getIterationCount(),
				                    config.getVolumeKeySize() +  //TODO: (*) Verify this
				                    EncFSVolume.ENCFS_VOLUME_IV_LENGTH * 8);
		SecretKey pbkdf2Key = null;
		try {
			pbkdf2Key = f.generateSecret(ks);
		} catch (InvalidKeySpecException e) {
			throw new EncFSInvalidConfigException(e.getMessage());
		}
        byte[] pbkdf2Data = pbkdf2Key.getEncoded();

        // Prepare key/IV for decryption
        //TODO: (*) Are these lengths hardcoded? Or depend on volume key size???
	    byte[] passKeyData = Arrays.copyOfRange(pbkdf2Data, 0, 32);
	    byte[] passIvData = Arrays.copyOfRange(pbkdf2Data, 32, 48);
        Key passKey = newKey(passKeyData);
	    byte[] ivSeed = Arrays.copyOfRange(cipherVolKeyData, 0, 4);
	    
	    // Decrypt the volume key data
	    Mac mac;
		try {
			mac = newMac(passKey);
		} catch (InvalidKeyException e) {
			throw new EncFSInvalidConfigException(e.getMessage());
		}
	    byte[] clearVolKeyData = null;
		try {
			clearVolKeyData = streamDecode(newStreamCipher(), mac,
					                       passKey, passIvData, ivSeed,
					                       encryptedVolKey);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSInvalidConfigException(e.getMessage());
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e.getMessage());
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e.getMessage());
		}
	    
	    // Perform checksum computation
	    byte[] mac32 = mac32(mac, clearVolKeyData, new byte[0]);
	    
	    if (!Arrays.equals(ivSeed, mac32)) {
	    	throw new EncFSChecksumException("Volume key checksum mismatch");
	    }

	    return clearVolKeyData;
	}
	
	private static IvParameterSpec newIvSpec(Mac mac, byte[] iv, byte[] ivSeed) {

		//TODO: Verify input byte[] lengths, raise Exception on bad ivSeed length

		byte[] concat = new byte[EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 8];
		for (int i = 0; i < EncFSVolume.ENCFS_VOLUME_IV_LENGTH;
			 i++)
			concat[i] = iv[i];

		if (ivSeed.length == 4) {
		    // Concat 4 bytes of IV seed and 4 bytes of 0
		    for (int i = EncFSVolume.ENCFS_VOLUME_IV_LENGTH;
		    	 i < EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 4;
		    	 i++)
		    	concat[i] = ivSeed[EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 3 - i];
		    for (int i = EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 4;
		    	 i < EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 8;
		    	 i++) concat[i] = 0;
	    } else {
	    	// Use 8 bytes from IV seed
	    	for (int i = EncFSVolume.ENCFS_VOLUME_IV_LENGTH;
	    		 i < EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 8; i++)
	    		concat[i] = ivSeed[EncFSVolume.ENCFS_VOLUME_IV_LENGTH + 7 - i];
	    }
	    
	    // Take first 16 bytes of the SHA-1 output (20 bytes)
	    byte[] ivResult = Arrays.copyOfRange(mac.doFinal(concat), 0,
	    		                             EncFSVolume.ENCFS_VOLUME_IV_LENGTH);
	    
	    return new IvParameterSpec(ivResult);
	}
}