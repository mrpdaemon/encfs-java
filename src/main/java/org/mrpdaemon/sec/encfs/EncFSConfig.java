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

import java.security.SecureRandom;

/**
 * Class representing volume configuration data for an EncFS volume.
 */
public class EncFSConfig {

	/**
	 * Volume configuration uses nameio/block for filename encryption
	 */
	public static final int ENCFS_CONFIG_NAME_ALG_BLOCK = 1;

	/**
	 * Volume configuration uses nameio/stream for filename encryption
	 */
	public static final int ENCFS_CONFIG_NAME_ALG_STREAM = 2;

	// Size of the volume encryption key in bits.
	private int volumeKeySize;

	// Size of encrypted file blocks in bytes.
	private int blockSize;

	// Whether unique IV is being used.
	private boolean uniqueIV;

	/*
	 * Whether name IV chaining is being used. When using IV chaining, each
	 * parent element in a file's path contributes to the IV that is used to
	 * encrypt the file's name.
	 */
	private boolean chainedNameIV;

	// Whether holes are allowed in files.
	private boolean holesAllowed;

	// Length of the encoded key data in bytes.
	private int encodedKeyLength;

	/*
	 * String containing the Base64 encoded representation of the volume
	 * encryption key encrypted with the password generated key.
	 */
	private String encodedKeyStr;

	// Length of the salt data in bytes.
	private int saltLength;

	/*
	 * String containing the salt data applied to the password hash for
	 * generating the password derived key.
	 */
	private String saltStr;

	// Iteration count used in the generation of the password derived key.
	private int iterationCount;

	// Algorithm used for file name encryption
	private int nameAlgorithm;

	/**
	 * Returns a default EncFS configuration that encfs-java supports
	 * 
	 * @return default EncFS configuration minus salt/password fields
	 */
	public static EncFSConfig newDefaultConfig() {
		EncFSConfig config = new EncFSConfig();
		
		config.setNameAlgorithm(ENCFS_CONFIG_NAME_ALG_BLOCK);
		config.setVolumeKeySize(192);
		config.setBlockSize(1024);
		config.setUniqueIV(true);
		config.setChainedNameIV(true);
		config.setHolesAllowed(false); //XXX: Not supported
		config.setIterationCount(5000);

		return config;
	}
	
	/**
	 * Encodes the given volume key using the supplied password parameters,
	 * placing it into the EncFSConfig
	 * 
	 * @param config Partially initialized volume configuration
	 * @param password Password to use for encoding the key
	 * @param volKey Volume key to encode
	 * 
	 * @throws EncFSUnsupportedException 
	 * @throws EncFSInvalidConfigException 
	 * @throws EncFSCorruptDataException 
	 */
	public static void encodeVolumeKey(EncFSConfig config, String password, byte[] volKey)
			throws EncFSInvalidConfigException, EncFSUnsupportedException, EncFSCorruptDataException {
		SecureRandom random = new SecureRandom();
		config.setSaltLength(20);
		
		// Generate random salt
		byte[] salt = new byte[20];
		random.nextBytes(salt);
		config.setSaltStr(EncFSBase64.encodeBytes(salt));
		
		// Get password key data
		byte[] pbkdf2Data = EncFSCrypto.derivePasswordKey(config, password);
		
		// Encode volume key
		byte[] encodedVolKey = EncFSCrypto.encryptVolumeKey(config, pbkdf2Data, volKey);
		
		config.setEncodedKeyLength(encodedVolKey.length);
		config.setEncodedKeyStr(EncFSBase64.encodeBytes(encodedVolKey));
	}

	/**
	 * @return the size of the volume encryption key in bits.
	 */
	public int getVolumeKeySize() {
		return volumeKeySize;
	}

	/**
	 * @param volumeKeySize
	 *            the size of the volume encryption key in bits.
	 */
	public void setVolumeKeySize(int volumeKeySize) {
		this.volumeKeySize = volumeKeySize;
	}

	/**
	 * @return size of encrypted file blocks in bytes.
	 */
	public int getBlockSize() {
		return blockSize;
	}

	/**
	 * @param blockSize
	 *            size of encrypted file blocks in bytes.
	 */
	public void setBlockSize(int blockSize) {
		this.blockSize = blockSize;
	}

	/**
	 * @return whether unique IV is being used.
	 */
	public boolean isUniqueIV() {
		return uniqueIV;
	}

	/**
	 * @param uniqueIV
	 *            whether unique IV is being used.
	 */
	public void setUniqueIV(boolean uniqueIV) {
		this.uniqueIV = uniqueIV;
	}

	/**
	 * When using IV chaining, each parent element in a file's path contributes
	 * to the IV that is used to encrypt the file's name.
	 * 
	 * @return whether name IV chaining is being used.
	 */
	public boolean isChainedNameIV() {
		return chainedNameIV;
	}

	/**
	 * When using IV chaining, each parent element in a file's path contributes
	 * to the IV that is used to encrypt the file's name.
	 * 
	 * @param chainedNameIV
	 *            whether name IV chaining is being used.
	 */
	public void setChainedNameIV(boolean chainedNameIV) {
		this.chainedNameIV = chainedNameIV;
	}

	/**
	 * @return whether holes are allowed in files.
	 */
	public boolean isHolesAllowed() {
		return holesAllowed;
	}

	/**
	 * @param holesAllowed
	 *            whether holes are allowed in files.
	 */
	public void setHolesAllowed(boolean holesAllowed) {
		this.holesAllowed = holesAllowed;
	}

	/**
	 * @return length of the encoded key data in bytes.
	 */
	public int getEncodedKeyLength() {
		return encodedKeyLength;
	}

	/**
	 * @param encodedKeyLength
	 *            length of the encoded key data in bytes.
	 */
	public void setEncodedKeyLength(int encodedKeyLength) {
		this.encodedKeyLength = encodedKeyLength;
	}

	/**
	 * @return string containing the Base64 encoded representation of the volume
	 *         encryption key encrypted with the password generated key.
	 */
	public String getEncodedKeyStr() {
		return encodedKeyStr;
	}

	/**
	 * @param encodedKeyStr
	 *            string containing the Base64 encoded representation of the
	 *            volume encryption key encrypted with the password generated
	 *            key.
	 */
	public void setEncodedKeyStr(String encodedKeyStr) {
		this.encodedKeyStr = encodedKeyStr;
	}

	/**
	 * @return the saltLength
	 */
	public int getSaltLength() {
		return saltLength;
	}

	/**
	 * @param saltLength
	 *            length of the salt data in bytes.
	 */
	public void setSaltLength(int saltLength) {
		this.saltLength = saltLength;
	}

	/**
	 * @return string containing the salt data applied to the password hash for
	 *         generating the password derived key.
	 */
	public String getSaltStr() {
		return saltStr;
	}

	/**
	 * @param saltStr
	 *            string containing the salt data applied to the password hash
	 *            for generating the password derived key.
	 */
	public void setSaltStr(String saltStr) {
		this.saltStr = saltStr;
	}

	/**
	 * @return iteration count used in the generation of the password derived
	 *         key.
	 */
	public int getIterationCount() {
		return iterationCount;
	}

	/**
	 * @param iterationCount
	 *            iteration count used in the generation of the password derived
	 *            key.
	 */
	public void setIterationCount(int iterationCount) {
		this.iterationCount = iterationCount;
	}

	/**
	 * @return algorithm used for filename encryption
	 */
	public int getNameAlgorithm() {
		return nameAlgorithm;
	}

	/**
	 * @param nameAlgorithm
	 *            algorithm used for filename encryption
	 */
	public void setNameAlgorithm(int nameAlgorithm) {
		this.nameAlgorithm = nameAlgorithm;
	}

	@Override
	public String toString() {
		return "EncFSConfig [volumeKeySize=" + volumeKeySize + ", blockSize=" + blockSize + ", uniqueIV=" + uniqueIV
				+ ", chainedNameIV=" + chainedNameIV + ", holesAllowed=" + holesAllowed + ", encodedKeyLength="
				+ encodedKeyLength + ", encodedKeyStr=" + encodedKeyStr + ", saltLength=" + saltLength + ", saltStr="
				+ saltStr + ", iterationCount=" + iterationCount + ", nameAlgorithm=" + nameAlgorithm + "]";
	}

}