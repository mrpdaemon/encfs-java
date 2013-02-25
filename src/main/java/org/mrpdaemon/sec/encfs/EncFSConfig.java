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

/**
 * Class representing an EncFS volume configuration.
 * 
 */
public class EncFSConfig {

	private int volumeKeySizeInBits;
	private int encryptedFileBlockSizeInBytes;
	private boolean useUniqueIV;

	/*
	 * Whether name IV chaining is being used. When using IV chaining, each
	 * parent element in a file's path contributes to the IV that is used to
	 * encrypt the file's name.
	 */
	private boolean chainedNameIV;
	private boolean holesAllowedInFiles;
	private int encodedKeyLengthInBytes;

	/*
	 * String containing the Base64 encoded representation of the volume
	 * encryption key encrypted with the password generated key.
	 */
	private String base64EncodedVolumeKey;
	private int saltLengthBytes;

	/*
	 * String containing the salt data applied to the password hash for
	 * generating the password derived key.
	 */
	private String base64Salt;
	private int iterationForPasswordKeyDerivationCount;
	private EncFSFilenameEncryptionAlgorithm filenameAlgorithm;
	private int numberOfMACBytesForEachFileBlock;
	private int numberOfRandomBytesInEachMACHeader;
	private boolean supportedExternalIVChaining;

	public EncFSConfig() {
	}

	public int getVolumeKeySizeInBits() {
		return volumeKeySizeInBits;
	}

	public void setVolumeKeySizeInBits(int volumeKeySizeInBits) {
		this.volumeKeySizeInBits = volumeKeySizeInBits;
	}

	public int getEncryptedFileBlockSizeInBytes() {
		return encryptedFileBlockSizeInBytes;
	}

	public void setEncryptedFileBlockSizeInBytes(
			int encryptedFileBlockSizeInBytes) {
		this.encryptedFileBlockSizeInBytes = encryptedFileBlockSizeInBytes;
	}

	public boolean isUseUniqueIV() {
		return useUniqueIV;
	}

	public void setUseUniqueIV(boolean useUniqueIV) {
		this.useUniqueIV = useUniqueIV;
	}

	public boolean isChainedNameIV() {
		return chainedNameIV;
	}

	public void setChainedNameIV(boolean chainedNameIV) {
		this.chainedNameIV = chainedNameIV;
	}

	public boolean isHolesAllowedInFiles() {
		return holesAllowedInFiles;
	}

	public void setHolesAllowedInFiles(boolean holesAllowedInFiles) {
		this.holesAllowedInFiles = holesAllowedInFiles;
	}

	public int getEncodedKeyLengthInBytes() {
		return encodedKeyLengthInBytes;
	}

	public void setEncodedKeyLengthInBytes(int encodedKeyLengthInBytes) {
		this.encodedKeyLengthInBytes = encodedKeyLengthInBytes;
	}

	public String getBase64EncodedVolumeKey() {
		return base64EncodedVolumeKey;
	}

	public void setBase64EncodedVolumeKey(String base64EncodedVolumeKey) {
		this.base64EncodedVolumeKey = base64EncodedVolumeKey;
	}

	public int getSaltLengthBytes() {
		return saltLengthBytes;
	}

	public void setSaltLengthBytes(int saltLengthBytes) {
		this.saltLengthBytes = saltLengthBytes;
	}

	public String getBase64Salt() {
		return base64Salt;
	}

	public void setBase64Salt(String salt) {
		this.base64Salt = salt;
	}

	public int getIterationForPasswordKeyDerivationCount() {
		return iterationForPasswordKeyDerivationCount;
	}

	public void setIterationForPasswordKeyDerivationCount(
			int iterationForPasswordKeyDerivationCount) {
		this.iterationForPasswordKeyDerivationCount = iterationForPasswordKeyDerivationCount;
	}

	public EncFSFilenameEncryptionAlgorithm getFilenameAlgorithm() {
		return filenameAlgorithm;
	}

	public void setFilenameAlgorithm(
			EncFSFilenameEncryptionAlgorithm filenameAlgorithm) {
		this.filenameAlgorithm = filenameAlgorithm;
	}

	public int getNumberOfMACBytesForEachFileBlock() {
		return numberOfMACBytesForEachFileBlock;
	}

	public void setNumberOfMACBytesForEachFileBlock(
			int numberOfMACBytesForEachFileBlock) {
		this.numberOfMACBytesForEachFileBlock = numberOfMACBytesForEachFileBlock;
	}

	public int getNumberOfRandomBytesInEachMACHeader() {
		return numberOfRandomBytesInEachMACHeader;
	}

	public void setNumberOfRandomBytesInEachMACHeader(
			int numberOfRandomBytesInEachMACHeader) {
		this.numberOfRandomBytesInEachMACHeader = numberOfRandomBytesInEachMACHeader;
	}

	public boolean isSupportedExternalIVChaining() {
		return supportedExternalIVChaining;
	}

	public void setSupportedExternalIVChaining(
			boolean supportedExternalIVChaining) {
		this.supportedExternalIVChaining = supportedExternalIVChaining;
	}

	public void validate() throws EncFSInvalidConfigException {
		if (isSupportedExternalIVChaining()
				&& (!isChainedNameIV() || !isUseUniqueIV())) {
			throw new EncFSInvalidConfigException(
					"External IV chaining requires chained name IV and unique IV to be enabled");
		}
	}

	@Override
	public String toString() {
		return "EncFSConfig [volumeKeySizeInBits=" + volumeKeySizeInBits
				+ ", encryptedFileBlockSizeInBytes="
				+ encryptedFileBlockSizeInBytes + ", useUniqueIV="
				+ useUniqueIV + ", chainedNameIV=" + chainedNameIV
				+ ", holesAllowedInFiles=" + holesAllowedInFiles
				+ ", encodedKeyLengthInBytes=" + encodedKeyLengthInBytes
				+ ", base64EncodedVolumeKey=" + base64EncodedVolumeKey
				+ ", saltLengthBytes=" + saltLengthBytes + ", base64Salt="
				+ base64Salt + ", iterationForPasswordKeyDerivationCount="
				+ iterationForPasswordKeyDerivationCount + ", algorithm="
				+ filenameAlgorithm + ", numberOfMACBytesForEachFileBlock="
				+ numberOfMACBytesForEachFileBlock
				+ ", numberOfRandomBytesInEachMACHeader="
				+ numberOfRandomBytesInEachMACHeader
				+ ", supportedExternalIVChaining="
				+ supportedExternalIVChaining + "]";
	}
}