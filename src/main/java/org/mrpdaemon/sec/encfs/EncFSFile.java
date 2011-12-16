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

import java.io.File;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;
import java.util.StringTokenizer;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

/**
 * Object representing a file in an EncFS volume.
 * 
 * Useful for decryption of file names.
 */
public class EncFSFile {
	
	// Volume path of this file
	private String volumePath;
	
	// Volume hosting this file
	private EncFSVolume volume;
	
	// Underlying File object ('this' doesn't extend File)
	private File file;

	// Cached plaintext name of the represented file
	private String plaintextName;

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume EncFS volume hosting the file 
	 * @param volumePath Relative path of the file within the volume. The root
	 *                   directory of the volume is "/" and files underneath
	 *                   the root directory are represented by their paths
	 *                   relative to the root.
	 * @param file Actual file object to use as a basis for this EncFS file.
	 *             Note that EncFSFile doesn't extend File since we'd like to
	 *             be able to overlay EncFSFile over any kind of abstraction
	 *             that extends File, for example network file storage etc.
	 *             
	 * @throws EncFSCorruptDataException File name doesn't follow EncFS standard
	 * @throws EncFSChecksumException Checksum error during name decoding
	 */
	public EncFSFile(EncFSVolume volume, String volumePath, File file)
			throws EncFSCorruptDataException, EncFSChecksumException
	{
		this.file = file;
		this.volume = volume;
		this.volumePath = volumePath;

		// Pre-compute plaintext name
		if (file.getName().equals(EncFSVolume.ENCFS_VOLUME_CONFIG_FILE_NAME) ||
			file.getName().equals(".") ||
			file.getName().equals("..") ||
			volume.getRootDir() == null) // hack, call is from EncFSVolume()
		{
			this.plaintextName = file.getName();
		} else {
			this.plaintextName = decodeName(volume, file.getName(), volumePath);
		}
	}

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume EncFS volume hosting the file 
	 * @param volumePath Relative path of the file within the volume. The root
	 *                   directory of the volume is "/" and files underneath
	 *                   the root directory are represented by their paths
	 *                   relative to the root.
	 * @param filePath Path to the actual file to use as a basis for this EncFS
	 *                 file.
	 *             
	 * @throws EncFSCorruptDataException File name doesn't follow EncFS standard
	 * @throws EncFSChecksumException Checksum error during name decoding
	 */
	public EncFSFile(EncFSVolume volume, String volumePath, String filePath)
			throws EncFSCorruptDataException, EncFSChecksumException
	{
		this(volume, volumePath, new File(filePath));
	}

	/* 
	 * Decode the given fileName under the given volume and volume path
	 */
	private static String decodeName(EncFSVolume volume, String fileName,
			                         String volumePath) throws EncFSCorruptDataException,
			                                                   EncFSChecksumException
	{
		byte[] base256FileName = EncFSBase64.decodeEncfs(fileName.getBytes());

		byte[] encFileName = Arrays.copyOfRange(base256FileName, 2,
				                                base256FileName.length);

		//TODO: make sure its multiple of 16
		byte[] macBytes = new byte[8];
		macBytes[6] = base256FileName[0];
		macBytes[7] = base256FileName[1];
		
		byte[] chainIv = new byte[8];
		
		// Chained IV computation
		if (volume.getConfig().isChainedNameIV()) {
			StringTokenizer st = new StringTokenizer(volumePath, "/");
			while (st.hasMoreTokens()) {
				String curPath = st.nextToken();
				if ((curPath.length() > 0) && (curPath != "/")) {
					int padLen = 16 - (curPath.length() % 16);
					if (padLen == 0) {
						padLen = 16;
					}
					byte[] encodeBytes = new byte[curPath.length() + padLen];
			
					for (int i = 0; i < curPath.length(); i++) {
						encodeBytes[i] = curPath.getBytes()[i];
					}
			
					// Pad to the nearest 16 bytes, add a full block if needed
					for (int i = 0; i < padLen; i++) {
						encodeBytes[curPath.length() + i] = (byte) padLen;
					}

					// Update chain IV
					EncFSCrypto.mac64(volume.getMac(), encodeBytes, chainIv);
				}
			}
		}

		byte[] fileIv = new byte[8];
		for (int i = 0; i < 8; i++) {
			fileIv[i] = (byte) (macBytes[i] ^ chainIv[i]);
		}

		Cipher cipher;
		byte[] decFileName;
		
		if (volume.getConfig().getNameAlgorithm() == 
				EncFSConfig.ENCFS_CONFIG_NAME_ALG_BLOCK) {
			//Block decryption
			cipher = volume.getBlockCipher();
			
			try {
				EncFSCrypto.cipherInit(volume, Cipher.DECRYPT_MODE,
						cipher, fileIv);	
			} catch (InvalidAlgorithmParameterException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			}

			try {
				decFileName = cipher.doFinal(encFileName);
			} catch (IllegalBlockSizeException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			} catch (BadPaddingException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			}
			
		} else {
			// Stream decryption
			try {
				decFileName = EncFSCrypto.streamDecode(volume, fileIv, encFileName);
			} catch (InvalidAlgorithmParameterException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			} catch (IllegalBlockSizeException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			} catch (BadPaddingException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			} catch (EncFSUnsupportedException e) {
				throw new EncFSCorruptDataException(e.getMessage());
			}
		}

		// Verify decryption worked
		byte[] mac16;
		if (volume.getConfig().isChainedNameIV()) {
			mac16 = EncFSCrypto.mac16(volume.getMac(), decFileName, chainIv);
		} else {
			mac16 = EncFSCrypto.mac16(volume.getMac(), decFileName);
		}
		byte[] expectedMac = Arrays.copyOfRange(base256FileName, 0, 2);
		if (!Arrays.equals(mac16, expectedMac)) {
			throw new EncFSChecksumException("Mismatch in file checksum");
		}

		// For the stream cipher directly return the result
		if (volume.getConfig().getNameAlgorithm() == 
				EncFSConfig.ENCFS_CONFIG_NAME_ALG_STREAM) {
			return new String(decFileName);
		}

		// For the block cipher remove padding before returning the result
		int padLen = decFileName[decFileName.length - 1];
		
		return new String(Arrays.copyOfRange(decFileName, 0,
				                             decFileName.length - padLen));
	}

	/**
	 * @return Volume path of the EncFS file
	 */
	public String getVolumePath() {
		return volumePath;
	}

	/**
	 * @return Volume containing the EncFS file
	 */
	public EncFSVolume getVolume() {
		return volume;
	}

	/**
	 * @return Underlying File object
	 */
	public File getFile() {
		return file;
	}

	/**
	 * List files/directories contained by the directory represented by this
	 * EncFSFile object.
	 * 
	 * @return null if not a directory, array of String names otherwise
	 * @throws EncFSCorruptDataException Invalid file name size
	 * @throws EncFSChecksumException Filename checksum mismatch
	 */
	public String[] list() throws EncFSCorruptDataException,
	                              EncFSChecksumException
	{
		if (!file.isDirectory()) {
			return null;
		}

		EncFSFile[] files = this.listFiles();
		String[] fileNames = new String[files.length];
		
		for (int i = 0; i < files.length; i++) {
			EncFSFile file = files[i];
			fileNames[i] = file.getName();
		}

		return fileNames;
	}
	
	/**
	 * @return Plaintext name of this EncFS file
	 */
	public String getName()
	{
		return plaintextName;
	}

	/**
	 * List of EncFSFile's for all files and directories that are children of
	 * the directory represented by this EncFSFile
	 * 
	 * @return null if not a directory, array of EncFSFile otherwise
	 * @throws EncFSCorruptDataException Invalid file name size
	 * @throws EncFSChecksumException Filename checksum mismatch
	 */
	public EncFSFile[] listFiles() throws EncFSCorruptDataException,
	                                      EncFSChecksumException {
		if (!file.isDirectory()) {
			return null;
		}

		File[] files = file.listFiles();
		EncFSFile[] encFSFiles = new EncFSFile[files.length];
		
		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			if (this == volume.getRootDir()) {
				encFSFiles[i] = new EncFSFile(volume, 
						EncFSVolume.ENCFS_VOLUME_ROOT_PATH, file);
			} else {
				if (volumePath.equals(EncFSVolume.ENCFS_VOLUME_ROOT_PATH)) {
					encFSFiles[i] = new EncFSFile(volume,
						                          volumePath + this.getName(),
						                          file);
				} else {
					encFSFiles[i] = new EncFSFile(volume,
							                      volumePath + "/" +
					                              this.getName(),
							                      file);
				}
			}
		}

		return encFSFiles;
	}
}
