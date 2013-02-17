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

import javax.crypto.Cipher;
import javax.crypto.Mac;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * Class representing an EncFS volume.
 *
 * The volume is defined by a root folder, which contains an EncFS configuration
 * file and a hierarchy of encrypted files and subdirectories created by a
 * compliant EncFS implementation.
 */
public class EncFSVolume {
	public final static String CONFIG_FILE_NAME = ".encfs6.xml";
	public final static String[] OLD_CONFIG_FILE_NAMES = { ".encfs5",	".encfs4", ".encfs3", ".encfs2", ".encfs" };

	/** String denoting the root path of an EncFS volume */
	public final static String ROOT_PATH = "/";

	/** String denoting the path separator for EncFS volumes */
	public final static String PATH_SEPARATOR = "/";

	/** Length in bytes of the volume initialization vector (IV) */
	public final static int IV_LENGTH = 16;

	// Path operations
	private static enum PathOperation {
		MOVE, COPY
	}

	// Volume configuration
	private EncFSConfig config;

	// Volume encryption/decryption VolumeCryptKey
	private Key VolumeCryptKey;

	// Volume initialization vector for use with the volume VolumeCryptKey
	private byte[] iv;

	// Password-based VolumeCryptKey/IV
	private byte[] passwordKey;

	// Volume MAC object to use for checksum computations
	private Mac mac;

	// Volume stream cipher
	private Cipher streamCipher;

	// Volume block cipher
	private Cipher blockCipher;

	// Root directory object
	private EncFSFile rootDir;

	// File provider for this volume
	private EncFSFileProvider fileProvider;

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param rootPath
	 *            Path of the root directory of the EncFS volume on the local
	 *            filesystem
	 * @param password
	 *            User supplied password to decrypt volume VolumeCryptKey
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(String rootPath, String password)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(new EncFSLocalFileProvider(new File(rootPath)), password);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param rootPath
	 *            Path of the root directory of the EncFS volume on the local
	 *            filesystem
	 * @param password
	 *            User supplied password to decrypt volume VolumeCryptKey
	 * @param pbkdf2Provider
	 *            Custom PBKDF2 computation provider
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(String rootPath, String password,
			EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(new EncFSLocalFileProvider(new File(rootPath)), password,
				pbkdf2Provider);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param rootPath
	 *            Path of the root directory of the EncFS volume on the local
	 *            filesystem
	 * @param passwordKey
	 *            Cached password-based VolumeCryptKey/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based VolumeCryptKey data can significantly speed up
	 *            volume creation.
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(String rootPath, byte[] passwordKey)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(new EncFSLocalFileProvider(new File(rootPath)), passwordKey);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for access to files stored in non-local storage
	 * @param password
	 *            User supplied password to decrypt volume VolumeCryptKey
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(EncFSFileProvider fileProvider, String password)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(fileProvider, password);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for access to files stored in non-local storage
	 * @param password
	 *            User supplied password to decrypt volume VolumeCryptKey
	 * @param pbkdf2Provider
	 *            Custom PBKDF2 computation provider
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(EncFSFileProvider fileProvider, String password,
			EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(fileProvider, password, pbkdf2Provider);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for access to files stored in non-local storage
	 * @param passwordKey
	 *            Cached password-based VolumeCryptKey/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based VolumeCryptKey data can significantly speed up
	 *            volume creation.
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(EncFSFileProvider fileProvider, byte[] passwordKey)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(fileProvider, passwordKey);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for access to files stored in non-local storage
	 * @param config
	 *            EncFSConfig if the config file is stored in a separate
	 *            location than the file provider's root directory
	 * @param password
	 *            User supplied password to decrypt volume VolumeCryptKey
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(EncFSFileProvider fileProvider, EncFSConfig config,
			String password) throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		this.init(fileProvider, config, password);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for access to files stored in non-local storage
	 * @param config
	 *            EncFSConfig if the config file is stored in a separate
	 *            location than the file provider's root directory
	 * @param password
	 *            User supplied password to decrypt volume VolumeCryptKey
	 * @param pbkdf2Provider
	 *            Custom PBKDF2 computation provider
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(EncFSFileProvider fileProvider, EncFSConfig config,
			String password, EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		this.init(fileProvider, config, password, pbkdf2Provider);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for access to files stored in non-local storage
	 * @param config
	 *            EncFSConfig if the config file is stored in a separate
	 *            location than the file provider's root directory
	 * @param passwordKey
	 *            Cached password-based VolumeCryptKey/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based VolumeCryptKey data can significantly speed up
	 *            volume creation.
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSVolume(EncFSFileProvider fileProvider, EncFSConfig config,
			byte[] passwordKey) throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		this.init(fileProvider, config, passwordKey);
	}

	// Read configuration, derive password VolumeCryptKey and initialize volume
	private void init(EncFSFileProvider fileProvider, String password)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		EncFSConfig config = EncFSConfigParser.parseConfig(fileProvider,
				CONFIG_FILE_NAME);
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password,
				null);

		this.init(fileProvider, config, passwordKey);
	}

	private void init(EncFSFileProvider fileProvider, String password,
			EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		EncFSConfig config = EncFSConfigParser.parseConfig(fileProvider,
				CONFIG_FILE_NAME);
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password,
				pbkdf2Provider);

		this.init(fileProvider, config, passwordKey, pbkdf2Provider);
	}

	// Derive password VolumeCryptKey and initialize volume
	private void init(EncFSFileProvider fileProvider, EncFSConfig config,
			String password) throws EncFSUnsupportedException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSInvalidPasswordException, IOException {
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password,
				null);

		this.init(fileProvider, config, passwordKey);
	}

	private void init(EncFSFileProvider fileProvider, EncFSConfig config,
			String password, EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password,
				pbkdf2Provider);

		this.init(fileProvider, config, passwordKey, pbkdf2Provider);
	}

	// Read configuration and initialize volume
	private void init(EncFSFileProvider fileProvider, byte[] passwordKey)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		EncFSConfig config = EncFSConfigParser.parseConfig(fileProvider,
				CONFIG_FILE_NAME);

		this.init(fileProvider, config, passwordKey);
	}

	// Main entry point for init functions without an EncFSPBKDF2Provider
	private void init(EncFSFileProvider fileProvider, EncFSConfig config,
			byte[] passwordKey) throws EncFSUnsupportedException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSInvalidPasswordException, IOException {
		this.init(fileProvider, config, passwordKey, null);
	}

	// Main method to perform volume variable initialization
	private void init(EncFSFileProvider fileProvider, EncFSConfig config,
			byte[] passwordKey, EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		this.fileProvider = fileProvider;

		this.config = config;
		this.passwordKey = passwordKey;
		// Derive volume VolumeCryptKey from the supplied password
		byte[] keyData = null;
		try {
			keyData = EncFSCrypto.decryptVolumeKey(this.config,
					this.passwordKey);
		} catch (EncFSChecksumException e) {
			throw new EncFSInvalidPasswordException(e);
		}

		// Create volume VolumeCryptKey
		int keyLength = this.config.getVolumeKeySizeInBits() / 8;
		if (keyData.length < keyLength) {
			throw new EncFSInvalidConfigException("Key size too large");
		}
		this.VolumeCryptKey = EncFSCrypto
				.newKey(Arrays.copyOfRange(keyData, 0, keyLength));

		// Copy IV data
		int ivLength = keyData.length - keyLength;
		if (ivLength != IV_LENGTH) {
			throw new EncFSInvalidConfigException("Non-standard IV length");
		}
		this.iv = Arrays.copyOfRange(keyData, keyLength, keyLength + ivLength);

		// Create volume MAC
		try {
			this.mac = EncFSCrypto.newMac(this.VolumeCryptKey);
		} catch (InvalidKeyException e) {
			throw new EncFSInvalidConfigException(e);
		}

		// Create stream cipher
		this.streamCipher = EncFSCrypto.newStreamCipher();

		// Create block cipher
		this.blockCipher = EncFSCrypto.newBlockCipher();

		rootDir = getFile(ROOT_PATH);
	}

	/**
	 * Combine the given directory and file name into a path string
	 *
	 * @param dir
	 *            Directory forming the first path component
	 * @param fileName
	 *            Filename forming the second path component
	 *
	 * @return String representing the combined path
	 */
	public static String combinePath(EncFSFile dir, String fileName) {
		EncFSVolume volume = dir.getVolume();
		String result;

		if (dir == volume.getRootDir()) {
			result = ROOT_PATH + fileName;
		} else {
			result = dir.getPath() + PATH_SEPARATOR + fileName;
		}

		return result;
	}

	/**
	 * Combine the given directory and file name into a path string
	 *
	 * @param dir
	 *            Directory forming the first path component
	 * @param file
	 *            File forming the second path component
	 *
	 * @return String representing the combined path
	 */
	public static String combinePath(EncFSFile dir, EncFSFile file) {
		return combinePath(dir, file.getName());
	}

	/**
	 * Combine the given directory and file name into a path string
	 *
	 * @param dirPath
	 *            Directory path forming the first path component
	 * @param fileName
	 *            File name forming the second path component
	 *
	 * @return String representing the combined path
	 */
	public static String combinePath(String dirPath, String fileName) {
		if (dirPath.equals(ROOT_PATH)) {
			return ROOT_PATH + fileName;
		} else {
			return dirPath + PATH_SEPARATOR + fileName;
		}
	}

	/**
	 * Combine the given directory and file name into a path string
	 *
	 * @param dirPath
	 *            Directory path forming the first path component
	 * @param file
	 *            File forming the second path component
	 *
	 * @return String representing the combined path
	 */
	public static String combinePath(String dirPath, EncFSFile file) {
		return combinePath(dirPath, file.getName());
	}

	/**
	 * Count files and directories under the given file
	 *
	 * @param file
	 *            File to count under
	 * @return Number of files/directories under the file
	 */
	public static int countFiles(EncFSFile file) {
		if (file.isDirectory()) {
			int dirCount = 1;
			try {
				for (EncFSFile subFile : file.listFiles()) {
					dirCount += countFiles(subFile);
				}
			} catch (Exception e) { /* Do nothing */
			}
			return dirCount;
		} else {
			return 1;
		}
	}

	/**
	 * Returns the configuration object for this volume
	 *
	 * @return Configuration for this EncFS volume
	 */
	public EncFSConfig getConfig() {
		return config;
	}

	/**
	 * Returns the volume VolumeCryptKey used for encryption/decryption
	 *
	 * @return Volume VolumeCryptKey for encryption/decryption
	 */
	public Key getVolumeCryptKey() {
		return VolumeCryptKey;
	}

	/**
	 * Returns the volume IV used for encryption/decryption
	 *
	 * @return Volume initialization vector (IV) for encryption/decryption
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * Returns the password based VolumeCryptKey/IV data for this volume
	 *
	 * @return Password-based VolumeCryptKey/IV data for this volume
	 */
	public byte[] getPasswordKey() {
		return passwordKey;
	}

	/**
	 * Returns the MAC object used for checksum verification
	 *
	 * @return Volume MAC for checksum verification
	 */
	public Mac getMac() {
		return mac;
	}

	/**
	 * Returns the stream cipher instance for stream encryption/decryption
	 *
	 * @return Stream cipher instance for stream encryption/decryption
	 */
	public Cipher getStreamCipher() {
		return streamCipher;
	}

	/**
	 * Returns the block cipher instance for block encryption/decryption
	 *
	 * @return Block cipher instance for block encryption/decryption
	 */
	public Cipher getBlockCipher() {
		return blockCipher;
	}

	/**
	 * Returns a file object representing the root directory of the volume
	 *
	 * @return EncFSFile representing the root directory of this volume
	 */
	public EncFSFile getRootDir() {
		return rootDir;
	}

	/**
	 * Returns the file provider used for this volume
	 *
	 * @return EncFSFileProvider for this volume
	 */
	public EncFSFileProvider getFileProvider() {
		return fileProvider;
	}

	/**
	 * Get an EncFSFile object representing the provided filename given the
	 * volume path of its parent directory
	 *
	 * @param parentPath
	 *            Volume path of the file's parent directory
	 * @param fileName
	 *            Name of the file
	 *
	 * @return EncFSFile representing the requested file
	 *
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSChecksumException
	 *             Corrupt data detected (checksum error)
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFile getFile(String parentPath, String fileName)
			throws EncFSCorruptDataException, EncFSChecksumException,
			IOException {
		validateAbsoluteFileName(parentPath, "parentPath");
		return getFile(combinePath(parentPath, fileName));
	}

	/**
	 * Get an EncFSFile object representing the provided absolute path in the
	 * volume
	 *
	 * @param filePath
	 *            Absolute volume path of the file
	 *
	 * @return EncFSFile representing the requested file
	 *
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFile getFile(String filePath) throws EncFSCorruptDataException,
			IOException {
		validateAbsoluteFileName(filePath, "filePath");

		String encryptedPath = EncFSCrypto
				.encodePath(this, filePath, ROOT_PATH);

		if (fileProvider.exists(encryptedPath) == false) {
			throw new FileNotFoundException();
		}
		EncFSFileInfo fileInfo = fileProvider.getFileInfo(encryptedPath);

		EncFSFileInfo decodedFileInfo;
		if (filePath.equals(ROOT_PATH)) {
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this, "",
					ROOT_PATH, fileInfo);
		} else {
			int lastIndexOfSeparator = filePath.lastIndexOf(PATH_SEPARATOR);
			String decDirName;
			String decFilename;
			if (filePath.lastIndexOf(PATH_SEPARATOR) == 0) {
				decDirName = PATH_SEPARATOR;
				decFilename = filePath.substring(1);

			} else {
				decDirName = filePath.substring(0, lastIndexOfSeparator);
				decFilename = filePath.substring(lastIndexOfSeparator + 1);
			}
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this,
					decDirName, decFilename, fileInfo);
		}

		return new EncFSFile(this, decodedFileInfo, fileInfo);
	}

	/**
	 * Returns the decrypted length a file would have in this volume given its
	 * encrypted length
	 *
	 * @param encryptedFileLength
	 *            Length of the encrypted file
	 *
	 * @return Length of the file after decryption
	 */
	public long getDecryptedFileLength(long encryptedFileLength) {
		long size = encryptedFileLength;

		if (size == 0) {
			return 0;
		}

		// Account for file header
		if (config.isUseUniqueIV()) {
			size -= EncFSFile.HEADER_SIZE;
		}

		// Account for block headers
		long headerLength = config.getNumberOfMACBytesForEachFileBlock()
				+ config.getNumberOfRandomBytesInEachMACHeader();
		if (headerLength > 0) {
			long blockLength = config.getEncryptedFileBlockSizeInBytes() + headerLength;

			// Calculate number of blocks
			long numBlocks = ((size - 1) / blockLength) + 1;

			// Subtract headers
			size -= numBlocks * headerLength;
		}

		return size;
	}

	/**
	 * Returns the encrypted length a file would have in this volume given its
	 * decrypted length
	 *
	 * @param decryptedFileLength
	 *            Length of the decrypted file
	 *
	 * @return Length of the file after encryption
	 */
	public long getEncryptedFileLength(long decryptedFileLength) {
		long size = decryptedFileLength;

		if (size == 0) {
			return 0;
		}

		// Account for block headers
		long headerLength = config.getNumberOfMACBytesForEachFileBlock()
				+ config.getNumberOfRandomBytesInEachMACHeader();
		if (headerLength > 0) {
			long blockLength = config.getEncryptedFileBlockSizeInBytes() + headerLength;

			// Calculate number of blocks
			long numBlocks = ((size - 1) / blockLength) + 1;

			// Add headers
			size += numBlocks * headerLength;
		}

		// Account for file header
		if (config.isUseUniqueIV()) {
			size += EncFSFile.HEADER_SIZE;
		}

		return size;
	}

	/**
	 * Checks whether the file or directory with the given path exists in the
	 * volume
	 *
	 * @param path
	 *            Absolute volume path of the file or directory
	 *
	 * @return true if path exists in the volume, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean pathExists(String path) throws EncFSCorruptDataException,
			IOException {
		validateAbsoluteFileName(path, "fileName");
		String encryptedPath = EncFSCrypto.encodePath(this, path, ROOT_PATH);
		return fileProvider.exists(encryptedPath);
	}

	/**
	 * Tests if the provided path contains EncFS volume
	 *
	 * @param path
	 *            Path to the presumed EncFS volume
	 * @return true if the volume is EncFS, false otherwise
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public static boolean isEncFSVolume(String path) throws IOException {
		return isEncFSVolume(new File(path));
	}

	/**
	 * Tests if the provided path contains EncFS volume
	 *
	 * @param file
	 *            File for the presumed EncFS volume
	 * @return true if the volume is EncFS, false otherwise
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public static boolean isEncFSVolume(File file) throws IOException {
		return isEncFSVolume(new EncFSLocalFileProvider(file));
	}

	/**
	 * Tests if the provided path contains EncFS volume
	 *
	 * @param fileProvider
	 *            File provider for the presumed EncFS volume
	 * @return true if the volume is EncFS, false otherwise
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public static boolean isEncFSVolume(EncFSFileProvider fileProvider)
			throws IOException {
		return (fileProvider.exists(fileProvider.getFilesystemRootPath()
				+ EncFSVolume.CONFIG_FILE_NAME));
	}

	/**
	 * Creates a new EncFS volume on the supplied file provider using the
	 * requested EncFSConfig parameters and the given password
	 *
	 * @param fileProvider
	 *            File provider to use for accessing storage
	 * @param config
	 *            Volume configuration to use, should have all fields except for
	 *            salt/VolumeCryptKey fields initialized
	 * @param password
	 *            Volume password to use
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public static void createVolume(EncFSFileProvider fileProvider,
			EncFSConfig config, String password)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		SecureRandom random = new SecureRandom();

		// Create a random volume VolumeCryptKey + IV pair
		byte[] randVolKey = new byte[config.getVolumeKeySizeInBits() / 8
				+ EncFSVolume.IV_LENGTH];
		random.nextBytes(randVolKey);

		EncFSCrypto.encodeVolumeKey(config, password, randVolKey, null);
		EncFSConfigWriter.writeConfig(fileProvider, config, password);
	}

	/**
	 * Creates a new EncFS volume on the supplied file provider using the
	 * requested EncFSConfig parameters and the given password
	 *
	 * @param fileProvider
	 *            File provider to use for accessing storage
	 * @param config
	 *            Volume configuration to use, should have all fields except for
	 *            salt/VolumeCryptKey fields initialized
	 * @param password
	 *            Volume password to use
	 * @param pbkdf2Provider
	 *            Custom PBKDF2 provider implementation
	 *
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public static void createVolume(EncFSFileProvider fileProvider,
			EncFSConfig config, String password,
			EncFSPBKDF2Provider pbkdf2Provider)
			throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		SecureRandom random = new SecureRandom();

		// Create a random volume VolumeCryptKey + IV pair
		byte[] randVolKey = new byte[config.getVolumeKeySizeInBits() / 8
				+ EncFSVolume.IV_LENGTH];
		random.nextBytes(randVolKey);

		EncFSCrypto.encodeVolumeKey(config, password, randVolKey,
				pbkdf2Provider);
		EncFSConfigWriter.writeConfig(fileProvider, config, password);
	}

	/**
	 * Creates a new file under the EncFS volume
	 *
	 * @param parentPath
	 *            Absolute volume path of the parent directory
	 * @param fileName
	 *            Name of the file to create
	 *
	 * @return EncFSFile handle for the newly created file
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSChecksumException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFile createFile(String parentPath, String fileName)
			throws EncFSCorruptDataException, EncFSChecksumException,
			IOException {
		validateAbsoluteFileName(parentPath, "volumePath");
		return createFile(combinePath(parentPath, fileName));
	}

	/**
	 * Creates a new file under the EncFS volume
	 *
	 * @param filePath
	 *            Absolute volume path of the file to create
	 *
	 * @return EncFSFile handle for the newly created file
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFile createFile(String filePath)
			throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(filePath, "fileName");

		String encryptedPath = EncFSCrypto
				.encodePath(this, filePath, ROOT_PATH);

		EncFSFileInfo fileInfo = fileProvider.createFile(encryptedPath);

		EncFSFileInfo decodedFileInfo;
		if (filePath.equals(ROOT_PATH)) {
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this, "",
					ROOT_PATH, fileInfo);
		} else {
			int lastIndexOfSeparator = filePath.lastIndexOf(PATH_SEPARATOR);
			String decDirName;
			String decFilename;
			if (filePath.lastIndexOf(PATH_SEPARATOR) == 0) {
				decDirName = PATH_SEPARATOR;
				decFilename = filePath.substring(1);

			} else {
				decDirName = filePath.substring(0, lastIndexOfSeparator);
				decFilename = filePath.substring(lastIndexOfSeparator + 1);
			}
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this,
					decDirName, decFilename, fileInfo);
		}

		return new EncFSFile(this, decodedFileInfo, fileInfo);
	}

	/**
	 * Create a new directory under the EncFS volume
	 *
	 * @param dirPath
	 *            Absolute volume path of the directory to create
	 *
	 * @return true if creation succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean makeDir(String dirPath) throws EncFSCorruptDataException,
			IOException {
		validateAbsoluteFileName(dirPath, "dirPath");

		String encryptedPath = EncFSCrypto.encodePath(this, dirPath, ROOT_PATH);

		boolean result = false;
		try {
			result = fileProvider.mkdir(encryptedPath);
		} catch (FileNotFoundException e) {
			throw new FileNotFoundException("One or more path element in '"
					+ dirPath + "' doesn't exist!");
		}

		return result;
	}

	/**
	 * Create a new directory under the EncFS volume, creating any missing
	 * directories in the path as well.
	 *
	 * @param dirPath
	 *            Absolute volume path of the directory to create
	 *
	 * @return true if creation succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean makeDirs(String dirPath) throws EncFSCorruptDataException,
			IOException {
		validateAbsoluteFileName(dirPath, "dirPath");

		String encryptedPath = EncFSCrypto.encodePath(this, dirPath, ROOT_PATH);
		return fileProvider.mkdirs(encryptedPath);
	}

	// Recursive method to delete a directory tree
	private boolean recursiveDelete(EncFSFile file,
			EncFSProgressListener progressListener) throws IOException {
		boolean result = true;

		if (file.isDirectory()) {
			for (EncFSFile subFile : file.listFiles()) {
				boolean subResult = recursiveDelete(subFile, progressListener);
				if (subResult == false) {
					result = false;
					break;
				}
			}

			if (result == true) {
				if (progressListener != null) {
					progressListener.setCurrentFile(file.getPath());
				}

				result = file.delete();

				if (progressListener != null) {
					progressListener
							.postEvent(EncFSProgressListener.FILE_PROCESS_EVENT);
				}
			}
		} else {
			if (progressListener != null) {
				progressListener.setCurrentFile(file.getPath());
			}

			result = file.delete();

			if (progressListener != null) {
				progressListener
						.postEvent(EncFSProgressListener.FILE_PROCESS_EVENT);
			}
		}

		return result;
	}

	/**
	 * Deletes the given file or directory in the EncFS volume
	 *
	 * @param filePath
	 *            Absolute volume path of the file/directory to delete
	 * @param recursive
	 *            Whether to recursively delete directories. Without this option
	 *            deletePath will fail to delete non-empty directories
	 * @param progressListener
	 *            Progress listener for getting individual file updates
	 *
	 * @return true if deletion succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 * @throws EncFSChecksumException
	 *             Filename encoding failed
	 */
	public boolean deletePath(String filePath, boolean recursive,
			EncFSProgressListener progressListener)
			throws EncFSCorruptDataException, IOException {
		EncFSFile file = this.getFile(filePath);
		boolean result;

		if (recursive == true) {

			if (progressListener != null) {
				progressListener.setNumFiles(countFiles(file));
			}

			result = recursiveDelete(file, progressListener);

			if (progressListener != null) {
				progressListener
						.postEvent(EncFSProgressListener.OP_COMPLETE_EVENT);
			}

			return result;
		} else {
			if (progressListener != null) {
				progressListener.setNumFiles(1);
				progressListener.setCurrentFile(file.getPath());
			}

			result = file.delete();

			if (progressListener != null) {
				progressListener
						.postEvent(EncFSProgressListener.FILE_PROCESS_EVENT);
				progressListener
						.postEvent(EncFSProgressListener.OP_COMPLETE_EVENT);
			}

			return result;
		}
	}

	/**
	 * Deletes the given file or directory in the EncFS volume
	 *
	 * @param filePath
	 *            Absolute volume path of the file/directory to delete
	 * @param recursive
	 *            Whether to recursively delete directories. Without this option
	 *            deletePath will fail to delete non-empty directories
	 *
	 * @return true if deletion succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 * @throws EncFSChecksumException
	 *             Filename encoding failed
	 */
	public boolean deletePath(String filePath, boolean recursive)
			throws EncFSCorruptDataException, IOException {
		return deletePath(filePath, recursive, null);
	}

	// Helper function to perform copy/move path operations
	private boolean copyOrMovePath(String srcPath, String dstPath,
			PathOperation op, EncFSProgressListener progressListener)
			throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(srcPath, "srcPath");
		validateAbsoluteFileName(dstPath, "dstPath");

		if (!pathExists(srcPath)) {
			throw new FileNotFoundException("Source path '" + srcPath
					+ "' doesn't exist!");
		}

		if (srcPath.equals(dstPath)) {
			throw new IOException("Can't copy/move onto the same path!");
		}

		String encSrcPath = EncFSCrypto.encodePath(this, srcPath, ROOT_PATH);
		String encDstPath = EncFSCrypto.encodePath(this, dstPath, ROOT_PATH);

		if (fileProvider.isDirectory(encSrcPath)
				&& (getConfig().isChainedNameIV() || op == PathOperation.COPY)) {
			/*
			 * To make this safe (for if we fail halfway through) we need to:
			 *
			 * 1) create the new directory 2) Recursively move the sub
			 * directories / folders 3) Delete the original directory
			 *
			 * We can do it as a rename of the parent / original folder or we
			 * could be left with files we can't read
			 */
			boolean result = true;

			// Need to copy/move the source dir to the destination
			EncFSFile thisDir = this.getFile(srcPath);
			// Update dstPath to point into the new target directory
			if (pathExists(dstPath)) {
				if (!fileProvider.isDirectory(encDstPath)) {
					throw new IOException(
							"Can't copy/move a directory onto a file!");
				}
				// dstPath is an existing dir, this is a copy/move into it
				dstPath = combinePath(dstPath, thisDir);
			} else {
				// If dstPath doesn't exist this is a rename, keep dstPath as-is
			}

			if (progressListener != null) {
				progressListener.setCurrentFile(dstPath);
			}

			result = this.makeDir(dstPath);

			if (progressListener != null) {
				progressListener
						.postEvent(EncFSProgressListener.FILE_PROCESS_EVENT);
			}

			if (result) {
				for (EncFSFile subFile : this.listFilesForPath(srcPath)) {
					boolean subResult = copyOrMovePath(subFile.getPath(),
							combinePath(dstPath, subFile), op, progressListener);

					if (!subResult) {
						result = false;
						break;
					}
				}
			}

			if (result) {
				// We only delete source directories for move, not copy
				if (op == PathOperation.MOVE) {
					result = fileProvider.delete(encSrcPath);
				}
			} else {
				// Attempt failure rollback
				fileProvider.delete(encDstPath);
			}

			return result;
		} else { // Simple file operation

			EncFSFile srcFile = getFile(srcPath);
			/*
			 * If dstPath is an existing directory we need to copy/move srcPath
			 * under it
			 */
			if (pathExists(dstPath)) {
				EncFSFile dstFile = getFile(dstPath);

				if (dstFile.isDirectory()) {
					return copyOrMovePath(srcPath,
							combinePath(dstPath, srcFile), op, progressListener);
				} else {
					throw new IOException("Destination file " + dstPath
							+ " exists, can't overwrite!");
				}
			} else {
				// dstPath doesn't exist, perform normal copy/move
				boolean result;

				if (progressListener != null) {
					progressListener.setCurrentFile(dstPath);
				}

				if (op == PathOperation.MOVE) {
					if (getConfig().isSupportedExternalIVChaining()) {
						/*
						 * Need to re-encrypt the file contents while moving
						 * since external IV chaining is being used. We'll just
						 * copy the file over to the destination path and delete
						 * the original file afterwards.
						 */
						result = srcFile.copy(createFile(dstPath));
						if (result == true) {
							result = srcFile.delete();
						}
					} else {
						// Simply move the file
						result = fileProvider.move(encSrcPath, encDstPath);
					}
				} else {
					result = srcFile.copy(createFile(dstPath));
				}

				if (progressListener != null) {
					progressListener
							.postEvent(EncFSProgressListener.FILE_PROCESS_EVENT);
				}

				return result;
			}
		}
	}

	/**
	 * Copies the source file or directory to the target file or directory
	 *
	 * @param srcPath
	 *            Absolute volume path of the source file or directory
	 * @param dstPath
	 *            Absolute volume path of the target file or directory
	 * @param progressListener
	 *            Progress listener for getting individual file updates
	 *
	 * @return true if copy succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean copyPath(String srcPath, String dstPath,
			EncFSProgressListener progressListener)
			throws EncFSCorruptDataException, IOException {
		if (progressListener != null) {
			progressListener.setNumFiles(countFiles(getFile(srcPath)) + 1);
		}

		boolean result = copyOrMovePath(srcPath, dstPath, PathOperation.COPY,
				progressListener);

		if (progressListener != null) {
			progressListener.postEvent(EncFSProgressListener.OP_COMPLETE_EVENT);
		}

		return result;
	}

	/**
	 * Copies the source file or directory to the target file or directory
	 *
	 * @param srcPath
	 *            Absolute volume path of the source file or directory
	 * @param dstPath
	 *            Absolute volume path of the target file or directory
	 *
	 * @return true if copy succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean copyPath(String srcPath, String dstPath)
			throws EncFSCorruptDataException, IOException {
		return copyPath(srcPath, dstPath, null);
	}

	/**
	 * Moves a file / directory
	 *
	 * @param srcPath
	 *            Absolute volume path of the file or directory to move
	 * @param dstPath
	 *            Absolute volume path of the destination file or directory
	 * @param progressListener
	 *            Progress listener for getting individual file updates
	 *
	 * @return true if the move succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean movePath(String srcPath, String dstPath,
			EncFSProgressListener progressListener)
			throws EncFSCorruptDataException, IOException {
		if (progressListener != null) {
			progressListener.setNumFiles(countFiles(getFile(srcPath)) + 1);
		}

		boolean result = copyOrMovePath(srcPath, dstPath, PathOperation.MOVE,
				progressListener);

		if (progressListener != null) {
			progressListener.postEvent(EncFSProgressListener.OP_COMPLETE_EVENT);
		}

		return result;
	}

	/**
	 * Moves a file / directory
	 *
	 * @param srcPath
	 *            Absolute volume path of the file or directory to move
	 * @param dstPath
	 *            Absolute volume path of the destination file or directory
	 *
	 * @return true if the move succeeds, false otherwise
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean movePath(String srcPath, String dstPath)
			throws EncFSCorruptDataException, IOException {
		return movePath(srcPath, dstPath, null);
	}

	/**
	 * Get list of EncFSFile's under the given directory
	 *
	 * @param dirPath
	 *            Absolute volume path of the directory to list
	 *
	 * @return list of EncFSFile under the given directory
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFile[] listFilesForPath(String dirPath)
			throws EncFSCorruptDataException, IOException {
		EncFSFile dir = getFile(dirPath);

		return dir.listFiles();
	}

	/**
	 * Opens the specified file as an EncFSInputStream that decrypts the file
	 * contents automatically
	 *
	 * @param filePath
	 *            Absolute volume path of the file
	 *
	 * @return EncFSInputStream that decrypts file contents
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSUnsupportedException
	 *             File header uses an unsupported IV length
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSInputStream openInputStreamForPath(String filePath)
			throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException {
		EncFSFile file = getFile(filePath);
		return file.openInputStream();
	}

	/**
	 * Opens the specified file as an EncFSOutputStream that encrypts the file
	 * contents automatically
	 *
	 * @param filePath
	 *            Absolute volume path of the file
	 * @param outputLength
	 *            Length of the output data that will be written to the returned
	 *            output stream. Note that this parameter is optional if using
	 *            EncFSLocalFileProvider, but some network based storage API's
	 *            require knowing the file length in advance.
	 *
	 * @return EncFSOutputStream that encrypts file contents
	 *
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSUnsupportedException
	 *             File header uses an unsupported IV length
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSOutputStream openOutputStreamForPath(String filePath,
			long outputLength) throws EncFSCorruptDataException,
			EncFSUnsupportedException, IOException, EncFSChecksumException {
		EncFSFile file = this.getFile(filePath);
		return file.openOutputStream(outputLength);
	}

	// Validate the given absolute file name format
	private void validateAbsoluteFileName(String fileName, String name) {
		if (name == null || name.length() == 0) {
			throw new IllegalStateException("name should not be blank");
		}

		if (fileName == null) {
			throw new IllegalArgumentException(name + " must not be null");
		}
		if (fileName.length() == 0) {
			throw new IllegalArgumentException(name + " must not be blank");
		}
		if (fileName.startsWith(PATH_SEPARATOR) == false) {
			throw new IllegalArgumentException(name + " must absolute");
		}
	}

}
