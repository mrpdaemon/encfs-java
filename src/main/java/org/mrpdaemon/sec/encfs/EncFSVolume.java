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
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 * Class representing an EncFS volume.
 * 
 * The volume is defined by a root folder, which contains an EncFS configuration
 * file and a hierarchy of encrypted files and subdirectories created by a
 * compliant EncFS implementation.
 */
public class EncFSVolume {
	/** Standard name of the EncFS volume configuration file */
	public final static String ENCFS_VOLUME_CONFIG_FILE_NAME = ".encfs6.xml";

	/** Old EncFS config file names */
	public final static String[] ENCFS_VOLUME_OLD_CONFIG_FILE_NAMES = {
			".encfs5", ".encfs4", ".encfs3", ".encfs2", ".encfs" };

	/** String denoting the root path of an EncFS volume */
	public final static String ENCFS_VOLUME_ROOT_PATH = "/";

	/** Length in bytes of the volume initialization vector (IV) */
	public final static int ENCFS_VOLUME_IV_LENGTH = 16;

	// Path operations
	private static enum PathOperation {
		MOVE, COPY
	}

	// Volume configuration
	private EncFSConfig config;

	// Volume encryption/decryption key
	private Key key;

	// Volume initialization vector for use with the volume key
	private byte[] iv;

	// Password-based key/IV
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
	 *            User supplied password to decrypt volume key
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
	 * @param passwordKey
	 *            Cached password-based key/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based key data can significantly speed up
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
	 *            User supplied password to decrypt volume key
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
	 * @param passwordKey
	 *            Cached password-based key/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based key data can significantly speed up
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
	 *            User supplied password to decrypt volume key
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
	 * @param passwordKey
	 *            Cached password-based key/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based key data can significantly speed up
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

	// Read configuration, derive password key and initialize volume
	private void init(EncFSFileProvider fileProvider, String password)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		EncFSConfig config = EncFSConfigParser.parseConfig(fileProvider,
				ENCFS_VOLUME_CONFIG_FILE_NAME);
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password);

		this.init(fileProvider, config, passwordKey);
	}

	// Derive password key and initialize volume
	private void init(EncFSFileProvider fileProvider, EncFSConfig config,
			String password) throws EncFSUnsupportedException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSInvalidPasswordException, IOException {
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password);

		this.init(fileProvider, config, passwordKey);
	}

	// Read configuration and initialize volume
	private void init(EncFSFileProvider fileProvider, byte[] passwordKey)
			throws EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException,
			IOException {
		EncFSConfig config = EncFSConfigParser.parseConfig(fileProvider,
				ENCFS_VOLUME_CONFIG_FILE_NAME);

		this.init(fileProvider, config, passwordKey);
	}

	// Main method to perform volume variable initialization
	private void init(EncFSFileProvider fileProvider, EncFSConfig config,
			byte[] passwordKey) throws EncFSUnsupportedException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSInvalidPasswordException, IOException {
		this.fileProvider = fileProvider;

		this.config = config;
		this.passwordKey = passwordKey;
		// Derive volume key from the supplied password
		byte[] keyData = null;
		try {
			keyData = EncFSCrypto.decryptVolumeKey(this.config,
					this.passwordKey);
		} catch (EncFSChecksumException e) {
			throw new EncFSInvalidPasswordException(e);
		}

		// Create volume key
		int keyLength = this.config.getVolumeKeySize() / 8;
		if (keyData.length < keyLength) {
			throw new EncFSInvalidConfigException("Key size too large");
		}
		this.key = EncFSCrypto
				.newKey(Arrays.copyOfRange(keyData, 0, keyLength));

		// Copy IV data
		int ivLength = keyData.length - keyLength;
		if (ivLength != ENCFS_VOLUME_IV_LENGTH) {
			throw new EncFSInvalidConfigException("Non-standard IV length");
		}
		this.iv = Arrays.copyOfRange(keyData, keyLength, keyLength + ivLength);

		// Create volume MAC
		try {
			this.mac = EncFSCrypto.newMac(this.key);
		} catch (InvalidKeyException e) {
			throw new EncFSInvalidConfigException(e);
		}

		// Create stream cipher
		this.streamCipher = EncFSCrypto.newStreamCipher();

		// Create block cipher
		this.blockCipher = EncFSCrypto.newBlockCipher();

		rootDir = getFile(ENCFS_VOLUME_ROOT_PATH);
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
	 * Returns the volume key used for encryption/decryption
	 * 
	 * @return Volume key for encryption/decryption
	 */
	public Key getKey() {
		return key;
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
	 * Returns the password based key/IV data for this volume
	 * 
	 * @return Password-based key/IV data for this volume
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
		return getFile(parentPath + "/" + fileName);
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

		String encryptedPath = EncFSCrypto.encodePath(this, filePath,
				ENCFS_VOLUME_ROOT_PATH);

		if (fileProvider.exists(encryptedPath) == false) {
			throw new FileNotFoundException();
		}
		EncFSFileInfo fileInfo = fileProvider.getFileInfo(encryptedPath);

		EncFSFileInfo decodedFileInfo;
		if (filePath.equals(ENCFS_VOLUME_ROOT_PATH)) {
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this, "", "/",
					fileInfo);
		} else {
			int lastIndexOfSlash = filePath.lastIndexOf("/");
			String decDirName;
			String decFilename;
			if (filePath.lastIndexOf("/") == 0) {
				decDirName = "/";
				decFilename = filePath.substring(1);

			} else {
				decDirName = filePath.substring(0, lastIndexOfSlash);
				decFilename = filePath.substring(lastIndexOfSlash + 1);
			}
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this,
					decDirName, decFilename, fileInfo);
		}

		return new EncFSFile(this, decodedFileInfo, fileInfo);
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
		String encryptedPath = EncFSCrypto.encodePath(this, path,
				ENCFS_VOLUME_ROOT_PATH);
		return fileProvider.exists(encryptedPath);
	}

	/**
	 * Creates a new EncFS volume on the supplied file provider using the
	 * requested EncFSConfig parameters and the given password
	 * 
	 * @param fileProvider
	 *            File provider to use for accessing storage
	 * @param config
	 *            Volume configuration to use, should have all fields except for
	 *            salt/key fields initialized
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

		// Create a random volume key + IV pair
		byte[] randVolKey = new byte[config.getVolumeKeySize() / 8
				+ EncFSVolume.ENCFS_VOLUME_IV_LENGTH];
		random.nextBytes(randVolKey);

		EncFSCrypto.encodeVolumeKey(config, password, randVolKey);
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
		return createFile(parentPath + "/" + fileName);
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

		String encryptedPath = EncFSCrypto.encodePath(this, filePath,
				ENCFS_VOLUME_ROOT_PATH);

		EncFSFileInfo fileInfo = fileProvider.createFile(encryptedPath);

		EncFSFileInfo decodedFileInfo;
		if (filePath.equals(ENCFS_VOLUME_ROOT_PATH)) {
			decodedFileInfo = EncFSFileInfo.getDecodedFileInfo(this, "", "/",
					fileInfo);
		} else {
			int lastIndexOfSlash = filePath.lastIndexOf("/");
			String decDirName;
			String decFilename;
			if (filePath.lastIndexOf("/") == 0) {
				decDirName = "/";
				decFilename = filePath.substring(1);

			} else {
				decDirName = filePath.substring(0, lastIndexOfSlash);
				decFilename = filePath.substring(lastIndexOfSlash + 1);
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

		String encryptedPath = EncFSCrypto.encodePath(this, dirPath,
				ENCFS_VOLUME_ROOT_PATH);

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

		String encryptedPath = EncFSCrypto.encodePath(this, dirPath,
				ENCFS_VOLUME_ROOT_PATH);
		return fileProvider.mkdirs(encryptedPath);
	}

	/**
	 * Deletes the given file or directory in the EncFS volume
	 * 
	 * @param filePath
	 *            Absolute volume path of the file/directory to delete
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
	public boolean deletePath(String filePath)
			throws EncFSCorruptDataException, IOException {
		EncFSFile file = this.getFile(filePath);
		return file.delete();
	}

	// Helper function to perform copy/move path operations
	private boolean copyOrMovePath(String srcPath, String dstPath,
			PathOperation op) throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(srcPath, "srcPath");
		validateAbsoluteFileName(dstPath, "dstPath");

		String encSrcPath = EncFSCrypto.encodePath(this, srcPath, "/");
		String encDstPath = EncFSCrypto.encodePath(this, dstPath, "/");

		if (fileProvider.isDirectory(encSrcPath)
				&& getConfig().isChainedNameIV()) {
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

			if (fileProvider.mkdir(encDstPath) == false) {
				result = false;
			}

			if (result) {
				for (EncFSFile subFile : this.listFilesForPath(srcPath)) {
					boolean subResult;
					if (op == PathOperation.MOVE) {
						subResult = this.movePath(subFile.getPath(), dstPath
								+ "/" + subFile.getName());
					} else {
						subResult = this.copyPath(subFile.getPath(), dstPath
								+ "/" + subFile.getName());
					}
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
			if (op == PathOperation.MOVE) {
				return fileProvider.move(encSrcPath, encDstPath);
			} else {
				if (!pathExists(srcPath)) {
					throw new FileNotFoundException("Source path '" + srcPath
							+ "' doesn't exist!");
				}
				EncFSFile srcFile = getFile(srcPath);
				EncFSFile dstFile;
				if (pathExists(dstPath)) {
					dstFile = getFile(dstPath);
				} else {
					dstFile = createFile(dstPath);
				}
				return srcFile.copy(dstFile);
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
		return copyOrMovePath(srcPath, dstPath, PathOperation.COPY);
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
		return copyOrMovePath(srcPath, dstPath, PathOperation.MOVE);
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
	 * Opens the specified file as an InputStream that decrypts the file
	 * contents automatically
	 * 
	 * @param filePath
	 *            Absolute volume path of the file
	 * 
	 * @return InputStream that decrypts file contents
	 * 
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSUnsupportedException
	 *             File header uses an unsupported IV length
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public InputStream openInputStreamForPath(String filePath)
			throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException {
		EncFSFile file = getFile(filePath);
		return file.openInputStream();
	}

	/**
	 * Opens the specified file as an OutputStream that encrypts the file
	 * contents automatically
	 * 
	 * @param filePath
	 *            Absolute volume path of the file
	 * 
	 * @return OutputStream that encrypts file contents
	 * 
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSUnsupportedException
	 *             File header uses an unsupported IV length
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public OutputStream openOutputStreamForPath(String filePath)
			throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException, EncFSChecksumException {
		EncFSFile file = this.getFile(filePath);
		return file.openOutputStream();
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
		if (fileName.startsWith("/") == false) {
			throw new IllegalArgumentException(name + " must absolute");
		}
	}

}
