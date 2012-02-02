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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.xml.parsers.ParserConfigurationException;

import org.xml.sax.SAXException;

/**
 * Class representing an EncFS volume.
 * 
 * The volume is defined by a root folder, which contains an EncFS configuration
 * file and a hierarchy of encrypted files and subdirectories created by a
 * compliant EncFS implementation.
 */
public class EncFSVolume {
	/**
	 * Standard name of the EncFS volume configuration file
	 */
	public final static String ENCFS_VOLUME_CONFIG_FILE_NAME = ".encfs6.xml";

	// Old EncFS config file names
	private final static String[] ENCFS_VOLUME_OLD_CONFIG_FILE_NAMES = { ".encfs5", ".encfs4", ".encfs3", ".encfs2",
			".encfs" };

	/**
	 * String denoting the root path of an EncFS volume
	 */
	public final static String ENCFS_VOLUME_ROOT_PATH = "/";

	/**
	 * Length in bytes of the volume initialization vector (IV)
	 */
	public final static int ENCFS_VOLUME_IV_LENGTH = 16;

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

	private EncFSFileProvider fileProvider;

	/**
	 * Creates a new object representing an existing EncFS volume
	 * 
	 * @param rootDir
	 *            Root directory of the EncFS volume
	 * @param configFile
	 *            Configuration file of the EncFS volume
	 * @param password
	 *            User supplied password to decrypt volume key
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public EncFSVolume(File rootDir, File configFile, String password) throws FileNotFoundException,
			EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException {
		init(new EncFSLocalFileProvider(rootDir), configFile, password);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 * 
	 * @param rootDir
	 *            Root directory of the EncFS volume
	 * @param configFile
	 *            Configuration file of the EncFS volume
	 * @param passwordKey
	 *            Cached password-based key/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based key data can significantly speed up
	 *            volume creation.
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public EncFSVolume(File rootDir, File configFile, byte[] passwordKey) throws FileNotFoundException,
			EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException {
		init(new EncFSLocalFileProvider(rootDir), configFile, passwordKey);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 * 
	 * @param rootDir
	 *            Root directory of the EncFS volume
	 * @param password
	 *            User supplied password to decrypt volume key
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public EncFSVolume(File rootDir, String password) throws FileNotFoundException, EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException, EncFSUnsupportedException {
		init(new EncFSLocalFileProvider(rootDir), password);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 * 
	 * @param rootDir
	 *            Root directory of the EncFS volume
	 * @param passwordKey
	 *            Cached password-based key/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based key data can significantly speed up
	 *            volume creation.
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public EncFSVolume(File rootDir, byte[] passwordKey) throws FileNotFoundException, EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException, EncFSUnsupportedException {
		this(rootDir, new File(rootDir.getAbsolutePath(), ENCFS_VOLUME_CONFIG_FILE_NAME), passwordKey);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 * 
	 * @param rootPath
	 *            Path of the root directory of the EncFS volume
	 * @param password
	 *            User supplied password to decrypt volume key
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public EncFSVolume(String rootPath, String password) throws FileNotFoundException, EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException, EncFSUnsupportedException {
		this(new File(rootPath), password);
	}

	/**
	 * Creates a new object representing an existing EncFS volume
	 * 
	 * @param rootPath
	 *            Path of the root directory of the EncFS volume
	 * @param passwordKey
	 *            Cached password-based key/IV data. Can be obtained using
	 *            getPasswordKey() on a volume created with a regular password.
	 *            Caching the password-based key data can significantly speed up
	 *            volume creation.
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public EncFSVolume(String rootPath, byte[] passwordKey) throws FileNotFoundException,
			EncFSInvalidPasswordException, EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException {
		this(new File(rootPath), passwordKey);
	}

	/**
	 * Initialises a new object representing an existing EncFS volume
	 * 
	 * @param encFsRootDir
	 *            Root directory of the EncFS volume
	 * @param password
	 *            User supplied password to decrypt volume key
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public void init(EncFSFileProvider nativeFileSource, String password) throws FileNotFoundException,
			EncFSUnsupportedException, EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSInvalidPasswordException {
		EncFSConfig config = parseConfig(nativeFileSource, ENCFS_VOLUME_CONFIG_FILE_NAME);
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password);

		this.init(nativeFileSource, config, passwordKey);
	}

	/**
	 * Initialises a new object representing an existing EncFS volume using
	 * cached password-based key/IV data. (Can be obtained using
	 * getPasswordKey() on a volume created with a regular password. Caching the
	 * password-based key data can significantly speed up volume creation.)
	 * 
	 * @param encFsRootDir
	 *            Root directory of the EncFS volume
	 * @param passwordKey
	 *            Cached password-based key/IV data.
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public void init(EncFSFileProvider nativeFileSource, byte[] passwordKey) throws FileNotFoundException,
			EncFSUnsupportedException, EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSInvalidPasswordException {
		EncFSConfig config = parseConfig(nativeFileSource, ENCFS_VOLUME_CONFIG_FILE_NAME);

		this.init(nativeFileSource, config, passwordKey);
	}

	/**
	 * Initialises a new object representing an existing EncFS volume with a
	 * user specified config file.
	 * 
	 * @param encFsRootDir
	 *            Root directory of the EncFS volume
	 * @param configFile
	 *            Configuration file of the EncFS volume
	 * @param password
	 *            User specified password
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public void init(EncFSFileProvider fileProvider, File encFsConfigFile, String password)
			throws FileNotFoundException, EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException {
		EncFSConfig config = parseConfig(encFsConfigFile);
		byte[] passwordKey = EncFSCrypto.derivePasswordKey(config, password);

		init(fileProvider, config, passwordKey);
	}

	/**
	 * Initialises a new object representing an existing EncFS volume with a
	 * user specified config file using cached password-based key/IV data. (Can
	 * be obtained using getPasswordKey() on a volume created with a regular
	 * password. Caching the password-based key data can significantly speed up
	 * volume creation.)
	 * 
	 * @param encFsRootDir
	 *            Root directory of the EncFS volume
	 * @param configFile
	 *            Configuration file of the EncFS volume
	 * @param passwordKey
	 *            Cached password-based key/IV data.
	 * 
	 * @throws FileNotFoundException
	 *             Root directory or configuration file not found
	 * @throws EncFSInvalidPasswordException
	 *             Given password is incorrect
	 * @throws EncFSCorruptDataException
	 *             Corrupt data detected (checksum error)
	 * @throws EncFSInvalidConfigException
	 *             Configuration file format not recognized
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS version or options
	 */
	public void init(EncFSFileProvider fileProvider, File encFsConfigFile, byte[] passwordKey)
			throws FileNotFoundException, EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException {

		EncFSConfig config = parseConfig(encFsConfigFile);

		init(fileProvider, config, passwordKey);
	}

	private void init(EncFSFileProvider fileProvider, EncFSConfig config, byte[] passwordKey)
			throws FileNotFoundException, EncFSUnsupportedException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSInvalidPasswordException {
		this.fileProvider = fileProvider;

		this.config = config;
		this.passwordKey = passwordKey;
		// Derive volume key from the supplied password
		byte[] keyData = null;
		try {
			keyData = EncFSCrypto.decryptVolumeKey(this.config, this.passwordKey);
		} catch (EncFSChecksumException e) {
			throw new EncFSInvalidPasswordException(e);
		}

		// Create volume key
		int keyLength = this.config.getVolumeKeySize() / 8;
		if (keyData.length < keyLength) {
			throw new EncFSInvalidConfigException("Key size too large");
		}
		this.key = EncFSCrypto.newKey(Arrays.copyOfRange(keyData, 0, keyLength));

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

		rootDir = getEncFSFile(ENCFS_VOLUME_ROOT_PATH);
	}

	// Parse the configuration file - common step for init functions
	private static EncFSConfig parseConfig(File configFile) throws FileNotFoundException, EncFSUnsupportedException,
			EncFSInvalidConfigException {
		return parseConfig(new EncFSLocalFileProvider(configFile.getParentFile()), configFile.getName());
	}

	private static EncFSConfig parseConfig(EncFSFileProvider nativeFileSystem, String name)
			throws EncFSUnsupportedException, EncFSInvalidConfigException {

		EncFSConfig config;
		if (!nativeFileSystem.exists("/" + name)) {
			// Try old versions
			for (String altConfigFileName : ENCFS_VOLUME_OLD_CONFIG_FILE_NAMES) {
				if (nativeFileSystem.exists("/" + altConfigFileName)) {
					throw new EncFSUnsupportedException("Unsupported EncFS version");
				}
			}

			throw new EncFSInvalidConfigException("No EncFS configuration file found");
		}

		// Parse the configuration file
		try {
			config = EncFSConfigParser.parseFile(nativeFileSystem.openInputStream("/" + name));
		} catch (ParserConfigurationException e2) {
			throw new EncFSUnsupportedException("XML parser not supported");
		} catch (SAXException e2) {
			throw new EncFSInvalidConfigException("Parse error in config file");
		} catch (IOException e2) {
			throw new EncFSInvalidConfigException("Couldn't open config file");
		}

		return config;
	}

	/**
	 * @return Configuration for this EncFS volume
	 */
	public EncFSConfig getConfig() {
		return config;
	}

	/**
	 * @return Volume key for encryption/decryption
	 */
	public Key getKey() {
		return key;
	}

	/**
	 * @return Volume initialization vector (IV) for encryption/decryption
	 */
	public byte[] getIV() {
		return iv;
	}

	/**
	 * @return Password-based key/IV data for this volume
	 */
	public byte[] getPasswordKey() {
		return passwordKey;
	}

	/**
	 * @return Volume MAC for checksum verification
	 */
	public Mac getMac() {
		return mac;
	}

	/**
	 * @return Stream cipher instance for stream encryption/decryption
	 */
	public Cipher getStreamCipher() {
		return streamCipher;
	}

	/**
	 * @return Block cipher instance for block encryption/decryption
	 */
	public Cipher getBlockCipher() {
		return blockCipher;
	}

	/**
	 * @return EncFSFile representing the root directory of this volume
	 */
	public EncFSFile getRootDir() {
		return rootDir;
	}

	public EncFSFile getEncFSFile(String volumePath, String fileName) throws EncFSCorruptDataException,
			EncFSChecksumException {
		validateAbsoluteFileName(volumePath, "volumePath");
		return getEncFSFile(volumePath + "/" + fileName);
	}

	public EncFSFile getEncFSFile(String fileName) throws EncFSCorruptDataException {
		validateAbsoluteFileName(fileName, "fileName");

		String toEncVolumePath = EncFSCrypto.encodePath(this, fileName, "/");

		EncFSFileInfo fileInfo = fileProvider.getFileInfo(toEncVolumePath);

		EncFSFileInfo decodedFileInfo;
		if (fileName.equals(ENCFS_VOLUME_ROOT_PATH)) {
			decodedFileInfo = convertNativeToDecodedFileInfo("", "/", fileInfo);
		} else {
			String decDirName = fileName.substring(0, fileName.lastIndexOf("/") - 1);
			String decFilename = fileName.substring(fileName.lastIndexOf("/") + 1);
			decodedFileInfo = convertNativeToDecodedFileInfo(decDirName, decFilename, fileInfo);
		}

		if (this.fileProvider instanceof EncFSLocalFileProvider) {
			File file = ((EncFSLocalFileProvider) fileProvider).getFile(fileInfo.getAbsoluteName());
			return new EncFSFile(this, decodedFileInfo, fileInfo, file);
		} else {
			return new EncFSFile(this, decodedFileInfo, fileInfo);
		}

	}

	/**
	 * Creates the directory in the EncFS volume
	 * 
	 * @param dirName
	 *            (absolute path name)
	 * @return
	 * @throws EncFSCorruptDataException
	 *             throw if the name can not be correctly encoded
	 * @throws IOException
	 */
	public boolean makeDir(String dirName) throws EncFSCorruptDataException, IOException {
		EncFSFile encfsFile = getEncFSFile(dirName);
		return makeDir(encfsFile);
	}

	public boolean makeDir(EncFSFile encfsFile) throws IOException {
		return fileProvider.mkdir(encfsFile.getEncrytedAbsoluteName());
	}

	/**
	 * Creates the directory path in the EncFS volume (i.e. creates missing
	 * intermediate directories)
	 * 
	 * @param dirName
	 *            (absolute path name)
	 * @return
	 * @throws EncFSCorruptDataException
	 *             throw if the name can not be correctly encoded
	 * @throws IOException
	 */
	public boolean makeDirs(String dirName) throws EncFSCorruptDataException, IOException {
		EncFSFile encfsFile = getEncFSFile(dirName);
		return makeDirs(encfsFile);
	}

	public boolean makeDirs(EncFSFile encfsFile) throws IOException {
		return fileProvider.mkdirs(encfsFile.getEncrytedAbsoluteName());
	}

	/**
	 * Deletes the file / directory in the EncFS volume
	 * 
	 * @param absoluteName
	 *            (absolute path name)
	 * @return
	 * @throws EncFSCorruptDataException
	 *             throw if the name can not be correctly encoded
	 * @throws IOException
	 * @throws EncFSChecksumException
	 */
	public boolean delete(String absoluteName) throws EncFSCorruptDataException, IOException {
		EncFSFile encfsFile = this.getEncFSFile(absoluteName);
		return delete(encfsFile);
	}

	public boolean delete(EncFSFile encfsFile) throws IOException {
		return fileProvider.delete(encfsFile.getEncrytedAbsoluteName());
	}

	/**
	 * Copies the src file / directory to the target file / directory
	 * 
	 * @param srcFile
	 * @param targetFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws IOException
	 */
	public boolean copy(String srcFile, String targetFile) throws EncFSCorruptDataException, IOException {

		EncFSFile srcEncFile = getEncFSFile(srcFile);
		EncFSFile targetEncFile = getEncFSFile(targetFile);

		return copy(srcEncFile, targetEncFile);
	}

	public boolean copy(EncFSFile srcEncFile, EncFSFile targetEncFile) throws IOException {
		if (config.isUniqueIV()) {
			// More complicated as we need to copy the files
			// by reading them in as a stream & writing them out again
			// so that we generate unique headers for the file copies

			if (targetEncFile.isDirectory()) {
				EncFSFile realTargetEncfsDirFile;
				try {
					realTargetEncfsDirFile = getEncFSFile(targetEncFile.getAbsoluteName(), srcEncFile.getName());
				} catch (EncFSCorruptDataException e) {
					throw new IOException(e);
				} catch (EncFSChecksumException e) {
					throw new IOException(e);
				}
				return copy(srcEncFile, realTargetEncfsDirFile);
			} else if (srcEncFile.isDirectory()) {
				boolean result = fileProvider.mkdir(targetEncFile.getEncrytedAbsoluteName());

				if (result) {
					try {

						// recurse in & copy each of the files within that
						// directory
						for (EncFSFile srcEncFsDirFile : srcEncFile.listFiles()) {
							EncFSFile targetEncfsDirFile = getEncFSFile(targetEncFile.getAbsoluteName(),
									srcEncFsDirFile.getName());
							result &= copy(srcEncFsDirFile, targetEncfsDirFile);

							if (!result) {
								break;
							}
						}
					} catch (EncFSCorruptDataException e) {
						throw new IOException(e);
					} catch (EncFSChecksumException e) {
						throw new IOException(e);
					}
				}
				return result;
			} else {
				try {
					copyViaStreams(srcEncFile, targetEncFile);
				} catch (EncFSCorruptDataException e) {
					throw new IOException(e);
				} catch (EncFSUnsupportedException e) {
					throw new IOException(e);
				} catch (EncFSChecksumException e) {
					throw new IOException(e);
				}

				return true;
			}
		} else {
			return fileProvider.copy(srcEncFile.getEncrytedAbsoluteName(), targetEncFile.getEncrytedAbsoluteName());
		}
	}

	/**
	 * Moves a file / directory
	 * 
	 * @param srcFile
	 *            (absolute path name)
	 * @param targetFile
	 *            (absolute path name)
	 * @return
	 * @throws EncFSCorruptDataException
	 *             throw if the name can not be correctly encoded
	 * @throws IOException
	 */
	public boolean move(String srcFile, String targetFile) throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(srcFile, "srcFile");
		validateAbsoluteFileName(targetFile, "targetFile");

		String encSrcFile = EncFSCrypto.encodePath(this, srcFile, "/");
		String encTargetFile = EncFSCrypto.encodePath(this, targetFile, "/");

		if (fileProvider.isDirectory(encSrcFile) && getConfig().isChainedNameIV()) {
			//
			// To make this safe (for if we fail halfway through) we need to
			// 1) create the new directory
			// 2) Recursively move the sub directories / folders
			// 3) Delete the original directory
			// We can do it as a rename of the parent / original folder or
			// we
			// could be left with files we can't read

			boolean result = true;
			if (fileProvider.mkdir(encTargetFile) == false) {
				result = false;
			}
			if (result) {
				for (EncFSFile subFile : this.listFiles(srcFile)) {
					boolean subResult = subFile.renameTo(srcFile, subFile.getName());
					if (!subResult) {
						result = false;
						break;
					}
				}

				// TODO: Decide how to handle files that are in the native
				// directory
				// but not part of this volume (do we move them? Do we leave
				// them in
				// the old directory?)

			}
			if (result) {
				result = fileProvider.delete(encSrcFile);
			}

			return result;
		} else {
			return fileProvider.move(encSrcFile, encTargetFile);
		}
	}

	public EncFSFile[] listFiles(String dirName2) throws EncFSCorruptDataException, IOException {
		EncFSFile encfsFile2 = getEncFSFile(dirName2);

		return listFiles(encfsFile2);
	}

	public EncFSFile[] listFiles(EncFSFile encfsDirFile) throws IOException {
		String encDirName;
		if (encfsDirFile == this.rootDir) {
			encDirName = "/";
		} else {
			encDirName = encfsDirFile.getEncrytedAbsoluteName();
		}
		String dirName = encfsDirFile.getAbsoluteName();

		List<EncFSFileInfo> fileInfos = fileProvider.listFiles(encDirName);
		List<EncFSFile> result = new ArrayList<EncFSFile>(fileInfos.size());

		for (EncFSFileInfo fileInfo : fileInfos) {
			String decodedFileName;
			try {
				decodedFileName = EncFSCrypto.decodeName(this, fileInfo.getName(), dirName);
			} catch (EncFSCorruptDataException e) {
				decodedFileName = null;
			} catch (EncFSChecksumException e) {
				decodedFileName = null;
			}

			if (decodedFileName != null) {
				EncFSFileInfo decEncFileInfo = convertNativeToDecodedFileInfo(dirName, decodedFileName, fileInfo);

				EncFSFile encfsFile;
				if (this.fileProvider instanceof EncFSLocalFileProvider) {
					File file = ((EncFSLocalFileProvider) fileProvider).getFile(fileInfo
							.getAbsoluteName());
					encfsFile = new EncFSFile(this, decEncFileInfo, fileInfo, file);
				} else {
					encfsFile = new EncFSFile(this, decEncFileInfo, fileInfo);
				}

				result.add(encfsFile);
			}
		}

		return result.toArray(new EncFSFile[result.size()]);
	}

	/**
	 * Checks if a specified file / path is a directory (or a file)
	 * 
	 * @param srcFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws IOException
	 */

	public boolean isDirectory(String srcFile) throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(srcFile, "srcFile");

		String encSrcFile = EncFSCrypto.encodePath(this, srcFile, "/");
		return fileProvider.isDirectory(encSrcFile);
	}

	/**
	 * Opens in specified file as an input stream (with the input stream doing
	 * the decoding automatically)
	 * 
	 * @param srcFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws EncFSUnsupportedException
	 * @throws IOException
	 */
	public InputStream openInputStream(String srcFile) throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException {
		EncFSFile encfsFile = getEncFSFile(srcFile);
		return openInputStream(encfsFile);
	}

	public InputStream openInputStream(EncFSFile encfsFile) throws EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		return new EncFSInputStream(this, fileProvider.openInputStream(encfsFile.getEncrytedAbsoluteName()));
	}

	/**
	 * Opens in specified file as a native input stream (without the input
	 * stream doing the decoding automatically)
	 * 
	 * @param srcFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws IOException
	 */
	@Deprecated
	public InputStream openNativeInputStream(String srcFile) throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(srcFile, "srcFile");

		String encSrcFile = EncFSCrypto.encodePath(this, srcFile, "/");
		return fileProvider.openInputStream(encSrcFile);
	}

	/**
	 * Opens in specified file as an output stream (with the input stream doing
	 * the encoding automatically)
	 * 
	 * @param srcFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws IOException
	 * @throws EncFSChecksumException
	 */
	public OutputStream openOutputStream(String srcFile) throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException, EncFSChecksumException {
		EncFSFile encfsFile = this.getEncFSFile(srcFile);
		return openOutputStream(encfsFile);
	}

	/**
	 * Opens in specified file as an output stream (with the input stream doing
	 * the encoding automatically)
	 * 
	 * @param srcFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws IOException
	 * @throws EncFSChecksumException
	 */
	public EncFSOutputStream openOutputStream(EncFSFile encfsFile) throws EncFSUnsupportedException,
			EncFSCorruptDataException, IOException {
		return new EncFSOutputStream(this, fileProvider.openOutputStream(encfsFile.getEncrytedAbsoluteName()));
	}

	/**
	 * Opens in specified file as a native output stream (without the stream
	 * doing the decoding automatically)
	 * 
	 * This is deprecated & openOutputStream should be used instead (to prevent
	 * un-encoded / native functions being exposed)
	 * 
	 * @param srcFile
	 * @return
	 * @throws EncFSCorruptDataException
	 * @throws IOException
	 */
	@Deprecated
	public OutputStream openNativeOutputStream(String srcFile) throws EncFSCorruptDataException, IOException {
		validateAbsoluteFileName(srcFile, "srcFile");

		String encSrcFile = EncFSCrypto.encodePath(this, srcFile, "/");
		return fileProvider.openOutputStream(encSrcFile);
	}

	private EncFSFileInfo convertNativeToDecodedFileInfo(String decodedDirName, String decodedFileName,
			EncFSFileInfo fileInfo) {
		long size;
		if (fileInfo.isDirectory()) {
			size = 0;
		} else {
			boolean haveHeader = getConfig().isUniqueIV();

			size = fileInfo.getSize();

			if (haveHeader && size > 0) {
				size -= EncFSFile.HEADER_SIZE;
			}
		}

		EncFSFileInfo decEncFileInfo = new EncFSFileInfo(decodedFileName, decodedDirName, fileInfo.isDirectory(),
				fileInfo.getModified(), size, fileInfo.canRead(), fileInfo.canWrite(), fileInfo.canExecute());
		return decEncFileInfo;
	}

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

	private static void copyViaStreams(EncFSFile srcEncFSFile, EncFSFile targetEncFSFile) throws IOException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException {

		if (srcEncFSFile.isDirectory() || targetEncFSFile.isDirectory()) {
			throw new IllegalArgumentException("Can't copy directories");
		}

		OutputStream efos = srcEncFSFile.openOutputStream();
		try {
			InputStream efis = srcEncFSFile.openInputStream();
			try {
				int bytesRead = 0;
				while (bytesRead >= 0) {
					byte[] readBuf = new byte[128];
					bytesRead = efis.read(readBuf);
					if (bytesRead >= 0) {
						efos.write(readBuf, 0, bytesRead);
					}
				}
			} finally {
				efis.close();
			}

		} finally {
			efos.close();
		}
	}

}