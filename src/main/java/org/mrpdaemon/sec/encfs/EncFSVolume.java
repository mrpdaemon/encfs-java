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
import java.security.InvalidKeyException;
import java.security.Key;
import java.util.Arrays;

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
	 * String denoting the root path of an EncFS volume
	 */
	public final static String ENCFS_VOLUME_ROOT_PATH = "/";

	/**
	 * Length in bytes of the volume initialization vector (IV)
	 */
	public final static int ENCFS_VOLUME_IV_LENGTH = 16;

	/**
	 * Standard name of the EncFS volume configuration file
	 */
	public final static String ENCFS_VOLUME_CONFIG_FILE_NAME = ".encfs6.xml";

	// Old EncFS config file names
	private final static String[] ENCFS_VOLUME_OLD_CONFIG_FILE_NAMES = { ".encfs5", ".encfs4", ".encfs3", ".encfs2",
			".encfs" };

	// Volume configuration
	private EncFSConfig config;

	// Volume encryption/decryption key
	private Key key;

	// Volume initialization vector for use with the volume key
	private byte[] iv;

	// Password-based key/IV
	private final byte[] passwordKey;

	// Volume MAC object to use for checksum computations
	private Mac mac;

	// Volume stream cipher
	private Cipher streamCipher;

	// Volume block cipher
	private Cipher blockCipher;

	// Root directory object
	private EncFSFile rootDir;

	private String configFileName;

	/**
	 * Returns the name of the EncFS volume configuration file present in the
	 * root directory of every EncFS volume
	 * 
	 * @return Standard name of the EncFS volume config file
	 */
	public String getConfigFileName() {
		return configFileName;
	}

	// Parse the configuration file - common step for constructor functions
	private void parseConfig(File rootDir, File configFile) throws FileNotFoundException, EncFSUnsupportedException,
			EncFSInvalidConfigException {
		if (!rootDir.exists()) {
			throw new FileNotFoundException("Root path doesn't exist " + rootDir.getAbsolutePath());
		}

		if (!configFile.exists()) {
			// Try old versions
			for (String altConfigFileName : ENCFS_VOLUME_OLD_CONFIG_FILE_NAMES) {
				File altConfigFile = new File(rootDir.getAbsolutePath() + File.separator + altConfigFileName);
				if (altConfigFile.exists()) {
					throw new EncFSUnsupportedException("Unsupported EncFS version");
				}
			}

			throw new EncFSInvalidConfigException("No EncFS configuration file found");
		}

		configFileName = configFile.getName();

		// Parse the configuration file
		try {
			this.config = EncFSConfigParser.parseFile(configFile);
		} catch (ParserConfigurationException e2) {
			throw new EncFSUnsupportedException("XML parser not supported");
		} catch (SAXException e2) {
			throw new EncFSInvalidConfigException("Parse error in config file");
		} catch (IOException e2) {
			throw new EncFSInvalidConfigException("Couldn't open config file");
		}
	}

	// Finish volume creation - common step for constructor functions
	private void createVolume(File rootDir) throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException {
		// Derive volume key from the supplied password
		byte[] keyData = null;
		try {
			keyData = EncFSCrypto.decryptVolumeKey(this.config, this.passwordKey);
		} catch (EncFSChecksumException e) {
			throw new EncFSInvalidPasswordException(e.getMessage());
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
			throw new EncFSInvalidConfigException(e.getMessage());
		}

		// Create stream cipher
		this.streamCipher = EncFSCrypto.newStreamCipher();

		// Create block cipher
		this.blockCipher = EncFSCrypto.newBlockCipher();

		// Create root file
		this.rootDir = null; // hack to let EncFSFile() know this is the root
								// dir
		try {
			this.rootDir = new EncFSFile(this, ENCFS_VOLUME_ROOT_PATH, rootDir);
		} catch (EncFSChecksumException e) {
			throw new EncFSCorruptDataException(e.getMessage());
		}
	}

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
		parseConfig(rootDir, configFile);

		this.passwordKey = EncFSCrypto.derivePasswordKey(this.config, password);

		createVolume(rootDir);
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
		parseConfig(rootDir, configFile);

		this.passwordKey = passwordKey;

		createVolume(rootDir);
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
		this(rootDir, new File(rootDir.getAbsolutePath(), ENCFS_VOLUME_CONFIG_FILE_NAME), password);
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
}