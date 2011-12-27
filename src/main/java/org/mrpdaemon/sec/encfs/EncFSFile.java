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
import java.io.FileFilter;

/**
 * Object representing a file in an EncFS volume.
 * 
 * Useful for decryption of file names.
 */
public class EncFSFile {

	private static final long HEADER_SIZE = 8; // 64 bit initialization vector..

	// Volume path of this file
	private final String volumePath;

	// Volume hosting this file
	private final EncFSVolume volume;

	// Underlying File object ('this' doesn't extend File)
	private final File file;

	// Cached plaintext name of the represented file
	private String plaintextName;

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume
	 *            EncFS volume hosting the file
	 * @param volumePath
	 *            Relative path of the file within the volume. The root
	 *            directory of the volume is "/" and files underneath the root
	 *            directory are represented by their paths relative to the root.
	 * @param file
	 *            Actual file object to use as a basis for this EncFS file. Note
	 *            that EncFSFile doesn't extend File since we'd like to be able
	 *            to overlay EncFSFile over any kind of abstraction that extends
	 *            File, for example network file storage etc.
	 * 
	 * @throws EncFSCorruptDataException
	 *             File name doesn't follow EncFS standard
	 * @throws EncFSChecksumException
	 *             Checksum error during name decoding
	 */
	public EncFSFile(EncFSVolume volume, String volumePath, File file) throws EncFSCorruptDataException,
			EncFSChecksumException {
		this.file = file;
		this.volume = volume;
		this.volumePath = volumePath;

		// Pre-compute plaintext name
		if (file.getName().equals(EncFSVolume.ENCFS_VOLUME_CONFIG_FILE_NAME) || file.getName().equals(".")
				|| file.getName().equals("..") || volume.getRootDir() == null) // hack,
																				// call
																				// is
																				// from
																				// EncFSVolume()
		{
			this.plaintextName = file.getName();
		} else {
			this.plaintextName = EncFSCrypto.decodeName(volume, file.getName(), volumePath);
		}
	}

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume
	 *            EncFS volume hosting the file
	 * @param volumePath
	 *            Relative path of the file within the volume. The root
	 *            directory of the volume is "/" and files underneath the root
	 *            directory are represented by their paths relative to the root.
	 * @param filePath
	 *            Path to the actual file to use as a basis for this EncFS file.
	 * 
	 * @throws EncFSCorruptDataException
	 *             File name doesn't follow EncFS standard
	 * @throws EncFSChecksumException
	 *             Checksum error during name decoding
	 */
	public EncFSFile(EncFSVolume volume, String volumePath, String filePath) throws EncFSCorruptDataException,
			EncFSChecksumException {
		this(volume, volumePath, new File(filePath));
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
	 * @throws EncFSCorruptDataException
	 *             Invalid file name size
	 * @throws EncFSChecksumException
	 *             Filename checksum mismatch
	 */
	public String[] list() throws EncFSCorruptDataException, EncFSChecksumException {
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
	public String getName() {
		return plaintextName;
	}

	/**
	 * List of EncFSFile's for all files and directories that are children of
	 * the directory represented by this EncFSFile
	 * 
	 * @return null if not a directory, array of EncFSFile otherwise
	 * @throws EncFSCorruptDataException
	 *             Invalid file name size
	 * @throws EncFSChecksumException
	 *             Filename checksum mismatch
	 */
	public EncFSFile[] listFiles() throws EncFSCorruptDataException, EncFSChecksumException {
		if (!file.isDirectory()) {
			return null;
		}

		final String subVolumePath;
		if (this == volume.getRootDir()) {
			subVolumePath = EncFSVolume.ENCFS_VOLUME_ROOT_PATH;
		} else {
			if (volumePath.equals(EncFSVolume.ENCFS_VOLUME_ROOT_PATH)) {
				subVolumePath = volumePath + this.getName();
			} else {
				subVolumePath = volumePath + "/" + this.getName();
			}
		}

		File[] files = file.listFiles(new FileFilter() {

			public boolean accept(File entry) {
				boolean result;
				if (volumePath.equals(EncFSVolume.ENCFS_VOLUME_ROOT_PATH)
						&& entry.getName().equals(volume.getConfigFileName())) {
					result = false;
				} else {
					try {
						EncFSCrypto.decodeName(volume, entry.getName(), subVolumePath);
						result = true;
					} catch (EncFSCorruptDataException e) {
						result = false;
					} catch (EncFSChecksumException e) {
						result = false;
					}
				}
				return result;
			}
		});

		EncFSFile[] encFSFiles = new EncFSFile[files.length];

		for (int i = 0; i < files.length; i++) {
			File file = files[i];
			encFSFiles[i] = new EncFSFile(volume, subVolumePath, file);
		}

		return encFSFiles;
	}

	public boolean isDirectory() {
		return file.isDirectory();
	}

	public long getContentsLength() {
		if (isDirectory()) {
			return 0;
		} else {
			boolean haveHeader = volume.getConfig().isUniqueIV();

			long size = file.length();

			if (haveHeader && size > 0) {
				size -= HEADER_SIZE;
			}

			return size;
		}
	}

	public boolean renameTo(String fileName) throws EncFSCorruptDataException {
		if (fileName.contains("/") == false) {
			return renameTo(volumePath, fileName);
		} else {
			String tmpVolumePath = fileName.substring(0, fileName.lastIndexOf("/"));
			if (tmpVolumePath.length() == 0) {
				tmpVolumePath = volume.getRootDir().getVolumePath();
			}
			String tmpFileName = fileName.substring(fileName.lastIndexOf("/") + 1);

			return renameTo(tmpVolumePath, tmpFileName);
		}
	}

	public boolean renameTo(String targetVolumePath, String fileName) throws EncFSCorruptDataException {
		if (fileName.contains("/")) {
			throw new IllegalArgumentException("file name must not contain /");
		}

		if (this.isDirectory() && volume.getConfig().isChainedNameIV()) {
			throw new UnsupportedOperationException("Directory renames with changed name IV not yet supported");
		}

		String toEncFileName = EncFSCrypto.encodeName(volume, fileName, targetVolumePath);
		String toEncVolumePath;
		if (targetVolumePath.startsWith("/")) {
			toEncVolumePath = EncFSCrypto.encodePath(volume, targetVolumePath, "/");
		} else {
			toEncVolumePath = EncFSCrypto.encodePath(volume, targetVolumePath, volumePath);
		}

		File toEncFile = new File(volume.getRootDir().getFile().getAbsolutePath() + "/" + toEncVolumePath,
				toEncFileName);
		return file.renameTo(toEncFile);
	}

	public boolean mkdir(String dirName) throws EncFSCorruptDataException {
		if (!isDirectory()) {
			throw new IllegalArgumentException("Files can't make directories");
		}

		if (dirName.startsWith("/")) {
			return volume.getRootDir().mkdir(dirName.substring(1));
		} else {
			String toEncFileName = EncFSCrypto.encodePath(volume, dirName, volumePath);
			File toEncFile = new File(file.getAbsolutePath(), toEncFileName);
			boolean result = toEncFile.mkdir();
			return result;
		}
	}

	public boolean mkdirs(String dirName) throws EncFSCorruptDataException {
		if (!isDirectory()) {
			throw new IllegalArgumentException("Files can't make directories");
		}

		if (dirName.startsWith("/")) {
			return volume.getRootDir().mkdirs(dirName.substring(1));
		} else {
			String toEncFileName = EncFSCrypto.encodePath(volume, dirName, volumePath);
			File toEncFile = new File(file.getAbsolutePath(), toEncFileName);
			boolean result = toEncFile.mkdirs();
			return result;
		}
	}

	public boolean delete(String fileName) throws EncFSCorruptDataException {
		if (fileName.startsWith("/")) {
			return volume.getRootDir().delete(fileName.substring(1));
		} else {
			String toEncFileName = EncFSCrypto.encodePath(volume, fileName, volumePath);
			File toEncFile = new File(file.getAbsolutePath(), toEncFileName);
			boolean result = toEncFile.delete();

			return result;
		}
	}
}
