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
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Object representing a file in an EncFS volume.
 * 
 * Useful for decryption of file names.
 */
public class EncFSFile {

	static final int HEADER_SIZE = 8; // 64 bit initialization vector..

	// Volume hosting this file
	private final EncFSVolume volume;

	// The info about the file (e.g. name / etc)
	private final EncFSFileInfo fileInfo;

	private final EncFSFileInfo encryptedFileInfo;

	private final File file;

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume
	 *            The volume that contains the file
	 * @param fileInfo
	 *            The information on the file
	 */
	public EncFSFile(EncFSVolume volume, EncFSFileInfo fileInfo, EncFSFileInfo encryptedFileInfo) {
		this.volume = volume;
		this.fileInfo = fileInfo;
		this.encryptedFileInfo = encryptedFileInfo;
		this.file = null;
	}

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume
	 *            The volume that contains the file
	 * @param fileInfo
	 *            The information on the file
	 */
	@Deprecated
	public EncFSFile(EncFSVolume volume, EncFSFileInfo fileInfo, EncFSFileInfo encryptedFileInfo, File file) {
		this.volume = volume;
		this.fileInfo = fileInfo;
		this.encryptedFileInfo = encryptedFileInfo;
		this.file = file;
	}

	/**
	 * @return Volume path of the EncFS file
	 */
	public String getVolumePath() {
		return fileInfo.getVolumePath();
	}

	/**
	 * @return Volume containing the EncFS file
	 */
	public EncFSVolume getVolume() {
		return volume;
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
	 * @throws IOException
	 */
	public String[] list() throws EncFSCorruptDataException, EncFSChecksumException, IOException {
		EncFSFile[] files = this.listFiles();

		String[] fileNames;
		if (files == null) {
			fileNames = null;
		} else {
			fileNames = new String[files.length];

			for (int i = 0; i < files.length; i++) {
				EncFSFile file = files[i];
				fileNames[i] = file.getName();
			}
		}

		return fileNames;
	}

	/**
	 * @return Plaintext name of this EncFS file
	 */
	public String getName() {
		return fileInfo.getName();
	}

	/**
	 * List of EncFSFile's for all files and directories that are children of
	 * the directory represented by this EncFSFile
	 * 
	 * @return null if not a directory, array of EncFSFile otherwise
	 * @throws EncFSCorruptDataException
	 *             Invalid file name size
	 * @throws IOException
	 * @throws EncFSChecksumException
	 *             Filename checksum mismatch
	 */
	public EncFSFile[] listFiles() throws EncFSCorruptDataException, IOException {
		if (!isDirectory()) {
			return null;
		}

		return volume.listFiles(this);
	}

	public boolean isDirectory() {
		return fileInfo.isDirectory();
	}

	public long getContentsLength() {
		return fileInfo.getSize();
	}

	public boolean renameTo(String fileName) throws EncFSCorruptDataException, IOException {
		return volume.move(this.getAbsoluteName(), fileName);
	}

	public boolean renameTo(String targetVolumePath, String fileName) throws EncFSCorruptDataException, IOException {
		return renameTo(targetVolumePath + "/" + fileName);
	}

	public boolean mkdir() throws EncFSCorruptDataException, IOException {
		return volume.makeDir(this);
	}

	public boolean mkdir(String subDirName) throws EncFSCorruptDataException, IOException {
		if (isDirectory()) {
			throw new IOException(getAbsoluteName() + " is not a directory");
		}
		if (subDirName.contains("/")) {
			throw new IOException("file name must not contain '/'");
		}
		return volume.makeDir(getAbsoluteName() + "/" + subDirName);
	}

	public boolean mkdirs() throws EncFSCorruptDataException, IOException {
		return volume.makeDirs(this);
	}

	public boolean mkdirs(String subDirName) throws EncFSCorruptDataException, IOException {
		if (isDirectory()) {
			throw new IOException(getAbsoluteName() + " is not a directory");
		}
		if (subDirName.contains("/")) {
			throw new IOException("file name must not contain '/'");
		}
		return volume.makeDirs(getAbsoluteName() + "/" + subDirName);
	}

	public boolean delete() throws EncFSCorruptDataException, IOException {
		return volume.delete(this);
	}

	public boolean delete(String file) throws EncFSCorruptDataException, IOException {
		if (isDirectory()) {
			throw new IOException(getAbsoluteName() + " is not a directory");
		}
		if (file.contains("/")) {
			throw new IOException("file name must not contain '/'");
		}
		return volume.delete(getAbsoluteName() + "/" + file);
	}

	public String getAbsoluteName() {
		return fileInfo.getAbsoluteName();
	}

	public InputStream openInputStream() throws EncFSCorruptDataException, EncFSUnsupportedException, IOException {
		return volume.openInputStream(this);
	}

	public OutputStream openOutputStream() throws EncFSCorruptDataException, EncFSUnsupportedException, IOException,
			EncFSChecksumException {
		return volume.openOutputStream(this);
	}

	public long lastModified() {
		return fileInfo.getModified();
	}

	public boolean canRead() {
		return fileInfo.canRead();
	}

	public boolean canWrite() {
		return fileInfo.canWrite();
	}

	public boolean canExecute() {
		return fileInfo.canExecute();
	}

	public String getEncrytedName() {
		return encryptedFileInfo.getName();
	}

	public String getEncrytedAbsoluteName() {
		return encryptedFileInfo.getAbsoluteName();
	}

	public String getEncrytedVolumePath() {
		return encryptedFileInfo.getVolumePath();
	}

	@Deprecated
	public File getFile() {
		if (file == null) {
			throw new UnsupportedOperationException();
		}
		return this.file;
	}
}
