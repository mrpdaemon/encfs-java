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
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Object representing a file in an EncFS volume.
 * 
 * Useful for decryption of file names as well as performing file operations
 * such as copying, moving, deletion etc.
 */
public class EncFSFile {

	/** Size in bytes of file header when file IV's are used (uniqueIV) */
	public static final int HEADER_SIZE = 8;

	// Volume hosting this file
	private final EncFSVolume volume;

	// Information about the plaintext file (decoded names etc.)
	private final EncFSFileInfo plainFileInfo;

	// Information about the ciphertext file (encrypted names etc.)
	private final EncFSFileInfo cipherFileInfo;

	/**
	 * Create a new object representing a file in an EncFS volume
	 * 
	 * @param volume
	 *            The volume that contains the file
	 * @param plainFileInfo
	 *            EncFSFileInfo representing the cleartext file (decoded)
	 * @param cipherFileInfo
	 *            EncFSFileInfo representing the ciphertext file (encoded)
	 */
	public EncFSFile(EncFSVolume volume, EncFSFileInfo plainFileInfo,
			EncFSFileInfo cipherFileInfo) {
		this.volume = volume;
		this.plainFileInfo = plainFileInfo;
		this.cipherFileInfo = cipherFileInfo;
	}

	/**
	 * Returns the volume path of this file
	 * 
	 * @return Absolute volume path of the file
	 */
	public String getPath() {
		return plainFileInfo.getPath();
	}

	/**
	 * Returns the encrypted volume path of this file
	 * 
	 * @return Encrypted volume path of the file
	 */
	public String getEncryptedPath() {
		return cipherFileInfo.getPath();
	}

	/**
	 * Returns the volume path of the parent directory hosting this file
	 * 
	 * This is the plaintext path starting from the volume's root up until the
	 * parent directory hosting the current file
	 * 
	 * @return Volume path of this file's parent directory
	 */
	public String getParentPath() {
		return plainFileInfo.getParentPath();
	}

	/**
	 * Returns the encrypted volume path of the parent directory hosting this
	 * file
	 * 
	 * @return Encrypted volume path of this file's parent directory
	 */
	public String getEncryptedParentPath() {
		return cipherFileInfo.getParentPath();
	}

	/**
	 * Returns the plaintext name of this file
	 * 
	 * @return decrypted name of this EncFS file
	 */
	public String getName() {
		return plainFileInfo.getName();
	}

	/**
	 * Returns the ciphertext name of this file
	 * 
	 * @return encrypted name of this EncFS file
	 */
	public String getEncrytedName() {
		return cipherFileInfo.getName();
	}

	/**
	 * Returns the length of decrypted contents for this file
	 * 
	 * @return Length of decrypted file contents
	 */
	public long getLength() {
		return plainFileInfo.getSize();
	}

	/**
	 * Returns the last modification time for this file
	 * 
	 * @return last modification time for the file
	 */
	public long getLastModified() {
		return plainFileInfo.getLastModified();
	}

	/**
	 * Returns the volume containing this file
	 * 
	 * @return Volume containing the EncFS file
	 */
	public EncFSVolume getVolume() {
		return volume;
	}

	/**
	 * Checks whether this EncFSFile represents a directory
	 * 
	 * @return true if directory, false otherwise
	 */
	public boolean isDirectory() {
		return plainFileInfo.isDirectory();
	}

	/**
	 * Checks whether the file is readable
	 * 
	 * @return true if the file is readable, false otherwise
	 */
	public boolean isReadable() {
		return plainFileInfo.isReadable();
	}

	/**
	 * Checks whether the file is writable
	 * 
	 * @return true if the file is writable, false otherwise
	 */
	public boolean isWritable() {
		return plainFileInfo.isWritable();
	}

	/**
	 * Checks whether the file is executable
	 * 
	 * @return true if the file is executable, false otherwise
	 */
	public boolean isExecutable() {
		return plainFileInfo.isExecutable();
	}

	/**
	 * List files/directory names contained by the directory represented by this
	 * EncFSFile object.
	 * 
	 * @return null if not a directory, array of String names otherwise
	 * @throws EncFSCorruptDataException
	 *             Invalid file name size
	 * @throws EncFSChecksumException
	 *             Filename checksum mismatch
	 * @throws IOException
	 *             FileProvider returned I/O error
	 */
	public String[] list() throws EncFSCorruptDataException,
			EncFSChecksumException, IOException {
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
	 * Get list of EncFSFile's under this directory
	 * 
	 * @return list of EncFSFile under the given directory
	 * 
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFile[] listFiles() throws IOException {

		if (this.isDirectory() == false) {
			return null;
		}

		String encDirName;
		if (this == volume.getRootDir()) {
			encDirName = EncFSVolume.ENCFS_VOLUME_ROOT_PATH;
		} else {
			encDirName = getEncryptedPath();
		}
		String dirName = getPath();

		List<EncFSFileInfo> fileInfos = volume.getFileProvider().listFiles(
				encDirName);
		List<EncFSFile> result = new ArrayList<EncFSFile>(fileInfos.size());

		for (EncFSFileInfo fileInfo : fileInfos) {
			String decodedFileName;
			try {
				decodedFileName = EncFSCrypto.decodeName(volume,
						fileInfo.getName(), dirName);
			} catch (EncFSCorruptDataException e) {
				decodedFileName = null;
			} catch (EncFSChecksumException e) {
				decodedFileName = null;
			}

			if (decodedFileName != null) {
				EncFSFileInfo decEncFileInfo = EncFSFileInfo
						.getDecodedFileInfo(volume, dirName, decodedFileName,
								fileInfo);

				result.add(new EncFSFile(volume, decEncFileInfo, fileInfo));
			}
		}

		return result.toArray(new EncFSFile[result.size()]);
	}

	/**
	 * Delete this file
	 * 
	 * @return true if deletion succeeds, false otherwise
	 * 
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean delete() throws IOException {
		return volume.getFileProvider().delete(getEncryptedPath());
	}

	/**
	 * Opens the file as an InputStream that decodes the file contents
	 * automatically
	 * 
	 * @return InputStream that decodes file contents
	 * 
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSUnsupportedException
	 *             File header uses an unsupported IV length
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public InputStream openInputStream() throws EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		return new EncFSInputStream(volume, volume.getFileProvider()
				.openInputStream(getEncryptedPath()));
	}

	/**
	 * Opens the file as an OutputStream that encrypts the file contents
	 * automatically
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
	public OutputStream openOutputStream() throws EncFSUnsupportedException,
			EncFSCorruptDataException, IOException {
		return new EncFSOutputStream(volume, volume.getFileProvider()
				.openOutputStream(getEncryptedPath()));
	}

	/**
	 * Copies this file/dir to a target file or directory
	 * 
	 * @param dstPath
	 *            EncFSFile representing the target file or directory
	 * 
	 * @return true if copy succeeds, false otherwise
	 * 
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public boolean copy(EncFSFile dstPath) throws IOException {
		if (this.isDirectory()) {
			// Recursive copy of this directory to the target path
			try {
				return volume.copyPath(this.getPath(), dstPath.getPath());
			} catch (EncFSCorruptDataException e) {
				throw new IOException(e);
			}
		} else if (dstPath.isDirectory()) {
			/*
			 * Trying to copy a file to a directory, copy it UNDER that
			 * directory instead
			 */
			EncFSFile realDstPath;
			try {
				realDstPath = volume.createFile(dstPath.getPath(), getName());
			} catch (EncFSCorruptDataException e) {
				throw new IOException(e);
			} catch (EncFSChecksumException e) {
				throw new IOException(e);
			}

			return this.copy(realDstPath);
		} else { // Trying to copy a file into a file
			if (volume.getConfig().isUniqueIV()) {
				/*
				 * More complicated as we need to copy the files by reading them
				 * in as a stream & writing them out again so that we generate
				 * unique headers for the file copies
				 */
				try {
					EncFSUtil.copyWholeStream(this.openInputStream(),
							dstPath.openOutputStream(), true, true);
				} catch (EncFSCorruptDataException e) {
					throw new IOException(e);
				} catch (EncFSUnsupportedException e) {
					throw new IOException(e);
				}
			} else {
				// Can just do a regular copy, no need to rewrite contents
				return volume.getFileProvider().copy(getEncryptedPath(),
						dstPath.getEncryptedPath());
			}

			return true;
		}
	}

}