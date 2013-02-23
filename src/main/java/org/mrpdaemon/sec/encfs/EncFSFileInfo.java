/*
 * EncFS Java Library
 * Copyright (C) 2011
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
 * Class representing information about an underlying file
 */
public class EncFSFileInfo {
	// Name of the file
	private final String name;

	// Volume path of the parent directory hosting the file
	private final String parentPath;

	// Whether the file is a directory
	private final boolean directory;

	// Last modification time of the file
	private final long lastModified;

	// Raw size of the underlying file
	private final long size;

	// Whether the file is readable
	private final boolean readable;

	// Whether the file is writable
	private final boolean writable;

	// Whether the file is executable
	private final boolean executable;

	/**
	 * Create a new EncFSFileInfo
	 * 
	 * @param name
	 *            Name of the file
	 * @param parentPath
	 *            Volume path of the parent directory hosting the file
	 * @param directory
	 *            Whether the file is a directory
	 * @param lastModified
	 *            Last modification time of the file
	 * @param size
	 *            Raw size of the underlying file
	 * @param readable
	 *            Whether the file is readable
	 * @param writable
	 *            Whether the file is writable
	 * @param executable
	 *            Whether the file is executable
	 */
	public EncFSFileInfo(String name, String parentPath, boolean directory,
			long lastModified, long size, boolean readable, boolean writable,
			boolean executable) {
		if (name.startsWith(EncFSVolume.PATH_SEPARATOR)
				&& (!name.equals(EncFSVolume.ROOT_PATH))) {
			throw new IllegalArgumentException("Invalid name " + name);
		}

		this.name = name;
		this.parentPath = parentPath;
		this.directory = directory;
		this.lastModified = lastModified;
		this.size = size;
		this.readable = readable;
		this.writable = writable;
		this.executable = executable;
	}

	/**
	 * Returns the name of the file
	 * 
	 * @return name of the file
	 */
	public String getName() {
		return name;
	}

	/**
	 * Returns the volume path of the parent directory hosting the file
	 * 
	 * @return volume path of the parent directory hosting the file
	 */
	public String getParentPath() {
		return parentPath;
	}

	/**
	 * Returns the volume path of the file
	 * 
	 * @return volume path of the file
	 */
	public String getPath() {
		String result;

		if (parentPath.endsWith(EncFSVolume.PATH_SEPARATOR)
				|| name.startsWith(EncFSVolume.PATH_SEPARATOR)) {
			result = parentPath + name;
		} else {
			result = EncFSVolume.combinePath(parentPath, name);
		}

		return result;
	}

	/**
	 * Returns the last modification time of the file
	 * 
	 * @return last modification time of the file
	 */
	public long getLastModified() {
		return lastModified;
	}

	/**
	 * Returns the raw size of the underlying file
	 * 
	 * @return raw size of the underlying file
	 */
	public long getSize() {
		return size;
	}

	/**
	 * Returns whether the file is a directory
	 * 
	 * @return whether the file is a directory
	 */
	public boolean isDirectory() {
		return directory;
	}

	/**
	 * Returns whether the file is readable
	 * 
	 * @return whether the file is readable
	 */
	public boolean isReadable() {
		return readable;
	}

	/**
	 * Returns whether the file is writable
	 * 
	 * @return whether the file is writable
	 */
	public boolean isWritable() {
		return writable;
	}

	/**
	 * Returns whether the file is executable
	 * 
	 * @return whether the file is executable
	 */
	public boolean isExecutable() {
		return executable;
	}

	/**
	 * Produces an EncFSFileInfo for the decoded version of the file represented
	 * by this object
	 * 
	 * @param volume
	 *            Volume hosting this file
	 * @param decodedParentPath
	 *            Decoded path of the parent directory for the output file
	 * @param decodedFileName
	 *            Decoded file name of the output file
	 * @param fileInfo
	 *            EncFSFileInfo for the file to be decoded
	 * @return EncFSFileInfo for the decoded file
	 */
	public static EncFSFileInfo getDecodedFileInfo(EncFSVolume volume,
			String decodedParentPath, String decodedFileName,
			EncFSFileInfo fileInfo) {
		long size;
		if (fileInfo.isDirectory()) {
			size = 0;
		} else {
			size = volume.getDecryptedFileLength(fileInfo.getSize());
		}

		return new EncFSFileInfo(decodedFileName, decodedParentPath,
				fileInfo.isDirectory(), fileInfo.getLastModified(), size,
				fileInfo.isReadable(), fileInfo.isWritable(),
				fileInfo.isExecutable());
	}
}
