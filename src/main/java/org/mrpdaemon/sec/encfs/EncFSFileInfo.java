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

public class EncFSFileInfo {
	private final String name;
	private final String volumePath;
	private final boolean isDirectory;
	private final long modified;
	private final long size;
	private final boolean canRead;
	private final boolean canWrite;
	private final boolean canExecute;

	public EncFSFileInfo(String name, String volumePath, boolean isDirectory, long modified, long size,
			boolean canRead, boolean canWrite, boolean canExecute) {
		if (name.startsWith("/") && (name.equals("/") == false))
			throw new IllegalArgumentException("Invalid name " + name);

		this.name = name;
		this.volumePath = volumePath;
		this.isDirectory = isDirectory;
		this.modified = modified;
		this.size = size;
		this.canRead = canRead;
		this.canWrite = canWrite;
		this.canExecute = canExecute;
	}

	public String getName() {
		return name;
	}

	public String getVolumePath() {
		return volumePath;
	}

	public boolean isDirectory() {
		return isDirectory;
	}

	public long getModified() {
		return modified;
	}

	public long getSize() {
		return size;
	}

	public String getAbsoluteName() {
		String result;
		if (volumePath.endsWith("/") || name.startsWith("/")) {
			result = volumePath + name;
		} else {
			result = volumePath + "/" + name;
		}
		return result;
	}

	public boolean canRead() {
		return canRead;
	}

	public boolean canWrite() {
		return canWrite;
	}

	public boolean canExecute() {
		return canExecute;
	}
	
	public static EncFSFileInfo getDecodedFileInfo(EncFSVolume volume, String decodedDirName, String decodedFileName,
			EncFSFileInfo fileInfo) {
		long size;
		if (fileInfo.isDirectory()) {
			size = 0;
		} else {
			boolean haveHeader = volume.getConfig().isUniqueIV();

			size = fileInfo.getSize();

			if (haveHeader && size > 0) {
				size -= EncFSFile.HEADER_SIZE;
			}
		}

		EncFSFileInfo decEncFileInfo = new EncFSFileInfo(decodedFileName, decodedDirName, fileInfo.isDirectory(),
				fileInfo.getModified(), size, fileInfo.canRead(), fileInfo.canWrite(), fileInfo.canExecute());
		return decEncFileInfo;
	}
}
