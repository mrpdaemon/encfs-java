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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.channels.FileChannel;
import java.util.ArrayList;
import java.util.List;

public class EncFSLocalFileSystemNativeFileSource implements EncFSNativeFileSource {
	private final File nativeRootDir;

	public EncFSLocalFileSystemNativeFileSource(File nativeRootDir) {
		this.nativeRootDir = nativeRootDir;
	}

	public boolean move(String encSrcFile, String encTargetFile) {
		File sourceFile = new File(nativeRootDir.getAbsoluteFile(), encSrcFile);
		File destFile = new File(nativeRootDir.getAbsoluteFile(), encTargetFile);

		return sourceFile.renameTo(destFile);
	}

	public boolean isDirectory(String srcFile) {
		File srcF = new File(nativeRootDir.getAbsoluteFile(), srcFile);
		return srcF.isDirectory();
	}

	public boolean copy(String encSrcFileName, String encTargetFileName) throws IOException {

		File sourceFile = new File(nativeRootDir.getAbsoluteFile(), encSrcFileName);
		File destFile = new File(nativeRootDir.getAbsoluteFile(), encTargetFileName);

		if (!destFile.exists()) {
			destFile.createNewFile();
		}

		FileChannel source = null;
		FileChannel destination = null;

		try {
			source = new FileInputStream(sourceFile).getChannel();
			destination = new FileOutputStream(destFile).getChannel();
			destination.transferFrom(source, 0, source.size());
		} finally {
			if (source != null) {
				source.close();
			}
			if (destination != null) {
				destination.close();
			}
		}

		return true;
	}

	public List<EncFSFileInfo> listFiles(String encDirName) {
		File sourceFile = new File(nativeRootDir.getAbsoluteFile(), encDirName);
		File[] files = sourceFile.listFiles();
		List<EncFSFileInfo> results = new ArrayList<EncFSFileInfo>(files.length);
		for (File file : files) {
			results.add(convertToFileInfo(file));
		}
		return results;
	}

	public InputStream openInputStream(String encSrcFile) throws FileNotFoundException {
		File srcF = new File(nativeRootDir.getAbsoluteFile(), encSrcFile);
		return new FileInputStream(srcF);
	}

	public EncFSFileInfo getFileInfo(String toEncVolumePath) {
		File sourceFile = new File(nativeRootDir.getAbsoluteFile(), toEncVolumePath);
		return convertToFileInfo(sourceFile);
	}

	public OutputStream openOutputStream(String encSrcFile) throws IOException {
		File srcF = new File(nativeRootDir.getAbsoluteFile(), encSrcFile);
		if (srcF.exists() == false) {
			try {
				srcF.createNewFile();
			} catch (Exception e) {
				throw new IOException(e);
			}
		}
		return new FileOutputStream(srcF);
	}

	public boolean mkdir(String encryptedDirName) {
		File toEncFile = new File(nativeRootDir.getAbsoluteFile(), encryptedDirName);
		boolean result = toEncFile.mkdir();
		return result;
	}

	public boolean mkdirs(String encryptedDirName) {
		File toEncFile = new File(nativeRootDir.getAbsoluteFile(), encryptedDirName);
		boolean result = toEncFile.mkdirs();
		return result;
	}

	public boolean delete(String encryptedName) {
		File toEncFile = new File(nativeRootDir.getAbsoluteFile(), encryptedName);
		boolean result = toEncFile.delete();
		return result;
	}

	private EncFSFileInfo convertToFileInfo(File file) {
		String realtivePath = file.getParentFile().getAbsolutePath()
				.substring(nativeRootDir.getAbsoluteFile().toString().length());
		realtivePath = "/" + realtivePath.replace("\\", "/");
		String name = file.getName();
		EncFSFileInfo result = new EncFSFileInfo(name, realtivePath, file.isDirectory(), file.lastModified(),
				file.length(), file.canRead(), file.canWrite(), file.canExecute());
		return result;
	}

	public boolean exists(String name) {
		File toEncFile = new File(nativeRootDir.getAbsoluteFile(), name);
		return toEncFile.exists();
	}

	public File getFile(String name) {
		File toEncFile = new File(nativeRootDir.getAbsoluteFile(), name);
		return toEncFile;
	}

}
