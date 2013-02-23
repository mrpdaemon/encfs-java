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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

/**
 * An EncFSFileProvider provides an abstraction for accessing file contents and
 * information in their encrypted form on a local disk or any other storage
 * type. This class can be extended to implement EncFS functionality on
 * non-local storage. For local storage access, see the built-in file provider
 * class EncFSLocalFileProvider.
 */
public interface EncFSFileProvider {

	boolean isDirectory(String srcPath) throws IOException;

	boolean exists(String srcPath) throws IOException;

	String getFilesystemRootPath();

	EncFSFileInfo getFileInfo(String srcPath) throws IOException;

	List<EncFSFileInfo> listFiles(String dirPath) throws IOException;

	boolean move(String srcPath, String dstPath) throws IOException;

	boolean delete(String srcPath) throws IOException;

	/**
	 * Create a directory with the given path
	 * <p/>
	 * Note that all path elements except the last one must exist for this
	 * method. If that is not true mkdirs should be used instead
	 */
	boolean mkdir(String dirPath) throws IOException;

	/**
	 * Create a directory with the given path
	 * <p/>
	 * Intermediate directories are also created by this method
	 */
	boolean mkdirs(String dirPath) throws IOException;

	EncFSFileInfo createFile(String dstFilePath) throws IOException;

	boolean copy(String srcFilePath, String dstFilePath) throws IOException;

	InputStream openInputStream(String srcFilePath) throws IOException;

	OutputStream openOutputStream(String dstFilePath, long outputLength)
			throws IOException;
}
