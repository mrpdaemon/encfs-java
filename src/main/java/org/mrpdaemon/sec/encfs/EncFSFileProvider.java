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

	/**
	 * Returns whether the given source path represents a directory in the
	 * underlying filesystem
	 * 
	 * @param srcPath
	 *            Path of the source file or directory
	 * 
	 * @return true if path represents a directory, false otherwise
	 * 
	 * @throws IOException
	 *             Source file/dir doesn't exist or misc. I/O error
	 */
	boolean isDirectory(String srcPath) throws IOException;

	/**
	 * Returns whether the file or directory exists
	 * 
	 * @param srcPath
	 *            Path of the file or directory
	 * 
	 * @return true if file or directory exists, false otherwise
	 * 
	 * @throws IOException
	 *             Misc. I/O error
	 */
	boolean exists(String srcPath) throws IOException;

	/**
	 * Returns the root path for the underlying filesystem
	 * 
	 * @return String representing the root path
	 */
	String getFilesystemRootPath();

	/**
	 * Return EncFSFileInfo for the given file or directory
	 * 
	 * @param srcPath
	 *            Path of the file or directory
	 * 
	 * @return EncFSFileInfo for the given file or directory
	 * 
	 * @throws IOException
	 *             Path doesn't exist or misc. I/O error
	 */
	EncFSFileInfo getFileInfo(String srcPath) throws IOException;

	/**
	 * Returns the list of files under the given directory path
	 * 
	 * @param dirPath
	 *            Path of the directory to list files from
	 * 
	 * @return a List of EncFSFileInfo representing files under the dir
	 * 
	 * @throws IOException
	 *             Path not a directory or misc. I/O error
	 */
	List<EncFSFileInfo> listFiles(String dirPath) throws IOException;

	/**
	 * Move a file/directory to a different location
	 * 
	 * @param srcPath
	 *            Path to the source file or directory
	 * @param dstPath
	 *            Path for the destination file or directory
	 * 
	 * @return true if the move is successful, false otherwise
	 * 
	 * @throws IOException
	 *             Source file/dir doesn't exist or misc. I/O error
	 */
	boolean move(String srcPath, String dstPath) throws IOException;

	/**
	 * Delete the file or directory with the given path
	 * 
	 * @param srcPath
	 *            Path of the source file or directory
	 * 
	 * @return true if deletion is successful, false otherwise
	 * 
	 * @throws IOException
	 *             Source file/dir doesn't exist or misc. I/O error
	 */
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

	/**
	 * Create a file with the given path
	 * 
	 * @param dstFilePath
	 *            Path for the file to create
	 * 
	 * @return EncFSFileInfo for the created file
	 * 
	 * @throws IOException
	 *             File already exists or misc. I/O error
	 */
	EncFSFileInfo createFile(String dstFilePath) throws IOException;

	/**
	 * Copy the file with the given path to another destination
	 * 
	 * @param srcFilePath
	 *            Path to the file to copy
	 * @param dstFilePath
	 *            Path to the destination file
	 * 
	 * @return true if copy was successful, false otherwise
	 * 
	 * @throws IOException
	 *             Destination file already exists, source file doesn't exist or
	 *             misc. I/O error
	 */
	boolean copy(String srcFilePath, String dstFilePath) throws IOException;

	/**
	 * Open an InputStream to the given file
	 * 
	 * @param srcFilePath
	 *            Path to the source file
	 * 
	 * @return InputStream to read from the file
	 * 
	 * @throws IOException
	 *             Source file doesn't exist or misc. I/O error
	 */
	InputStream openInputStream(String srcFilePath) throws IOException;

	/**
	 * Open an OutputStream to the given file
	 * 
	 * @param dstFilePath
	 *            Path to the destination file
	 * @param outputLength
	 *            Length in bytes of the stream that will be written to this
	 *            stream. It is up to the file provider to determine whether
	 *            this parameter is optional or required.
	 * 
	 * @return OutputStream to write to the file
	 * 
	 * @throws IOException
	 *             Misc. I/O error
	 */
	OutputStream openOutputStream(String dstFilePath, long outputLength)
			throws IOException;
}
