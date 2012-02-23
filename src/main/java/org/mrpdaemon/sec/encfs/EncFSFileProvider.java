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
 * Interface for a File provider. By this we mean that this provides access to
 * the file contents / information in their encrypted form as they would be
 * stored on a local disk or any other storage type.
 */
public interface EncFSFileProvider {

	public boolean move(String encOrigFileName, String encNewFileName) throws IOException;

	public boolean isDirectory(String encFileName) throws IOException;

	public boolean delete(String encFileName) throws IOException;

	public boolean mkdir(String encDirName) throws IOException;

	public boolean mkdirs(String encDirName) throws IOException;

	public boolean copy(String encSrcFileName, String encTargetFileName) throws IOException;

	public List<EncFSFileInfo> listFiles(String encDirName) throws IOException;

	public InputStream openInputStream(String encSrcFile) throws IOException;

	public OutputStream openOutputStream(String encSrcFile) throws IOException;

	public EncFSFileInfo getFileInfo(String encSrcFile) throws IOException;

	public boolean exists(String name) throws IOException;

	public EncFSFileInfo createFile(String encTargetFile) throws IOException;
}
