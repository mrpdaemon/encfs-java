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

/**
 * FileInputStream extension that allows data to be read from a file on an EncFS
 * volume.
 */
public class EncFSFileInputStream extends InputStream {
	private final InputStream is;

	public EncFSFileInputStream(EncFSFile encfsFile) throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException {
		is = encfsFile.openInputStream();
	}

	@Override
	public int read(byte[] b) throws IOException {
		return is.read(b);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return is.read(b, off, len);
	}

	@Override
	public int read() throws IOException {
		return is.read();
	}
}