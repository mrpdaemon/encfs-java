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
import java.io.OutputStream;

public class EncFSFileOutputStream extends OutputStream {
	private final OutputStream encfsOs;

	public EncFSFileOutputStream(EncFSFile encfsFile) throws IOException, EncFSUnsupportedException,
			EncFSCorruptDataException, EncFSChecksumException {
		this.encfsOs = encfsFile.openOutputStream();
	}

	@Override
	public void write(int b) throws IOException {
		encfsOs.write(b);
	}

	@Override
	public void write(byte[] b) throws IOException {
		encfsOs.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		encfsOs.write(b, off, len);
	}

	@Override
	public void close() throws IOException {
		encfsOs.close();
	}

	@Override
	public void flush() throws IOException {
		encfsOs.flush();
	}

}
