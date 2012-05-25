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

/**
 * FileOutputStream abstraction that allows writing encrypted data to a file on
 * an EncFS volume.
 */
public class EncFSFileOutputStream extends OutputStream {

	// Underlying EncFSOutputStream
	private final OutputStream encfsOs;

	/**
	 * Creates an EncFSFileOutputStream to write encrypted data to a file under
	 * and EncFS volume
	 * 
	 * @param encfsFile
	 *            EncFSFile to open an output stream to
	 * @param inputLength
	 *            Length of the input file that will be written to this output
	 *            stream. Note that this parameter is optional if using
	 *            EncFSLocalFileProvider, but some network based storage API's
	 *            require knowing the file length in advance.
	 * 
	 * @throws EncFSCorruptDataException
	 *             Filename encoding failed
	 * @throws EncFSUnsupportedException
	 *             File header uses an unsupported IV length
	 * @throws IOException
	 *             File provider returned I/O error
	 */
	public EncFSFileOutputStream(EncFSFile encfsFile, long inputLength)
			throws IOException, EncFSUnsupportedException,
			EncFSCorruptDataException, EncFSChecksumException {
		this.encfsOs = encfsFile.openOutputStream(inputLength);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.OutputStream#write(int)
	 */
	@Override
	public void write(int b) throws IOException {
		encfsOs.write(b);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.OutputStream#write(byte[])
	 */
	@Override
	public void write(byte[] b) throws IOException {
		encfsOs.write(b);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.OutputStream#write(byte[])
	 */
	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		encfsOs.write(b, off, len);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.OutputStream#write(byte[])
	 */
	@Override
	public void close() throws IOException {
		encfsOs.close();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.OutputStream#write(byte[])
	 */
	@Override
	public void flush() throws IOException {
		encfsOs.flush();
	}

}
