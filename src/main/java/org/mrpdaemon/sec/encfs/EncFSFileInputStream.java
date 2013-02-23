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

import java.io.FilterInputStream;
import java.io.IOException;

/**
 * FileInputStream abstraction that allows decrypted data to be read from a file
 * on an EncFS volume.
 */
public class EncFSFileInputStream extends FilterInputStream {

	/**
	 * Creates an EncFSFileInputStream to read decrypted data from a file under
	 * and EncFS volume
	 * 
	 * @param encfsFile
	 *            EncFSFile to open an input stream for
	 *            <p/>
	 *            <p/>
	 *            Filename encoding failed
	 *            <p/>
	 *            File header uses an unsupported IV length
	 *            <p/>
	 *            File provider returned I/O error
	 */
	public EncFSFileInputStream(EncFSFile encfsFile)
			throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException {
		super(encfsFile.openInputStream());
	}
}