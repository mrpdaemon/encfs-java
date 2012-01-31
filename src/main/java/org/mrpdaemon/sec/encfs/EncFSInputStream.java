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
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

/**
 * InputStream extension that allows data to be read from a file on an EncFS
 * volume.
 */
public class EncFSInputStream extends InputStream {

	// Volume that underlying file belongs to
	private final EncFSVolume volume;

	// Volume configuration for this file
	private final EncFSConfig config;

	// Cached block size for this volume
	private final int blockSize;

	// Current block number for generating block IV
	private int blockNum;

	// Buffer containing decrypted data from the current block
	private byte[] blockBuf;

	// Cursor into blockBuf denoting current stream position
	private int bufCursor;

	// File IV computed from the first 8 bytes of the file
	private byte[] fileIv;

	private final InputStream inStream;

	/**
	 * Create a new EncFSInputStream for reading data off a file on an EncFS
	 * volume
	 * 
	 * @param file
	 *            Underlying file location to read from
	 * 
	 * @throws EncFSCorruptDataException
	 *             File data is corrupt
	 * @throws EncFSUnsupportedException
	 *             Unsupported EncFS configuration
	 * @throws IOException
	 */
	public EncFSInputStream(EncFSVolume volume, InputStream in) throws EncFSCorruptDataException,
			EncFSUnsupportedException {
		super();
		this.inStream = in;
		this.volume = volume;
		this.config = volume.getConfig();
		this.blockSize = config.getBlockSize();
		this.blockBuf = null;
		this.bufCursor = 0;
		this.blockNum = 0;

		if (config.isUniqueIV()) {
			// Compute file IV
			byte[] fileHeader = new byte[EncFSFile.HEADER_SIZE];
			try {
				inStream.read(fileHeader);
			} catch (IOException e) {
				throw new EncFSCorruptDataException("Could't read file IV");
			}
			byte[] zeroIv = new byte[8];
			// TODO: external IV chaining changes zeroIv
			try {
				this.fileIv = EncFSCrypto.streamDecode(volume, zeroIv, fileHeader);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				throw new EncFSCorruptDataException(e);
			} catch (BadPaddingException e) {
				throw new EncFSCorruptDataException(e);
			}
		} else {
			// No unique IV per file, just use 0
			this.fileIv = new byte[EncFSFile.HEADER_SIZE];
		}
	}

	/*
	 * Return the block IV for the current block
	 */
	private byte[] getBlockIV() {
		long fileIvLong = EncFSUtil.byteArrayToLong(fileIv);
		return EncFSUtil.longToByteArray(blockNum ^ fileIvLong);
	}

	/*
	 * Read one block (blockSize bytes) of data from the underlying
	 * FileInputStream, decrypt it and store it in blockBuf for consumption via
	 * read() methods
	 */
	private int readBlock() throws IOException, EncFSCorruptDataException, EncFSUnsupportedException {
		byte[] cipherBuf = new byte[blockSize];
		int bytesRead = inStream.read(cipherBuf, 0, blockSize);
		if (bytesRead == blockSize) { // block decode
			try {
				blockBuf = EncFSCrypto.blockDecode(volume, getBlockIV(), cipherBuf);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				throw new EncFSCorruptDataException(e);
			} catch (BadPaddingException e) {
				throw new EncFSCorruptDataException(e);
			}
			bufCursor = 0;
			blockNum++;
		} else if (bytesRead > 0) { // stream decode
			/*
			 * Need to copy cipherBuf into another buffer otherwise streamDecode
			 * will not work correctly.
			 */
			byte[] cipherBuf2 = Arrays.copyOfRange(cipherBuf, 0, bytesRead);
			try {
				blockBuf = EncFSCrypto.streamDecode(volume, getBlockIV(), cipherBuf2);
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				throw new EncFSCorruptDataException(e);
			} catch (BadPaddingException e) {
				throw new EncFSCorruptDataException(e);
			}
			bufCursor = 0;
			blockNum++;
		}

		return bytesRead;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FileInputStream#read()
	 */
	@Override
	public int read() throws IOException {
		byte[] oneByte = new byte[1];
		int ret = this.read(oneByte, 0, 1);
		if (ret == 1) {
			return oneByte[0];
		}
		return ret;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FileInputStream#read(byte[])
	 */
	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	@Override
	public int read(byte[] output, int offset, int size) throws IOException {
		byte[] b = output;
		int len = size;
		int bytesRead = 0;
		int destOffset = offset;
		int bytesToCopy;
		int ret;

		while (bytesRead < len) {

			// Read more data if the data buffer is out
			if ((blockBuf == null) || (bufCursor == (blockBuf.length))) {
				try {
					ret = readBlock();
				} catch (EncFSCorruptDataException e) {
					throw new IOException(e);
				} catch (EncFSUnsupportedException e) {
					throw new IOException(e);
				}

				if (ret < 0) {
					if (bytesRead == 0) {
						return -1;
					} else {
						return bytesRead;
					}
				}
			}

			bytesToCopy = Math.min(blockBuf.length - bufCursor, len - bytesRead);
			System.arraycopy(blockBuf, bufCursor, b, destOffset, bytesToCopy);

			bufCursor += bytesToCopy;
			bytesRead += bytesToCopy;
			destOffset += bytesToCopy;
		}

		return bytesRead;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FileInputStream#skip(long)
	 */
	@Override
	public long skip(long n) throws IOException {
		long bytesSkipped = 0;
		int toSkip;
		int bytesRead;

		byte[] skipBuf = new byte[config.getBlockSize()];

		if (n < 0) {
			throw new IOException("Negative skip count");
		}

		while (bytesSkipped < n) {
			toSkip = (int) Math.min(n - bytesSkipped, config.getBlockSize());
			bytesRead = this.read(skipBuf, 0, toSkip);
			bytesSkipped += bytesRead;
			if (bytesRead == -1) {
				return -1; // Already at EOF
			} else if (bytesRead < toSkip) {
				return bytesSkipped; // Hit EOF now
			}
		}

		return bytesSkipped;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.InputStream#markSupported()
	 */
	@Override
	public boolean markSupported() {
		// TODO: could support mark()/reset()
		return false;
	}

	@Override
	public void close() throws IOException {
		inStream.close();
		super.close();
	}
}