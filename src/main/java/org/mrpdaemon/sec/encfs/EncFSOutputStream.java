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

import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class EncFSOutputStream extends FilterOutputStream {
	private static final SecureRandom secureRandom = new SecureRandom();

	private final EncFSVolume volume;
	private final EncFSConfig config;
	private final int blockSize;
	private byte[] fileIv;
	private byte[] fileHeader;

	private SecureRandom random;

	private final byte buf[];

	private int count;
	private int blockHeaderSize;
	private int blockMACRandLen;
	private int blockMACLen;
	private int blockNum;

	private final Cipher blockCipher;

	private final Cipher streamCipher;

	public EncFSOutputStream(EncFSVolume volume, OutputStream out) throws EncFSUnsupportedException,
			EncFSCorruptDataException {
		super(out);
		this.volume = volume;
		this.config = volume.getConfig();
		this.blockSize = config.getBlockSize();
		this.blockHeaderSize = config.getBlockMACBytes() + config.getBlockMACRandBytes();
		this.count = this.blockHeaderSize;
		this.blockMACLen = config.getBlockMACBytes();
		this.blockMACRandLen = config.getBlockMACRandBytes();
		
		this.random = new SecureRandom();

		if (config.isUniqueIV()) {
			// Compute file IV
			this.fileHeader = new byte[8];

			secureRandom.nextBytes(fileHeader);

			byte[] zeroIv = new byte[8];
			// TODO: external IV chaining changes zeroIv
			try {
				this.fileIv = EncFSCrypto.streamDecode(volume, zeroIv, Arrays.copyOf(fileHeader, fileHeader.length));
			} catch (InvalidAlgorithmParameterException e) {
				e.printStackTrace();
			} catch (IllegalBlockSizeException e) {
				throw new EncFSCorruptDataException(e);
			} catch (BadPaddingException e) {
				throw new EncFSCorruptDataException(e);
			}
		} else {
			// No unique IV per file, just use 0
			this.fileIv = new byte[8];
		}

		this.blockCipher = EncFSCrypto.newBlockCipher();
		try {
			EncFSCrypto.cipherInit(volume, Cipher.ENCRYPT_MODE, blockCipher, fileIv);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		}
		this.streamCipher = EncFSCrypto.newStreamCipher();
		try {
			EncFSCrypto.cipherInit(volume, Cipher.ENCRYPT_MODE, streamCipher, fileIv);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		}

		// blockSize = blockHeaderSize + blockDataLen
		buf = new byte[blockSize];
	}

	/** Flush the internal buffer */
	private void writeBuffer(boolean isFinal) throws IOException {

		if (isFinal == false && count != buf.length) {
			throw new IllegalStateException("Buffer not full");
		}

		if (blockNum == 0 && config.isUniqueIV()) {
			out.write(this.fileHeader);
		}

		// Fill in the block header
		if (blockHeaderSize > 0) {
			
			// Add random bytes to the buffer
			if (blockMACRandLen > 0) {
				byte randomBytes[] = new byte[blockMACRandLen];
				random.nextBytes(randomBytes);
				for (int i = 0; i < blockMACRandLen; i++) {
					buf[blockMACLen + i] = randomBytes[i];
				}
			}

			// Compute MAC bytes and add them to the buffer
			byte mac[] = EncFSCrypto.mac64(volume.getMac(), buf, blockMACLen,
					count - blockMACLen);
			for (int i = 0; i < blockMACLen; i++) {
				buf[i] = mac[7 - i];
			}
		}

		byte[] encBuffer;
		try {
			if (count == buf.length) {
				encBuffer = EncFSCrypto.blockEncode(volume, getBlockIV(), buf);
			} else {
				encBuffer = EncFSCrypto.streamEncode(volume, getBlockIV(), buf, 0, count);
			}
		} catch (IllegalBlockSizeException e) {
			throw new IOException(e);
		} catch (BadPaddingException e) {
			throw new IOException(e);
		} catch (InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		} catch (EncFSUnsupportedException e) {
			throw new IOException(e);
		}

		out.write(encBuffer);
		count = blockHeaderSize;
		blockNum++;
	}

	/*
	 * Return the block IV for the current block
	 */
	private byte[] getBlockIV() {
		long fileIvLong = EncFSUtil.byteArrayToLong(fileIv);
		return EncFSUtil.longToByteArray(blockNum ^ fileIvLong);
	}

	/** Flush the internal buffer */
	private void writeBuffer() throws IOException {
		writeBuffer(false);
	}

	@Override
	public synchronized void write(int b) throws IOException {
		buf[count++] = (byte) b;

		if (count == buf.length) {
			writeBuffer();
		}
	}

	@Override
	public synchronized void write(byte b[], int off, int len) throws IOException {
		if (count + len <= buf.length) {
			System.arraycopy(b, off, buf, count, len);
			count += len;

			if (count == buf.length) {
				writeBuffer();
			}
		} else {
			int tmpOff = off;
			int remaining = len;
			while (remaining > 0) {
				int chunk = Math.min(remaining, buf.length - count);

				write(b, tmpOff, chunk);

				remaining -= chunk;
				tmpOff += chunk;
			}
		}
	}

	@Override
	public void close() throws IOException {
		writeBuffer(true);
		super.close();
	}
}
