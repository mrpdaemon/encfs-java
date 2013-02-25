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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.FilterOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * FilterOutputStream extension that allows encrypted data to be written to a
 * file on an EncFS volume.
 */
public class EncFSOutputStream extends FilterOutputStream {

	// SecureRandom instance for random data generation
	private static final SecureRandom secureRandom = new SecureRandom();

	// Underlying volume
	private final EncFSVolume volume;

	// Volume configuration
	private final EncFSConfig config;

	// IV used for this file
	private byte[] fileIv;

	// Buffer to hold file header contents (uniqueIV)
	private byte[] fileHeader;

	// Buffer to hold the currently cached data contents to be written
	private final byte dataBuf[];

	// Count of the cached data bytes about to be written
	private int dataBytes;

	// Size of the block header for this file
	private int blockHeaderSize;

	// Number of random bytes per block header
	private int blockMACRandLen;

	// Number of MAC bytes per block header
	private int blockMACLen;

	// Index of the current block to be written
	private int curBlockIndex;

	/**
	 * Create a new EncFSOutputStream for writing encrypted data to a file on an
	 * EncFS volume
	 * 
	 * @param volume
	 *            Volume hosting the file to write
	 * @param out
	 *            Output stream for writing the encrypted (raw) data
	 * @param volumePath
	 *            Volume path of the file being encrypted (needed for
	 *            externalIVChaining)
	 *            <p/>
	 *            <p/>
	 *            File data is corrupt
	 *            <p/>
	 *            Unsupported EncFS configuration
	 */
	public EncFSOutputStream(EncFSVolume volume, OutputStream out,
			String volumePath) throws EncFSUnsupportedException,
			EncFSCorruptDataException {
		super(out);
		this.volume = volume;
		this.config = volume.getConfig();
		int blockSize = config.getEncryptedFileBlockSizeInBytes();
		this.blockHeaderSize = config.getNumberOfMACBytesForEachFileBlock()
				+ config.getNumberOfRandomBytesInEachMACHeader();
		this.dataBytes = this.blockHeaderSize;
		this.blockMACLen = config.getNumberOfMACBytesForEachFileBlock();
		this.blockMACRandLen = config.getNumberOfRandomBytesInEachMACHeader();

		if (config.isUseUniqueIV()) {
			// Compute file IV
			this.fileHeader = new byte[8];

			secureRandom.nextBytes(fileHeader);

			byte[] initIv;
			if (config.isSupportedExternalIVChaining()) {
				/*
				 * When using external IV chaining we compute initIv based on
				 * the file path.
				 */
				initIv = StreamCrypto.computeChainIv(volume, volumePath);
			} else {
				// When not using external IV chaining initIv is just zero's.
				initIv = new byte[8];
			}

			try {
				this.fileIv = StreamCrypto.streamDecrypt(volume, initIv,
						Arrays.copyOf(fileHeader, fileHeader.length));
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

		Cipher blockCipher = BlockCrypto.newBlockCipher();
		try {
			EncFSCrypto.cipherInit(volume, Cipher.ENCRYPT_MODE, blockCipher,
					fileIv);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		}
		Cipher streamCipher = StreamCrypto.newStreamCipher();
		try {
			EncFSCrypto.cipherInit(volume, Cipher.ENCRYPT_MODE, streamCipher,
					fileIv);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		}

		// blockSize = blockHeaderSize + blockDataLen
		dataBuf = new byte[blockSize];
	}

	// Flush the internal buffer
	private void writeBuffer(boolean isFinal) throws IOException {

		if (!isFinal && dataBytes != dataBuf.length) {
			throw new IllegalStateException("Buffer not full");
		}

		if (curBlockIndex == 0 && config.isUseUniqueIV()) {
			out.write(this.fileHeader);
		}

		// Fill in the block header
		if (blockHeaderSize > 0) {

			// Add random bytes to the buffer
			if (blockMACRandLen > 0) {
				byte randomBytes[] = new byte[blockMACRandLen];
				secureRandom.nextBytes(randomBytes);
				System.arraycopy(randomBytes, 0, dataBuf, blockMACLen,
						blockMACRandLen);
			}

			// Compute MAC bytes and add them to the buffer
			byte mac[] = EncFSCrypto.mac64(volume.getMAC(), dataBuf,
					blockMACLen, dataBytes - blockMACLen);
			for (int i = 0; i < blockMACLen; i++) {
				dataBuf[i] = mac[7 - i];
			}
		}

		byte[] encBuffer;
		try {
			if (dataBytes == dataBuf.length) {
				/*
				 * If allowHoles is configured, we scan the buffer to determine
				 * whether we should pass this block through as a zero block.
				 * Note that it is intended for the presence of a MAC header to
				 * cause this check to fail.
				 */
				boolean zeroBlock = false;
				if (config.isHolesAllowedInFiles()) {
					zeroBlock = true;
					for (byte aDataBuf : dataBuf) {
						if (aDataBuf != 0) {
							zeroBlock = false;
							break;
						}
					}
				}

				if (zeroBlock) {
					encBuffer = dataBuf;
				} else {
					encBuffer = BlockCrypto.blockEncrypt(volume,
							getBlockIV(), dataBuf);
				}
			} else {
				encBuffer = StreamCrypto.streamEncrypt(volume,
						getBlockIV(), dataBuf, 0, dataBytes);
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
		dataBytes = blockHeaderSize;
		curBlockIndex++;
	}

	// Return the block IV for the current block
	private byte[] getBlockIV() {
		long fileIvLong = EncFSUtil.convertByteArrayToLong(fileIv);
		return EncFSUtil.convertLongToByteArrayBigEndian(curBlockIndex
				^ fileIvLong);
	}

	// Flush the internal buffer
	private void writeBuffer() throws IOException {
		writeBuffer(false);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterOutputStream#write(int)
	 */
	@Override
	public synchronized void write(int b) throws IOException {
		dataBuf[dataBytes++] = (byte) b;

		if (dataBytes == dataBuf.length) {
			writeBuffer();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterOutputStream#write(int)
	 */
	@Override
	public synchronized void write(byte b[], int off, int len)
			throws IOException {
		if (dataBytes + len <= dataBuf.length) {
			System.arraycopy(b, off, dataBuf, dataBytes, len);
			dataBytes += len;

			if (dataBytes == dataBuf.length) {
				writeBuffer();
			}
		} else {
			int tmpOff = off;
			int remaining = len;
			while (remaining > 0) {
				int chunk = Math.min(remaining, dataBuf.length - dataBytes);

				write(b, tmpOff, chunk);

				remaining -= chunk;
				tmpOff += chunk;
			}
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterOutputStream#write(int)
	 */
	@Override
	public void close() throws IOException {
		writeBuffer(true);
		super.close();
	}
}
