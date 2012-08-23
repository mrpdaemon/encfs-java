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

import java.io.File;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.junit.Assert;
import org.junit.Test;

public class EncFSCryptoTest {

	@Test
	public void testStreamEncodeDecode() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);

		byte[] orig = new byte[] { 116, 101, 115, 116, 102, 105, 108, 101, 46,
				116, 120, 116 };
		byte[] ivSeed = new byte[] { 0, 0, 0, 0, 0, 0, 98, -63 };

		byte[] b1 = EncFSCrypto.streamEncode(volume, ivSeed,
				Arrays.copyOf(orig, orig.length));
		byte[] b2 = EncFSCrypto.streamDecode(volume, ivSeed,
				Arrays.copyOf(b1, b1.length));

		Assert.assertArrayEquals(orig, b2);
	}

	@Test
	public void testStreamEncodeDecode2() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);

		String str = "test file\r";

		byte[] orig = str.getBytes();
		byte[] ivSeed = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

		byte[] b1 = EncFSCrypto.streamEncode(volume, ivSeed,
				Arrays.copyOf(orig, orig.length));
		byte[] b2 = EncFSCrypto.streamDecode(volume, ivSeed,
				Arrays.copyOf(b1, b1.length));

		Assert.assertArrayEquals(orig, b2);
	}

}
