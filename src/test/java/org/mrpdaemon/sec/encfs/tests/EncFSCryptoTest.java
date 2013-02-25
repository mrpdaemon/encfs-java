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

package org.mrpdaemon.sec.encfs.tests;

import org.junit.Assert;
import org.junit.Test;
import org.mrpdaemon.sec.encfs.EncFSVolume;
import org.mrpdaemon.sec.encfs.EncFSVolumeBuilder;
import org.mrpdaemon.sec.encfs.StreamCrypto;

import java.io.File;
import java.util.Arrays;

public class EncFSCryptoTest {
	private final static String password = "test";
	private final static String pathname = "test/encfs_samples/boxcryptor_1";

	@Test
	public void testStreamEncodeDecode() throws Exception {
		EncFSVolume volume = getEncFSVolume();
		byte[] orig = new byte[] { 116, 101, 115, 116, 102, 105, 108, 101, 46,
				116, 120, 116 };
		byte[] ivSeed = new byte[] { 0, 0, 0, 0, 0, 0, 98, -63 };

		byte[] b1 = StreamCrypto.streamEncrypt(volume, ivSeed,
				Arrays.copyOf(orig, orig.length));
		byte[] b2 = StreamCrypto.streamDecrypt(volume, ivSeed,
				Arrays.copyOf(b1, b1.length));

		Assert.assertArrayEquals(orig, b2);
	}

	@Test
	public void testStreamEncodeDecode2() throws Exception {
		EncFSVolume volume = getEncFSVolume();
		byte[] orig = "test file\r".getBytes();
		byte[] ivSeed = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0 };

		byte[] b1 = StreamCrypto.streamEncrypt(volume, ivSeed,
				Arrays.copyOf(orig, orig.length));
		byte[] b2 = StreamCrypto.streamDecrypt(volume, ivSeed,
				Arrays.copyOf(b1, b1.length));

		Assert.assertArrayEquals(orig, b2);
	}

	private static EncFSVolume getEncFSVolume() throws Exception {
		File encFSDir = assertExistingPath(EncFSCryptoTest.pathname);
		return new EncFSVolumeBuilder()
				.withRootPath(encFSDir.getAbsolutePath())
				.withPassword(EncFSCryptoTest.password).buildVolume();
	}

	private static File assertExistingPath(String pathname) {
		File encFSDir = new File(pathname);
		Assert.assertTrue(encFSDir.exists());
		return encFSDir;
	}
}
