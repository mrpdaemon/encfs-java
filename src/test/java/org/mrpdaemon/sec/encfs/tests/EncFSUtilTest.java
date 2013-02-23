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
import org.mrpdaemon.sec.encfs.EncFSUtil;

import java.nio.ByteBuffer;
import java.util.Random;

public class EncFSUtilTest {
	@Test
	public void testInt_99() {
		int testInt = 99;
		ByteBuffer b = ByteBuffer.allocate(Integer.SIZE / 8).putInt(testInt);

		Assert.assertArrayEquals(b.array(),
				EncFSUtil.convertIntToByteArrayBigEndian(testInt));
		Assert.assertEquals(testInt,
				EncFSUtil.convertBigEndianByteArrayToInt(b.array()));
	}

	@Test
	public void testLong_1198() {
		long testLong = 1198;
		ByteBuffer b = ByteBuffer.allocate(Long.SIZE / 8).putLong(testLong);

		Assert.assertArrayEquals(b.array(),
				EncFSUtil.convertLongToByteArrayBigEndian(testLong));
		Assert.assertEquals(testLong,
				EncFSUtil.convertByteArrayToLong(b.array()));
	}

	@Test
	public void testRandomIntToBytesAndBack() {
		Random random = new Random();
		for (int i = 0; i < 100; i++) {
			int iIn = random.nextInt();

			int iOut1 = toBytesAndBack(iIn);
			int iOut2 = toBytesAndBack(-1 * iIn);

			Assert.assertEquals(iIn, iOut1);
			Assert.assertEquals(-1 * iIn, iOut2);
		}
	}

	@Test
	public void testRandomLongToBytesAndBack() {
		Random random = new Random();
		for (int i = 0; i < 100; i++) {
			long lIn = random.nextLong();

			long lOut1 = toBytesAndBack(lIn);
			long lOut2 = toBytesAndBack(-1 * lIn);

			Assert.assertEquals(lIn, lOut1);
			Assert.assertEquals(-1 * lIn, lOut2);
		}
	}

	private long toBytesAndBack(long lIn) {
		byte[] b = EncFSUtil.convertLongToByteArrayBigEndian(lIn);
		return EncFSUtil.convertByteArrayToLong(b);
	}

	private int toBytesAndBack(int iIn) {
		byte[] b = EncFSUtil.convertIntToByteArrayBigEndian(iIn);
		return EncFSUtil.convertBigEndianByteArrayToInt(b);
	}

}
