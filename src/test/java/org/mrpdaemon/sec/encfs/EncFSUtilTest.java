package org.mrpdaemon.sec.encfs;

import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

public class EncFSUtilTest {
	@Test
	public void testInt_99() {
		int testInt = 99;
		byte[] testBytes = new byte[] { 0, 0, 0, 99 };

		Assert.assertArrayEquals(testBytes, EncFSUtil.intToByteArray(testInt));
		Assert.assertEquals(testInt, EncFSUtil.byteArrayToInt(testBytes));
	}

	@Test
	public void testLong_1198() {
		long testLong = 1198;
		byte[] testBytes = new byte[] { 0, 0, 0, 0, 0, 0, 4, -82 };

		Assert.assertArrayEquals(testBytes, EncFSUtil.longToByteArray(testLong));
		Assert.assertEquals(testLong, EncFSUtil.byteArrayToLong(testBytes));
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
		byte[] b = EncFSUtil.longToByteArray(lIn);
		long lOut = EncFSUtil.byteArrayToLong(b);
		return lOut;
	}

	private int toBytesAndBack(int iIn) {
		byte[] b = EncFSUtil.intToByteArray(iIn);
		int iOut = EncFSUtil.byteArrayToInt(b);
		return iOut;
	}

}
