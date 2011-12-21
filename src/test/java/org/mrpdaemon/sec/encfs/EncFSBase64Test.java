package org.mrpdaemon.sec.encfs;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class EncFSBase64Test {

	@Ignore("Still under development")
	@Test
	public void testDecodeEncodeEncfs() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {

		byte[] in = new byte[] { 87, 51, 103, 76, 111, 85, 113, 76, 45, 48, 89, 122, 85, 104, 56, 117, 100, 80, 56 };
		byte[] out = new byte[] { 98, -63, 94, 52, 104, 95, -127, 64, -2, 96, -85, -24, -23, -90 };

		byte[] out1 = EncFSBase64.decodeEncfs(in);
		Assert.assertArrayEquals(out, out1);

		byte[] in1 = EncFSBase64.encodeEncfs(out);
		String in1s = new String(in1);
		String ins = new String(in);

		Assert.assertArrayEquals(in, in1);
	}
}
