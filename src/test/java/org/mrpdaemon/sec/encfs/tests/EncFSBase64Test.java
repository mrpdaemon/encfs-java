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
import org.mrpdaemon.sec.encfs.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;

public class EncFSBase64Test {

	@Test
	public void testDecodeEncodeEncfs() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {

		byte[] in = new byte[] { 87, 51, 103, 76, 111, 85, 113, 76, 45, 48, 89,
				122, 85, 104, 56, 117, 100, 80, 56 };
		byte[] out = new byte[] { 98, -63, 94, 52, 104, 95, -127, 64, -2, 96,
				-85, -24, -23, -90 };

		byte[] out1 = EncFSBase64.decodeEncfs(in);
		Assert.assertArrayEquals(out, out1);

		byte[] in1 = EncFSBase64.encodeEncfs(out);

		Assert.assertArrayEquals(in, in1);
	}
}
