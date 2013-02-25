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
import org.mrpdaemon.sec.encfs.tests.vfs.CommonsVFSRamFileProvider;

import java.io.*;

import static org.junit.Assert.*;
import static org.mrpdaemon.sec.encfs.EncFSCrypto.decodeName;
import static org.mrpdaemon.sec.encfs.EncFSCrypto.encodeName;

public class EncFSVolumeIntegrationTest {

	@Test
	public void testIsEncFSVolume() throws Exception {
		assertTrue(EncFSVolume.isEncFSVolume("test/encfs_samples/boxcryptor_1"));
		Assert.assertFalse(EncFSVolume.isEncFSVolume("test/encfs_samples"));
	}

	@Test(expected = EncFSInvalidPasswordException.class)
	public void testBoxCryptor_1_badPassword() throws Exception {
		new EncFSVolumeBuilder()
				.withRootPath("test/encfs_samples/boxcryptor_1")
				.withPassword("badPassword").buildVolume();
	}

	@Test(expected = EncFSInvalidConfigException.class)
	public void testBoxCryptor_1_wrongPath() throws Exception {
		new EncFSVolumeBuilder()
				.withRootPath("test/encfs_samples/boxcryptor_12")
				.withPassword("test").buildVolume();
	}

	@Test
	public void testDefaultVol() throws Exception {
		String pathname = "test/encfs_samples/testvol-default";

		EncFSFile rootDir = getVolumeRootDir(pathname, "test");

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(3, files.length);

		int numMatches = 0;
		for (EncFSFile encFSFile : files) {
			if (encFSFile.getName().equals("longfile.txt")) {
				numMatches++;
				Assert.assertFalse(encFSFile.isDirectory());

				String contents = readInputStreamAsString(encFSFile);
				assertEquals(contents.length(), 6000);
				for (int i = 0; i < contents.length(); i++) {
					assertTrue(contents.charAt(i) == 'a');
				}
			} else if (encFSFile.getName().equals("zerofile.bin")) {
				numMatches++;
				Assert.assertFalse(encFSFile.isDirectory());

				byte zeroBytes[] = readInputStreamAsByteArray(encFSFile);
				assertEquals(zeroBytes.length, 10000);

				for (byte zeroByte : zeroBytes) {
					assertTrue(zeroByte == 0);
				}
			} else if (encFSFile.getName().equals("test.txt")) {
				numMatches++;
				Assert.assertFalse(encFSFile.isDirectory());

				String contents = readInputStreamAsString(encFSFile);
				assertEquals("This is a test file.\n", contents);
			}
		}
		assertEquals(numMatches, 3);
		assertFinalTests(rootDir);
	}

	@Test
	public void testNoUniqueIV() throws Exception {
		String pathname = "test/encfs_samples/testvol-nouniqueiv";

		EncFSFile rootDir = getVolumeRootDir(pathname, "test");

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(2, files.length);

		int numMatches = 0;
		for (EncFSFile encFSFile : files) {
			if (encFSFile.getName().equals("longfile.txt")) {
				numMatches++;
				Assert.assertFalse(encFSFile.isDirectory());
				String contents = readInputStreamAsString(encFSFile);
				assertEquals(contents.length(), 6000);
				for (int i = 0; i < contents.length(); i++) {
					assertTrue(contents.charAt(i) == 'a');
				}
			} else if (encFSFile.getName().equals("testfile.txt")) {
				numMatches++;
				Assert.assertFalse(encFSFile.isDirectory());
				assertEquals("testfile.txt", encFSFile.getName());
				String contents = readInputStreamAsString(encFSFile);
				assertEquals("Test file for non-unique-IV file.\n", contents);
			}
		}
		assertEquals(numMatches, 2);
		assertFinalTests(rootDir);
	}

	@Test
	public void testStreamName() throws Exception {
		String pathname = "test/encfs_samples/testvol-streamname";
		String password = "test";

		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(1, files.length);

		EncFSFile dir = files[0];
		assertTrue(dir.isDirectory());
		assertEquals("dir", dir.getName());

		EncFSFile[] dirFiles = dir.listFiles();
		assertEquals(1, files.length);

		EncFSFile encFSFile = dirFiles[0];
		Assert.assertFalse(encFSFile.isDirectory());
		assertEquals("testfile.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		assertEquals("stream name algorithm\n", contents);
		assertFinalTests(rootDir);
	}

	@Test
	public void testBlockMAC() throws Exception {
		String pathname = "test/encfs_samples/testvol-blockmac";
		String password = "test";

		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(1, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		assertEquals("longfile.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		assertEquals(contents.length(), 6000);

		for (int i = 0; i < contents.length(); i++) {
			assertTrue(contents.charAt(i) == 'a');
		}
		assertFinalTests(rootDir);
	}

	@Test
	public void testExtIvChain() throws Exception {
		String pathname = "test/encfs_samples/testvol-extivchn";
		String password = "test";

		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(2, files.length);

		int numOuterMatches = 0;
		int numInnerMatches = 0;
		for (EncFSFile encFSFile : files) {
			if (encFSFile.getName().equals("test.txt")) {
				numOuterMatches++;
				Assert.assertFalse(encFSFile.isDirectory());

				String contents = readInputStreamAsString(encFSFile);
				assertEquals("this is a test file with external IV chaining",
						contents);
			} else if (encFSFile.getName().equals("directory")) {
				numOuterMatches++;
				assertTrue(encFSFile.isDirectory()); /*
													 * Traverse down the
													 * directory
													 */

				for (EncFSFile subFile : encFSFile.listFiles()) {
					numInnerMatches++;
					assertEquals(subFile.getName(), "another-test-file.txt");

					String contents = readInputStreamAsString(subFile);
					assertEquals(
							"this is another test file with external IV chaining",
							contents);
				}
			}
		}
		assertEquals(numOuterMatches, 2);
		assertEquals(numInnerMatches, 1);
		assertFinalTests(rootDir);
	}

	@Test
	public void testBoxCryptor_1() throws Exception {
		String pathname = "test/encfs_samples/boxcryptor_1";
		String password = "test";

		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(1, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		assertEquals("testfile.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		assertEquals("test file\r\n", contents);

		assertFinalTests(rootDir);
	}

	@Test
	public void testBoxCryptor_2() throws Exception {
		String pathname = "test/encfs_samples/boxcryptor_2";
		String password = "test2";

		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(2, files.length);

		int numMatches = 0;
		for (EncFSFile encFSFile : files) {
			if (encFSFile.getName().equals("file1.txt")) {
				numMatches++;
				Assert.assertFalse(encFSFile.isDirectory());

				String contents = readInputStreamAsString(encFSFile);
				assertEquals("Some contents for file1", contents);
			} else if (encFSFile.getName().equals("Dir1")) {
				numMatches++;
				assertTrue(encFSFile.isDirectory());

				EncFSFile[] subFiles = encFSFile.listFiles();
				assertEquals(subFiles.length, 1);
				assertEquals(subFiles[0].getName(), "file2.txt");
			}
		}
		assertEquals(numMatches, 2);
		assertFinalTests(rootDir);
	}

	@Test
	public void testBoxCryptor_3() throws Exception {
		String pathname = "test/encfs_samples/boxcryptor_3";
		String password = "test";
		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(1, files.length);

		String dirListing = getDirListing(rootDir);
		assertNotNull(dirListing);

		assertFinalTests(rootDir);
	}

	@Test
	public void testBoxCryptor_null() throws Exception {
		String pathname = "test/encfs_samples/boxcryptor_null";
		String password = "test";
		EncFSFile rootDir = getVolumeRootDir(pathname, password);

		EncFSFile[] files = rootDir.listFiles();
		assertEquals(1, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());

		assertEquals("testfile.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		assertEquals("Contents for test fileAlpha.txt", contents);

		assertFinalTests(rootDir);
	}

	private void assertFinalTests(EncFSFile rootDir) throws Exception {
		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
		assertLengthCalculations(rootDir);
	}

	private EncFSFile getVolumeRootDir(String pathname, String password)
			throws EncFSUnsupportedException, IOException,
			EncFSInvalidConfigException, EncFSInvalidPasswordException,
			EncFSCorruptDataException {
		assertTrue(new File(pathname).exists());
		EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(pathname)
				.withPassword(password).buildVolume();
		return volume.getRootDir();
	}

	@Test
	public void createVolume_1() throws Exception {
		CommonsVFSRamFileProvider fileProvider = new CommonsVFSRamFileProvider();
		fileProvider.init();

		EncFSConfig config = EncFSConfigFactory.createDefault();
		String password = "test";

		new EncFSVolumeBuilder().withFileProvider(fileProvider)
				.withConfig(config).withPassword(password).writeVolumeConfig();
		new EncFSVolumeBuilder().withFileProvider(fileProvider)
				.withConfig(config).withPassword(password).buildVolume();
	}

	private void assertFileNameEncoding(EncFSFile encfsFileDir)
			throws Exception {
		for (EncFSFile encfFile : encfsFileDir.listFiles()) {
			EncFSVolume volume = encfsFileDir.getVolume();
			String decName = decodeName(volume, encfFile.getEncrytedName(),
					encfFile.getParentPath());
			assertEquals(encfFile.getPath() + " decoded file name",
					encfFile.getName(), decName);
			String encName = encodeName(volume, decName,
					encfFile.getParentPath());
			assertEquals(encfFile.getPath() + " re-encoded file name",
					encfFile.getEncrytedName(), encName);
			if (encfFile.isDirectory()) {
				assertFileNameEncoding(encfFile);
			}
		}
	}

	private void assertEncFSFileRoundTrip(EncFSFile encFsFile) throws Exception {
		if (!encFsFile.isDirectory()) { /*
										 * Copy the file via input/output
										 * streams & then check that the file is
										 * the same
										 */
			File t = File.createTempFile(this.getClass().getName(), ".tmp");
			try {
				EncFSUtil.copyWholeStreamAndClose(new EncFSFileInputStream(
						encFsFile), new EncFSOutputStream(
						encFsFile.getVolume(), new BufferedOutputStream(
								new FileOutputStream(t)), encFsFile.getPath()));
				if (!encFsFile.getVolume().getConfig().isUseUniqueIV()) {
					FileInputStream reEncFSIs = new FileInputStream(t);
					try {
						InputStream origEncFSIs = encFsFile.getVolume()
								.getFileProvider()
								.openInputStream(encFsFile.getEncryptedPath());
						try {
							assertInputStreamsAreEqual(encFsFile.getPath(),
									origEncFSIs, reEncFSIs);
						} finally {
							origEncFSIs.close();
						}
					} finally {
						reEncFSIs.close();
					}
				} else {
					EncFSFileInputStream efis = new EncFSFileInputStream(
							encFsFile);
					try {
						EncFSInputStream efisCopy = new EncFSInputStream(
								encFsFile.getVolume(), new FileInputStream(t),
								encFsFile.getPath());
						try {
							assertInputStreamsAreEqual(encFsFile.getPath(),
									efis, efisCopy);
						} finally {
							efisCopy.close();
						}
					} finally {
						efis.close();
					}
				}
			} finally {
				if (t.exists()) {
					t.delete();
				}
			}
		} else {
			for (EncFSFile subEncfFile : encFsFile.listFiles()) {
				assertEncFSFileRoundTrip(subEncfFile);
			}
		}
	}

	private void assertLengthCalculations(EncFSFile encFsFile) throws Exception {
		if (!encFsFile.isDirectory()) {
			long encryptedSize = encFsFile.getVolume().getFileProvider()
					.getFileInfo(encFsFile.getEncryptedPath()).getSize();
			assertInputStreamLength(encFsFile.openInputStream(), encFsFile
					.getVolume().getDecryptedFileLength(encryptedSize));
			assertEquals(encryptedSize, encFsFile.getVolume()
					.getEncryptedFileLength(encFsFile.getLength()));
		} else {
			for (EncFSFile subEncfFile : encFsFile.listFiles()) {
				assertLengthCalculations(subEncfFile);
			}
		}
	}

	private void assertInputStreamsAreEqual(String msg, InputStream encfsIs,
			InputStream decFsIs) throws Exception {
		int bytesRead = 0;
		int bytesRead2;

		while (bytesRead >= 0) {
			byte[] readBuf = new byte[128];
			byte[] readBuf2 = new byte[128];
			bytesRead = encfsIs.read(readBuf);
			bytesRead2 = decFsIs.read(readBuf2);
			assertEquals(msg, bytesRead, bytesRead2);
			Assert.assertArrayEquals(msg, readBuf, readBuf2);
		}
	}

	private void assertInputStreamLength(InputStream encfsIs, long length)
			throws Exception {
		int bytesRead = 0;
		long totalSize = 0;
		while (bytesRead >= 0) {
			totalSize += bytesRead;
			byte[] readBuf = new byte[128];
			bytesRead = encfsIs.read(readBuf);
		}
		assertEquals(totalSize, length);
	}

	private static String getDirListing(EncFSFile rootDir) throws Exception {
		StringBuilder sb = new StringBuilder();
		getDirListing(rootDir, true, sb);
		return sb.toString();
	}

	private static void getDirListing(EncFSFile rootDir, boolean recursive,
			StringBuilder sb) throws Exception {
		for (EncFSFile encFile : rootDir.listFiles()) {
			if (sb.length() > 0) {
				sb.append("\n");
			}
			sb.append(encFile.getParentPath());
			if (!encFile.getParentPath().equals(EncFSVolume.ROOT_PATH)) {
				sb.append(EncFSVolume.PATH_SEPARATOR);
			}
			sb.append(encFile.getName());
			if (encFile.isDirectory() && recursive) {
				getDirListing(encFile, recursive, sb);
			}
		}
	}

	private static byte[] readInputStreamAsByteArray(EncFSFile encFSFile)
			throws Exception {
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		EncFSUtil.copyWholeStreamAndCloseInput(new EncFSFileInputStream(
				encFSFile), buf);
		return buf.toByteArray();
	}

	private static String readInputStreamAsString(EncFSFile encFSFile)
			throws Exception {
		return new String(readInputStreamAsByteArray(encFSFile));
	}
}