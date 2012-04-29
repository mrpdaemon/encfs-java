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

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class EncFSVolumeIntegrationTest {

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testBoxCryptor_1_badPassword()
			throws EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "badPassword";

		try {
			new EncFSVolume(encFSDir.getAbsolutePath(), password);
			Assert.fail();
		} catch (EncFSInvalidPasswordException e) {
			// this is correct that we should have got this exception
			Assert.assertNotNull(e);
		}
	}

	@Test
	public void testDefaultVol() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/testvol-default");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(3, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("longfile.txt", encFSFile.getName());
		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals(contents.length(), 6000);
		for (int i = 0; i < contents.length(); i++) {
			Assert.assertTrue(contents.charAt(i) == 'a');
		}

		encFSFile = files[1];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("test.txt", encFSFile.getName());
		contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals("This is a test file.\n", contents);

		encFSFile = files[2];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("zerofile.bin", encFSFile.getName());
		byte zeroBytes[] = readInputStreamAsByteArray(encFSFile);
		Assert.assertEquals(zeroBytes.length, 10000);
		for (int i = 0; i < zeroBytes.length; i++) {
			Assert.assertTrue(zeroBytes[i] == 0);
		}

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void testNoUniqueIV() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/testvol-nouniqueiv");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(2, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("longfile.txt", encFSFile.getName());
		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals(contents.length(), 6000);
		for (int i = 0; i < contents.length(); i++) {
			Assert.assertTrue(contents.charAt(i) == 'a');
		}

		encFSFile = files[1];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("testfile.txt", encFSFile.getName());
		contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals("Test file for non-unique-IV file.\n", contents);

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void testStreamName() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/testvol-streamname");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(1, files.length);

		EncFSFile dir = files[0];
		Assert.assertTrue(dir.isDirectory());
		Assert.assertEquals("dir", dir.getName());
		
		EncFSFile[] dirFiles = dir.listFiles();
		Assert.assertEquals(1, files.length);
		
		EncFSFile encFSFile = dirFiles[0];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("testfile.txt", encFSFile.getName());
		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals("stream name algorithm\n", contents);

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void testBlockMAC() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/testvol-blockmac");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(1, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("longfile.txt", encFSFile.getName());
		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals(contents.length(), 6000);
		for (int i = 0; i < contents.length(); i++) {
			Assert.assertTrue(contents.charAt(i) == 'a');
		}

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void testBoxCryptor_1() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(1, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("testfile.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals("test file\r\n", contents);

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void testBoxCryptor_2() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_2");
		Assert.assertTrue(encFSDir.exists());

		String password = "test2";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(2, files.length);

		EncFSFile encFSSubDir = files[0];
		Assert.assertTrue(encFSSubDir.isDirectory());
		Assert.assertEquals("Dir1", encFSSubDir.getName());

		EncFSFile encFSFile = files[1];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("file1.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals("Some contents for file1", contents);

		String dirListing = getDirListing(rootDir, true);
		String expectedListing = "";
		expectedListing += "/Dir1" + "\n";
		expectedListing += "/Dir1/file2.txt" + "\n";
		expectedListing += "/file1.txt";
		Assert.assertEquals(expectedListing, dirListing);

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void testBoxCryptor_3() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_3");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir.getAbsolutePath(),
				password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(1, files.length);

		String dirListing = getDirListing(rootDir, true);
		Assert.assertNotNull(dirListing);

		assertFileNameEncoding(rootDir);
		assertEncFSFileRoundTrip(rootDir);
	}

	@Test
	public void createVolume_1() {
		File rootDir;
		try {
			rootDir = EncFSVolumeTestCommon.createTempDir();
		} catch (IOException e) {
			Assert.fail("Could not create temporary directory");
			return;
		}

		EncFSConfig config = new EncFSConfig();
		String password = "test";

		EncFSLocalFileProvider fileProvider = new EncFSLocalFileProvider(
				rootDir);

		try {
			EncFSVolume.createVolume(fileProvider, config, password);
			@SuppressWarnings("unused")
			EncFSVolume volume = new EncFSVolume(fileProvider, config, password);
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}

		// Clean up after ourselves
		File configFile = new File(rootDir.getAbsolutePath(),
				EncFSVolume.CONFIG_FILE_NAME);
		Assert.assertTrue(configFile.exists());
		configFile.delete();

		Assert.assertTrue(rootDir.exists());
		rootDir.delete();
	}

	private void assertFileNameEncoding(EncFSFile encfsFileDir)
			throws EncFSCorruptDataException, EncFSChecksumException,
			IOException {
		for (EncFSFile encfFile : encfsFileDir.listFiles()) {
			EncFSVolume volume = encfsFileDir.getVolume();
			String decName = EncFSCrypto.decodeName(volume,
					encfFile.getEncrytedName(), encfFile.getParentPath());
			Assert.assertEquals(encfFile.getPath() + " decoded file name",
					encfFile.getName(), decName);

			String encName = EncFSCrypto.encodeName(volume, decName,
					encfFile.getParentPath());
			Assert.assertEquals(encfFile.getPath() + " re-encoded file name",
					encfFile.getEncrytedName(), encName);

			if (encfFile.isDirectory()) {
				assertFileNameEncoding(encfFile);
			}
		}
	}

	private void assertEncFSFileRoundTrip(EncFSFile encFsFile)
			throws IOException, EncFSUnsupportedException,
			EncFSCorruptDataException, EncFSChecksumException {
		if (encFsFile.isDirectory() == false) {
			// Copy the file via input/output streams & then check that
			// the file is the same
			File t = File.createTempFile(this.getClass().getName(), ".tmp");
			try {
				EncFSUtil.copyWholeStream(new EncFSFileInputStream(encFsFile),
						new EncFSOutputStream(encFsFile.getVolume(),
								new BufferedOutputStream(
										new FileOutputStream(t))), true, true);

				if (encFsFile.getVolume().getConfig().isUniqueIV() == false) {
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
								encFsFile.getVolume(), new FileInputStream(t));
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

	private void assertInputStreamsAreEqual(String msg, InputStream encfsIs,
			InputStream decFsIs) throws IOException {
		int bytesRead = 0, bytesRead2 = 0;
		while (bytesRead >= 0) {
			byte[] readBuf = new byte[128];
			byte[] readBuf2 = new byte[128];

			bytesRead = encfsIs.read(readBuf);
			bytesRead2 = decFsIs.read(readBuf2);

			Assert.assertEquals(msg, bytesRead, bytesRead2);
			Assert.assertArrayEquals(msg, readBuf, readBuf2);
		}
	}

	private static String getDirListing(EncFSFile rootDir, boolean recursive)
			throws EncFSCorruptDataException, EncFSChecksumException,
			IOException {
		StringBuilder sb = new StringBuilder();
		getDirListing(rootDir, recursive, sb);
		return sb.toString();

	}

	private static void getDirListing(EncFSFile rootDir, boolean recursive,
			StringBuilder sb) throws EncFSCorruptDataException,
			EncFSChecksumException, IOException {

		for (EncFSFile encFile : rootDir.listFiles()) {
			if (sb.length() > 0) {
				sb.append("\n");
			}
			sb.append(encFile.getParentPath());
			if (encFile.getParentPath().equals(EncFSVolume.ROOT_PATH) == false) {
				sb.append(EncFSVolume.PATH_SEPARATOR);
			}
			sb.append(encFile.getName());
			if (encFile.isDirectory() && recursive) {
				getDirListing(encFile, recursive, sb);
			}
		}
	}

	public static byte[] readInputStreamAsByteArray(EncFSFile encFSFile)
			throws IOException, EncFSCorruptDataException,
			EncFSUnsupportedException {

		ByteArrayOutputStream buf = new ByteArrayOutputStream();

		EncFSUtil.copyWholeStream(new EncFSFileInputStream(encFSFile), buf,
				true, false);

		return buf.toByteArray();
	}

	public static String readInputStreamAsString(EncFSFile encFSFile)
			throws IOException, EncFSCorruptDataException,
			EncFSUnsupportedException {
		return new String(readInputStreamAsByteArray(encFSFile));
	}

}
