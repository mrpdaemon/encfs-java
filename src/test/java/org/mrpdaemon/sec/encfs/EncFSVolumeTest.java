package org.mrpdaemon.sec.encfs;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class EncFSVolumeTest {

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
	public void testBoxCryptor_1() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir, password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(1, files.length);

		EncFSFile encFSFile = files[0];
		Assert.assertFalse(encFSFile.isDirectory());
		Assert.assertEquals("testfile.txt", encFSFile.getName());

		String contents = readInputStreamAsString(encFSFile);
		Assert.assertEquals("test file\r", contents);
	}

	@Test
	public void testBoxCryptor_2() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_2");
		String password = "test2";
		EncFSVolume volume = new EncFSVolume(encFSDir, password);
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
		Assert.assertEquals("Some contents for file", contents);

		String dirListing = GetDirListing(rootDir, true);
		String expectedListing = "";
		expectedListing += "/Dir1" + "\n";
		expectedListing += "/Dir1/file2.txt" + "\n";
		expectedListing += "/file1.txt";
		Assert.assertEquals(expectedListing, dirListing);
	}

	@Test
	public void testBoxCryptor_3() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_3");
		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir, password);
		EncFSFile rootDir = volume.getRootDir();
		EncFSFile[] files = rootDir.listFiles();
		Assert.assertEquals(1, files.length);

		String dirListing = GetDirListing(rootDir, true);
		Assert.assertNotNull(dirListing);
	}

	private static String GetDirListing(EncFSFile rootDir, boolean recursive) throws EncFSCorruptDataException,
			EncFSChecksumException {
		StringBuilder sb = new StringBuilder();
		GetDirListing(rootDir, recursive, sb);
		return sb.toString();

	}

	private static void GetDirListing(EncFSFile rootDir, boolean recursive, StringBuilder sb)
			throws EncFSCorruptDataException, EncFSChecksumException {

		for (EncFSFile encFile : rootDir.listFiles()) {
			if (sb.length() > 0) {
				sb.append("\n");
			}
			sb.append(encFile.getVolumePath());
			if (encFile.getVolumePath().equals("/") == false) {
				sb.append("/");
			}
			sb.append(encFile.getName());
			if (encFile.isDirectory() && recursive) {
				GetDirListing(encFile, recursive, sb);
			}
		}
	}

	public static String readInputStreamAsString(EncFSFile encFSFile) throws IOException, EncFSCorruptDataException,
			EncFSUnsupportedException {

		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		EncFSFileInputStream efis = new EncFSFileInputStream(encFSFile);
		try {
			BufferedInputStream bis = new BufferedInputStream(efis);
			try {
				int bytesRead = 0;
				while (bytesRead >= 0) {
					byte[] readBuf = new byte[128];
					bytesRead = bis.read(readBuf);
					if (bytesRead >= 0) {
						buf.write(readBuf, 0, bytesRead);
					}
				}
			} finally {
				bis.close();
			}
		} finally {
			efis.close();
		}

		return new String(buf.toByteArray());
	}

}
