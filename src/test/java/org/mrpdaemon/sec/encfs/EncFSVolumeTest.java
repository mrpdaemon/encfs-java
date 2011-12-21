package org.mrpdaemon.sec.encfs;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
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
	public void testBoxCryptor_1_badPassword() throws FileNotFoundException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "badPassword";

		try {
			new EncFSVolume(encFSDir, password);
			Assert.fail();
		} catch (EncFSInvalidPasswordException e) {
			// this is correct that we should have got this exception
		}
	}

	@Test
	public void testBoxCryptor_1() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

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

	@Ignore("Still under development")
	@Test
	public void testBoxCryptor_1_encode() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir, password);

		String fileName = "W3gLoUqL-0YzUh8udP8";
		String volumePath = "/";

		String decName = EncFSCrypto.decodeName(volume, fileName, volumePath);

		String encName = EncFSCrypto.encodeName(volume, decName, volumePath);
		Assert.assertEquals(fileName, encName);
	}

	@Ignore("Still under development")
	@Test
	public void testBoxCryptor_1_encode2() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_1");
		Assert.assertTrue(encFSDir.exists());

		String password = "test";
		EncFSVolume volume = new EncFSVolume(encFSDir, password);

		// byte[] ivSeed = new byte[4];
		// byte[] orig = new byte[] { 1, 2, 3, 4 };

		byte[] orig = new byte[] { 116, 101, 115, 116, 102, 105, 108, 101, 46, 116, 120, 116 };
		byte[] ivSeed = new byte[] { 0, 0, 0, 0, 0, 0, 98, -63 };

		byte[] b1 = EncFSCrypto.streamEncode(volume, ivSeed, Arrays.copyOf(orig, orig.length));
		byte[] b2 = EncFSCrypto.streamDecode(volume, ivSeed, Arrays.copyOf(b1, b1.length));

		Assert.assertArrayEquals(orig, b2);
	}

	@Ignore("Still under development")
	@Test
	public void testBoxCryptor_1_encode3() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
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

	@Test
	public void testBoxCryptor_2() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException, IOException {
		File encFSDir = new File("test/encfs_samples/boxcryptor_2");
		Assert.assertTrue(encFSDir.exists());

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
		Assert.assertTrue(encFSDir.exists());

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
