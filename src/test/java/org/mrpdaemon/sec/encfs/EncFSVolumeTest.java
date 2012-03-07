package org.mrpdaemon.sec.encfs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import junit.framework.Assert;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mrpdaemon.sec.encfs.vfs.CommonsVFSRamFileProvider;

public class EncFSVolumeTest {

	private final String password = "testPassword";

	private CommonsVFSRamFileProvider fileProvider;

	@Before
	public void setUp() throws Exception {
		this.fileProvider = new CommonsVFSRamFileProvider();
		this.fileProvider.init();
	}

	@After
	public void tearDown() throws Exception {
		this.fileProvider.close();
	}

	@Test
	public void testNoExistingConfigFile()
			throws EncFSInvalidPasswordException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		try {
			@SuppressWarnings("unused")
			EncFSVolume v = new EncFSVolume(fileProvider, new byte[] {});
		} catch (EncFSInvalidConfigException e) {
			Assert.assertEquals("No EncFS configuration file found",
					e.getMessage());
		}
	}

	@Test
	public void testVolumeCreation() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		EncFSConfig config = new EncFSConfig();

		EncFSVolume volume = null;
		try {
			EncFSVolume.createVolume(fileProvider, config, password);
			volume = new EncFSVolume(fileProvider, config, password);
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}

		Assert.assertNotNull(volume);

		Assert.assertEquals(1, fileProvider.listFiles("/").size());
		Assert.assertTrue(fileProvider.exists("/.encfs6.xml"));
	}

	@Test
	public void testFileOperations() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException, EncFSChecksumException {
		EncFSConfig config = new EncFSConfig();

		EncFSVolume volume = null;
		try {
			EncFSVolume.createVolume(fileProvider, config, password);
			volume = new EncFSVolume(fileProvider, config, password);
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}

		// Create a file
		Assert.assertFalse(volume.pathExists("/test.txt"));
		Assert.assertEquals(0, volume.listFilesForPath("/").length);
		EncFSFile outFile = volume.createFile("/test.txt");
		OutputStream os = outFile.openOutputStream();
		try {
			os.write("hello\nworld".getBytes());
		} finally {
			os.close();
		}

		// Check the file got created
		Assert.assertEquals(1, volume.listFilesForPath("/").length);
		Assert.assertEquals(2, fileProvider.listFiles("/").size()); // 1 for the
																	// config
																	// file & 1
																	// data file
		EncFSFile encFsFile = volume.getFile("/test.txt");
		Assert.assertNotNull(encFsFile);
		Assert.assertEquals("test.txt", encFsFile.getName());
		Assert.assertEquals("/test.txt", encFsFile.getPath());
		Assert.assertTrue(encFsFile.getLength() > 0);
		long contentsLength = encFsFile.getLength();

		// Check that it's name is encrypted
		List<EncFSFileInfo> fileList = fileProvider.listFiles("/");
		Assert.assertEquals(".encfs6.xml", fileList.get(0).getName());
		Assert.assertFalse(fileList.get(1).getName().equals("test.txt"));

		String encFileName = fileList.get(1).getName();

		// Now rename / move the file
		boolean moveResult = volume.movePath(encFsFile.getPath(), "/test2.txt");
		Assert.assertTrue(moveResult);

		// Check that the file name has changed
		List<EncFSFileInfo> fileList2 = fileProvider.listFiles("/");
		Assert.assertEquals(".encfs6.xml", fileList2.get(0).getName());
		Assert.assertFalse(fileList2.get(1).getName().equals("test.txt"));
		Assert.assertFalse(fileList2.get(1).getName().equals(encFileName));

		// Try re-moving the original file (should fail as we just moved it)
		boolean moveResult2 = volume
				.movePath(encFsFile.getPath(), "/test3.txt");
		Assert.assertFalse(moveResult2);

		// now get the proper file (that we moved the orig to)
		encFsFile = volume.getFile("/test2.txt");
		Assert.assertEquals("test2.txt", encFsFile.getName());
		Assert.assertEquals("/test2.txt", encFsFile.getPath());

		// Try moving to a non-existant directory
		boolean moveResult3 = volume.movePath(encFsFile.getPath(),
				"/dir1/t.txt");
		Assert.assertFalse(moveResult3);

		// Make dir1
		boolean mkdirResult = volume.makeDir("/dir1");
		Assert.assertTrue(mkdirResult);

		// Check the dir got created
		EncFSFile[] volumeFileList = volume.listFilesForPath("/");
		Assert.assertEquals(2, volumeFileList.length);
		Assert.assertEquals(false, volumeFileList[0].isDirectory());
		Assert.assertEquals(true, volumeFileList[1].isDirectory());

		// Try to make the same dir again (it should fail)
		boolean mkdirResult2 = volume.makeDir("/dir1");
		Assert.assertFalse(mkdirResult2);

		// Try to make a dir where the parent doesn't exist (it should fail)
		boolean mkdirResult3 = volume.makeDir("/dir2/def");
		Assert.assertFalse(mkdirResult3);

		// Move the file we created in to this sub directory
		boolean moveToDirResult = volume.movePath(encFsFile.getPath(),
				"/dir1/test.txt");
		Assert.assertTrue(moveToDirResult);
		encFsFile = volume.getFile("/dir1/test.txt");
		Assert.assertEquals("test.txt", encFsFile.getName());
		Assert.assertEquals("/dir1/test.txt", encFsFile.getPath());
		Assert.assertEquals(contentsLength, encFsFile.getLength());

		// Check the file was moved
		Assert.assertEquals(1, volume.listFilesForPath("/").length);
		Assert.assertEquals("dir1", volume.listFilesForPath("/")[0].getName());
		Assert.assertEquals(1, volume.listFilesForPath("/dir1").length);
		Assert.assertEquals("test.txt",
				volume.listFilesForPath("/dir1")[0].getName());

		// Now do a copy to a new nested directory
		boolean mkdirsResult = volume.makeDirs("/dir2/dir3");
		Assert.assertTrue(mkdirsResult);
		boolean copyResult = volume.copyPath("/dir1/test.txt", "/dir2/dir3");
		Assert.assertTrue(copyResult);
		Assert.assertEquals("test.txt",
				volume.listFilesForPath("/dir1")[0].getName());
		Assert.assertEquals("test.txt",
				volume.listFilesForPath("/dir2/dir3")[0].getName());
		Assert.assertEquals(contentsLength, volume.getFile("/dir1/test.txt")
				.getLength());
		Assert.assertEquals(contentsLength,
				volume.getFile("/dir2/dir3/test.txt").getLength());

		// Try to delete the src dir (should fail as it has files)
		boolean deleteDirResult = volume.deletePath("/dir1", false);
		Assert.assertFalse(deleteDirResult);

		// Delete the src file
		boolean deleteFileResult = volume.deletePath("/dir1/test.txt", false);
		Assert.assertTrue(deleteFileResult);

		// Check the file has been removed
		Assert.assertEquals(2, volume.listFilesForPath("/").length);
		Assert.assertEquals("dir1", volume.listFilesForPath("/")[0].getName());
		Assert.assertEquals("dir2", volume.listFilesForPath("/")[1].getName());
		Assert.assertEquals(0, volume.listFilesForPath("/dir1").length);
		Assert.assertEquals(1, volume.listFilesForPath("/dir2").length);
		Assert.assertEquals(1, volume.listFilesForPath("/dir2/dir3").length);
		Assert.assertEquals("test.txt",
				volume.listFilesForPath("/dir2/dir3")[0].getName());

		// now delete the empty directory
		boolean deleteEmptyDirResult = volume.deletePath("/dir1", false);
		Assert.assertTrue(deleteEmptyDirResult);

		// recreate the directory
		mkdirResult = volume.makeDir("/dir1");
		Assert.assertTrue(mkdirResult);

		// Copy the file back under it
		copyResult = volume.copyPath("/dir2/dir3/test.txt", "/dir1");
		Assert.assertTrue(copyResult);

		// Create a few more directories to test recursive deletion
		mkdirsResult = volume.makeDirs("/dir1/dir4/dir5/dir6/dir7");
		Assert.assertTrue(mkdirsResult);

		// Attempt to recursively delete the directory - should succeed
		boolean deleteRecursiveResult = volume.deletePath("/dir1", true);
		Assert.assertTrue(deleteRecursiveResult);

		// Check the directory has been removed
		Assert.assertEquals(1, volume.listFilesForPath("/").length);
		Assert.assertEquals("dir2", volume.listFilesForPath("/")[0].getName());
		Assert.assertEquals(1, volume.listFilesForPath("/dir2").length);
		Assert.assertEquals(1, volume.listFilesForPath("/dir2/dir3").length);
		Assert.assertEquals("test.txt",
				volume.listFilesForPath("/dir2/dir3")[0].getName());

		// Read the contents of the file to check that it's been copied / moved
		// around OK
		InputStream is = volume.openInputStreamForPath("/dir2/dir3/test.txt");
		try {
			StringBuffer sb = new StringBuffer();
			int bytesRead = 0;
			while (bytesRead >= 0) {
				byte[] readBuf = new byte[128];
				bytesRead = is.read(readBuf);
				if (bytesRead > 0) {
					sb.append(new String(readBuf, 0, bytesRead));
				}
			}

			String readContents = sb.toString();
			Assert.assertEquals("hello\nworld", readContents);
		} finally {
			is.close();
		}

	}
}
