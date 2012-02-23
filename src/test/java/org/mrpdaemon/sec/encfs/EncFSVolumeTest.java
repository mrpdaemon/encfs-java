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
	public void testNoExistingConfigFile() throws EncFSInvalidPasswordException, EncFSCorruptDataException,
			EncFSUnsupportedException, IOException {
		try {
			@SuppressWarnings("unused")
			EncFSVolume v = new EncFSVolume(fileProvider, new byte[] {});
		} catch (EncFSInvalidConfigException e) {
			Assert.assertEquals("No EncFS configuration file found", e.getMessage());
		}
	}

	@Test
	public void testVolumeCreation() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException {
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
	public void testFileOperations() throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, IOException, EncFSChecksumException {
		EncFSConfig config = new EncFSConfig();

		EncFSVolume volume = null;
		try {
			EncFSVolume.createVolume(fileProvider, config, password);
			volume = new EncFSVolume(fileProvider, config, password);
		} catch (Exception e) {
			Assert.fail(e.getMessage());
		}

		// Create a file
		Assert.assertFalse(volume.exists("/test.txt"));
		Assert.assertEquals(0, volume.listFiles("/").length);
		EncFSFile outFile = volume.createEncFSFile("/test.txt");
		OutputStream os = outFile.openOutputStream();
					try {
			os.write("hello\nworld".getBytes());
			} finally {
			os.close();
		}

		// Check the file got created
		Assert.assertEquals(1, volume.listFiles("/").length);
		Assert.assertEquals(2, fileProvider.listFiles("/").size()); // 1 for the
																	// config
																	// file & 1
																	// data file
		EncFSFile encFsFile = volume.getEncFSFile("/test.txt");
		Assert.assertNotNull(encFsFile);
		Assert.assertEquals("test.txt", encFsFile.getName());
		Assert.assertEquals("/test.txt", encFsFile.getAbsoluteName());
		Assert.assertTrue(encFsFile.getContentsLength() > 0);
		long contentsLength = encFsFile.getContentsLength();

		// Check that it's name is encrypted
		List<EncFSFileInfo> fileList = fileProvider.listFiles("/");
		Assert.assertEquals(".encfs6.xml", fileList.get(0).getName());
		Assert.assertFalse(fileList.get(1).getName().equals("test.txt"));

		String encFileName = fileList.get(1).getName();

		// Now rename / move the file

		boolean moveResult = encFsFile.renameTo("/test2.txt");
		Assert.assertTrue(moveResult);

		// Check that the file name has changed
		List<EncFSFileInfo> fileList2 = fileProvider.listFiles("/");
		Assert.assertEquals(".encfs6.xml", fileList2.get(0).getName());
		Assert.assertFalse(fileList2.get(1).getName().equals("test.txt"));
		Assert.assertFalse(fileList2.get(1).getName().equals(encFileName));

		// Try re-moving the original file (should fail as we just moved it)
		boolean moveResult2 = encFsFile.renameTo("/test3.txt");
		Assert.assertFalse(moveResult2);

		// now get the proper file (that we moved the orig to)
		encFsFile = volume.getEncFSFile("/test2.txt");
		Assert.assertEquals("test2.txt", encFsFile.getName());
		Assert.assertEquals("/test2.txt", encFsFile.getAbsoluteName());

		// Try moving to a non-existant directory
		boolean moveResult3 = encFsFile.renameTo("/dir1/t.txt");
		Assert.assertFalse(moveResult3);

		// Make dir1
		boolean mkdirResult = volume.makeDir("/dir1");
		Assert.assertTrue(mkdirResult);

		// Check the dir got created
		EncFSFile[] volumeFileList = volume.listFiles("/");
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
		boolean moveToDirResult = encFsFile.renameTo("/dir1/test.txt");
		Assert.assertTrue(moveToDirResult);
		encFsFile = volume.getEncFSFile("/dir1/test.txt");
		Assert.assertEquals("test.txt", encFsFile.getName());
		Assert.assertEquals("/dir1/test.txt", encFsFile.getAbsoluteName());
		Assert.assertEquals(contentsLength, encFsFile.getContentsLength());

		// Check the file was moved
		Assert.assertEquals(1, volume.listFiles("/").length);
		Assert.assertEquals("dir1", volume.listFiles("/")[0].getName());
		Assert.assertEquals(1, volume.listFiles("/dir1").length);
		Assert.assertEquals("test.txt", volume.listFiles("/dir1")[0].getName());

		// Now do a copy to a new nested directory
		boolean mkdirsResult = volume.makeDirs("/dir2/dir3");
		Assert.assertTrue(mkdirsResult);
		boolean copyResult = volume.copy("/dir1/test.txt", "/dir2/dir3");
		Assert.assertTrue(copyResult);
		Assert.assertEquals("test.txt", volume.listFiles("/dir1")[0].getName());
		Assert.assertEquals("test.txt", volume.listFiles("/dir2/dir3")[0].getName());
		Assert.assertEquals(contentsLength, volume.getEncFSFile("/dir1/test.txt").getContentsLength());
		Assert.assertEquals(contentsLength, volume.getEncFSFile("/dir2/dir3/test.txt").getContentsLength());

		// Try to delete the src dir (should fail as it has files)
		boolean deleteDirResult = volume.delete("/dir1");
		Assert.assertFalse(deleteDirResult);

		// Delete the src file
		boolean deleteFileResult = volume.delete("/dir1/test.txt");
		Assert.assertTrue(deleteFileResult);

		// Check the file has been removed
		Assert.assertEquals(2, volume.listFiles("/").length);
		Assert.assertEquals("dir1", volume.listFiles("/")[0].getName());
		Assert.assertEquals("dir2", volume.listFiles("/")[1].getName());
		Assert.assertEquals(0, volume.listFiles("/dir1").length);
		Assert.assertEquals(1, volume.listFiles("/dir2").length);
		Assert.assertEquals(1, volume.listFiles("/dir2/dir3").length);
		Assert.assertEquals("test.txt", volume.listFiles("/dir2/dir3")[0].getName());

		// now delete the empty directory
		boolean deleteEmptyDirResult = volume.delete("/dir1");
		Assert.assertTrue(deleteEmptyDirResult);

		// Check the directory has been removed
		Assert.assertEquals(1, volume.listFiles("/").length);
		Assert.assertEquals("dir2", volume.listFiles("/")[0].getName());
		Assert.assertEquals(1, volume.listFiles("/dir2").length);
		Assert.assertEquals(1, volume.listFiles("/dir2/dir3").length);
		Assert.assertEquals("test.txt", volume.listFiles("/dir2/dir3")[0].getName());

		// Read the contents of the file to check that it's been copied / moved
		// around OK
		InputStream is = volume.openInputStream("/dir2/dir3/test.txt");
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
