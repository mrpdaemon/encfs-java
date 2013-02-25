package org.mrpdaemon.sec.encfs.tests;

import junit.framework.Assert;
import org.mrpdaemon.sec.encfs.*;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.util.*;

class EncFSVolumeTestCommon {
	private final static String password = "testPassword";

	public static File createTempDir() throws IOException {
		File temp;

		temp = File.createTempFile("encfs-java-tmp",
				Long.toString(System.nanoTime()));
		if (!temp.delete()) {
			throw new IOException("Could not delete temporary file "
					+ temp.getAbsolutePath());
		}

		if (!temp.mkdir()) {
			throw new IOException("Could not create temporary directory");
		}

		return temp;
	}

	public static EncFSVolume createVolume(EncFSConfig config,
			EncFSFileProvider fileProvider) throws Exception {
		try {
			new EncFSVolumeBuilder().withFileProvider(fileProvider)
					.withConfig(config).withPassword(password)
					.writeVolumeConfig();
			// EncFSVolume.createVolume(fileProvider, config, password);
			return new EncFSVolumeBuilder().withFileProvider(fileProvider)
					.withConfig(config).withPassword(password).buildVolume();
		} catch (Exception e) {
			Assert.fail(e.getMessage());
			throw e;
		}
	}

	private static class EncFSFileInfoComparator implements
			Comparator<EncFSFileInfo> {
		@Override
		public int compare(EncFSFileInfo info1, EncFSFileInfo info2) {
			return info1.getName().compareTo(info2.getName());
		}
	}

	private static class EncFSFileComparator implements Comparator<EncFSFile> {
		@Override
		public int compare(EncFSFile file1, EncFSFile file2) {
			return file1.getName().compareTo(file2.getName());
		}
	}

	public static void testFileOperations(EncFSVolume volume)
			throws EncFSCorruptDataException, EncFSUnsupportedException,
			IOException {
		// Create a file
		Assert.assertFalse(volume.pathExists("/test.txt"));
		Assert.assertEquals(0,
				volume.listFilesForPath(EncFSVolume.ROOT_PATH).length);
		EncFSFile outFile = volume.createFile("/test.txt");
		EncFSOutputStream os = outFile.openOutputStream(11);
		try {
			os.write("hello\nworld".getBytes());
		} finally {
			os.close();
		}

		// Check the file got created
		Assert.assertEquals(1,
				volume.listFilesForPath(EncFSVolume.ROOT_PATH).length);
		Assert.assertEquals(
				2,
				volume.getFileProvider()
						.listFiles(
								volume.getFileProvider()
										.getFilesystemRootPath()).size()); // 1
		// for
		// the
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
		List<EncFSFileInfo> fileList = volume.getFileProvider().listFiles(
				volume.getFileProvider().getFilesystemRootPath());
		Collections.sort(fileList, new EncFSFileInfoComparator());
		if (fileList.get(0).getName().equals(EncFSVolume.CONFIG_FILE_NAME)) {
			Assert.assertFalse(fileList.get(1).getName().equals("test.txt"));
		} else {
			Assert.assertEquals(EncFSVolume.CONFIG_FILE_NAME, fileList.get(1)
					.getName());
			Assert.assertFalse(fileList.get(1).getName().equals("test.txt"));
		}

		String encFileName = fileList.get(1).getName();

		// Now rename / move the file
		boolean moveResult = volume.movePath(encFsFile.getPath(), "/test2.txt");
		Assert.assertTrue(moveResult);

		// Check that the file name has changed
		List<EncFSFileInfo> fileList2 = volume.getFileProvider().listFiles(
				volume.getFileProvider().getFilesystemRootPath());
		Collections.sort(fileList2, new EncFSFileInfoComparator());
		if (fileList2.get(0).getName().equals(EncFSVolume.CONFIG_FILE_NAME)) {
			// File at index 1 must have changed
			Assert.assertFalse(fileList2.get(1).getName().equals("test.txt"));
			Assert.assertFalse(fileList2.get(1).getName().equals(encFileName));
		} else {
			Assert.assertEquals(EncFSVolume.CONFIG_FILE_NAME, fileList2.get(1)
					.getName());
			// File at index 0 must have changed
			Assert.assertFalse(fileList2.get(0).getName().equals("test.txt"));
			Assert.assertFalse(fileList2.get(0).getName().equals(encFileName));
		}

		// Try re-moving the original file (should fail as we just moved it)
		try {
			boolean moveResult2 = volume.movePath(encFsFile.getPath(),
					"/test3.txt");
			Assert.assertFalse(moveResult2);
		} catch (FileNotFoundException e) {
			// Some file providers throw exceptions instead of returning false
		}

		// now get the proper file (that we moved the orig to)
		encFsFile = volume.getFile("/test2.txt");
		Assert.assertEquals("test2.txt", encFsFile.getName());
		Assert.assertEquals("/test2.txt", encFsFile.getPath());

		// Try moving to a non-existant directory
		try {
			boolean moveResult3 = volume.movePath(encFsFile.getPath(),
					"/dir1/t.txt");
			Assert.assertFalse(moveResult3);
		} catch (FileNotFoundException e) {
			// Some file providers throw exceptions instead of returning false
		}

		// Make dir1
		boolean mkdirResult = volume.makeDir("/dir1");
		Assert.assertTrue(mkdirResult);

		// Check the dir got created
		ArrayList<EncFSFile> volumeFileList = new ArrayList<EncFSFile>(
				Arrays.asList(volume.listFilesForPath(EncFSVolume.ROOT_PATH)));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals(2, volumeFileList.size());
		Assert.assertEquals(true, volumeFileList.get(0).isDirectory());
		Assert.assertEquals(false, volumeFileList.get(1).isDirectory());

		// Try to make the same dir again (it should fail)
		try {
			boolean mkdirResult2 = volume.makeDir("/dir1");
			Assert.assertFalse(mkdirResult2);
		} catch (FileNotFoundException e) {
			// Some file providers throw exceptions instead of returning false
		}

		// Try to make a dir where the parent doesn't exist (it should fail)
		try {
			boolean mkdirResult3 = volume.makeDir("/dir2/def");
			Assert.assertFalse(mkdirResult3);
		} catch (FileNotFoundException e) {
			// Some file providers throw exceptions instead of returning false
		}

		// Move the file we created in to this sub directory
		boolean moveToDirResult = volume.movePath(encFsFile.getPath(),
				"/dir1/test.txt");
		Assert.assertTrue(moveToDirResult);
		encFsFile = volume.getFile("/dir1/test.txt");
		Assert.assertEquals("test.txt", encFsFile.getName());
		Assert.assertEquals("/dir1/test.txt", encFsFile.getPath());
		Assert.assertEquals(contentsLength, encFsFile.getLength());

		// Check the file was moved
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath(EncFSVolume.ROOT_PATH)));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals(1, volumeFileList.size());
		Assert.assertEquals("dir1", volumeFileList.get(0).getName());
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath("/dir1")));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals(1, volumeFileList.size());
		Assert.assertEquals("test.txt", volumeFileList.get(0).getName());

		// Now do a copy to a new nested directory
		boolean mkdirsResult = volume.makeDirs("/dir2/dir3");
		Assert.assertTrue(mkdirsResult);
		boolean copyResult = volume.copyPath("/dir1/test.txt", "/dir2/dir3");
		Assert.assertTrue(copyResult);
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath("/dir1")));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals("test.txt", volumeFileList.get(0).getName());
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath("/dir2/dir3")));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals("test.txt", volumeFileList.get(0).getName());
		Assert.assertEquals(contentsLength, volume.getFile("/dir1/test.txt")
				.getLength());
		Assert.assertEquals(contentsLength,
				volume.getFile("/dir2/dir3/test.txt").getLength());

		// Try to recursively copy a directory
		boolean recursiveCopyResult = volume.copyPath("/dir1", "/dir2");
		Assert.assertTrue(recursiveCopyResult);
		recursiveCopyResult = volume.pathExists("/dir2/dir1");
		Assert.assertTrue(recursiveCopyResult);
		recursiveCopyResult = volume.pathExists("/dir2/dir1/test.txt");
		Assert.assertTrue(recursiveCopyResult);
		// Delete the recursively copied directory
		recursiveCopyResult = volume.deletePath("/dir2/dir1", true);
		Assert.assertTrue(recursiveCopyResult);

		// Delete the src file
		boolean deleteFileResult = volume.deletePath("/dir1/test.txt", false);
		Assert.assertTrue(deleteFileResult);

		// Check the file has been removed
		Assert.assertEquals(2,
				volume.listFilesForPath(EncFSVolume.ROOT_PATH).length);
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath(EncFSVolume.ROOT_PATH)));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals("dir1", volumeFileList.get(0).getName());
		Assert.assertEquals("dir2", volumeFileList.get(1).getName());
		Assert.assertEquals(0, volume.listFilesForPath("/dir1").length);
		Assert.assertEquals(1, volume.listFilesForPath("/dir2").length);
		Assert.assertEquals(1, volume.listFilesForPath("/dir2/dir3").length);
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath("/dir2/dir3")));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals("test.txt", volumeFileList.get(0).getName());

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
		Assert.assertEquals(1,
				volume.listFilesForPath(EncFSVolume.ROOT_PATH).length);
		Assert.assertEquals("dir2",
				volume.listFilesForPath(EncFSVolume.ROOT_PATH)[0].getName());
		Assert.assertEquals(1, volume.listFilesForPath("/dir2").length);
		Assert.assertEquals(1, volume.listFilesForPath("/dir2/dir3").length);
		volumeFileList = new ArrayList<EncFSFile>(Arrays.asList(volume
				.listFilesForPath("/dir2/dir3")));
		Collections.sort(volumeFileList, new EncFSFileComparator());
		Assert.assertEquals("test.txt", volumeFileList.get(0).getName());

		// Read the contents of the file to check that it's been copied / moved
		// around OK
		InputStream is = volume.openInputStreamForPath("/dir2/dir3/test.txt");
		try {
			StringBuilder sb = new StringBuilder();
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
