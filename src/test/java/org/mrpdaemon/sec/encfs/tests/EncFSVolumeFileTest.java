package org.mrpdaemon.sec.encfs.tests;

import org.junit.After;
import org.junit.Before;
import org.mrpdaemon.sec.encfs.EncFSLocalFileProvider;

import java.io.File;

public class EncFSVolumeFileTest extends EncFSVolumeTest {

	private File tempDir;

	@Before
	public void setUp() throws Exception {
		tempDir = EncFSVolumeTestCommon.createTempDir();
		EncFSLocalFileProvider fileProvider = new EncFSLocalFileProvider(
				tempDir);
		setFileProvider(fileProvider);
	}

	private void recursiveDelete(File file) {
		if (file.isDirectory()) {
			for (File subFile : file.listFiles()) {
				recursiveDelete(subFile);
			}
		} else {
			file.delete();
		}
	}

	@After
	public void tearDown() throws Exception {
		recursiveDelete(tempDir);
	}

}
