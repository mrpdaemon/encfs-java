package org.mrpdaemon.sec.encfs.tests;

import org.junit.After;
import org.junit.Before;
import org.mrpdaemon.sec.encfs.tests.vfs.CommonsVFSRamFileProvider;

public class EncFSVolumeVFSTest extends EncFSVolumeTest {

	@Before
	public void setUp() throws Exception {
		CommonsVFSRamFileProvider fileProvider = new CommonsVFSRamFileProvider();
		fileProvider.init();
		setFileProvider(fileProvider);
	}

	@After
	public void tearDown() throws Exception {
		((CommonsVFSRamFileProvider) getFileProvider()).close();
	}
}
