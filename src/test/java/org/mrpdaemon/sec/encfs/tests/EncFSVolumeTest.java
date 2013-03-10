package org.mrpdaemon.sec.encfs.tests;

import junit.framework.Assert;
import org.junit.Test;
import org.mrpdaemon.sec.encfs.*;

public abstract class EncFSVolumeTest {
	private EncFSFileProvider fileProvider;

	void setFileProvider(EncFSFileProvider encFSFileProvider) {
		this.fileProvider = encFSFileProvider;
	}

	EncFSFileProvider getFileProvider() {
		return fileProvider;
	}

	@Test
	public void testNoExistingConfigFile() throws Exception {
		try {
			new EncFSVolumeBuilder().withFileProvider(fileProvider)
					.withDerivedKeyData(new byte[] {});
		} catch (EncFSInvalidConfigException e) {
			Assert.assertEquals("No EncFS configuration file found",
					e.getMessage());
		}
	}

	@Test
	public void testVolumeCreation() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();

		EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
				fileProvider);
		Assert.assertNotNull(volume);
		Assert.assertEquals(1,
				fileProvider.listFiles(fileProvider.getFilesystemRootPath())
						.size());
		Assert.assertTrue(fileProvider.exists(fileProvider
				.getFilesystemRootPath() + ".encfs6.xml"));
	}

	@Test
	public void testDefaultVolume() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();

		testFileOperations(config);
	}

	@Test
	public void testNoUniqueIV() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setUseUniqueIV(false);

		testFileOperations(config);
	}

	@Test
	public void testNoChainedIV() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setChainedNameIV(false);

		testFileOperations(config);
	}

	@Test
	public void testNoUniqueOrChainedIV() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setChainedNameIV(false);
		config.setUseUniqueIV(false);

		testFileOperations(config);
	}

	@Test
	public void testNoHolesWithZeroBlockPassThrough() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setHolesAllowedInFiles(false);

		testFileOperations(config);
	}

	@Test
	public void test256BitKey() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setVolumeKeySizeInBits(256);

		testFileOperations(config);
	}

	@Test
	public void test128BitKey() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setVolumeKeySizeInBits(128);

		testFileOperations(config);
	}

	@Test
	public void test4096ByteBlocks() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setEncryptedFileBlockSizeInBytes(4096);

		testFileOperations(config);
	}

	@Test
	public void testStreamNameAlg() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setFilenameAlgorithm(EncFSFilenameEncryptionAlgorithm.STREAM);

		testFileOperations(config);
	}

	@Test
	public void testBlockMAC() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setNumberOfMACBytesForEachFileBlock(8);

		testFileOperations(config);
	}

	@Test
	public void testBlockMACWithRandBytes() throws Exception {
		EncFSConfig config = EncFSConfigFactory.createDefault();
		config.setNumberOfMACBytesForEachFileBlock(8);
		config.setNumberOfRandomBytesInEachMACHeader(8);

		testFileOperations(config);
	}

	private void testFileOperations(EncFSConfig config) throws Exception {
		EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
				fileProvider);
		EncFSVolumeTestCommon.testFileOperations(volume);
	}
}
