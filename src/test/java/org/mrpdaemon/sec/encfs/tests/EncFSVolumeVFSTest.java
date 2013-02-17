package org.mrpdaemon.sec.encfs.tests;

import junit.framework.Assert;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mrpdaemon.sec.encfs.*;
import org.mrpdaemon.sec.encfs.tests.vfs.CommonsVFSRamFileProvider;

import java.io.IOException;

public class EncFSVolumeVFSTest {

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
      EncFSVolume v = new EncFSVolume(fileProvider, new byte[]{});
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

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    Assert.assertNotNull(volume);

    Assert.assertEquals(1,
        fileProvider.listFiles(fileProvider.getRootPath()).size());
    Assert.assertTrue(fileProvider.exists("/.encfs6.xml"));
  }

  // Default volume
  @Test
  public void testDefaultVolume() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // No Unique IV
  @Test
  public void testNoUniqueIV() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setUniqueIV(false);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // No chained name IV
  @Test
  public void testNoChainedIV() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setChainedNameIV(false);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // No unique IV OR chained name IV
  @Test
  public void testNoUniqueOrChainedIV() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setChainedNameIV(false);
    config.setUniqueIV(false);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // No zero block passthrough
  @Test
  public void testNoHoles() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setHolesAllowed(false);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // 256 bit volume key
  @Test
  public void test256BitKey() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setVolumeKeySize(256);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // 128 bit volume key
  @Test
  public void test128BitKey() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setVolumeKeySize(128);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // 4096 byte block size
  @Test
  public void test4096ByteBlocks() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setBlockSize(4096);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // Stream name algorithm
  @Test
  public void testStreamNameAlg() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setNameAlgorithm(EncFSConfig.ENCFS_CONFIG_NAME_ALG_STREAM);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // Block level MAC header with no random bytes
  @Test
  public void testBlockMAC() throws EncFSInvalidPasswordException,
      EncFSInvalidConfigException, EncFSCorruptDataException,
      EncFSUnsupportedException, IOException, EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setBlockMACBytes(8);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }

  // Block level MAC header with random bytes
  @Test
  public void testBlockMACWithRandBytes()
      throws EncFSInvalidPasswordException, EncFSInvalidConfigException,
      EncFSCorruptDataException, EncFSUnsupportedException, IOException,
      EncFSChecksumException {
    EncFSConfig config = new EncFSConfig();
    config.setBlockMACBytes(8);
    config.setBlockMACRandBytes(8);

    EncFSVolume volume = EncFSVolumeTestCommon.createVolume(config,
        fileProvider);

    EncFSVolumeTestCommon.testFileOperations(volume);
  }
}
