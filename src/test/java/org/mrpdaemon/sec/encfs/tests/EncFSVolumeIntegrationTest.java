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

package org.mrpdaemon.sec.encfs.tests;

import org.junit.Assert;
import org.junit.Test;
import org.mrpdaemon.sec.encfs.*;

import java.io.*;

import static org.junit.Assert.*;
import static org.mrpdaemon.sec.encfs.EncFSCrypto.decodeName;
import static org.mrpdaemon.sec.encfs.EncFSCrypto.encodeName;

public class EncFSVolumeIntegrationTest {

  @Test
  public void testIsEncFSVolume() throws Exception {
    assertTrue(EncFSVolume.isEncFSVolume("test/encfs_samples/boxcryptor_1"));
    Assert.assertFalse(EncFSVolume.isEncFSVolume("test/encfs_samples"));
  }

  @Test
  public void testBoxCryptor_1_badPassword() throws Exception {
    File encFSDir = assertFileExists("test/encfs_samples/boxcryptor_1");

    try {
      new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword("badPassword").access();
      fail();
    } catch (EncFSInvalidPasswordException e) {
    /* this is correct that we should have got this exception */
      assertNotNull(e);
    }
  }

  private File assertFileExists(String s) {
    File file = new File(s);
    assertTrue(file.exists());
    return file;
  }

  @Test
  public void testDefaultVol() throws Exception {
    File encFSDir = new File("test/encfs_samples/testvol-default");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(3, files.length);
    String contents;
    int numMatches = 0;
    for (EncFSFile encFSFile : files) {
      if (encFSFile.getName().equals("longfile.txt")) {
        numMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        contents = readInputStreamAsString(encFSFile);
        assertEquals(contents.length(), 6000);
        for (int i = 0; i < contents.length(); i++) {
          assertTrue(contents.charAt(i) == 'a');
        }
      } else if (encFSFile.getName().equals("zerofile.bin")) {
        numMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        byte zeroBytes[] = readInputStreamAsByteArray(encFSFile);
        assertEquals(zeroBytes.length, 10000);
        for (int i = 0; i < zeroBytes.length; i++) {
          assertTrue(zeroBytes[i] == 0);
        }
      } else if (encFSFile.getName().equals("test.txt")) {
        numMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        contents = readInputStreamAsString(encFSFile);
        assertEquals("This is a test file.\n", contents);
      }
    }
    assertEquals(numMatches, 3);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testNoUniqueIV() throws Exception {
    File encFSDir = new File("test/encfs_samples/testvol-nouniqueiv");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(2, files.length);
    String contents;
    int numMatches = 0;
    for (EncFSFile encFSFile : files) {
      if (encFSFile.getName().equals("longfile.txt")) {
        numMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        contents = readInputStreamAsString(encFSFile);
        assertEquals(contents.length(), 6000);
        for (int i = 0; i < contents.length(); i++) {
          assertTrue(contents.charAt(i) == 'a');
        }
      } else if (encFSFile.getName().equals("testfile.txt")) {
        numMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        assertEquals("testfile.txt", encFSFile.getName());
        contents = readInputStreamAsString(encFSFile);
        assertEquals("Test file for non-unique-IV file.\n", contents);
      }
    }
    assertEquals(numMatches, 2);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testStreamName() throws Exception {
    File encFSDir = new File("test/encfs_samples/testvol-streamname");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(1, files.length);
    EncFSFile dir = files[0];
    assertTrue(dir.isDirectory());
    assertEquals("dir", dir.getName());
    EncFSFile[] dirFiles = dir.listFiles();
    assertEquals(1, files.length);
    EncFSFile encFSFile = dirFiles[0];
    Assert.assertFalse(encFSFile.isDirectory());
    assertEquals("testfile.txt", encFSFile.getName());
    String contents = readInputStreamAsString(encFSFile);
    assertEquals("stream name algorithm\n", contents);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testBlockMAC() throws Exception {
    File encFSDir = new File("test/encfs_samples/testvol-blockmac");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(1, files.length);
    EncFSFile encFSFile = files[0];
    Assert.assertFalse(encFSFile.isDirectory());
    assertEquals("longfile.txt", encFSFile.getName());
    String contents = readInputStreamAsString(encFSFile);
    assertEquals(contents.length(), 6000);
    for (int i = 0; i < contents.length(); i++) {
      assertTrue(contents.charAt(i) == 'a');
    }
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testExtIvChain() throws Exception {
    File encFSDir = new File("test/encfs_samples/testvol-extivchn");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(2, files.length);
    String contents;
    int numOuterMatches = 0, numInnerMatches = 0;
    for (EncFSFile encFSFile : files) {
      if (encFSFile.getName().equals("test.txt")) {
        numOuterMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        contents = readInputStreamAsString(encFSFile);
        assertEquals("this is a test file with external IV chaining", contents);
      } else if (encFSFile.getName().equals("directory")) {
        numOuterMatches++;
        assertTrue(encFSFile.isDirectory());        /* Traverse down the directory */
        for (EncFSFile subFile : encFSFile.listFiles()) {
          numInnerMatches++;
          assertEquals(subFile.getName(), "another-test-file.txt");
          contents = readInputStreamAsString(subFile);
          assertEquals("this is another test file with external IV chaining", contents);
        }
      }
    }
    assertEquals(numOuterMatches, 2);
    assertEquals(numInnerMatches, 1);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testBoxCryptor_1() throws Exception {
    File encFSDir = new File("test/encfs_samples/boxcryptor_1");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(1, files.length);
    EncFSFile encFSFile = files[0];
    Assert.assertFalse(encFSFile.isDirectory());
    assertEquals("testfile.txt", encFSFile.getName());
    String contents = readInputStreamAsString(encFSFile);
    assertEquals("test file\r\n", contents);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testBoxCryptor_2() throws Exception {
    File encFSDir = new File("test/encfs_samples/boxcryptor_2");
    assertTrue(encFSDir.exists());
    String password = "test2";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(2, files.length);
    String contents;
    int numMatches = 0;
    for (EncFSFile encFSFile : files) {
      if (encFSFile.getName().equals("file1.txt")) {
        numMatches++;
        Assert.assertFalse(encFSFile.isDirectory());
        contents = readInputStreamAsString(encFSFile);
        assertEquals("Some contents for file1", contents);
      } else if (encFSFile.getName().equals("Dir1")) {
        numMatches++;
        assertTrue(encFSFile.isDirectory());
        EncFSFile[] subFiles = encFSFile.listFiles();
        assertEquals(subFiles.length, 1);
        assertEquals(subFiles[0].getName(), "file2.txt");
      }
    }
    assertEquals(numMatches, 2);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testBoxCryptor_3() throws Exception {
    File encFSDir = new File("test/encfs_samples/boxcryptor_3");
    assertTrue(encFSDir.exists());
    String password = "test";
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword(password).access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(1, files.length);
    String dirListing = getDirListing(rootDir, true);
    assertNotNull(dirListing);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void testBoxCryptor_null() throws Exception {
    File encFSDir = new File("test/encfs_samples/boxcryptor_null");
    assertTrue(encFSDir.exists());
    EncFSVolume volume = new EncFSVolumeBuilder().withRootPath(encFSDir.getAbsolutePath()).withPassword("test").access();
    EncFSFile rootDir = volume.getRootDir();
    EncFSFile[] files = rootDir.listFiles();
    assertEquals(1, files.length);
    EncFSFile encFSFile = files[0];
    Assert.assertFalse(encFSFile.isDirectory());
    assertEquals("testfile.txt", encFSFile.getName());
    String contents = readInputStreamAsString(encFSFile);
    assertEquals("Contents for test fileAlpha.txt", contents);
    assertFileNameEncoding(rootDir);
    assertEncFSFileRoundTrip(rootDir);
    assertLengthCalculations(rootDir);
  }

  @Test
  public void createVolume_1() throws Exception {
    File rootDir = EncFSVolumeTestCommon.createTempDir();

    EncFSConfig config = EncFSConfigFactory.createDefault();
    String password = "test";
    EncFSLocalFileProvider fileProvider = new EncFSLocalFileProvider(rootDir);
    try {
      EncFSVolume.createVolume(fileProvider, config, password);
      new EncFSVolumeBuilder().withFileProvider(fileProvider).withConfig(config).withPassword(password).access();
    } catch (Exception e) {
      fail(e.getMessage());
    }
    /* Clean up after ourselves */
    File configFile = new File(rootDir.getAbsolutePath(), EncFSVolume.CONFIG_FILE_NAME);

    assertTrue(configFile.delete());
    assertTrue(rootDir.delete());
  }

  private void assertFileNameEncoding(EncFSFile encfsFileDir) throws Exception {
    for (EncFSFile encfFile : encfsFileDir.listFiles()) {
      EncFSVolume volume = encfsFileDir.getVolume();
      String decName = decodeName(volume, encfFile.getEncrytedName(), encfFile.getParentPath());
      assertEquals(encfFile.getPath() + " decoded file name", encfFile.getName(), decName);
      String encName = encodeName(volume, decName, encfFile.getParentPath());
      assertEquals(encfFile.getPath() + " re-encoded file name", encfFile.getEncrytedName(), encName);
      if (encfFile.isDirectory()) {
        assertFileNameEncoding(encfFile);
      }
    }
  }

  private void assertEncFSFileRoundTrip(EncFSFile encFsFile) throws Exception {
    if (encFsFile.isDirectory() == false) {      /* Copy the file via input/output streams & then check that       the file is the same */
      File t = File.createTempFile(this.getClass().getName(), ".tmp");
      try {
        EncFSUtil.copyWholeStream(new EncFSFileInputStream(encFsFile), new EncFSOutputStream(encFsFile.getVolume(), new BufferedOutputStream(new FileOutputStream(t)), encFsFile.getPath()), true, true);
        if (encFsFile.getVolume().getVolumeConfiguration().isUseUniqueIV() == false) {
          FileInputStream reEncFSIs = new FileInputStream(t);
          try {
            InputStream origEncFSIs = encFsFile.getVolume().getFileProvider().openInputStream(encFsFile.getEncryptedPath());
            try {
              assertInputStreamsAreEqual(encFsFile.getPath(), origEncFSIs, reEncFSIs);
            } finally {
              origEncFSIs.close();
            }
          } finally {
            reEncFSIs.close();
          }
        } else {
          EncFSFileInputStream efis = new EncFSFileInputStream(encFsFile);
          try {
            EncFSInputStream efisCopy = new EncFSInputStream(encFsFile.getVolume(), new FileInputStream(t), encFsFile.getPath());
            try {
              assertInputStreamsAreEqual(encFsFile.getPath(), efis, efisCopy);
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

  private void assertLengthCalculations(EncFSFile encFsFile) throws Exception {
    if (encFsFile.isDirectory() == false) {
      long encryptedSize = encFsFile.getVolume().getFileProvider().getFileInfo(encFsFile.getEncryptedPath()).getSize();
      assertInputStreamLength((InputStream) encFsFile.openInputStream(), encFsFile.getVolume().getDecryptedFileLength(encryptedSize));
      assertEquals(encryptedSize, encFsFile.getVolume().getEncryptedFileLength(encFsFile.getLength()));
    } else {
      for (EncFSFile subEncfFile : encFsFile.listFiles()) {
        assertLengthCalculations(subEncfFile);
      }
    }
  }

  private void assertInputStreamsAreEqual(String msg, InputStream encfsIs, InputStream decFsIs) throws Exception {
    int bytesRead = 0, bytesRead2 = 0;
    while (bytesRead >= 0) {
      byte[] readBuf = new byte[128];
      byte[] readBuf2 = new byte[128];
      bytesRead = encfsIs.read(readBuf);
      bytesRead2 = decFsIs.read(readBuf2);
      assertEquals(msg, bytesRead, bytesRead2);
      Assert.assertArrayEquals(msg, readBuf, readBuf2);
    }
  }

  private void assertInputStreamLength(InputStream encfsIs, long length) throws Exception {
    int bytesRead = 0;
    long totalSize = 0;
    while (bytesRead >= 0) {
      totalSize += bytesRead;
      byte[] readBuf = new byte[128];
      bytesRead = encfsIs.read(readBuf);
    }
    assertEquals(totalSize, length);
  }

  private static String getDirListing(EncFSFile rootDir, boolean recursive) throws Exception {
    StringBuilder sb = new StringBuilder();
    getDirListing(rootDir, recursive, sb);
    return sb.toString();
  }

  private static void getDirListing(EncFSFile rootDir, boolean recursive, StringBuilder sb) throws Exception {
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

  public static byte[] readInputStreamAsByteArray(EncFSFile encFSFile) throws Exception {
    ByteArrayOutputStream buf = new ByteArrayOutputStream();
    EncFSUtil.copyWholeStream(new EncFSFileInputStream(encFSFile), buf, true, false);
    return buf.toByteArray();
  }

  public static String readInputStreamAsString(EncFSFile encFSFile) throws Exception {
    return new String(readInputStreamAsByteArray(encFSFile));
  }
}