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

import org.mrpdaemon.sec.encfs.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Arrays;
import java.util.Comparator;

/**
 * Simple tool that takes a raw encfs volume (& uses encfs-java to unencrypt it)
 * and compares it to a the same mounted encfs volume to check they are the
 * same.
 */
public class EncFSComparer {
	private static final Logger logger = LoggerFactory
			.getLogger(EncFSComparer.class);

	public static void main(String[] args) throws Exception {
		if (args == null || args.length != 3)
			throw new IllegalArgumentException("Missing required args");

		File rawEncFSVolume = new File(args[0]);
		String password = args[1];
		File decodedEncFSOutput = new File(args[2]);

		EncFSComparer encFSComparer = new EncFSComparer(rawEncFSVolume,
				password, decodedEncFSOutput);
		int result = encFSComparer.compare();
		System.exit(result);
	}

	private final File rawEncFSVolume;
	private final String password;
	private final File decodedEncFSOutput;

	private EncFSComparer(File rawEncFSVolume, String password,
			File decodedEncFSOutput) {
		this.rawEncFSVolume = rawEncFSVolume;
		this.password = password;
		this.decodedEncFSOutput = decodedEncFSOutput;
	}

	private int compare() throws EncFSInvalidPasswordException,
			EncFSInvalidConfigException, EncFSCorruptDataException,
			EncFSUnsupportedException, EncFSChecksumException, IOException {
		logger.info(
				"Performing compare between encfs raw volume at {} and output files at {}",
				rawEncFSVolume, decodedEncFSOutput);

		EncFSVolume volume = new EncFSVolumeBuilder()
				.withRootPath(rawEncFSVolume.getAbsolutePath())
				.withPassword(password).buildVolume();
		EncFSFile rootDir = volume.getRootDir();
		int result = compare(rootDir, decodedEncFSOutput);

		if (result == 0) {
			logger.info("All files / folders match");
		} else {
			logger.info("Errors between files / folders found");
		}

		return result;
	}

	private int compare(EncFSFile encFsDir, File decodedFsDir)
			throws EncFSUnsupportedException, IOException,
			EncFSCorruptDataException {
		logger.info("Comparing directory {}", decodedFsDir.getAbsoluteFile());

		EncFSFile[] encFsFiles = encFsDir.listFiles();
		File[] decodedFsFiles = decodedFsDir.listFiles();

		Arrays.sort(encFsFiles, SimpleEncFSFileComparator.getInstance());
		Arrays.sort(decodedFsFiles, SimpleFileComparator.getInstance());

		if (encFsFiles.length != decodedFsFiles.length) {
			logger.error("File count miss match in directory {}",
					decodedFsDir.getAbsoluteFile());
			return -1;
		} else {
			for (int i = 0; i < encFsFiles.length; i++) {
				EncFSFile encFsFile = encFsFiles[i];
				File decodedFsFile = decodedFsFiles[i];

				if (!encFsFile.getName().equals(decodedFsFile.getName())) {
					logger.error("File name miss match ({}, {}, {})",
							new Object[] { i, encFsFile.getName(),
									decodedFsFile.getName() });
					return -1;
				}

				String reEncEncfsName = EncFSCrypto.encodeName(
						encFsFile.getVolume(), encFsFile.getName(),
						encFsFile.getParentPath());
				String rawFileName = encFsFile.getEncrytedName();
				if (!rawFileName.equals(reEncEncfsName)) {
					logger.error("Re-encoded name miss match ({}, {}, {}, {})",
							new Object[] { i, encFsFile.getName(), rawFileName,
									reEncEncfsName });
					return -1;
				}

				if (encFsFile.getLastModified() != decodedFsFile.lastModified()) {
					logger.error("File {} lastModified miss match",
							decodedFsFile.getName());
					return -1;
				}

				if (encFsFile.getLength() != decodedFsFile.length()) {
					logger.error(
							"File {} size miss match ({}, {})",
							new Object[] { decodedFsFile.getName(),
									encFsFile.getLength(),
									decodedFsFile.length() });
					return -1;
				}

				if (decodedFsFile.isDirectory()) {
					int subResult = compare(encFsFile, decodedFsFile);
					if (subResult != 0) {
						return subResult;
					}
				} else {
					// Check that the EncFSFileInputStream reads the file the
					// same as
					// reading the file directly from the mounted encfs volume

					EncFSFileInputStream encfsIs = new EncFSFileInputStream(
							encFsFile);
					try {
						BufferedInputStream decFsIs = new BufferedInputStream(
								new FileInputStream(decodedFsFile));
						String decodedFsFileName = decodedFsFile
								.getAbsoluteFile().getName();
						try {
							int streamresult = compareInputStreams(encfsIs,
									decFsIs, decodedFsFileName);
							if (streamresult != 0) {
								return streamresult;
							}
						} finally {
							decFsIs.close();
						}
					} finally {
						encfsIs.close();
					}

					// Copy the file via input/output streams & then check that
					// the file is the same
					File t = File.createTempFile(this.getClass().getName(),
							".tmp");
					try {
						EncFSUtil.copyWholeStreamAndClose(
								new EncFSFileInputStream(encFsFile),
								new EncFSOutputStream(encFsDir.getVolume(),
										new BufferedOutputStream(
												new FileOutputStream(t)),
										encFsFile.getPath()));

						FileInputStream reEncFSIs = new FileInputStream(t);
						try {
							InputStream origEncFSIs = encFsFile
									.getVolume()
									.getFileProvider()
									.openInputStream(
											encFsFile.getEncryptedPath());
							try {
								int streamresult = compareInputStreams(
										origEncFSIs, reEncFSIs,
										encFsFile.getPath());
								if (streamresult != 0) {
									return streamresult;
								}
							} finally {
								origEncFSIs.close();
							}
						} finally {
							reEncFSIs.close();
						}

					} finally {
						if (t.exists()) {
							t.delete();
						}
					}
				}
			}
		}

		return 0;
	}

	private int compareInputStreams(InputStream encfsIs, InputStream decFsIs,
			String decodedFsFileName) throws IOException {
		int bytesRead = 0;
		int bytesRead2;
		while (bytesRead >= 0) {
			byte[] readBuf = new byte[128];
			byte[] readBuf2 = new byte[128];

			bytesRead = encfsIs.read(readBuf);
			bytesRead2 = decFsIs.read(readBuf2);

			if (bytesRead != bytesRead2) {
				logger.error(
						"File bytes read missmatch {} ({}, {})",
						new Object[] { decodedFsFileName, bytesRead, bytesRead2 });
				return -1;
			}

			if (!Arrays.equals(readBuf, readBuf2)) {
				logger.error("File bytes missmatch {}", decodedFsFileName);
				return -1;
			}
		}
		return 0;
	}

	private static class SimpleEncFSFileComparator implements
			Comparator<EncFSFile> {
		private static final SimpleEncFSFileComparator instance = new SimpleEncFSFileComparator();

		public static SimpleEncFSFileComparator getInstance() {
			return instance;
		}

		public int compare(EncFSFile arg0, EncFSFile arg1) {
			if (arg0.isDirectory() != arg1.isDirectory()) {
				if (arg0.isDirectory()) {
					return -1;
				} else {
					return 1;
				}
			} else {
				return arg0.getName().compareTo(arg1.getName());
			}
		}
	}

	private static class SimpleFileComparator implements Comparator<File> {
		private static final SimpleFileComparator instance = new SimpleFileComparator();

		public static SimpleFileComparator getInstance() {
			return instance;
		}

		public int compare(File arg0, File arg1) {
			if (arg0.isDirectory() != arg1.isDirectory()) {
				if (arg0.isDirectory()) {
					return -1;
				} else {
					return 1;
				}
			} else {
				return arg0.getName().compareTo(arg1.getName());
			}
		}
	}
}
