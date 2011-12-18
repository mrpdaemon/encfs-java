package org.mrpdaemon.sec.encfs;

import java.io.File;
import java.io.FileNotFoundException;
import java.util.Arrays;
import java.util.Comparator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Simple tool that takes a raw encfs volume (& uses encfs-java to unencrypt it)
 * and compares it to a the same mounted encfs volume to check they are the
 * same.
 */
public class EncFSComparer {
	private static final Logger logger = LoggerFactory.getLogger(EncFSComparer.class);

	/**
	 * @param args
	 * @throws EncFSUnsupportedException
	 * @throws EncFSCorruptDataException
	 * @throws EncFSInvalidConfigException
	 * @throws EncFSInvalidPasswordException
	 * @throws FileNotFoundException
	 */
	public static void main(String[] args) throws Exception {
		if (args == null || args.length != 3)
			throw new IllegalArgumentException("Missing required args");

		File rawEncFSVolume = new File(args[0]);
		String password = args[1];
		File decodedEncFSOutput = new File(args[2]);

		EncFSComparer encFSComparer = new EncFSComparer(rawEncFSVolume, password, decodedEncFSOutput);
		int result = encFSComparer.compare();
		System.exit(result);
	}

	private final File rawEncFSVolume;
	private final String password;
	private final File decodedEncFSOutput;

	public EncFSComparer(File rawEncFSVolume, String password, File decodedEncFSOutput) {
		this.rawEncFSVolume = rawEncFSVolume;
		this.password = password;
		this.decodedEncFSOutput = decodedEncFSOutput;
	}

	private int compare() throws FileNotFoundException, EncFSInvalidPasswordException, EncFSInvalidConfigException,
			EncFSCorruptDataException, EncFSUnsupportedException, EncFSChecksumException {
		logger.info("Performing compare between encfs raw volume at {} and output files at {}", rawEncFSVolume,
				decodedEncFSOutput);

		EncFSVolume volume = new EncFSVolume(rawEncFSVolume.getAbsoluteFile(), password);
		EncFSFile rootDir = volume.getRootDir();
		int result = compare(rootDir, decodedEncFSOutput);

		if (result == 0) {
			logger.info("All files / folders match");
		} else {
			logger.info("Errors between files / folders found");
		}

		return result;
	}

	private int compare(EncFSFile encFsDir, File decodedFsDir) throws EncFSCorruptDataException, EncFSChecksumException {
		logger.info("Comparing directory {}", decodedFsDir.getAbsoluteFile());

		EncFSFile[] encFsFiles = encFsDir.listFiles();
		File[] decodedFsFiles = decodedFsDir.listFiles();

		Arrays.sort(encFsFiles, SimpleEncFSFileComparator.getInstance());
		Arrays.sort(decodedFsFiles, SimpleFileComparator.getInstance());

		if (encFsFiles.length != decodedFsFiles.length) {
			logger.error("File count miss match in directory {}", decodedFsDir.getAbsoluteFile());
			return -1;
		} else {
			for (int i = 0; i < encFsFiles.length; i++) {
				EncFSFile encFsFile = encFsFiles[i];
				File decodedFsFile = decodedFsFiles[i];

				if (encFsFile.getName().equals(decodedFsFile.getName()) == false) {
					logger.error("File name miss match ({}, {}, {})", new Object[] { i, encFsFile.getName(),
							decodedFsFile.getName() });
					return -1;
				}

				// if (encFsFile.getFile().lastModified() !=
				// decodedFsFile.lastModified()) {
				// logger.error("File {} lastModified miss match",
				// decodedFsFile.getName());
				// return -1;
				// }

				if (encFsFile.getContentsLength() != decodedFsFile.length()) {
					logger.error(
							"File {} size miss match ({}, {})",
							new Object[] { decodedFsFile.getName(), encFsFile.getContentsLength(),
									decodedFsFile.length() });
					return -1;
				}

				if (decodedFsFile.isDirectory()) {
					int subResult = compare(encFsFile, decodedFsFile);
					if (subResult != 0) {
						return subResult;
					}
				}
			}
		}

		return 0;
	}

	private static class SimpleEncFSFileComparator implements Comparator<EncFSFile> {
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
