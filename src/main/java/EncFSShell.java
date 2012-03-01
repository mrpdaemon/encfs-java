/*
 * EncFS Java Library
 * Copyright (C) 2011 Mark R. Pariente
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

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.Stack;
import java.util.StringTokenizer;

import org.mrpdaemon.sec.encfs.EncFSChecksumException;
import org.mrpdaemon.sec.encfs.EncFSCorruptDataException;
import org.mrpdaemon.sec.encfs.EncFSFile;
import org.mrpdaemon.sec.encfs.EncFSFileInputStream;
import org.mrpdaemon.sec.encfs.EncFSInvalidConfigException;
import org.mrpdaemon.sec.encfs.EncFSInvalidPasswordException;
import org.mrpdaemon.sec.encfs.EncFSUnsupportedException;
import org.mrpdaemon.sec.encfs.EncFSVolume;

public class EncFSShell {
	// EncFSFile stack representing the current directory path
	private static Stack<EncFSFile> dirStack = new Stack<EncFSFile>();

	// EncFSFile representing the current directory
	private static EncFSFile curDir;

	// Search method to find a child under the current directory
	private static EncFSFile findChild(String childName)
			throws EncFSCorruptDataException, EncFSChecksumException,
			IOException {
		// curDir.getVolume().getFile(curDir.getVolumePath() + "/" +
		// curDir.getName(), childName);

		EncFSFile[] files = curDir.listFiles();
		for (EncFSFile file : files) {
			if (file.getName().equals(childName)) {
				return file;
			}
		}

		return null;
	}

	public static void main(String[] args) {

		if (args.length != 1) {
			System.out.println("This application takes one argument:"
					+ " path to an EncFS volume");
			System.exit(1);
		}

		// Password input
		System.out.print("Enter password: ");
		BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
		String password = null;
		try {
			password = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		// Create a new EncFS volume
		EncFSVolume volume = null;
		try {
			volume = new EncFSVolume(args[0], password);
		} catch (EncFSUnsupportedException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		} catch (EncFSInvalidConfigException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		} catch (EncFSCorruptDataException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		} catch (EncFSInvalidPasswordException e) {
			System.out.println("Invalid password!");
			System.exit(1);
		} catch (FileNotFoundException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		} catch (IOException e) {
			System.out.println(e.getMessage());
			System.exit(1);
		}

		// Start at the root of the EncFS volume
		curDir = volume.getRootDir();

		// Shell loop
		while (true) {
			try {
				// Print banner
				if (curDir == volume.getRootDir()) {
					System.out.print("/ > ");
				} else {
					if (curDir.getParentPath().equals(
							EncFSVolume.ENCFS_VOLUME_ROOT_PATH)) {
						System.out.print("/" + curDir.getName() + " > ");
					} else {
						System.out.print(curDir.getParentPath() + "/"
								+ curDir.getName() + " > ");
					}
				}

				// Read next command
				String inputBuffer = null;
				try {
					inputBuffer = br.readLine();
				} catch (IOException e) {
					e.printStackTrace();
					System.exit(1);
				}

				// Tokenize the input line
				StringTokenizer st = new StringTokenizer(inputBuffer, " ");

				if (!st.hasMoreTokens()) { // Just ENTER or some spaces
					continue;
				}

				// Command processing
				String command = st.nextToken();
				if (command.equals("ls")) { // list child directories

					final String options;
					if (st.hasMoreTokens()) {
						options = st.nextToken();
					} else {
						options = "";
					}

					if (options.equals("")) {
						EncFSFile[] files = curDir.listFiles();
						for (EncFSFile file : files) {
							if (file.isDirectory()) {
								System.out.println(file.getName() + "/");
							} else {
								System.out.println(file.getName());
							}
						}
					} else {
						EncFSFile[] files = curDir.listFiles();

						Comparator<EncFSFile> comparator = new Comparator<EncFSFile>() {

							private final boolean reverse = (options
									.contains("r"));
							private final boolean sortByTime = (options
									.contains("t"));

							public int compare(EncFSFile arg0, EncFSFile arg1) {
								int result;
								if (sortByTime) {
									long diff = arg0.getLastModified()
											- arg1.getLastModified();
									if (diff > 0) {
										result = -1;
									} else if (diff == 0) {
										result = 0;
									} else {
										result = 1;
									}
								} else {
									result = arg0.getName().compareTo(
											arg1.getName());
								}

								if (reverse) {
									result = -1 * result;
								}

								return result;
							}

						};

						Arrays.sort(files, comparator);

						boolean longListingFormat = options.contains("l");
						for (EncFSFile file : files) {
							if (longListingFormat) {
								if (file.isDirectory()) {
									System.out.print("d");
								} else {
									System.out.print("-");
								}

								if (file.isReadable()) {
									System.out.print("r");
								} else {
									System.out.print("-");
								}

								if (file.isWritable()) {
									System.out.print("w");
								} else {
									System.out.print("-");
								}

								if (file.isExecutable()) {
									System.out.print("x");
								} else {
									System.out.print("-");
								}

								System.out.print("???");
								System.out.print("???");

								System.out.print(" ");
								String tmpSize = "         " + file.getLength();
								System.out.print(tmpSize.substring(tmpSize
										.length() - 9));

								System.out.print(" ");
								System.out.print(new Date(file
										.getLastModified()));

								System.out.print(" ");
								System.out.print(file.getName());

								System.out.println();
							} else {
								if (file.isDirectory()) {
									System.out.println(file.getName() + "/");
								} else {
									System.out.println(file.getName());
								}
							}
						}
					}
				} else if (command.equals("mkdir") || command.equals("mkdirs")) {
					String dirName = (st.hasMoreTokens() ? st.nextToken()
							: null);
					if (dirName == null) {
						System.out.println("mkdir {dirname}");
						continue;
					}

					boolean result;
					if (command.equals("mkdir")) {
						result = volume.makeDir(curDir.getPath() + "/"
								+ dirName);
					} else {
						result = volume.makeDirs(curDir.getPath() + "/"
								+ dirName);
					}

					System.out.println(command + " " + dirName
							+ " result was: " + result);

				} else if (command.equals("rm")) { // remove
					String fileName = (st.hasMoreTokens() ? st.nextToken()
							: null);
					if (fileName == null) {
						System.out.println("rm {filename}");
						continue;
					}

					boolean result = volume.deletePath(curDir.getPath() + "/"
							+ fileName);

					System.out.println("rm " + fileName + " result was: "
							+ result);

				} else if (command.equals("mv")) { // move / rename

					String[] tokens = new String[3];
					int tokenCount = 0;
					for (int i = 0; i < tokens.length; i++) {
						if (st.hasMoreTokens()) {
							tokens[tokenCount++] = st.nextToken();
						}

					}

					String fileName1 = null, fileName2 = null;
					boolean force;
					if (tokenCount == 2) {
						force = false;
						fileName1 = tokens[0];
						fileName2 = tokens[1];
					} else {
						force = "/f".equals(tokens[0]);
						fileName1 = tokens[1];
						fileName2 = tokens[2];
					}

					if (fileName1 == null || fileName2 == null) {
						System.out.println("mv {src} {dst}");
					} else {
						EncFSFile file1 = findChild(fileName1);
						EncFSFile file2 = findChild(fileName2);

						if (file1 == null) {
							System.out.println("file " + fileName1
									+ " not found");
							continue;
						}
						if (force == false && file2 != null) {
							System.out.println("file " + fileName2
									+ " already exists, aborting");
							continue;
						}

						boolean result = volume.movePath(file1.getPath(),
								fileName2);
						System.out.println("Result of move " + fileName1
								+ " to " + fileName2 + " was: " + result);
					}
				} else if (command.equals("exit")) { // bail out
					System.exit(0);
				} else if (command.equals("cd")) { // go into a child directory
					if (!st.hasMoreTokens()) {
						System.out.println("No directory name specified");
						continue;
					}
					String dirName = st.nextToken();

					// .. handling
					if (dirName.equals("..")) {
						if (dirStack.empty()) {
							System.out.println("Can't go above root directory");
							continue;
						}
						curDir = dirStack.pop(); // go back one level
						continue;
					}

					// regular directory name, find and cd into it
					EncFSFile file = findChild(dirName);
					if (file != null) {
						if (!file.isDirectory()) {
							System.out.println("Not a directory");
							continue;
						}
						dirStack.push(curDir);
						curDir = file;
					} else {
						System.out.println("Directory not found!");
					}

				} else if (command.equals("cat")) {
					if (!st.hasMoreTokens()) {
						System.out.println("No file name specified");
						continue;
					}
					String fileName = st.nextToken();

					// Find and print file
					EncFSFile file = findChild(fileName);
					if (file != null) {
						if (file.isDirectory()) {
							System.out.println("Not a file");
							continue;
						}

						EncFSFileInputStream efis = new EncFSFileInputStream(
								file);
						int bytesRead = 0;
						while (bytesRead >= 0) {
							byte[] readBuf = new byte[128];
							bytesRead = efis.read(readBuf);
							System.out.print(new String(readBuf));
						}
						System.out.println();
					} else {
						System.out.println("File not found!");
					}
				}

			} catch (EncFSCorruptDataException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
				System.exit(1);
			} catch (EncFSChecksumException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
				System.exit(1);
			} catch (FileNotFoundException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
				System.exit(1);
			} catch (EncFSUnsupportedException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
				System.exit(1);
			} catch (IOException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
				System.exit(1);
			}
		}
	}
}