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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.Date;
import java.util.Iterator;
import java.util.Stack;
import java.util.StringTokenizer;

import org.mrpdaemon.sec.encfs.EncFSCorruptDataException;
import org.mrpdaemon.sec.encfs.EncFSFile;
import org.mrpdaemon.sec.encfs.EncFSFileInputStream;
import org.mrpdaemon.sec.encfs.EncFSInvalidConfigException;
import org.mrpdaemon.sec.encfs.EncFSInvalidPasswordException;
import org.mrpdaemon.sec.encfs.EncFSUnsupportedException;
import org.mrpdaemon.sec.encfs.EncFSUtil;
import org.mrpdaemon.sec.encfs.EncFSVolume;

public class EncFSShell {
	// EncFSFile stack representing the current directory path
	private static Stack<EncFSFile> dirStack = new Stack<EncFSFile>();

	// EncFSFile representing the current directory
	private static EncFSFile curDir;

	// EncFSVolume that we're working on
	private static EncFSVolume volume;

	// Search method that returns individual path elements for a given path
	private static ArrayList<EncFSFile> getPath(String path) throws IOException {
		ArrayList<EncFSFile> result = new ArrayList<EncFSFile>();
		EncFSFile curFile;
		boolean found;

		// Absolute vs. relative path handling
		if (path.startsWith("/")) {
			curFile = volume.getRootDir();
		} else {
			curFile = curDir;
		}

		StringTokenizer st = new StringTokenizer(path, "/");
		while (st.hasMoreTokens()) {
			String pathElement = st.nextToken();
			found = false;
			if (curFile.isDirectory()) {
				EncFSFile[] files = curFile.listFiles();
				for (EncFSFile file : files) {
					if (file.getName().equals(pathElement)) {
						result.add(file);
						curFile = file;
						found = true;
					}
				}
			} else {
				// Not a directory, better be the last token
				if (st.hasMoreTokens()) {
					throw new FileNotFoundException("'" + pathElement
							+ "' is not a directory!");
				} else {
					result.add(curFile);
					found = true;
				}
			}

			if (!found) {
				throw new FileNotFoundException("Path '" + path
						+ "' not found!");
			}
		}

		return result;
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

					// Options
					class ListOptions {
						public boolean reverse = false;
						public boolean sortByTime = false;
						public boolean longListingFormat = false;
					}
					;

					final ListOptions options = new ListOptions();
					String pathStr = null;

					// Option parsing
					String token;
					while (st.hasMoreTokens()) {
						token = st.nextToken();
						if (token.startsWith("-")) {
							// Option switches
							if (token.contains("l")) {
								options.longListingFormat = true;
							} else if (token.contains("r")) {
								options.reverse = true;
							} else if (token.contains("s")) {
								options.sortByTime = true;
							}
						} else {
							// Path specifier
							pathStr = token;
						}
					}

					// Obtain list of files in the target directory
					EncFSFile[] files;
					if (pathStr == null) {
						files = curDir.listFiles();
					} else {
						try {
							ArrayList<EncFSFile> pathList = getPath(pathStr);
							EncFSFile lastPathElement = pathList.get(pathList
									.size() - 1);
							if (lastPathElement.isDirectory()) {
								files = lastPathElement.listFiles();
							} else {
								System.out.println("'" + pathStr + "'"
										+ " is not a directory!");
								continue;
							}
						} catch (FileNotFoundException e) {
							System.out.println(e.getMessage());
							continue;
						}
					}

					// Comparator implementation for sorting
					Comparator<EncFSFile> comparator = new Comparator<EncFSFile>() {

						public int compare(EncFSFile arg0, EncFSFile arg1) {
							int result;
							if (options.sortByTime) {
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

							if (options.reverse) {
								result = -1 * result;
							}

							return result;
						}

					};

					// Sort files if needed
					if (options.reverse || options.sortByTime) {
						Arrays.sort(files, comparator);
					}

					// Print the listing
					for (EncFSFile file : files) {
						if (options.longListingFormat) {
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
							System.out
									.print(tmpSize.substring(tmpSize.length() - 9));

							System.out.print(" ");
							System.out.print(new Date(file.getLastModified()));

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
				} else if (command.equals("mkdir") || command.equals("mkdirs")) {
					String dirPath = (st.hasMoreTokens() ? st.nextToken()
							: null);
					if (dirPath == null) {
						System.out.println("mkdir {dirname}");
						continue;
					}

					boolean result;
					if (command.equals("mkdir")) {
						try {
							result = volume.makeDir(curDir.getPath() + "/"
									+ dirPath);
						} catch (FileNotFoundException e) {
							System.out.println(e.getMessage());
							continue;
						}
					} else {
						result = volume.makeDirs(curDir.getPath() + "/"
								+ dirPath);
					}

					if (result == false) {
						System.out.println("Failed to create directory '"
								+ dirPath + "'");
					}
				} else if (command.equals("rm")) { // remove
					String filePath = null;
					boolean recursive = false;

					// Options / path parsing
					while (st.hasMoreTokens()) {
						String token = st.nextToken();
						if (token.startsWith("-")) {
							if (token.contains("r")) {
								recursive = true;
							}
						} else {
							filePath = token;
						}
					}

					if (filePath == null) {
						System.out.println("rm [-r] <filename>");
						continue;
					}

					boolean result;
					try {
						result = volume.deletePath(curDir.getPath() + "/"
								+ filePath, recursive);
					} catch (FileNotFoundException e) {
						System.out
								.println("File not found: '" + filePath + "'");
						continue;
					}

					if (result == false) {
						System.out.println("Failed to delete path '" + filePath
								+ "'");
					}

				} else if (command.equals("mv")) { // move / rename
					int pathCount = 0;
					boolean force = false;
					String pathArray[] = new String[2];

					// Option/path parsing
					while (st.hasMoreTokens()) {
						String token = st.nextToken();
						if (token.startsWith("-")) {
							if (token.contains("f")) {
								force = true;
							}
						} else {
							pathArray[pathCount++] = token;
						}
					}

					if (pathCount < 2) {
						System.out
								.println("Usage: mv [-f] <srcPath> <dstPath>");
						continue;
					}

					ArrayList<EncFSFile> srcPathList;
					try {
						srcPathList = getPath(pathArray[0]);
					} catch (FileNotFoundException e) {
						System.out.println(e.getMessage());
						continue;
					}

					@SuppressWarnings("unused")
					ArrayList<EncFSFile> dstPathList;
					try {
						dstPathList = getPath(pathArray[1]);
						if (force == false) {
							System.out.println("Destination path '"
									+ pathArray[1] + "' exists!");
							continue;
						}
					} catch (FileNotFoundException e) {
						// This is expected without -f
					}

					String srcPath = srcPathList.get(srcPathList.size() - 1)
							.getPath();

					// Need to convert destination path to an absolute path
					String dstPath = null;
					if (pathArray[1].startsWith("/")) {
						// Already an absolute path
						dstPath = pathArray[1];
					} else {
						// Combine with current path
						dstPath = curDir.getPath() + "/" + pathArray[1];
					}

					boolean result = false;
					try {
						result = volume.movePath(srcPath, dstPath);
					} catch (IOException e) {
						System.out.println(e.getMessage());
						continue;
					}

					if (result == false) {
						System.out.println("Failed to move '" + srcPath
								+ "' to '" + dstPath + "'");
					}
				} else if (command.equals("cp")) { // copy a file or directory
					int pathCount = 0;
					boolean recursive = false;
					String pathArray[] = new String[2];

					// Option/path parsing
					while (st.hasMoreTokens()) {
						String token = st.nextToken();
						if (token.startsWith("-")) {
							if (token.contains("r")) {
								recursive = true;
							}
						} else {
							pathArray[pathCount++] = token;
						}
					}

					if (pathCount < 2) {
						System.out
								.println("Usage: cp [-r] <srcPath> <dstPath>");
						continue;
					}

					EncFSFile lastPathElement;
					ArrayList<EncFSFile> srcPathList;
					try {
						srcPathList = getPath(pathArray[0]);
						/*
						 * If source path is a directory require recursive flag
						 * to proceed
						 */
						lastPathElement = srcPathList
								.get(srcPathList.size() - 1);
						if (lastPathElement.isDirectory()) {
							if (recursive == false) {
								System.out.println("Source path '"
										+ pathArray[0]
										+ "' is a directory. Use -r to copy.");
								continue;
							}
						}
					} catch (FileNotFoundException e) {
						System.out.println(e.getMessage());
						continue;
					}

					String srcPath = srcPathList.get(srcPathList.size() - 1)
							.getPath();

					// Need to convert destination path to an absolute path
					String dstPath = null;
					if (pathArray[1].startsWith("/")) {
						// Already an absolute path
						dstPath = pathArray[1];
					} else {
						// Combine with current path
						if (curDir == volume.getRootDir()) {
							dstPath = "/" + pathArray[1];
						} else {
							dstPath = curDir.getPath() + "/" + pathArray[1];
						}
					}

					boolean result = false;
					try {
						result = volume.copyPath(srcPath, dstPath);
					} catch (IOException e) {
						System.out.println(e.getMessage());
						continue;
					}

					if (result == false) {
						System.out.println("Failed to copy '" + srcPath
								+ "' to '" + dstPath + "'");
					}
				} else if (command.equals("exit")) { // bail out
					System.exit(0);
				} else if (command.equals("cd")) { // go into a child directory
					if (!st.hasMoreTokens()) {
						System.out.println("No directory name specified");
						continue;
					}
					String dirPath = st.nextToken();

					// .. handling
					if (dirPath.equals("..")) {
						if (dirStack.empty()) {
							System.out.println("Can't go above root directory");
							continue;
						}
						curDir = dirStack.pop(); // go back one level
						continue;
					}

					// '/' handling
					if (dirPath.equals("/")) {
						dirStack.clear();
						curDir = volume.getRootDir();
						continue;
					}

					// regular directory path, find and cd into it
					ArrayList<EncFSFile> pathList = null;
					try {
						pathList = getPath(dirPath);
					} catch (FileNotFoundException e) {
						System.out.println("Path '" + dirPath
								+ "' doesn't exist!");
						continue;
					}

					// Make sure the last element is a directory
					EncFSFile lastPathElement = pathList
							.get(pathList.size() - 1);
					if (!lastPathElement.isDirectory()) {
						System.out.println("'" + lastPathElement.getName()
								+ "' is not a directory!");
						continue;
					}

					/*
					 * Current directory goes into the stack also Special
					 * handling for absolute paths
					 */
					if (dirPath.startsWith("/")) {
						// Clear the existing stack first
						dirStack.clear();
						dirStack.push(volume.getRootDir());
					} else {
						dirStack.push(curDir);
					}

					// Push all path elements except the last one into the stack
					Iterator<EncFSFile> itr = pathList.iterator();
					while (itr.hasNext()) {
						EncFSFile dir = itr.next();
						if (itr.hasNext()) {
							dirStack.push(dir);
						}
					}

					curDir = lastPathElement;
				} else if (command.equals("cat")) {
					if (!st.hasMoreTokens()) {
						System.out.println("No file name specified");
						continue;
					}
					String filePath = st.nextToken();

					// Find and print file
					ArrayList<EncFSFile> pathList = null;
					try {
						pathList = getPath(filePath);
					} catch (FileNotFoundException e) {
						System.out.println(e.getMessage());
						continue;
					}

					EncFSFile lastPathElement = pathList
							.get(pathList.size() - 1);

					if (lastPathElement.isDirectory()) {
						System.out.println("'" + filePath + "' is not a file!");
						continue;
					}

					EncFSUtil.copyWholeStream(new EncFSFileInputStream(
							lastPathElement), System.out, true, false);
					System.out.println();
				}

			} catch (EncFSCorruptDataException e) {
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