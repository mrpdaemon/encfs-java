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

import org.mrpdaemon.sec.encfs.*;

import java.io.*;
import java.util.*;

public class EncFSShell {
	// EncFSFile stack representing the current directory path
	private static Stack<EncFSFile> dirStack = new Stack<EncFSFile>();

	// EncFSFile representing the current directory
	private static EncFSFile curDir;

	// EncFSVolume that we're working on
	private static EncFSVolume volume;

	// Buffered reader for reading input stream
	private static BufferedReader br;

	// Search method that returns individual path elements for a given path
	private static ArrayList<EncFSFile> getPath(String path) throws IOException {
		ArrayList<EncFSFile> result = new ArrayList<EncFSFile>();
		EncFSFile curFile;
		boolean found;

		// Root directory handling
		if (path.equals(EncFSVolume.ROOT_PATH)) {
			result.add(volume.getRootDir());
			return result;
		}

		// Absolute vs. relative path handling
		if (path.startsWith(EncFSVolume.PATH_SEPARATOR)) {
			curFile = volume.getRootDir();
		} else {
			curFile = curDir;
		}

		StringTokenizer st = new StringTokenizer(path,
				EncFSVolume.PATH_SEPARATOR);
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

	// Method for accepting password input
	private static String passwordInput() {
		System.out.print("Enter password: ");
		String password = null;

		try {
			password = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(1);
		}

		return password;
	}

	// Method to create a new volume
	private static boolean createVolume(String path) {
		System.out.print("No EncFS volume found at '" + path
				+ "' would you like to create it? [Yes/No]: ");

		String response;
		try {
			response = br.readLine();
		} catch (IOException e) {
			e.printStackTrace();
			return false;
		}

		if (response.toLowerCase().equals("yes")
				|| response.toLowerCase().equals("y")) {

			// If the directory doesn't exist create it first
			File inputDir = new File(path);
			if (!inputDir.exists()) {
				if (!inputDir.mkdir()) {
					return true;
				}
			}

			String password = passwordInput();

			// Create the volume
			try {
				EncFSFileProvider fileProvider = new EncFSLocalFileProvider(
						inputDir);
				EncFSConfig config = EncFSConfigFactory.createDefault();
				// new
				// EncFSVolumeBuilder().withFileProvider(fileProvider).withConfig(config).withPassword(password).create();
				new EncFSVolumeBuilder().withFileProvider(fileProvider)
						.withConfig(config).withPassword(password)
						.writeVolumeConfig();
			} catch (Exception e) {
				e.printStackTrace();
				return false;
			}

			System.out.println("New volume '" + path
					+ "' created successfully.");

			// Open the volume
			try {
				volume = new EncFSVolumeBuilder().withRootPath(path)
						.withPassword(password).buildVolume();
			} catch (Exception e) {
				System.out.println(e.getMessage());
				return false;
			}

			return true;
		}

		return false;
	}

	public static void main(String[] args) {

		if (args.length != 1) {
			System.out.println("This application takes one argument:"
					+ " path to an EncFS volume");
			System.exit(1);
		}

		br = new BufferedReader(new InputStreamReader(System.in));

		/*
		 * If the given directory or the config file doesn't exist ask for
		 * creation.
		 */
		File inputDir = new File(args[0]);
		File configFile = new File(args[0], EncFSVolume.CONFIG_FILE_NAME);
		if (!inputDir.exists() || !configFile.exists()) {
			if (!createVolume(args[0])) {
				System.exit(1);
			}
		} else {
			String password = passwordInput();

			// Try to open the EncFSVolume at args[0] using the given password
			try {
				volume = new EncFSVolumeBuilder().withRootPath(args[0])
						.withPassword(password).buildVolume();
			} catch (EncFSInvalidPasswordException e) {
				System.out.println("Invalid password!");
				System.exit(1);
			} catch (EncFSException e) {
				System.out.println(e.getMessage());
				System.exit(1);
			} catch (FileNotFoundException e) {
				System.out.println(e.getMessage());
				System.exit(1);
			} catch (IOException e) {
				System.out.println(e.getMessage());
				System.exit(1);
			}
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
					if (curDir.getParentPath().equals(EncFSVolume.ROOT_PATH)) {
						System.out.print(EncFSVolume.ROOT_PATH
								+ curDir.getName() + " > ");
					} else {
						System.out.print(EncFSVolume.combinePath(
								curDir.getParentPath(), curDir.getName())
								+ " > ");
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
							pathStr = readFileName(st, token);
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
								System.out.println(file.getName()
										+ EncFSVolume.PATH_SEPARATOR);
							} else {
								System.out.println(file.getName());
							}
						}
					}
				} else if (command.equals("mkdir") || command.equals("mkdirs")) {
					String dirPath = (st.hasMoreTokens() ? readFileName(st)
							: null);
					if (dirPath == null) {
						System.out.println("mkdir {dirname}");
						continue;
					}

					boolean result;
					if (command.equals("mkdir")) {
						try {
							result = volume.makeDir(EncFSVolume.combinePath(
									curDir, dirPath));
						} catch (FileNotFoundException e) {
							System.out.println(e.getMessage());
							continue;
						}
					} else {
						result = volume.makeDirs(EncFSVolume.combinePath(
								curDir, dirPath));
					}

					if (!result) {
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
							filePath = readFileName(st, token);
						}
					}

					if (filePath == null) {
						System.out.println("rm [-r] <filename>");
						continue;
					}

					boolean result;
					try {
						result = volume.deletePath(
								EncFSVolume.combinePath(curDir, filePath),
								recursive, new EncFSShellProgressListener());
					} catch (FileNotFoundException e) {
						System.out
								.println("File not found: '" + filePath + "'");
						continue;
					}

					if (!result) {
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
							pathArray[pathCount++] = readFileName(st, token);
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

					try {
						ArrayList<EncFSFile> dstPathList = getPath(pathArray[1]);
						EncFSFile lastPathElement = dstPathList.get(dstPathList
								.size() - 1);
						/*
						 * It is ok for the last path element to exist if it is
						 * a directory - in that case we'll just move the source
						 * path into that directory
						 */
						if (!force && !lastPathElement.isDirectory()) {
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
					if (pathArray[1].startsWith(EncFSVolume.PATH_SEPARATOR)) {
						// Already an absolute path
						dstPath = pathArray[1];
					} else {
						// Combine with current path
						dstPath = EncFSVolume.combinePath(curDir, pathArray[1]);
					}

					boolean result;
					try {
						result = volume.movePath(srcPath, dstPath,
								new EncFSShellProgressListener());
					} catch (IOException e) {
						System.out.println(e.getMessage());
						continue;
					}

					if (!result) {
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
							pathArray[pathCount++] = readFileName(st, token);
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
							if (!recursive) {
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
					String dstPath;
					if (pathArray[1].startsWith(EncFSVolume.PATH_SEPARATOR)) {
						// Already an absolute path
						dstPath = pathArray[1];
					} else {
						// Combine with current path
						dstPath = EncFSVolume.combinePath(curDir, pathArray[1]);
					}

					boolean result;
					try {
						result = volume.copyPath(srcPath, dstPath,
								new EncFSShellProgressListener());
					} catch (IOException e) {
						System.out.println(e.getMessage());
						continue;
					}

					if (!result) {
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
					String dirPath = readFileName(st);

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
					if (dirPath.equals(EncFSVolume.ROOT_PATH)) {
						dirStack.clear();
						curDir = volume.getRootDir();
						continue;
					}

					// regular directory path, find and cd into it
					ArrayList<EncFSFile> pathList;
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
					if (dirPath.startsWith(EncFSVolume.PATH_SEPARATOR)) {
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
					String filePath = readFileName(st);
					// Find and print file
					ArrayList<EncFSFile> pathList;
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

					EncFSUtil.copyWholeStreamAndCloseInput(
							new EncFSFileInputStream(lastPathElement),
							System.out);
					System.out.println();
				}

			} catch (EncFSException e) {
				System.out.println(e.getMessage());
				e.printStackTrace();
				System.exit(1);
			} catch (FileNotFoundException e) {
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

	static class EncFSShellProgressListener extends EncFSProgressListener {

		int numProcessed = 0;

		@Override
		public void handleEvent(int eventType) {
			switch (eventType) {
			case EncFSProgressListener.FILES_COUNTED_EVENT:
				break;
			case EncFSProgressListener.NEW_FILE_EVENT:
				if (this.getNumFiles() != 0) {
					System.out.println("[" + (numProcessed * 100)
							/ this.getNumFiles() + "%] Processing: "
							+ this.getCurrentFile());
					numProcessed++;
				} else {
					System.out.println("Processing: " + this.getCurrentFile());
				}
				break;
			case EncFSProgressListener.FILE_PROCESS_EVENT:
				break;
			case EncFSProgressListener.OP_COMPLETE_EVENT:
				System.out.println("[100%] Operation complete!");
				break;
			default:
				System.out.println("Unknown event type: " + eventType);
				break;
			}
		}
	}

	private static String readFileName(StringTokenizer st) {
		return readFileName(st, null);
	}

	// Read a path orfilename from StringTokenizer st - can include spaces is
	// quoted with "token1 token2 token3"
	// if token != null, this is the first token already read from st
	// if the path starts with ", read multiple tokens (separated by "
	// ") until the name ends with " or the last token is read.
	private static String readFileName(StringTokenizer st, String token) {
		String filePath = (token == null) ? st.nextToken() : token;
		if (filePath.startsWith("\"")) {
			filePath = filePath.substring(1);
			while (st.hasMoreTokens()) {
				filePath += " " + st.nextToken();
				if (filePath.endsWith("\"")) {
					filePath = filePath.substring(0, filePath.length() - 1);
					break;
				}
			}
		}
		return filePath;
	}
}