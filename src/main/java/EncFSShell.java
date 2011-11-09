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
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Stack;
import java.util.StringTokenizer;

import org.mrpdaemon.sec.encfs.*;

public class EncFSShell {
	// EncFSFile stack representing the current directory path
	private static Stack<EncFSFile> dirStack = new Stack<EncFSFile>();
			
	// EncFSFile representing the current directory
	private static EncFSFile curDir;

	// Search method to find a child under the current directory
	private static EncFSFile findChild(String childName)
			throws EncFSCorruptDataException, EncFSChecksumException {
		EncFSFile[] files = curDir.listFiles();
		for (EncFSFile file: files) {
			if (file.getName().equals(childName)) {
				return file;
			}
		}

		return null;
	}

	public static void main(String[] args) {
		
		if (args.length != 1) {
			System.out.println("This application takes one argument:" +
			                   " path to an EncFS volume");
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
			volume = new EncFSVolume(new File(args[0]), password);
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
					if (curDir.getVolumePath().equals(
							EncFSVolume.ENCFS_VOLUME_ROOT_PATH)) {
						System.out.print("/" + curDir.getName() + " > ");
					} else {
						System.out.print(curDir.getVolumePath() + "/" +
								         curDir.getName() + " > ");
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
					EncFSFile[] files = curDir.listFiles();
					for (EncFSFile file : files) {
						if (file.getFile().isDirectory()) {
							System.out.println(file.getName() + "/");
						} else {
							System.out.println(file.getName());
						}
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
						if (!file.getFile().isDirectory()) {
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
						if (!file.getFile().isFile()) {
							System.out.println("Not a file");
							continue;
						}
						
						EncFSFileInputStream efis = new EncFSFileInputStream(file);
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