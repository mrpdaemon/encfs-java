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

package org.mrpdaemon.sec.encfs;

/**
 * Class representing a progress listener for long running operations
 */
public abstract class EncFSProgressListener {

	/**
	 * Event notifying that the number of affected files/directories have been
	 * counted.
	 */
	public static final int FILES_COUNTED_EVENT = 0;

	/**
	 * Event notifying that a new file has started to be processed
	 */
	public static final int NEW_FILE_EVENT = 1;

	/**
	 * Event notifying that a single file or directory has been processed.
	 */
	public static final int FILE_PROCESS_EVENT = 2;

	/**
	 * Event notifying completion of the whole operation.
	 */
	public static final int OP_COMPLETE_EVENT = 3;

	// Name of the current file being operated on
	private String currentFile = null;

	// Number of files being operated on
	private int numFiles = 0;

	/**
	 * Method that must be overridden by extending class to handle events posted
	 * to the event listener
	 * 
	 * @param eventType
	 *            Type of the event that just occured
	 */
	public abstract void handleEvent(int eventType);

	/**
	 * Get the name of the current file being operated on
	 * 
	 * @return name of the current file being operated on
	 */
	public String getCurrentFile() {
		return currentFile;
	}

	/**
	 * Get the total number of files that the operation will proceed on. Note
	 * that this value is undefined until a FILES_COUNTED_EVENT is posted first
	 * 
	 * @return total number of files that the operation will proceed on
	 */
	public int getNumFiles() {
		return numFiles;
	}

	// Post an event to the progress listener
	void postEvent(int eventType) {
		handleEvent(eventType);
	}

	// Set the current file
	void setCurrentFile(String fileName) {
		currentFile = fileName;
		postEvent(NEW_FILE_EVENT);
	}

	// Set the total number of files being operated on
	void setNumFiles(int numFiles) {
		this.numFiles = numFiles;
		postEvent(FILES_COUNTED_EVENT);
	}
}