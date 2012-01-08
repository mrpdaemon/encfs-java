package org.mrpdaemon.sec.encfs;

public class EncFSFileInfo {
	private final String name;
	private final String volumePath;
	private final boolean isDirectory;
	private final long modified;
	private final long size;
	private final boolean canRead;
	private final boolean canWrite;
	private final boolean canExecute;

	public EncFSFileInfo(String name, String volumePath, boolean isDirectory, long modified, long size,
			boolean canRead, boolean canWrite, boolean canExecute) {
		if (name.startsWith("/") && (name.equals("/") == false))
			throw new IllegalArgumentException("Invalid name " + name);

		this.name = name;
		this.volumePath = volumePath;
		this.isDirectory = isDirectory;
		this.modified = modified;
		this.size = size;
		this.canRead = canRead;
		this.canWrite = canWrite;
		this.canExecute = canExecute;
	}

	public String getName() {
		return name;
	}

	public String getVolumePath() {
		return volumePath;
	}

	public boolean isDirectory() {
		return isDirectory;
	}

	public long getModified() {
		return modified;
	}

	public long getSize() {
		return size;
	}

	public String getAbsoluteName() {
		String result;
		if (volumePath.endsWith("/") || name.startsWith("/")) {
			result = volumePath + name;
		} else {
			result = volumePath + "/" + name;
		}
		return result;
	}

	public boolean canRead() {
		return canRead;
	}

	public boolean canWrite() {
		return canWrite;
	}

	public boolean canExecute() {
		return canExecute;
	}

}
