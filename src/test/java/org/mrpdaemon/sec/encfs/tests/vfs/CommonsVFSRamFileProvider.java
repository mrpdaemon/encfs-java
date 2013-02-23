package org.mrpdaemon.sec.encfs.tests.vfs;

import org.apache.commons.vfs2.FileSystemException;
import org.apache.commons.vfs2.impl.DefaultFileSystemManager;
import org.apache.commons.vfs2.provider.ram.RamFileProvider;

import java.io.IOException;

public class CommonsVFSRamFileProvider extends CommonsVFSFileProvider {

	private DefaultFileSystemManager fileSystemManager;

	public CommonsVFSRamFileProvider() {
		super(createFileSystemManager());
		this.fileSystemManager = (DefaultFileSystemManager) super.fileSystemManager;
	}

	private static DefaultFileSystemManager createFileSystemManager() {
		RamFileProvider ramFileProvider = new RamFileProvider();
		DefaultFileSystemManager fileSystemManager = new DefaultFileSystemManager();
		// this.fileSystemManager.setLogger(log);
		try {
			fileSystemManager.addProvider("ram", ramFileProvider);
			fileSystemManager.setDefaultProvider(ramFileProvider);
		} catch (FileSystemException e) {
			throw new IllegalStateException(e);
		}

		return fileSystemManager;
	}

	public void init() throws IOException {
		fileSystemManager.init();
	}

	public void close() {
		fileSystemManager.close();
	}
}
