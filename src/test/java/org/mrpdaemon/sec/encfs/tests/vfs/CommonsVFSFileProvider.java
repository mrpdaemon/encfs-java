package org.mrpdaemon.sec.encfs.tests.vfs;

import org.apache.commons.vfs2.*;
import org.mrpdaemon.sec.encfs.EncFSFileInfo;
import org.mrpdaemon.sec.encfs.EncFSFileProvider;
import org.mrpdaemon.sec.encfs.EncFSVolume;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

public class CommonsVFSFileProvider implements EncFSFileProvider {

	private final String separator;

	final FileSystemManager fileSystemManager;

	CommonsVFSFileProvider(FileSystemManager fileSystemManager) {
		this.fileSystemManager = fileSystemManager;
		this.separator = FileName.SEPARATOR;
	}

	public final String getSeparator() {
		return separator;
	}

	public final String getFilesystemRootPath() {
		return FileName.ROOT_PATH;
	}

	public boolean move(String encOrigFileName, String encNewFileName)
			throws IOException {
		FileObject origFile = resolveFile(encOrigFileName);
		if (!origFile.exists())
			return false;

		FileObject newFile = resolveFile(encNewFileName);
		if (encNewFileName.lastIndexOf(separator) > 0) {
			if (!newFile.getParent().exists()) {
				return false;
			}
		}
		origFile.moveTo(newFile);
		return true;
	}

	private FileObject resolveFile(String encOrigFileName)
			throws FileSystemException {
		return fileSystemManager.resolveFile(fileSystemManager.getSchemes()[0]
				+ ":" + encOrigFileName);
	}

	public boolean isDirectory(String encFileName) throws IOException {
		FileObject file = resolveFile(encFileName);
		return file.getType() == FileType.FOLDER;
	}

	public boolean delete(String encFileName) throws IOException {
		FileObject file = resolveFile(encFileName);
		return file.delete();
	}

	public boolean mkdir(String encDirName) throws IOException {
		FileObject file = resolveFile(encDirName);
		if (file.exists()) {
			return false;
		} else {
			if (encDirName.lastIndexOf(separator) != 0) {
				if (!file.getParent().exists()) {
					return false;
				}
			}
			file.createFolder();
			return true;
		}
	}

	public boolean mkdirs(String encDirName) throws IOException {
		String[] dirNameParts = encDirName.split(separator);

		String tmpDirName = "";
		for (String dirNamePart : dirNameParts) {
			if (!tmpDirName.endsWith(separator)) {
				tmpDirName += separator;
			}
			tmpDirName += dirNamePart;

			FileObject tmpDirFile = resolveFile(tmpDirName);
			boolean partResult = true;
			if (!tmpDirFile.exists()) {
				partResult = mkdir(tmpDirName);
			} else if (tmpDirFile.getType() == FileType.FILE) {
				partResult = false;
			}

			if (!partResult) {
				return false;
			}
		}

		return true;
	}

	public boolean copy(String encSrcFileName, String encTargetFileName)
			throws IOException {
		FileObject srcFile = resolveFile(encSrcFileName);
		FileObject targetFile = resolveFile(encTargetFileName);

		FileUtil.copyContent(srcFile, targetFile);
		return true;
	}

	public List<EncFSFileInfo> listFiles(String encDirName) throws IOException {
		FileObject srcDir = resolveFile(encDirName);
		FileObject[] children = srcDir.getChildren();

		List<EncFSFileInfo> result = new ArrayList<EncFSFileInfo>(
				children.length);
		for (FileObject aChildren : children) {
			result.add(getFileInfo(aChildren));
		}

		return result;
	}

	public InputStream openInputStream(String encSrcFile) throws IOException {
		FileObject srcFile = resolveFile(encSrcFile);
		return srcFile.getContent().getInputStream();
	}

	public OutputStream openOutputStream(String encSrcFile, long outputLength)
			throws IOException {
		FileObject srcFile = resolveFile(encSrcFile);
		return srcFile.getContent().getOutputStream();
	}

	public EncFSFileInfo getFileInfo(String encSrcFile) throws IOException {
		FileObject srcFile = resolveFile(encSrcFile);
		return getFileInfo(srcFile);
	}

	public boolean exists(String encSrcFile) throws IOException {
		FileObject srcFile = resolveFile(encSrcFile);
		return srcFile.exists();
	}

	private EncFSFileInfo getFileInfo(FileObject fileObject) throws IOException {
		String name = fileObject.getName().getBaseName();
		String volumePath = fileObject.getName().getPath();
		volumePath = volumePath.substring(0,
				volumePath.length() - (name.length() + 1));
		if (volumePath.equals("")) {
			volumePath = EncFSVolume.ROOT_PATH;
		}

		boolean isDirectory = fileObject.getType() == FileType.FOLDER;
		long modified = fileObject.getContent().getLastModifiedTime();
		long size = (isDirectory ? 0 : fileObject.getContent().getSize());
		boolean canRead = fileObject.isReadable();
		boolean canWrite = fileObject.isWriteable();
		boolean canExecute = false;

		return new EncFSFileInfo(name, volumePath, isDirectory, modified, size,
				canRead, canWrite, canExecute);
	}

	public EncFSFileInfo createFile(String encTargetFile) throws IOException {
		if (exists(encTargetFile)) {
			throw new IOException("File already exists");
		}

		FileObject targetFile = resolveFile(encTargetFile);
		targetFile.createFile();

		return getFileInfo(targetFile);
	}

}
