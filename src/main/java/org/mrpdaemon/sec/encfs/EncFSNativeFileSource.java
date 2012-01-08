package org.mrpdaemon.sec.encfs;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

public interface EncFSNativeFileSource {

	public boolean nativeMove(String encSrcFile, String encTargetFile) throws IOException;

	public boolean nativeIsDirectory(String srcFile) throws IOException;

	public boolean nativeDelete(String toEncFileName) throws IOException;

	public boolean nativeMakeDir(String encryptedDirName) throws IOException;

	public boolean nativeMakeDirs(String encryptedName) throws IOException;

	public boolean nativeCopy(String encSrcFileName, String encTargetFileName) throws IOException;

	public List<EncFSFileInfo> nativeListFiles(String encDirName) throws IOException;

	public InputStream nativeOpenInputStream(String encSrcFile) throws IOException;

	public EncFSFileInfo nativeGetFileInfo(String toEncVolumePath);

	public OutputStream nativeOpenOutputStream(String encSrcFile) throws IOException;

	public boolean exists(String name);
}
