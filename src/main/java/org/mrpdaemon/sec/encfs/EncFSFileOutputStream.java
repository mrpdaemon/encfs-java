package org.mrpdaemon.sec.encfs;

import java.io.IOException;
import java.io.OutputStream;

public class EncFSFileOutputStream extends OutputStream {
	private final OutputStream encfsOs;

	public EncFSFileOutputStream(EncFSFile encfsFile) throws IOException, EncFSUnsupportedException,
			EncFSCorruptDataException, EncFSChecksumException {
		this.encfsOs = encfsFile.openOutputStream();
	}

	@Override
	public void write(int b) throws IOException {
		encfsOs.write(b);
	}

	@Override
	public void write(byte[] b) throws IOException {
		encfsOs.write(b);
	}

	@Override
	public void write(byte[] b, int off, int len) throws IOException {
		encfsOs.write(b, off, len);
	}

	@Override
	public void close() throws IOException {
		encfsOs.close();
	}

	@Override
	public void flush() throws IOException {
		encfsOs.flush();
	}

}
