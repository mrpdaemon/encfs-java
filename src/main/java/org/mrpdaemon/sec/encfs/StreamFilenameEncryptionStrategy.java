package org.mrpdaemon.sec.encfs;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.security.InvalidAlgorithmParameterException;

public class StreamFilenameEncryptionStrategy extends
		BasicFilenameEncryptionStrategy {

	public StreamFilenameEncryptionStrategy(EncFSVolume volume,
			String volumePath) {
		super(volume, volumePath, EncFSFilenameEncryptionAlgorithm.STREAM);
	}

	@Override
	protected byte[] encryptConcrete(EncFSVolume volume,
			byte[] paddedDecFileName, byte[] fileIv)
			throws EncFSCorruptDataException {
		try {
			return StreamCrypto.streamEncode(volume, fileIv,
					paddedDecFileName);
		} catch (InvalidAlgorithmParameterException e) {
			throw new EncFSCorruptDataException(e);
		} catch (IllegalBlockSizeException e) {
			throw new EncFSCorruptDataException(e);
		} catch (BadPaddingException e) {
			throw new EncFSCorruptDataException(e);
		} catch (EncFSUnsupportedException e) {
			throw new EncFSCorruptDataException(e);
		}
	}

	protected byte[] getPaddedDecFilename(byte[] decFileName) {
		return decFileName;
	}
}
