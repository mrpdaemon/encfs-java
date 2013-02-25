package org.mrpdaemon.sec.encfs;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import java.security.InvalidAlgorithmParameterException;
import java.security.Key;
import java.util.Arrays;
import java.util.StringTokenizer;

/**
 * User: lars
 */
public class StreamCrypto {

	public static Cipher newStreamCipher() throws EncFSUnsupportedException {
		return EncFSCrypto.getCipher(EncFSCrypto.STREAM_CIPHER);
	}

	private static byte[] streamDecode(Cipher cipher, Mac mac, Key key,
			byte[] iv, byte[] ivSeed, byte[] data, int offset, int len)
			throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// First round uses IV seed + 1 for IV generation
		byte[] ivSeedPlusOne = EncFSCrypto.incrementIvSeedByOne(ivSeed);

		EncFSCrypto.cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv,
				ivSeedPlusOne);
		byte[] firstDecResult = cipher.doFinal(data, offset, len);

		EncFSCrypto.unshuffleBytes(firstDecResult);

		byte[] flipBytesResult = EncFSCrypto.flipBytes(firstDecResult);

		// Second round of decryption with IV seed itself used for IV generation
		EncFSCrypto.cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv,
				ivSeed);
		byte[] result = cipher.doFinal(flipBytesResult);

		EncFSCrypto.unshuffleBytes(result);

		return result;
	}

	static byte[] streamDecode(Cipher cipher, Mac mac, Key key, byte[] iv,
			byte[] ivSeed, byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamDecode(cipher, mac, key, iv, ivSeed, data, 0, data.length);
	}

	public static byte[] streamDecode(EncFSVolume volume, byte[] ivSeed,
			byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		Cipher streamCipher = volume.getStreamCipher();
		return streamDecode(streamCipher, volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data);
	}

	public static byte[] streamDecode(EncFSVolume volume, byte[] ivSeed,
			byte[] data, int offset, int len) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamDecode(volume.getStreamCipher(), volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data,
				offset, len);
	}

	private static byte[] streamEncode(Cipher cipher, Mac mac, Key key,
			byte[] iv, byte[] ivSeed, byte[] data, int offset, int len)
			throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		// First round uses IV seed + 1 for IV generation
		byte[] ivSeedPlusOne = EncFSCrypto.incrementIvSeedByOne(ivSeed);

		byte[] encBuf = Arrays.copyOfRange(data, offset, offset + len);
		EncFSCrypto.shuffleBytes(encBuf);

		EncFSCrypto.cipherInit(key, mac, Cipher.ENCRYPT_MODE, cipher, iv,
				ivSeed);
		byte[] firstEncResult = cipher.doFinal(encBuf);

		byte[] flipBytesResult = EncFSCrypto.flipBytes(firstEncResult);

		EncFSCrypto.shuffleBytes(flipBytesResult);

		// Second round of encryption with IV seed itself used for IV generation
		EncFSCrypto.cipherInit(key, mac, Cipher.ENCRYPT_MODE, cipher, iv,
				ivSeedPlusOne);

		return cipher.doFinal(flipBytesResult);
	}

	static byte[] streamEncode(Cipher cipher, Mac mac, Key key, byte[] iv,
			byte[] ivSeed, byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamEncode(cipher, mac, key, iv, ivSeed, data, 0, data.length);
	}

	public static byte[] streamEncode(EncFSVolume volume, byte[] ivSeed,
			byte[] data) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamEncode(volume.getStreamCipher(), volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data);
	}

	public static byte[] streamEncode(EncFSVolume volume, byte[] ivSeed,
			byte[] data, int offset, int len) throws EncFSUnsupportedException,
			InvalidAlgorithmParameterException, IllegalBlockSizeException,
			BadPaddingException {
		return streamEncode(volume.getStreamCipher(), volume.getMAC(),
				volume.getKey(), volume.getIV(), ivSeed, data,
				offset, len);
	}

	/**
	 * Compute chain IV for the given volume path
	 * 
	 * @param volume
	 *            Volume to compute chain IV for
	 * @param volumePath
	 *            Volume path to compute chain IV for
	 * @return Computed chain IV
	 */
	public static byte[] computeChainIv(EncFSVolume volume, String volumePath) {
		byte[] chainIv = new byte[8];
		StringTokenizer st = new StringTokenizer(volumePath,
				EncFSVolume.PATH_SEPARATOR);
		while (st.hasMoreTokens()) {
			String curPath = st.nextToken();
			if ((curPath.length() > 0)
					&& (!curPath.equals(EncFSVolume.PATH_SEPARATOR))) {
				byte[] encodeBytes;
				if (volume.getConfig().getAlgorithm() == EncFSFilenameEncryptionAlgorithm.BLOCK) {
					encodeBytes = EncFSCrypto
							.getBytesForBlockAlgorithm(curPath);
				} else {
					encodeBytes = curPath.getBytes();
				}

				// Update chain IV
				EncFSCrypto.mac64(volume.getMAC(), encodeBytes, chainIv);
			}
		}

		return chainIv;
	}
}
