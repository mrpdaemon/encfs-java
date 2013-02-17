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

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.StringTokenizer;

/**
 * Class containing static methods implementing crypto functionality for the
 * rest of the library
 */
public class EncFSCrypto {

  /**
   * Create a new Mac object for the given key.
   *
   * @param key Key to create a new Mac for.
   * @return New Mac object.
   */
  public static Mac newMac(Key key) throws InvalidKeyException,
      EncFSUnsupportedException {
    Mac hmac;
    try {
      hmac = Mac.getInstance("HmacSHA1");
    } catch (NoSuchAlgorithmException e) {
      throw new EncFSUnsupportedException(e);
    }
    SecretKeySpec hmacKey = new SecretKeySpec(key.getEncoded(), "HmacSHA1");
    hmac.init(hmacKey);
    return hmac;
  }

  /**
   * Creates a new AES key with the given key bytes.
   *
   * @param keyBytes Key data.
   * @return New AES key.
   */
  public static Key newKey(byte[] keyBytes) {
    return new SecretKeySpec(keyBytes, "AES");
  }

  /**
   * Returns a new stream cipher with AES/CFB/NoPadding.
   *
   * @return A new Cipher object.
   */
  public static Cipher newStreamCipher() throws EncFSUnsupportedException {
    Cipher result = null;
    try {
      result = Cipher.getInstance("AES/CFB/NoPadding");
    } catch (NoSuchAlgorithmException e) {
      throw new EncFSUnsupportedException(e);
    } catch (NoSuchPaddingException e) {
      throw new EncFSUnsupportedException(e);
    }
    return result;
  }

  /**
   * Returns a new block cipher with AES/CBC/NoPadding.
   *
   * @return A new Cipher object.
   */
  public static Cipher newBlockCipher() throws EncFSUnsupportedException {
    Cipher result = null;
    try {
      result = Cipher.getInstance("AES/CBC/NoPadding");
    } catch (NoSuchAlgorithmException e) {
      throw new EncFSUnsupportedException(e);
    } catch (NoSuchPaddingException e) {
      throw new EncFSUnsupportedException(e);
    }
    return result;
  }

  // Returns an IvParameterSpec for the given iv/seed
  private static IvParameterSpec newIvSpec(Mac mac, byte[] iv, byte[] ivSeed) {

    // TODO: Verify input byte[] lengths, raise Exception on bad ivSeed
    // length

    byte[] concat = new byte[EncFSVolume.IV_LENGTH_IN_BYTES + 8];
    for (int i = 0; i < EncFSVolume.IV_LENGTH_IN_BYTES; i++)
      concat[i] = iv[i];

    if (ivSeed.length == 4) {
      // Concat 4 bytes of IV seed and 4 bytes of 0
      for (int i = EncFSVolume.IV_LENGTH_IN_BYTES; i < EncFSVolume.IV_LENGTH_IN_BYTES + 4; i++)
        concat[i] = ivSeed[EncFSVolume.IV_LENGTH_IN_BYTES + 3 - i];
      for (int i = EncFSVolume.IV_LENGTH_IN_BYTES + 4; i < EncFSVolume.IV_LENGTH_IN_BYTES + 8; i++)
        concat[i] = 0;
    } else {
      // Use 8 bytes from IV seed
      for (int i = EncFSVolume.IV_LENGTH_IN_BYTES; i < EncFSVolume.IV_LENGTH_IN_BYTES + 8; i++)
        concat[i] = ivSeed[EncFSVolume.IV_LENGTH_IN_BYTES + 7 - i];
    }

    // Take first 16 bytes of the SHA-1 output (20 bytes)
    byte[] ivResult = Arrays.copyOfRange(mac.doFinal(concat), 0,
        EncFSVolume.IV_LENGTH_IN_BYTES);

    return new IvParameterSpec(ivResult);
  }

  // Initialize the given cipher in the requested mode
  private static void cipherInit(Key key, Mac mac, int opMode, Cipher cipher,
                                 byte[] iv, byte[] ivSeed) throws InvalidAlgorithmParameterException {
    try {
      cipher.init(opMode, key, newIvSpec(mac, iv, ivSeed));
    } catch (InvalidKeyException e) {
      e.printStackTrace();
    }
  }

  /**
   * Initialize the given cipher for a volume with the given parameters
   *
   * @param volume Volume to initialize the cipher for
   * @param opMode Operation mode of the cipher
   * @param cipher Cipher object
   * @param ivSeed IV seed for initialization
   *               <p/>
   *               Inappropriate algorithm parameters
   */
  public static void cipherInit(EncFSVolume volume, int opMode,
                                Cipher cipher, byte[] ivSeed)
      throws InvalidAlgorithmParameterException {
    cipherInit(volume.getVolumeCryptKey(), volume.getVolumeMAC(), opMode, cipher,
        volume.getIV(), ivSeed);
  }

  /**
   * Derive password-based key from input/config parameters using PBKDF2
   *
   * @param config         Volume configuration
   * @param password       Volume password
   * @param pbkdf2Provider Custom PBKDF2 provider implementation
   * @return Derived PBKDF2 key + IV bits
   */
  public static byte[] derivePasswordKey(EncFSConfig config, String password,
                                         EncFSPBKDF2Provider pbkdf2Provider)
      throws EncFSInvalidConfigException, EncFSUnsupportedException {
    // Decode base 64 salt data
    byte[] cipherSaltData;
    try {
      cipherSaltData = EncFSBase64.decode(config.getBase64Salt());
    } catch (IOException e) {
      throw new EncFSInvalidConfigException("Corrupt salt data in config");
    }

    if (pbkdf2Provider == null) {
      // Execute PBKDF2 to derive key data from the password
      SecretKeyFactory f;
      try {
        f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
      } catch (NoSuchAlgorithmException e) {
        throw new EncFSUnsupportedException(e);
      }
      KeySpec ks = new PBEKeySpec(password.toCharArray(), cipherSaltData, config.getIterationForPasswordKeyDerivationCount(), config.getVolumeKeySizeInBits() + EncFSVolume.IV_LENGTH_IN_BYTES * 8);
      SecretKey pbkdf2Key;
      try {
        pbkdf2Key = f.generateSecret(ks);
      } catch (InvalidKeySpecException e) {
        throw new EncFSInvalidConfigException(e);
      }

      return pbkdf2Key.getEncoded();
    } else {
      return pbkdf2Provider.doPBKDF2(password.length(), password,
          cipherSaltData.length, cipherSaltData,
          config.getIterationForPasswordKeyDerivationCount(), (config.getVolumeKeySizeInBits() / 8)
          + EncFSVolume.IV_LENGTH_IN_BYTES);
    }
  }

  /**
   * Derive volume key for the given config and password-based key/IV data
   *
   * @param config     Volume configuration
   * @param pbkdf2Data PBKDF2 key material + IV (from derivePasswordKey())
   * @return Volume key + IV bits
   */
  public static byte[] decryptVolumeKey(EncFSConfig config, byte[] pbkdf2Data)
      throws EncFSChecksumException, EncFSInvalidConfigException,
      EncFSCorruptDataException, EncFSUnsupportedException {
    // Decode Base64 encoded ciphertext data
    // TODO: validate key/IV lengths
    byte[] cipherVolKeyData;
    try {
      cipherVolKeyData = EncFSBase64.decode(config.getBase64EncodedVolumeKey());
    } catch (IOException e) {
      throw new EncFSInvalidConfigException("Corrupt key data in config");
    }

    byte[] encryptedVolKey = Arrays.copyOfRange(cipherVolKeyData, 4,
        cipherVolKeyData.length);

    // Prepare key/IV for decryption
    int keySizeInBytes = config.getVolumeKeySizeInBits() / 8;
    byte[] passKeyData = Arrays.copyOfRange(pbkdf2Data, 0, keySizeInBytes);
    byte[] passIvData = Arrays.copyOfRange(pbkdf2Data, keySizeInBytes,
        keySizeInBytes + EncFSVolume.IV_LENGTH_IN_BYTES);

    Key passKey = newKey(passKeyData);
    byte[] ivSeed = Arrays.copyOfRange(cipherVolKeyData, 0, 4);

    // Decrypt the volume key data
    Mac mac;
    try {
      mac = newMac(passKey);
    } catch (InvalidKeyException e) {
      throw new EncFSInvalidConfigException(e);
    }
    byte[] clearVolKeyData = null;
    try {
      clearVolKeyData = streamDecode(newStreamCipher(), mac, passKey,
          passIvData, ivSeed, encryptedVolKey);
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSInvalidConfigException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    }

    // Perform checksum computation
    byte[] mac32 = mac32(mac, clearVolKeyData, new byte[0]);

    if (!Arrays.equals(ivSeed, mac32)) {
      throw new EncFSChecksumException("Volume key checksum mismatch");
    }

    return clearVolKeyData;
  }

  /**
   * Derive volume key for the given config and password-based key/IV data
   *
   * @param config     Volume configuration
   * @param pbkdf2Data PBKDF2 key material + IV (from derivePasswordKey())
   * @return Volume key + IV bits
   */
  public static byte[] encryptVolumeKey(EncFSConfig config,
                                        byte[] pbkdf2Data, byte[] volKeyData)
      throws EncFSUnsupportedException, EncFSInvalidConfigException,
      EncFSCorruptDataException {
    // Prepare key/IV for decryption
    int keySizeInBytes = config.getVolumeKeySizeInBits() / 8;
    byte[] passKeyData = Arrays.copyOfRange(pbkdf2Data, 0, keySizeInBytes);
    byte[] passIvData = Arrays.copyOfRange(pbkdf2Data, keySizeInBytes,
        keySizeInBytes + EncFSVolume.IV_LENGTH_IN_BYTES);

    Key passKey = newKey(passKeyData);

    // Encrypt the volume key data
    Mac mac;
    try {
      mac = newMac(passKey);
    } catch (InvalidKeyException e) {
      throw new EncFSInvalidConfigException(e);
    }

    // Calculate MAC for the key
    byte[] mac32 = mac32(mac, volKeyData, new byte[0]);

    // Encrypt the key data
    byte[] cipherVolKeyData = null;
    try {
      cipherVolKeyData = streamEncode(newStreamCipher(), mac, passKey,
          passIvData, mac32, volKeyData);
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSInvalidConfigException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    }

    // Combine MAC with key data
    byte[] result = new byte[mac32.length + cipherVolKeyData.length];

    for (int i = 0; i < mac32.length; i++) {
      result[i] = mac32[i];
    }

    for (int i = 0; i < cipherVolKeyData.length; i++) {
      result[i + mac32.length] = cipherVolKeyData[i];
    }

    return result;
  }

  /**
   * Encodes the given volume key using the supplied password parameters,
   * placing it into the EncFSConfig
   *
   * @param config         Partially initialized volume configuration
   * @param password       Password to use for encoding the key
   * @param volKey         Volume key to encode
   * @param pbkdf2Provider Custom PBKDF2 provider implementation
   */
  public static void encodeVolumeKey(EncFSConfig config, String password,
                                     byte[] volKey, EncFSPBKDF2Provider pbkdf2Provider)
      throws EncFSInvalidConfigException, EncFSUnsupportedException,
      EncFSCorruptDataException {
    SecureRandom random = new SecureRandom();
    config.setSaltLengthBytes(20);

    // Generate random salt
    byte[] salt = new byte[20];
    random.nextBytes(salt);
    config.setBase64Salt(EncFSBase64.encodeBytes(salt));

    // Get password key data
    byte[] pbkdf2Data = derivePasswordKey(config, password, pbkdf2Provider);

    // Encode volume key
    byte[] encodedVolKey = encryptVolumeKey(config, pbkdf2Data, volKey);

    config.setEncodedKeyLengthInBytes(encodedVolKey.length);
    config.setBase64EncodedVolumeKey(EncFSBase64.encodeBytes(encodedVolKey));
  }

  // Decode the given input bytes using stream cipher
  private static byte[] streamDecode(Cipher cipher, Mac mac, Key key,
                                     byte[] iv, byte[] ivSeed, byte[] data, int offset, int len)
      throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    // First round uses IV seed + 1 for IV generation
    byte[] ivSeedPlusOne = incrementIvSeedByOne(ivSeed);

    cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv, ivSeedPlusOne);
    byte[] firstDecResult = cipher.doFinal(data, offset, len);

    unshuffleBytes(firstDecResult);

    byte[] flipBytesResult = flipBytes(firstDecResult);

    // Second round of decryption with IV seed itself used for IV generation
    cipherInit(key, mac, Cipher.DECRYPT_MODE, cipher, iv, ivSeed);
    byte[] result = cipher.doFinal(flipBytesResult);

    unshuffleBytes(result);

    return result;
  }

  // Decode the given input bytes using stream cipher
  private static byte[] streamDecode(Cipher cipher, Mac mac, Key key,
                                     byte[] iv, byte[] ivSeed, byte[] data)
      throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    return streamDecode(cipher, mac, key, iv, ivSeed, data, 0, data.length);
  }

  /**
   * Decode the given data using stream mode
   *
   * @param volume Volume for the data
   * @param ivSeed IV seed for the decryption
   * @param data   Encrypted data contents
   * @return Decrypted (plaintext) data
   *         <p/>
   *         <p/>
   *         Invalid algorithm parameters
   */
  public static byte[] streamDecode(EncFSVolume volume, byte[] ivSeed,
                                    byte[] data) throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    return streamDecode(volume.getStreamCipher(), volume.getVolumeMAC(),
        volume.getVolumeCryptKey(), volume.getIV(), ivSeed, data);
  }

  /**
   * Decode the given data using stream mode
   *
   * @param volume Volume for the data
   * @param ivSeed IV seed for the decryption
   * @param data   Encrypted data contents
   * @param offset Offset into the data buffer to decode from
   * @param len    Number of bytes in the data buffer to decode
   * @return Decrypted (plaintext) data
   *         <p/>
   *         <p/>
   *         Invalid algorithm parameters
   */
  public static byte[] streamDecode(EncFSVolume volume, byte[] ivSeed,
                                    byte[] data, int offset, int len) throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    return streamDecode(volume.getStreamCipher(), volume.getVolumeMAC(),
        volume.getVolumeCryptKey(), volume.getIV(), ivSeed, data, offset, len);
  }

  // Encode the given data in stream mode
  private static byte[] streamEncode(Cipher cipher, Mac mac, Key key,
                                     byte[] iv, byte[] ivSeed, byte[] data, int offset, int len)
      throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    // First round uses IV seed + 1 for IV generation
    byte[] ivSeedPlusOne = incrementIvSeedByOne(ivSeed);

    byte[] encBuf = Arrays.copyOfRange(data, offset, offset + len);
    shuffleBytes(encBuf);

    cipherInit(key, mac, Cipher.ENCRYPT_MODE, cipher, iv, ivSeed);
    byte[] firstEncResult = cipher.doFinal(encBuf);

    byte[] flipBytesResult = flipBytes(firstEncResult);

    shuffleBytes(flipBytesResult);

    // Second round of encryption with IV seed itself used for IV generation
    cipherInit(key, mac, Cipher.ENCRYPT_MODE, cipher, iv, ivSeedPlusOne);
    byte[] result = cipher.doFinal(flipBytesResult);

    return result;
  }

  private static byte[] streamEncode(Cipher cipher, Mac mac, Key key,
                                     byte[] iv, byte[] ivSeed, byte[] data)
      throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    return streamEncode(cipher, mac, key, iv, ivSeed, data, 0, data.length);
  }

  /**
   * Encode the given data using stream mode
   *
   * @param volume Volume for the data
   * @param ivSeed IV seed for the encryption
   * @param data   Plaintext data contents
   * @return Encrypted (ciphertext) data
   *         <p/>
   *         <p/>
   *         Invalid algorithm parameters
   */
  public static byte[] streamEncode(EncFSVolume volume, byte[] ivSeed,
                                    byte[] data) throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    return streamEncode(volume.getStreamCipher(), volume.getVolumeMAC(),
        volume.getVolumeCryptKey(), volume.getIV(), ivSeed, data);
  }

  /**
   * Encode the given data using stream mode
   *
   * @param volume Volume for the data
   * @param ivSeed IV seed for the encryption
   * @param data   Plaintext data contents
   * @param offset Offset into the data buffer to start encoding from
   * @param len    Length of the data in the data buffer to encode
   * @return Encrypted (ciphertext) data
   *         <p/>
   *         <p/>
   *         Invalid algorithm parameters
   */
  public static byte[] streamEncode(EncFSVolume volume, byte[] ivSeed,
                                    byte[] data, int offset, int len) throws EncFSUnsupportedException,
      InvalidAlgorithmParameterException, IllegalBlockSizeException,
      BadPaddingException {
    return streamEncode(volume.getStreamCipher(), volume.getVolumeMAC(),
        volume.getVolumeCryptKey(), volume.getIV(), ivSeed, data, offset, len);
  }

  private static byte[] blockOperation(EncFSVolume volume, byte[] ivSeed,
                                       byte[] data, int opMode) throws InvalidAlgorithmParameterException,
      IllegalBlockSizeException, BadPaddingException {
    // if (data.length != volume.getVolumeConfiguration().getEncryptedFileBlockSizeInBytes()) {
    // throw new
    // IllegalBlockSizeException("Data length must match block size ("
    // + volume.getVolumeConfiguration().getEncryptedFileBlockSizeInBytes() + " vs. " + data.length);
    // }
    Cipher cipher = volume.getBlockCipher();
    cipherInit(volume, opMode, cipher, ivSeed);
    byte[] result = cipher.doFinal(data);
    return result;
  }

  /**
   * Decode the given data using block mode
   *
   * @param volume Volume for the data
   * @param ivSeed IV seed for the decryption
   * @param data   Encrypted data contents
   * @return Decrypted (plaintext) data
   *         <p/>
   *         Invalid algorithm parameters
   */
  public static byte[] blockDecode(EncFSVolume volume, byte[] ivSeed,
                                   byte[] data) throws InvalidAlgorithmParameterException,
      IllegalBlockSizeException, BadPaddingException {
    return blockOperation(volume, ivSeed, data, Cipher.DECRYPT_MODE);
  }

  /**
   * Encode the given data using block mode
   *
   * @param volume Volume for the data
   * @param ivSeed IV seed for the encryption
   * @param data   Plaintext data contents
   * @return Encrypted (ciphertext) data
   *         <p/>
   *         Invalid algorithm parameters
   */
  public static byte[] blockEncode(EncFSVolume volume, byte[] ivSeed,
                                   byte[] data) throws IllegalBlockSizeException,
      InvalidAlgorithmParameterException, BadPaddingException {
    return blockOperation(volume, ivSeed, data, Cipher.ENCRYPT_MODE);
  }

  /**
   * Compute chain IV for the given volume path
   *
   * @param volume     Volume to compute chain IV for
   * @param volumePath Volume path to compute chain IV for
   * @return Computed chain IV
   */
  public static byte[] computeChainIv(EncFSVolume volume, String volumePath) {
    byte[] chainIv = new byte[8];
    StringTokenizer st = new StringTokenizer(volumePath,
        EncFSVolume.PATH_SEPARATOR);
    while (st.hasMoreTokens()) {
      String curPath = st.nextToken();
      if ((curPath.length() > 0)
          && (curPath != EncFSVolume.PATH_SEPARATOR)) {

        byte[] encodeBytes;

        if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.BLOCK) {
          encodeBytes = getBytesForBlockAlgorithm(curPath);
        } else {
          encodeBytes = curPath.getBytes();
        }

        // Update chain IV
        EncFSCrypto.mac64(volume.getVolumeMAC(), encodeBytes, chainIv);
      }
    }

    return chainIv;
  }

  private static byte[] getBytesForBlockAlgorithm(String curPath) {
    byte[] encodeBytes;// Only pad for block mode
    int padLen = 16 - (curPath.length() % 16);
    if (padLen == 0) {
      padLen = 16;
    }
    encodeBytes = new byte[curPath.length() + padLen];

    for (int i = 0; i < curPath.length(); i++) {
      encodeBytes[i] = curPath.getBytes()[i];
    }

    // Pad to the nearest 16 bytes, add a full block if needed
    for (int i = 0; i < padLen; i++) {
      encodeBytes[curPath.length() + i] = (byte) padLen;
    }
    return encodeBytes;
  }

  /**
   * Decode the given fileName under the given volume and volume path
   *
   * @param volume     Volume hosting the file
   * @param fileName   Encrypted file name
   * @param volumePath Cleartext path of the file in the volume
   * @return Decrypted file name
   */
  public static String decodeName(EncFSVolume volume, String fileName,
                                  String volumePath) throws EncFSCorruptDataException,
      EncFSChecksumException {

    // No decryption for nameio/null algorithm
    if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.NULL) {
      // Filter out config file
      if (volumePath.equals(volume.getRootDir().getPath()) && fileName.equals(EncFSVolume.CONFIG_FILE_NAME)) {
        return null;
      }
      return new String(fileName);
    }

    byte[] base256FileName = EncFSBase64.decodeEncfs(fileName.getBytes());

    byte[] encFileName = Arrays.copyOfRange(base256FileName, 2,
        base256FileName.length);

    // TODO: make sure its multiple of 16
    byte[] macBytes = new byte[8];
    macBytes[6] = base256FileName[0];
    macBytes[7] = base256FileName[1];

    byte[] chainIv = new byte[8];

    // Chained IV computation
    if (volume.getVolumeConfiguration().isChainedNameIV()) {
      chainIv = computeChainIv(volume, volumePath);
    }

    byte[] fileIv = new byte[8];
    for (int i = 0; i < 8; i++) {
      fileIv[i] = (byte) (macBytes[i] ^ chainIv[i]);
    }

    byte[] decFileName;

    try {
      if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.BLOCK) {
        decFileName = EncFSCrypto.blockDecode(volume, fileIv, encFileName);
      } else {
        decFileName = EncFSCrypto.streamDecode(volume, fileIv, encFileName);
      }
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSCorruptDataException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    } catch (EncFSUnsupportedException e) {
      throw new EncFSCorruptDataException(e);
    }

    // Verify decryption worked
    // current versions store the checksum at the beginning (encfs 0.x
    // stored checksums at the end)
    byte[] mac16;
    if (volume.getVolumeConfiguration().isChainedNameIV()) {
      mac16 = EncFSCrypto.mac16(volume.getVolumeMAC(), decFileName, chainIv);
    } else {
      mac16 = EncFSCrypto.mac16(volume.getVolumeMAC(), decFileName);
    }
    byte[] expectedMac = Arrays.copyOfRange(base256FileName, 0, 2);
    if (!Arrays.equals(mac16, expectedMac)) {
      throw new EncFSChecksumException("Mismatch in file name checksum");
    }

    // For the stream cipher directly return the result
    if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.STREAM) {
      return new String(decFileName);
    }

    // For the block cipher remove padding before returning the result
    int padLen = decFileName[decFileName.length - 1];

    return new String(Arrays.copyOfRange(decFileName, 0, decFileName.length
        - padLen));
  }

  /**
   * Encode the given fileName under the given volume and volume path
   *
   * @param volume     Volume hosting the file
   * @param fileName   Cleartext file name
   * @param volumePath Cleartext path of the file in the volume
   * @return Encrypted file name
   */
  public static String encodeName(EncFSVolume volume, String fileName,
                                  String volumePath) throws EncFSCorruptDataException {

    // No encryption for nameio/null algorithm
    if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.NULL) {
      return fileName;
    }

    byte[] decFileName = fileName.getBytes();

    byte[] paddedDecFileName;
    if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.BLOCK) {
      // Pad to the nearest 16 bytes, add a full block if needed
      int padBytesSize = 16;
      int padLen = padBytesSize - (decFileName.length % padBytesSize);
      if (padLen == 0) {
        padLen = padBytesSize;
      }
      paddedDecFileName = Arrays.copyOf(decFileName, decFileName.length + padLen);
      Arrays.fill(paddedDecFileName, decFileName.length, paddedDecFileName.length, (byte) padLen);
    } else {
      // Stream encryption
      paddedDecFileName = decFileName;
    }

    byte[] chainIv = new byte[8];

    // Chained IV computation
    if (volume.getVolumeConfiguration().isChainedNameIV()) {
      chainIv = computeChainIv(volume, volumePath);
    }

    byte[] mac16;
    if (volume.getVolumeConfiguration().isChainedNameIV()) {
      mac16 = EncFSCrypto.mac16(volume.getVolumeMAC(), paddedDecFileName,
          Arrays.copyOf(chainIv, chainIv.length));
    } else {
      mac16 = EncFSCrypto.mac16(volume.getVolumeMAC(), paddedDecFileName);
    }

    // TODO: make sure its multiple of 16
    byte[] macBytes = new byte[8];
    macBytes[6] = mac16[0];
    macBytes[7] = mac16[1];

    byte[] fileIv = new byte[8];
    for (int i = 0; i < 8; i++) {
      fileIv[i] = (byte) (macBytes[i] ^ chainIv[i]);
    }

    byte[] encFileName;
    try {
      if (volume.getVolumeConfiguration().getAlgorithm() == EncFSAlgorithm.BLOCK) {
        encFileName = EncFSCrypto.blockEncode(volume, fileIv, paddedDecFileName);
      } else {
        encFileName = EncFSCrypto.streamEncode(volume, fileIv, paddedDecFileName);
      }
    } catch (InvalidAlgorithmParameterException e) {
      throw new EncFSCorruptDataException(e);
    } catch (IllegalBlockSizeException e) {
      throw new EncFSCorruptDataException(e);
    } catch (BadPaddingException e) {
      throw new EncFSCorruptDataException(e);
    } catch (EncFSUnsupportedException e) {
      throw new EncFSCorruptDataException(e);
    }

    // current versions store the checksum at the beginning (encfs 0.x
    // stored checksums at the end)

    byte[] base256FileName = new byte[encFileName.length + 2];
    base256FileName[0] = mac16[0];
    base256FileName[1] = mac16[1];
    System.arraycopy(encFileName, 0, base256FileName, 2, encFileName.length);

    byte[] fileNameOutput = EncFSBase64.encodeEncfs(base256FileName);

    return new String(fileNameOutput);
  }

  /**
   * Encode a given path under the given volume and volume path
   *
   * @param volume     Volume hosting the path
   * @param pathName   Cleartext name of the path to encode (relative to volumePath)
   * @param volumePath Cleartext volume path containing the path to encode
   * @return Encrypted path
   */
  public static String encodePath(EncFSVolume volume, String pathName,
                                  String volumePath) throws EncFSCorruptDataException {
    String[] pathParts = pathName.split(EncFSVolume.PATH_SEPARATOR);
    String tmpVolumePath = volumePath;
    String result = "";
    if (pathName.startsWith(EncFSVolume.PATH_SEPARATOR)) {
      result += EncFSVolume.PATH_SEPARATOR;
    }

    for (int i = 0; i < pathParts.length; i++) {
      String pathPart = pathParts[i];

      // Check that we have a valid pathPart (to handle cases of // in the
      // path)
      if (pathPart.length() > 0) {
        String toEncFileName = EncFSCrypto.encodeName(volume, pathPart,
            tmpVolumePath);

        if (result.length() > 0
            && result.endsWith(EncFSVolume.PATH_SEPARATOR) == false) {
          result += EncFSVolume.PATH_SEPARATOR;
        }

        result += toEncFileName;

        if (tmpVolumePath.endsWith(EncFSVolume.PATH_SEPARATOR) == false) {
          tmpVolumePath += EncFSVolume.PATH_SEPARATOR;
        }
        tmpVolumePath += pathPart;
      }
    }

    return result;
  }

  /**
   * Compute 64-bit MAC over the given input bytes
   *
   * @param mac         MAC object to use
   * @param input       Input bytes
   * @param inputOffset Offset into 'input' to start computing MAC from
   * @return Computed 64-bit MAC result
   */
  protected static byte[] mac64(Mac mac, byte[] input, int inputOffset) {
    return mac64(mac, input, inputOffset, input.length - inputOffset);
  }

  /**
   * Compute 64-bit MAC over the given input bytes
   *
   * @param mac         MAC object to use
   * @param input       Input bytes
   * @param inputOffset Offset into 'input' to start computing MAC from
   * @param inputLen    Number of bytes to compute MAC for
   * @return Computed 64-bit MAC result
   */
  protected static byte[] mac64(Mac mac, byte[] input, int inputOffset,
                                int inputLen) {
    mac.reset();
    mac.update(input, inputOffset, inputLen);
    byte[] macResult = mac.doFinal();
    byte[] mac64 = new byte[8];
    for (int i = 0; i < 19; i++)
      // Note the 19 not 20
      mac64[i % 8] ^= macResult[i];

    return mac64;
  }

  // Compute 64-bit MAC
  private static byte[] mac64(Mac mac, byte[] input) {

    byte[] macResult = mac.doFinal(input);
    byte[] mac64 = new byte[8];
    for (int i = 0; i < 19; i++)
      // Note the 19 not 20
      mac64[i % 8] ^= macResult[i];

    return mac64;
  }

  // Compute 32-bit MAC
  private static byte[] mac32(Mac mac, byte[] input) {
    byte[] mac64 = mac64(mac, input);
    byte[] mac32 = new byte[4];
    mac32[0] = (byte) (mac64[4] ^ mac64[0]);
    mac32[1] = (byte) (mac64[5] ^ mac64[1]);
    mac32[2] = (byte) (mac64[6] ^ mac64[2]);
    mac32[3] = (byte) (mac64[7] ^ mac64[3]);

    return mac32;
  }

  // Compute 16-bit MAC
  private static byte[] mac16(Mac mac, byte[] input) {
    byte[] mac32 = mac32(mac, input);
    byte[] mac16 = new byte[2];
    mac16[0] = (byte) (mac32[2] ^ mac32[0]);
    mac16[1] = (byte) (mac32[3] ^ mac32[1]);

    return mac16;
  }

  // Compute 64-bit MAC and update chainedIv
  private static byte[] mac64(Mac mac, byte[] input, byte[] chainedIv) {
    byte[] concat = new byte[input.length + chainedIv.length];
    for (int i = 0; i < input.length; i++) {
      concat[i] = input[i];
    }
    for (int i = input.length; i < input.length + chainedIv.length; i++) {
      concat[i] = chainedIv[7 - (i - input.length)];
    }
    byte[] macResult = mac.doFinal(concat);
    byte[] mac64 = new byte[8];
    for (int i = 0; i < 19; i++)
      // Note the 19 not 20
      mac64[i % 8] ^= macResult[i];

    if (chainedIv.length > 0) {
      // Propagate the result as the new chained IV
      for (int i = 0; i < 8; i++) {
        chainedIv[i] = mac64[i];
      }
    }

    return mac64;
  }

  // Compute 32-bit MAC and update chainedIv
  private static byte[] mac32(Mac mac, byte[] input, byte[] chainedIv) {
    byte[] mac64 = mac64(mac, input, chainedIv);
    byte[] mac32 = new byte[4];
    mac32[0] = (byte) (mac64[4] ^ mac64[0]);
    mac32[1] = (byte) (mac64[5] ^ mac64[1]);
    mac32[2] = (byte) (mac64[6] ^ mac64[2]);
    mac32[3] = (byte) (mac64[7] ^ mac64[3]);

    return mac32;
  }

  // Compute 16-bit MAC and update chainedIv
  private static byte[] mac16(Mac mac, byte[] input, byte[] chainedIv) {
    byte[] mac32 = mac32(mac, input, chainedIv);
    byte[] mac16 = new byte[2];
    mac16[0] = (byte) (mac32[2] ^ mac32[0]);
    mac16[1] = (byte) (mac32[3] ^ mac32[1]);

    return mac16;
  }

  private static void unshuffleBytes(byte[] input) {
    for (int i = (input.length - 1); i > 0; i--) {
      // Note size - 1
      input[i] ^= input[i - 1];
    }
  }

  private static void shuffleBytes(byte[] buf) {
    int size = buf.length;
    for (int i = 0; i < size - 1; ++i) {
      buf[i + 1] ^= buf[i];
    }
  }

  private static byte[] flipBytes(byte[] input) {
    byte[] result = new byte[input.length];

    int offset = 0;
    int bytesLeft = input.length;

    while (bytesLeft > 0) {
      // TODO: 64 should be defined?
      int toFlip = Math.min(64, bytesLeft);

      for (int i = 0; i < toFlip; i++)
        result[offset + i] = input[offset + toFlip - i - 1];

      bytesLeft -= toFlip;
      offset += toFlip;
    }

    return result;
  }

  private static byte[] incrementIvSeedByOne(byte[] ivSeed) throws EncFSUnsupportedException {
    if (ivSeed.length == 4) {
      return EncFSUtil.convertIntToByteArrayBigEndian(EncFSUtil.convertBigEndianByteArrayToInt(ivSeed) + 1);
    } else if (ivSeed.length == 8) {
      return EncFSUtil.convertLongToByteArrayBigEndian(EncFSUtil.convertByteArrayToLong(ivSeed) + 1);
    } else {
      throw new EncFSUnsupportedException("Unsupported IV length");
    }
  }
}
