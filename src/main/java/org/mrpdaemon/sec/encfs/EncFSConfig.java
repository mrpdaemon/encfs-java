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
 * Class representing volume configuration data for an EncFS volume.
 */
public class EncFSConfig {

  /**
   * Volume configuration uses nameio/block for filename encryption
   */
  public static final int ENCFS_CONFIG_NAME_ALG_BLOCK = 1;

  /**
   * Volume configuration uses nameio/stream for filename encryption
   */
  public static final int ENCFS_CONFIG_NAME_ALG_STREAM = 2;

  /**
   * Volume configuration uses nameio/null for filename encryption
   */
  public final static int ENCFS_CONFIG_NAME_ALG_NULL = 3;

  // Size of the volume encryption key in bits.
  private int volumeKeySize;

  // Size of encrypted file blocks in bytes.
  private int blockSize;

  // Whether unique IV is being used.
  private boolean uniqueIV;

  /*
   * Whether name IV chaining is being used. When using IV chaining, each
   * parent element in a file's path contributes to the IV that is used to
   * encrypt the file's name.
   */
  private boolean chainedNameIV;

  // Whether holes are allowed in files.
  private boolean holesAllowed;

  // Length of the encoded key data in bytes.
  private int encodedKeyLength;

  /*
   * String containing the Base64 encoded representation of the volume
   * encryption key encrypted with the password generated key.
   */
  private String encodedKeyStr;

  // Length of the salt data in bytes.
  private int saltLength;

  /*
   * String containing the salt data applied to the password hash for
   * generating the password derived key.
   */
  private String saltStr;

  // Iteration count used in the generation of the password derived key.
  private int iterationCount;

  // Algorithm used for file name encryption
  private int nameAlgorithm;

  // Number of MAC bytes for each file block
  private int blockMACBytes;

  // Number of random bytes in each block MAC header
  private int blockMACRandBytes;

  // Whether externalIVChaining is supported
  private boolean externalIVChaining;

  /**
   * Creates a default EncFS configuration that encfs-java supports
   */
  public EncFSConfig() {
    setNameAlgorithm(ENCFS_CONFIG_NAME_ALG_BLOCK);
    setVolumeKeySize(192);
    setBlockSize(1024);
    setUniqueIV(true);
    setChainedNameIV(true);
    setHolesAllowed(true);
    setIterationCount(5000);
    setBlockMACBytes(0);
    setBlockMACRandBytes(0);
    setExternalIVChaining(false);
  }

  /**
   * Returns the size of the volume encryption key in bits.
   *
   * @return the size of the volume encryption key in bits.
   */
  public int getVolumeKeySize() {
    return volumeKeySize;
  }

  /**
   * Sets the size of the volume encryption key in bits.
   *
   * @param volumeKeySize the size of the volume encryption key in bits.
   */
  public void setVolumeKeySize(int volumeKeySize) {
    this.volumeKeySize = volumeKeySize;
  }

  /**
   * Returns the size of encrypted file blocks in bytes.
   *
   * @return size of encrypted file blocks in bytes.
   */
  public int getBlockSize() {
    return blockSize;
  }

  /**
   * Sets the size of encrypted file blocks in bytes.
   *
   * @param blockSize size of encrypted file blocks in bytes.
   */
  public void setBlockSize(int blockSize) {
    this.blockSize = blockSize;
  }

  /**
   * Checks whether unique IV is being used.
   *
   * @return whether unique IV is being used.
   */
  public boolean isUniqueIV() {
    return uniqueIV;
  }

  /**
   * Sets whether unique IV is being used.
   *
   * @param uniqueIV whether unique IV is being used.
   */
  public void setUniqueIV(boolean uniqueIV) {
    this.uniqueIV = uniqueIV;
  }

  /**
   * When using IV chaining, each parent element in a file's path contributes
   * to the IV that is used to encrypt the file's name.
   *
   * @return whether name IV chaining is being used.
   */
  public boolean isChainedNameIV() {
    return chainedNameIV;
  }

  /**
   * When using IV chaining, each parent element in a file's path contributes
   * to the IV that is used to encrypt the file's name.
   *
   * @param chainedNameIV whether name IV chaining is being used.
   */
  public void setChainedNameIV(boolean chainedNameIV) {
    this.chainedNameIV = chainedNameIV;
  }

  /**
   * Checks whether holes are allowed in files.
   *
   * @return whether holes are allowed in files.
   */
  public boolean isHolesAllowed() {
    return holesAllowed;
  }

  /**
   * Sets whether holes are allowed in files.
   *
   * @param holesAllowed whether holes are allowed in files.
   */
  public void setHolesAllowed(boolean holesAllowed) {
    this.holesAllowed = holesAllowed;
  }

  /**
   * Returns the length of the encoded key data in bytes.
   *
   * @return length of the encoded key data in bytes.
   */
  public int getEncodedKeyLength() {
    return encodedKeyLength;
  }

  /**
   * Sets the length of the encoded key data in bytes.
   *
   * @param encodedKeyLength length of the encoded key data in bytes.
   */
  public void setEncodedKeyLength(int encodedKeyLength) {
    this.encodedKeyLength = encodedKeyLength;
  }

  /**
   * Returns the Base64 encoded representation of the volume encryption key
   * encrypted with the password generated key.
   *
   * @return string containing the Base64 encoded representation of the volume
   *         encryption key encrypted with the password generated key.
   */
  public String getEncodedKeyStr() {
    return encodedKeyStr;
  }

  /**
   * Sets the volume encryption key string
   *
   * @param encodedKeyStr string containing the Base64 encoded representation of the
   *                      volume encryption key encrypted with the password generated
   *                      key.
   */
  public void setEncodedKeyStr(String encodedKeyStr) {
    this.encodedKeyStr = encodedKeyStr;
  }

  /**
   * Returns the salt length
   *
   * @return the saltLength
   */
  public int getSaltLength() {
    return saltLength;
  }

  /**
   * Sets the salt length
   *
   * @param saltLength length of the salt data in bytes.
   */
  public void setSaltLength(int saltLength) {
    this.saltLength = saltLength;
  }

  /**
   * Returns the Base64 encoded salt string
   *
   * @return string containing the salt data applied to the password hash for
   *         generating the password derived key.
   */
  public String getSaltStr() {
    return saltStr;
  }

  /**
   * Set the Base64 encoded salt string
   *
   * @param saltStr string containing the salt data applied to the password hash
   *                for generating the password derived key.
   */
  public void setSaltStr(String saltStr) {
    this.saltStr = saltStr;
  }

  /**
   * Returns the iteration count
   *
   * @return iteration count used in the generation of the password derived
   *         key.
   */
  public int getIterationCount() {
    return iterationCount;
  }

  /**
   * Set the iteration count
   *
   * @param iterationCount iteration count used in the generation of the password derived
   *                       key.
   */
  public void setIterationCount(int iterationCount) {
    this.iterationCount = iterationCount;
  }

  /**
   * Returns the filename encryption algorithm
   *
   * @return algorithm used for filename encryption
   */
  public int getNameAlgorithm() {
    return nameAlgorithm;
  }

  /**
   * Set the filename encryption algorithm
   *
   * @param nameAlgorithm algorithm used for filename encryption
   */
  public void setNameAlgorithm(int nameAlgorithm) {
    this.nameAlgorithm = nameAlgorithm;
  }

  /**
   * Returns the number of MAC bytes in file block headers
   *
   * @return number of MAC bytes in file block headers
   */
  public int getBlockMACBytes() {
    return blockMACBytes;
  }

  /**
   * Set the number of MAC bytes in file block headers
   *
   * @param blockMACBytes number of MAC bytes in file block headers
   */
  public void setBlockMACBytes(int blockMACBytes) {
    this.blockMACBytes = blockMACBytes;
  }

  /**
   * Returns the number of random bytes in file block headers
   *
   * @return number of random bytes in file block headers
   */
  public int getBlockMACRandBytes() {
    return blockMACRandBytes;
  }

  /**
   * Sets the number of random bytes in file block headers
   *
   * @param blockMACRandBytes number of random bytes in file block headers
   */
  public void setBlockMACRandBytes(int blockMACRandBytes) {
    this.blockMACRandBytes = blockMACRandBytes;
  }

  /**
   * Checks whether external IV chaining is used.
   *
   * @return whether external IV chaining is used.
   */
  public boolean isExternalIVChaining() {
    return externalIVChaining;
  }

  /**
   * When using external IV chaining, each parent element in a file's path
   * contributes to the IV that is used to encrypt the file's contents.
   *
   * @param externalIVChaining whether external IV chaining is being used.
   */
  public void setExternalIVChaining(boolean externalIVChaining) {
    this.externalIVChaining = externalIVChaining;
  }

  /**
   * Validate this configuration
   *
   * @throws EncFSInvalidConfigException Configuration is invalid
   */
  public void validate() throws EncFSInvalidConfigException {
    if (isExternalIVChaining()) {
      if (!isChainedNameIV() || !isUniqueIV()) {
        throw new EncFSInvalidConfigException(
            "External IV chaining requires chained name IV and "
                + "unique IV to be enabled");
      }
    }
  }

  /*
   * (non-Javadoc)
   *
   * @see java.lang.Object#toString()
   */
  @Override
  public String toString() {
    return "EncFSConfig [volumeKeySize=" + volumeKeySize + ", blockSize="
        + blockSize + ", uniqueIV=" + uniqueIV + ", chainedNameIV="
        + chainedNameIV + ", holesAllowed=" + holesAllowed
        + ", encodedKeyLength=" + encodedKeyLength + ", encodedKeyStr="
        + encodedKeyStr + ", saltLength=" + saltLength + ", saltStr="
        + saltStr + ", iterationCount=" + iterationCount
        + ", nameAlgorithm=" + nameAlgorithm + ", blockMACBytes="
        + blockMACBytes + ", blockMACRandBytes=" + blockMACRandBytes
        + ", externalIVChaining=" + externalIVChaining + "]";
  }

}