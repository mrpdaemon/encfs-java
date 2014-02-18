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
 * Abstract class for providing a custom PBKDF2 implementation
 */
public abstract class EncFSPBKDF2Provider {

	/**
	 * @param passwordLen
	 *            Length of the password provided in 'password'
	 * @param password
	 *            Password to hash
	 * @param saltLen
	 *            Length of the salt provided in 'salt'
	 * @param salt
	 *            Salt data
	 * @param iterations
	 *            Number of PBKDF2 iterations to perform
	 * @param keyLen
	 *            Desired length of the resulting key material in bytes
	 * @return Byte array containing the result of the PBKDF2 computation. null
	 *         if the computation failed.
	 */
	public abstract byte[] doPBKDF2(String password, int saltLen, byte[] salt,
			int iterations, int keyLen);

}