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

public class EncFSUtil {

	public static int byteArrayToInt(byte[] b) {
		if (b.length > 4)
			return -1;
		return (int) ((0xff & b[0]) << 24 |
		              (0xff & b[1]) << 16 |
		              (0xff & b[2]) << 8 |
		              (0xff & b[3]) << 0);
	}
	
	public static byte[] intToByteArray(int i) {
		return new byte[] {
				(byte)((i >> 24) & 0xff),
	            (byte)((i >> 16) & 0xff),
	            (byte)((i >> 8) & 0xff),
	            (byte)((i >> 0) & 0xff),
	        };
	}
	
	public static long byteArrayToLong(byte[] b) {
		if (b.length > 8)
			return -1;
		return ((long) (0xff & b[0]) << 56 |
				(long) (0xff & b[1]) << 48 |
				(long) (0xff & b[2]) << 40 |
				(long) (0xff & b[3]) << 32 |
				(long) (0xff & b[4]) << 24 |
				(long) (0xff & b[5]) << 16 |
				(long) (0xff & b[6]) << 8 |
				(long) (0xff & b[7]) << 0);
	}
	
	public static byte[] longToByteArray(long l) {
		return new byte[] {
				(byte)((l >> 56) & 0xff),
				(byte)((l >> 48) & 0xff),
				(byte)((l >> 40) & 0xff),
				(byte)((l >> 32) & 0xff),
				(byte)((l >> 24) & 0xff),
	            (byte)((l >> 16) & 0xff),
	            (byte)((l >> 8) & 0xff),
	            (byte)((l >> 0) & 0xff),
	        };
	}
}
