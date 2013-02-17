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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

public class EncFSUtil {

  public static int convertBigEndianByteArrayToInt(byte[] b) {
    int capacity = Integer.SIZE / 8;
    if (b.length > capacity) {
      return -1;
    }
    return ByteBuffer.allocate(capacity).wrap(b).getInt();
  }

  public static byte[] convertIntToByteArrayBigEndian(int i) {
    return ByteBuffer.allocate(Integer.SIZE / 8).putInt(i).array();
  }

  public static long convertByteArrayToLong(byte[] b) {
    int capacity = Long.SIZE / 8;
    if (b.length > capacity) {
      return -1;
    }
    return ByteBuffer.allocate(capacity).wrap(b).getLong();
  }

  public static byte[] convertLongToByteArrayBigEndian(long l) {
    return ByteBuffer.allocate(Long.SIZE / 8).putLong(l).array();
  }

  public static void copyWholeStream(InputStream in, OutputStream out, boolean closeInput, boolean closeOutput) throws IOException {
    try {
      try {
        readFromAndWriteTo(in, out);
      } finally {
        if (closeInput) {
          in.close();
        }
      }
    } finally {
      if (closeOutput) {
        out.close();
      }
    }
  }

  private static void readFromAndWriteTo(InputStream in, OutputStream out) throws IOException {
    byte[] buf = new byte[8192];
    int bytesRead = in.read(buf);
    while (bytesRead >= 0) {
      out.write(buf, 0, bytesRead);
      bytesRead = in.read(buf);
    }
  }
}