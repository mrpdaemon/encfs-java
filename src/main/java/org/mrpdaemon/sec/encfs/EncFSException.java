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
 * Parent class of all encfs-java exceptions
 */
public class EncFSException extends Exception {

  private static final long serialVersionUID = 1L;

  /**
   * Creates a new EncFSException
   *
   * @param message Exception message
   */
  public EncFSException(String message) {
    super(message);
  }

  /**
   * Creates a new EncFSException
   *
   * @param cause Underlying Throwable for the exception
   */
  public EncFSException(Throwable cause) {
    super(cause);
  }

  /**
   * Creates a new EncFSException
   *
   * @param message Exception message
   * @param cause   Underlying Throwable for the exception
   */
  public EncFSException(String message, Throwable cause) {
    super(message, cause);
  }

}
