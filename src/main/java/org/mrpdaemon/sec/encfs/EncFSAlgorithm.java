/*
 * EncFS Java Library
 * Copyright (C) 2013 encfs-java authors
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
 * User: lars
 */
public enum EncFSAlgorithm {
	BLOCK("nameio/block", 3, 0), STREAM("nameio/stream", 2, 1), NULL(
			"nameio/null", 1, 0);

	private final String identifier;
	private final int major;
	private final int minor;

	EncFSAlgorithm(String identifier, int major, int minor) {
		this.identifier = identifier;
		this.major = major;
		this.minor = minor;
	}

	public static EncFSAlgorithm parse(String identifier) {
		for (EncFSAlgorithm a : values()) {
			if (a.identifier.equals(identifier)) {
				return a;
			}
		}
		throw new IllegalArgumentException("could not parse: " + identifier);
	}

	public int getMajor() {
		return major;
	}

	public int getMinor() {
		return minor;
	}

	public String getIdentifier() {
		return identifier;
	}
}
