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

public final class EncFSConfigFactory {

	public static EncFSConfig createDefault() {
		EncFSConfig config = new EncFSConfig();
		config.setAlgorithm(EncFSAlgorithm.BLOCK);
		config.setVolumeKeySizeInBits(192);
		config.setEncryptedFileBlockSizeInBytes(1024);
		config.setUseUniqueIV(true);
		config.setChainedNameIV(true);
		config.setHolesAllowedInFiles(true);
		config.setIterationForPasswordKeyDerivationCount(5000);
		config.setNumberOfMACBytesForEachFileBlock(0);
		config.setNumberOfRandomBytesInEachMACHeader(0);
		config.setSupportedExternalIVChaining(false);
		return config;
	}
}
