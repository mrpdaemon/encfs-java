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

import java.io.File;

import java.io.IOException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

/**
 * Parser methods that read and interpret EncFS configuration files.
 */
public class EncFSConfigParser {
	
	private static String getNodeValue(Node n)
	{
		return n.getChildNodes().item(0).getNodeValue();
	}

	/**
	 * Parse the given configuration file
	 * 
	 * @param configFile  EncFS volume configuration file.
	 * @return            An EncFSConfig object containing the configuration
	 *                    data interpreted from the given file.
	 * @throws ParserConfigurationException 
	 * @throws IOException 
	 * @throws SAXException 
	 * @throws EncFSInvalidConfigException 
	 */
	public static EncFSConfig parseFile(File configFile)
			throws ParserConfigurationException,
			       SAXException,
			       IOException,
			       EncFSInvalidConfigException
	{
		EncFSConfig config = new EncFSConfig();

		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
		Document doc = dBuilder.parse(configFile);
		doc.getDocumentElement().normalize();

		NodeList cfgNodeList = doc.getElementsByTagName("cfg").item(0).getChildNodes();

		if (cfgNodeList.getLength() == 0) {
			throw new EncFSInvalidConfigException("<cfg> element not present in config file");
		}

		for (int i = 0; i < cfgNodeList.getLength(); i++) {
			Node cfgNode = cfgNodeList.item(i);
			
			if (cfgNode.getNodeType() == Node.ELEMENT_NODE) {
				if (cfgNode.getNodeName().equals("nameAlg")) {
					NodeList nameAlgNodeList = cfgNode.getChildNodes();
					for (int j = 0; j < nameAlgNodeList.getLength(); j++) {
						Node nameAlgChildNode = nameAlgNodeList.item(j);
						if (nameAlgChildNode.getNodeName().equals("name")) {
							String algName = getNodeValue(nameAlgChildNode);
							if (algName.equals("nameio/block")) {
								config.setNameAlgorithm(
										EncFSConfig.ENCFS_CONFIG_NAME_ALG_BLOCK);
							} else if (algName.equals("nameio/stream")) {
								config.setNameAlgorithm(
										EncFSConfig.ENCFS_CONFIG_NAME_ALG_STREAM);
							} else {
								throw new EncFSInvalidConfigException(
										"Unknown name algorithm in config file: " +
										algName);
							}
						}
					}
				} else if (cfgNode.getNodeName().equals("keySize")) {
					config.setVolumeKeySize(Integer.parseInt(
							                    getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("blockSize")) {
					config.setBlockSize(Integer.parseInt(
							                getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("uniqueIV")) {
					config.setUniqueIV(Integer.parseInt(
							               getNodeValue(cfgNode)) == 1);
				} else if (cfgNode.getNodeName().equals("chainedNameIV")) {
					config.setChainedNameIV(Integer.parseInt(
							                    getNodeValue(cfgNode)) == 1);
				} else if (cfgNode.getNodeName().equals("allowHoles")) {
					config.setHolesAllowed(Integer.parseInt(
		                                       getNodeValue(cfgNode)) == 1);
				} else if (cfgNode.getNodeName().equals("encodedKeySize")) {
					config.setEncodedKeyLength(Integer.parseInt(
		                                           getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("encodedKeyData")) {
					config.setEncodedKeyStr(getNodeValue(cfgNode));
				} else if (cfgNode.getNodeName().equals("saltLen")) {
					config.setSaltLength(Integer.parseInt(
                                             getNodeValue(cfgNode)));
				} else if (cfgNode.getNodeName().equals("saltData")) {
					config.setSaltStr(getNodeValue(cfgNode));
				} else if (cfgNode.getNodeName().equals("kdfIterations")) {
					config.setIterationCount(Integer.parseInt(
                                                 getNodeValue(cfgNode)));
				}
			}
		}

		return config;
	}
}