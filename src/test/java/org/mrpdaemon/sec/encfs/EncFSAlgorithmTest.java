package org.mrpdaemon.sec.encfs;

import org.junit.Test;

/**
 * User: lars
 */
public class EncFSAlgorithmTest {
  @Test(expected = IllegalArgumentException.class)
  public void testParse() throws Exception {
    EncFSAlgorithm.parse("nameio/sstream");
  }
}
