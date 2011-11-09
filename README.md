encfs-java
==========

encfs-java is a Java library for accessing data in
[EncFS](http://www.arg0.net/encfs) volumes. It is able to derive the volume key
from a user password, decode encrypted filenames (IV chaining is implemented)
and decrypt file contents.

Currently write mode operations aren't implemented, but ability to rename/move,
write file data and volume creation support are in the works. Also the EncFS
configurations supported are fairly limited but that is also going to change.

## Building

encfs-java uses [Maven](http://maven.apache.org) for building. Assuming you
have a working installation, simply run the following to build the code:

  $ mvn compile

To create a JAR file for using encfs-java from another application, do:

  $ mvn package

Which will create a JAR file in the {$PROJECT_ROOT}/target/ directory.

## Usage

This library comes with a demo/example application called EncFSShell. It is a
simple shell supporting a few commands such as 'ls', 'cd' and 'cat' on an EncFS
volume. After building the library, add the {$PROJECT_ROOT}/target/classes/
directory to your CLASSPATH, and run like so:

  $ java -classpath ${PROJECT_ROOT}/target/classes EncFSShell /path/to/an/encfs/volume

## Licensing

encfs-java is licensed under the Lesser GNU Public License, which allows non-GPL
applications to make use of the library with the restriction that the source code
for any modifications to the library itself need to be made available to be able
to legally redistribute the modified library. For more information, please see the
LICENSE file and the Free Software Foundation
(website)[http://www.gnu.org/licenses/lgpl.html].

## TODO
* Post JavaDoc on GitHub
* Support different EncFS volume configurations (key size, advanced options)
* Rename/move files
* Write file contents
* Volume creation