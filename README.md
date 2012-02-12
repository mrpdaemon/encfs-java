encfs-java
==========

encfs-java is a Java library for accessing data in
[EncFS](http://www.arg0.net/encfs) volumes. It is able to derive the volume key
from a user password, decode encrypted filenames (IV chaining is implemented)
and decrypt file contents. Currently we also have experimental support for
creating new volumes, moving/renaming files as well as copying file contents.

We do support most encfs volume configuration options, and are interoperable
with the official encfs implementation (http://www.arg0.net/encfs). Currently
we only support the latest version (1.7.4), but we target to be able to
support volumes created with legacy versions as well.

## Building

encfs-java uses [Maven](http://maven.apache.org) for building. Assuming you
have a working installation, simply run the following to build the code:

    $ mvn compile

To create a JAR file for using encfs-java from another application, do:

    $ mvn package

Which will create a JAR file in the {$PROJECT_ROOT}/target/ directory.

## Usage

This library comes with a demo/example application called EncFSShell. It is a
simple shell supporting a few commands such as 'ls', 'cd', 'cat', 'mv' and 'cp'
on an EncFS volume. After building the library, add the
{$PROJECT_ROOT}/target/classes/ directory to your CLASSPATH, and run like so:

    $ java -classpath ${PROJECT_ROOT}/target/classes EncFSShell /path/to/an/encfs/volume

For using the library from another project, include the .JAR file in your
classpath and import the org.mrpdaemon.encfs.sec package. For API documentation,
you can generate JavaDoc's using Maven:

    $ mvn javadoc:javadoc

Which will place your documentation in ${PROJECT_ROOT}/target/site/apidocs/

## Common issues

If you are getting an exception due to "Illegal key size" and you are using Sun's JDK,
you need to install the Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction
Policy Files. See the following link for more information:

http://www.oracle.com/technetwork/java/javase/downloads/jce-6-download-429243.html

Thanks to aormerod for pointing this out!

## Licensing

encfs-java is licensed under the Lesser GNU Public License, which allows non-GPL
applications to make use of the library with the restriction that the source code
for any modifications to the library itself need to be made available to be able
to legally redistribute the modified library. For more information, please see the
LICENSE file and the Free Software Foundation
[website](http://www.gnu.org/licenses/lgpl.html).