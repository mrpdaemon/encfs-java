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

/*
 * Adapted from the public domain implementation by Robert Harder at:
 * http://iharder.sourceforge.net/current/java/base64/
 */

package org.mrpdaemon.sec.encfs;

import java.io.IOException;
import java.math.BigInteger;

/**
 * Static class to perform Base64 encoding/decoding
 * 
 */
public final class EncFSBase64 {

	/* ******** P U B L I C F I E L D S ******** */

	/**
	 * No options specified. Value is zero.
	 */
	private final static int NO_OPTIONS = 0;

	/**
	 * Specify encoding in first bit. Value is one.
	 */
	private final static int ENCODE = 1;

	/**
	 * Specify decoding in first bit. Value is zero.
	 */
	private final static int DECODE = 0;

	/**
	 * Specify that data should be gzip-compressed in second bit. Value is two.
	 */
	private final static int GZIP = 2;

	/**
	 * Specify that gzipped data should <em>not</em> be automatically gunzipped.
	 */
	private final static int DONT_GUNZIP = 4;

	/**
	 * Do break lines when encoding. Value is 8.
	 */
	private final static int DO_BREAK_LINES = 8;

	/**
	 * Encode using Base64-like encoding that is URL- and Filename-safe as
	 * described in Section 4 of RFC3548: <a
	 * href="http://www.faqs.org/rfcs/rfc3548.html"
	 * >http://www.faqs.org/rfcs/rfc3548.html</a>. It is important to note that
	 * data encoded this way is <em>not</em> officially valid Base64, or at the
	 * very least should not be called Base64 without also specifying that is
	 * was encoded using the URL- and Filename-safe dialect.
	 */
	private final static int URL_SAFE = 16;

	/**
	 * Encode using the special "ordered" dialect of Base64 described here: <a
	 * href="http://www.faqs.org/qa/rfcc-1940.html">http://www.faqs.org/qa/rfcc-
	 * 1940.html</a>.
	 */
	private final static int ORDERED = 32;

	/* ******** P R I V A T E F I E L D S ******** */

	/**
	 * Maximum line length (76) of Base64 output.
	 */
	private final static int MAX_LINE_LENGTH = 76;

	/**
	 * The equals sign (=) as a byte.
	 */
	private final static byte EQUALS_SIGN = (byte) '=';

	/**
	 * The new line character (\n) as a byte.
	 */
	private final static byte NEW_LINE = (byte) '\n';

	/**
	 * Preferred encoding.
	 */
	private final static String PREFERRED_ENCODING = "US-ASCII";

	private final static byte WHITE_SPACE_ENC = -5; // Indicates white space in
	// encoding
	private final static byte EQUALS_SIGN_ENC = -1; // Indicates equals sign in
	// encoding

	/* ******** S T A N D A R D B A S E 6 4 A L P H A B E T ******** */

	/**
	 * The 64 valid Base64 values.
	 */
	/*
	 * Host platform me be something funny like EBCDIC, so we hardcode these
	 * values.
	 */
	private final static byte[] _STANDARD_ALPHABET = { (byte) 'A', (byte) 'B',
			(byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
			(byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L',
			(byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q',
			(byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V',
			(byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z', (byte) 'a',
			(byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f',
			(byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k',
			(byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p',
			(byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
			(byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
			(byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
			(byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
			(byte) '+', (byte) '/' };

	/**
	 * Translates a Base64 value to either its 6-bit reconstruction value or a
	 * negative number indicating some other meaning.
	 */
	private final static byte[] _STANDARD_DECODABET = { -9, -9, -9, -9, -9, -9,
			-9, -9, -9, // Decimal
			// 0
			// -
			// 8
			-5, -5, // Whitespace: Tab and Linefeed
			-9, -9, // Decimal 11 - 12
			-5, // Whitespace: Carriage Return
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
			// 26
			-9, -9, -9, -9, -9, // Decimal 27 - 31
			-5, // Whitespace: Space
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
			62, // Plus sign at decimal 43
			-9, -9, -9, // Decimal 44 - 46
			63, // Slash at decimal 47
			52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // Numbers zero through nine
			-9, -9, -9, // Decimal 58 - 60
			-1, // Equals sign at decimal 61
			-9, -9, -9, // Decimal 62 - 64
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // Letters 'A' through
			// 'N'
			14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // Letters 'O'
			// through 'Z'
			-9, -9, -9, -9, -9, -9, // Decimal 91 - 96
			26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, // Letters 'a'
			// through 'm'
			39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // Letters 'n'
			// through 'z'
			-9, -9, -9, -9, -9 // Decimal 123 - 127
			, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128 -
			// 139
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
			// 152
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
			// 165
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
			// 178
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
			// 191
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
			// 204
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
			// 217
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
			// 230
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
			// 243
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
	};

	/* ******** U R L S A F E B A S E 6 4 A L P H A B E T ******** */

	/**
	 * Used in the URL- and Filename-safe dialect described in Section 4 of
	 * RFC3548: <a
	 * href="http://www.faqs.org/rfcs/rfc3548.html">http://www.faqs.org
	 * /rfcs/rfc3548.html</a>. Notice that the last two bytes become "hyphen"
	 * and "underscore" instead of "plus" and "slash."
	 */
	private final static byte[] _URL_SAFE_ALPHABET = { (byte) 'A', (byte) 'B',
			(byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F', (byte) 'G',
			(byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K', (byte) 'L',
			(byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P', (byte) 'Q',
			(byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U', (byte) 'V',
			(byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z', (byte) 'a',
			(byte) 'b', (byte) 'c', (byte) 'd', (byte) 'e', (byte) 'f',
			(byte) 'g', (byte) 'h', (byte) 'i', (byte) 'j', (byte) 'k',
			(byte) 'l', (byte) 'm', (byte) 'n', (byte) 'o', (byte) 'p',
			(byte) 'q', (byte) 'r', (byte) 's', (byte) 't', (byte) 'u',
			(byte) 'v', (byte) 'w', (byte) 'x', (byte) 'y', (byte) 'z',
			(byte) '0', (byte) '1', (byte) '2', (byte) '3', (byte) '4',
			(byte) '5', (byte) '6', (byte) '7', (byte) '8', (byte) '9',
			(byte) '-', (byte) '_' };

	/**
	 * Used in decoding URL- and Filename-safe dialects of Base64.
	 */
	private final static byte[] _URL_SAFE_DECODABET = { -9, -9, -9, -9, -9, -9,
			-9, -9, -9, // Decimal
			// 0
			// -
			// 8
			-5, -5, // Whitespace: Tab and Linefeed
			-9, -9, // Decimal 11 - 12
			-5, // Whitespace: Carriage Return
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
			// 26
			-9, -9, -9, -9, -9, // Decimal 27 - 31
			-5, // Whitespace: Space
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
			-9, // Plus sign at decimal 43
			-9, // Decimal 44
			62, // Minus sign at decimal 45
			-9, // Decimal 46
			-9, // Slash at decimal 47
			52, 53, 54, 55, 56, 57, 58, 59, 60, 61, // Numbers zero through nine
			-9, -9, -9, // Decimal 58 - 60
			-1, // Equals sign at decimal 61
			-9, -9, -9, // Decimal 62 - 64
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, // Letters 'A' through
			// 'N'
			14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, // Letters 'O'
			// through 'Z'
			-9, -9, -9, -9, // Decimal 91 - 94
			63, // Underscore at decimal 95
			-9, // Decimal 96
			26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, // Letters 'a'
			// through 'm'
			39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, // Letters 'n'
			// through 'z'
			-9, -9, -9, -9, -9 // Decimal 123 - 127
			, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128 -
			// 139
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
			// 152
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
			// 165
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
			// 178
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
			// 191
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
			// 204
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
			// 217
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
			// 230
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
			// 243
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
	};

	/* ******** O R D E R E D B A S E 6 4 A L P H A B E T ******** */

	/**
	 * I don't get the point of this technique, but someone requested it, and it
	 * is described here: <a
	 * href="http://www.faqs.org/qa/rfcc-1940.html">http://
	 * www.faqs.org/qa/rfcc-1940.html</a>.
	 */
	private final static byte[] _ORDERED_ALPHABET = { (byte) '-', (byte) '0',
			(byte) '1', (byte) '2', (byte) '3', (byte) '4', (byte) '5',
			(byte) '6', (byte) '7', (byte) '8', (byte) '9', (byte) 'A',
			(byte) 'B', (byte) 'C', (byte) 'D', (byte) 'E', (byte) 'F',
			(byte) 'G', (byte) 'H', (byte) 'I', (byte) 'J', (byte) 'K',
			(byte) 'L', (byte) 'M', (byte) 'N', (byte) 'O', (byte) 'P',
			(byte) 'Q', (byte) 'R', (byte) 'S', (byte) 'T', (byte) 'U',
			(byte) 'V', (byte) 'W', (byte) 'X', (byte) 'Y', (byte) 'Z',
			(byte) '_', (byte) 'a', (byte) 'b', (byte) 'c', (byte) 'd',
			(byte) 'e', (byte) 'f', (byte) 'g', (byte) 'h', (byte) 'i',
			(byte) 'j', (byte) 'k', (byte) 'l', (byte) 'm', (byte) 'n',
			(byte) 'o', (byte) 'p', (byte) 'q', (byte) 'r', (byte) 's',
			(byte) 't', (byte) 'u', (byte) 'v', (byte) 'w', (byte) 'x',
			(byte) 'y', (byte) 'z' };

	/**
	 * Used in decoding the "ordered" dialect of Base64.
	 */
	private final static byte[] _ORDERED_DECODABET = { -9, -9, -9, -9, -9, -9,
			-9, -9, -9, // Decimal
			// 0
			// -
			// 8
			-5, -5, // Whitespace: Tab and Linefeed
			-9, -9, // Decimal 11 - 12
			-5, // Whitespace: Carriage Return
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
			// 26
			-9, -9, -9, -9, -9, // Decimal 27 - 31
			-5, // Whitespace: Space
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
			-9, // Plus sign at decimal 43
			-9, // Decimal 44
			0, // Minus sign at decimal 45
			-9, // Decimal 46
			-9, // Slash at decimal 47
			1, 2, 3, 4, 5, 6, 7, 8, 9, 10, // Numbers zero through nine
			-9, -9, -9, // Decimal 58 - 60
			-1, // Equals sign at decimal 61
			-9, -9, -9, // Decimal 62 - 64
			11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, // Letters 'A'
			// through 'M'
			24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, // Letters 'N'
			// through 'Z'
			-9, -9, -9, -9, // Decimal 91 - 94
			37, // Underscore at decimal 95
			-9, // Decimal 96
			38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, // Letters 'a'
			// through 'm'
			51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, // Letters 'n'
			// through 'z'
			-9, -9, -9, -9, -9 // Decimal 123 - 127
			, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128
			// - 139
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
			// 152
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
			// 165
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
			// 178
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
			// 191
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
			// 204
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
			// 217
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
			// 230
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
			// 243
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
	};

	/**
	 * Used in decoding the "ENCFS" dialect of Base64.
	 */
	private final static byte[] _ENCFS_DECODABET = { -9, -9, -9, -9, -9, -9,
			-9, -9, -9, // Decimal
			// 0
			// -
			// 8
			-5, -5, // Whitespace: Tab and Linefeed
			-9, -9, // Decimal 11 - 12
			-5, // Whitespace: Carriage Return
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 14 -
			// 26
			-9, -9, -9, -9, -9, // Decimal 27 - 31
			-5, // Whitespace: Space
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 33 - 42
			-9, // Plus sign at decimal 43
			0, // Comma at decimal 44
			1, // Minus sign at decimal 45
			-9, // Decimal 46
			-9, // Slash at decimal 47
			2, 3, 4, 5, 6, 7, 8, 9, 10, 11, // Numbers zero through nine
			-9, -9, -9, // Decimal 58 - 60
			-1, // Equals sign at decimal 61
			-9, -9, -9, // Decimal 62 - 64
			12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, // Letters 'A'
			// through 'M'
			25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, // Letters 'N'
			// through 'Z'
			-9, -9, -9, -9, -9, -9, // Decimal 91 - 96
			38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, // Letters 'a'
			// through 'm'
			51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, // Letters 'n'
			// through 'z'
			-9, -9, -9, -9, -9 // Decimal 123 - 127
			, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 128
			// - 139
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 140 -
			// 152
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 153 -
			// 165
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 166 -
			// 178
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 179 -
			// 191
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 192 -
			// 204
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 205 -
			// 217
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 218 -
			// 230
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, // Decimal 231 -
			// 243
			-9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9, -9 // Decimal 244 - 255
	};

	/* ******** D E T E R M I N E W H I C H A L H A B E T ******** */

	/**
	 * Returns one of the _SOMETHING_ALPHABET byte arrays depending on the
	 * options specified. It's possible, though silly, to specify ORDERED
	 * <b>and</b> URLSAFE in which case one of them will be picked, though there
	 * is no guarantee as to which one will be picked.
	 */
	private static byte[] getAlphabet(int options) {
		if ((options & URL_SAFE) == URL_SAFE) {
			return _URL_SAFE_ALPHABET;
		} else if ((options & ORDERED) == ORDERED) {
			return _ORDERED_ALPHABET;
		} else {
			return _STANDARD_ALPHABET;
		}
	}

	/**
	 * Returns one of the _SOMETHING_DECODABET byte arrays depending on the
	 * options specified. It's possible, though silly, to specify ORDERED and
	 * URL_SAFE in which case one of them will be picked, though there is no
	 * guarantee as to which one will be picked.
	 */
	private static byte[] getDecodabet(int options) {
		if ((options & URL_SAFE) == URL_SAFE) {
			return _URL_SAFE_DECODABET;
		} else if ((options & ORDERED) == ORDERED) {
			return _ORDERED_DECODABET;
		} else {
			return _STANDARD_DECODABET;
		}
	}

	/**
	 * Defeats instantiation.
	 */
	private EncFSBase64() {
	}

	/**
	 * Encodes up to the first three bytes of array <var>threeBytes</var> and
	 * returns a four-byte array in Base64 notation. The actual number of
	 * significant bytes in your array is given by <var>numSigBytes</var>. The
	 * array <var>threeBytes</var> needs only be as big as
	 * <var>numSigBytes</var>. Code can reuse a byte array by passing a
	 * four-byte array as <var>b4</var>.
	 * 
	 * @param b4
	 *            A reusable byte array to reduce array instantiation
	 * @param threeBytes
	 *            the array to convert
	 * @param numSigBytes
	 *            the number of significant bytes in your array
	 * @return four byte array in Base64 notation.
	 * @since 1.5.1
	 */
	private static byte[] encode3to4(byte[] b4, byte[] threeBytes,
			int numSigBytes, int options) {
		encode3to4(threeBytes, 0, numSigBytes, b4, 0, options);
		return b4;
	}

	/**
	 * <p>
	 * Encodes up to three bytes of the array <var>source</var> and writes the
	 * resulting four Base64 bytes to <var>destination</var>. The source and
	 * destination arrays can be manipulated anywhere along their length by
	 * specifying <var>srcOffset</var> and <var>destOffset</var>. This method
	 * does not check to make sure your arrays are large enough to accomodate
	 * <var>srcOffset</var> + 3 for the <var>source</var> array or
	 * <var>destOffset</var> + 4 for the <var>destination</var> array. The
	 * actual number of significant bytes in your array is given by
	 * <var>numSigBytes</var>.
	 * </p>
	 * <p>
	 * This is the lowest level of the encoding methods with all possible
	 * parameters.
	 * </p>
	 * 
	 * @param source
	 *            the array to convert
	 * @param srcOffset
	 *            the index where conversion begins
	 * @param numSigBytes
	 *            the number of significant bytes in your array
	 * @param destination
	 *            the array to hold the conversion
	 * @param destOffset
	 *            the index where output will be put
	 * @return the <var>destination</var> array
	 * @since 1.3
	 */
	private static byte[] encode3to4(byte[] source, int srcOffset,
			int numSigBytes, byte[] destination, int destOffset, int options) {

		byte[] ALPHABET = getAlphabet(options);

		// 1 2 3
		// 01234567890123456789012345678901 Bit position
		// --------000000001111111122222222 Array position from threeBytes
		// --------| || || || | Six bit groups to index ALPHABET
		// >>18 >>12 >> 6 >> 0 Right shift necessary
		// 0x3f 0x3f 0x3f Additional AND

		// Create buffer with zero-padding if there are only one or two
		// significant bytes passed in the array.
		// We have to shift left 24 in order to flush out the 1's that appear
		// when Java treats a value as negative that is cast from a byte to an
		// int.
		int inBuff = (numSigBytes > 0 ? ((source[srcOffset] << 24) >>> 8) : 0)
				| (numSigBytes > 1 ? ((source[srcOffset + 1] << 24) >>> 16) : 0)
				| (numSigBytes > 2 ? ((source[srcOffset + 2] << 24) >>> 24) : 0);

		switch (numSigBytes) {
		case 3:
			destination[destOffset] = ALPHABET[(inBuff >>> 18)];
			destination[destOffset + 1] = ALPHABET[(inBuff >>> 12) & 0x3f];
			destination[destOffset + 2] = ALPHABET[(inBuff >>> 6) & 0x3f];
			destination[destOffset + 3] = ALPHABET[(inBuff) & 0x3f];
			return destination;

		case 2:
			destination[destOffset] = ALPHABET[(inBuff >>> 18)];
			destination[destOffset + 1] = ALPHABET[(inBuff >>> 12) & 0x3f];
			destination[destOffset + 2] = ALPHABET[(inBuff >>> 6) & 0x3f];
			destination[destOffset + 3] = EQUALS_SIGN;
			return destination;

		case 1:
			destination[destOffset] = ALPHABET[(inBuff >>> 18)];
			destination[destOffset + 1] = ALPHABET[(inBuff >>> 12) & 0x3f];
			destination[destOffset + 2] = EQUALS_SIGN;
			destination[destOffset + 3] = EQUALS_SIGN;
			return destination;

		default:
			return destination;
		}
	}

	/**
	 * Encodes a byte array into Base64 notation. Does not GZip-compress data.
	 * 
	 * @param source
	 *            The data to convert
	 * @return The data in Base64-encoded form
	 * @since 1.4
	 */
	public static String encodeBytes(byte[] source) {
		// Since we're not going to have the GZIP encoding turned on,
		// we're not going to have an IOException thrown, so
		// we should not force the user to have to catch it.
		String encoded = null;
		try {
			encoded = encodeBytes(source, source.length);
		} catch (IOException ex) {
			assert false : ex.getMessage();
		}
		assert encoded != null;
		return encoded;
	}

	/**
	 * Encodes a byte array into Base64 notation.
	 * <p>
	 * Example options:
	 * <p/>
	 * 
	 * <pre>
	 *   GZIP: gzip-compresses object before encoding it.
	 *   DO_BREAK_LINES: break lines at 76 characters
	 *     <i>Note: Technically, this makes your encoding non-compliant.</i>
	 * </pre>
	 * <p>
	 * Example: <code>encodeBytes( myData, Base64.GZIP )</code> or
	 * <p>
	 * Example:
	 * <code>encodeBytes( myData, Base64.GZIP | Base64.DO_BREAK_LINES )</code>
	 * <p/>
	 * <p/>
	 * <p>
	 * As of v 2.3, if there is an error with the GZIP stream, the method will
	 * throw an IOException. <b>This is new to v2.3!</b> In earlier versions, it
	 * just returned a null value, but in retrospect that's a pretty poor way to
	 * handle it.
	 * </p>
	 * 
	 * @param source
	 *            The data to convert
	 * @param len
	 *            Length of data to convert
	 * @return The Base64-encoded data as a String
	 * @see EncFSBase64#GZIP
	 * @see EncFSBase64#DO_BREAK_LINES
	 * @since 2.0
	 */
	private static String encodeBytes(byte[] source, int len)
			throws IOException {
		byte[] encoded = encodeBytesToBytes(source, 0, len,
				EncFSBase64.NO_OPTIONS);

		// Return value according to relevant encoding.
		try {
			return new String(encoded, PREFERRED_ENCODING);
		} catch (java.io.UnsupportedEncodingException uue) {
			return new String(encoded);
		}

	}

	/**
	 * Similar to {@link #encodeBytes(byte[], int)} but returns a byte array
	 * instead of instantiating a String. This is more efficient if you're
	 * working with I/O streams and have large data sets to encode.
	 * 
	 * @param source
	 *            The data to convert
	 * @param off
	 *            Offset in array where conversion should begin
	 * @param len
	 *            Length of data to convert
	 * @param options
	 *            Specified options
	 * @return The Base64-encoded data as a String
	 * @see EncFSBase64#GZIP
	 * @see EncFSBase64#DO_BREAK_LINES
	 * @since 2.3.1
	 */
	private static byte[] encodeBytesToBytes(byte[] source, int off, int len,
			int options) throws IOException {

		if (source == null) {
			throw new NullPointerException("Cannot serialize a null array.");
		}

		if (off < 0) {
			throw new IllegalArgumentException("Cannot have negative offset: "
					+ off);
		}

		if (len < 0) {
			throw new IllegalArgumentException("Cannot have length offset: "
					+ len);
		}

		if (off + len > source.length) {
			throw new IllegalArgumentException(
					String.format(
							"Cannot have offset of %d and length of %d with array of length %d",
							off, len, source.length));
		}

		// Compress?
		if ((options & GZIP) != 0) {
			java.io.ByteArrayOutputStream baos = null;
			java.util.zip.GZIPOutputStream gzos = null;
			EncFSBase64.OutputStream b64os = null;

			try {
				// GZip -> Base64 -> ByteArray
				baos = new java.io.ByteArrayOutputStream();
				b64os = new EncFSBase64.OutputStream(baos, ENCODE | options);
				gzos = new java.util.zip.GZIPOutputStream(b64os);

				gzos.write(source, off, len);
				gzos.close();
			} catch (IOException e) {
				// Catch it and then throw it immediately so that
				// the finally{} block is called for cleanup.
				throw e;
			} finally {
				try {
					gzos.close();
				} catch (Exception e) {
				}
				try {
					b64os.close();
				} catch (Exception e) {
				}
				try {
					baos.close();
				} catch (Exception e) {
				}
			}

			return baos.toByteArray();
		}

		// Else, don't compress. Better not to use streams at all then.
		else {
			boolean breakLines = (options & DO_BREAK_LINES) != 0;

			// int len43 = len * 4 / 3;
			// byte[] outBuff = new byte[ ( len43 ) // Main 4:3
			// + ( (len % 3) > 0 ? 4 : 0 ) // Account for padding
			// + (breakLines ? ( len43 / MAX_LINE_LENGTH ) : 0) ]; // New lines
			// Try to determine more precisely how big the array needs to be.
			// If we get it right, we don't have to do an array copy, and
			// we save a bunch of memory.
			int encLen = (len / 3) * 4 + (len % 3 > 0 ? 4 : 0); // Bytes needed
			// for actual
			// encoding
			if (breakLines) {
				encLen += encLen / MAX_LINE_LENGTH; // Plus extra newline
				// characters
			}
			byte[] outBuff = new byte[encLen];

			int d = 0;
			int e = 0;
			int len2 = len - 2;
			int lineLength = 0;
			for (; d < len2; d += 3, e += 4) {
				encode3to4(source, d + off, 3, outBuff, e, options);

				lineLength += 4;
				if (breakLines && lineLength >= MAX_LINE_LENGTH) {
					outBuff[e + 4] = NEW_LINE;
					e++;
					lineLength = 0;
				}
			} // en dfor: each piece of array

			if (d < len) {
				encode3to4(source, d + off, len - d, outBuff, e, options);
				e += 4;
			}

			// Only resize array if we didn't guess it right.
			if (e <= outBuff.length - 1) {
				// If breaking lines and the last byte falls right at
				// the line length (76 bytes per line), there will be
				// one extra byte, and the array will need to be resized.
				// Not too bad of an estimate on array size, I'd say.
				byte[] finalOut = new byte[e];
				System.arraycopy(outBuff, 0, finalOut, 0, e);
				// System.err.println("Having to resize array from " +
				// outBuff.length + " to " + e );
				return finalOut;
			} else {
				// System.err.println("No need to resize array.");
				return outBuff;
			}

		}

	}

	/* ******** D E C O D I N G M E T H O D S ******** */

	/**
	 * Decodes four bytes from array <var>source</var> and writes the resulting
	 * bytes (up to three of them) to <var>destination</var>. The source and
	 * destination arrays can be manipulated anywhere along their length by
	 * specifying <var>srcOffset</var> and <var>destOffset</var>. This method
	 * does not check to make sure your arrays are large enough to accomodate
	 * <var>srcOffset</var> + 4 for the <var>source</var> array or
	 * <var>destOffset</var> + 3 for the <var>destination</var> array. This
	 * method returns the actual number of bytes that were converted from the
	 * Base64 encoding.
	 * <p>
	 * This is the lowest level of the decoding methods with all possible
	 * parameters.
	 * </p>
	 * 
	 * @param source
	 *            the array to convert
	 * @param destination
	 *            the array to hold the conversion
	 * @param destOffset
	 *            the index where output will be put
	 * @param options
	 *            alphabet type is pulled from this (standard, url-safe,
	 *            ordered)
	 * @return the number of decoded bytes converted
	 *         <p/>
	 *         <p/>
	 *         room in the array.
	 * @since 1.3
	 */
	private static int decode4to3(byte[] source, byte[] destination,
			int destOffset, int options) {

		// Lots of error checking and exception throwing
		if (source == null) {
			throw new NullPointerException("Source array was null.");
		}
		if (destination == null) {
			throw new NullPointerException("Destination array was null.");
		}
		if (3 >= source.length) {
			throw new IllegalArgumentException(
					String.format(
							"Source array with length %d cannot have offset of %d and still process four bytes.",
							source.length, 0));
		}
		if (destOffset < 0 || destOffset + 2 >= destination.length) {
			throw new IllegalArgumentException(
					String.format(
							"Destination array with length %d cannot have offset of %d and still store three bytes.",
							destination.length, destOffset));
		}

		byte[] DECODABET = getDecodabet(options);

		// Example: Dk==
		if (source[2] == EQUALS_SIGN) {
			// Two ways to do the same thing. Don't know which way I like best.
			// int outBuff = ( ( DECODABET[ source[ srcOffset ] ] << 24 ) >>> 6
			// )
			// | ( ( DECODABET[ source[ srcOffset + 1] ] << 24 ) >>> 12 );
			int outBuff = ((DECODABET[source[0]] & 0xFF) << 18)
					| ((DECODABET[source[1]] & 0xFF) << 12);

			destination[destOffset] = (byte) (outBuff >>> 16);
			return 1;
		}

		// Example: DkL=
		else if (source[3] == EQUALS_SIGN) {
			// Two ways to do the same thing. Don't know which way I like best.
			// int outBuff = ( ( DECODABET[ source[ srcOffset ] ] << 24 ) >>> 6
			// )
			// | ( ( DECODABET[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
			// | ( ( DECODABET[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 );
			int outBuff = ((DECODABET[source[0]] & 0xFF) << 18)
					| ((DECODABET[source[1]] & 0xFF) << 12)
					| ((DECODABET[source[2]] & 0xFF) << 6);

			destination[destOffset] = (byte) (outBuff >>> 16);
			destination[destOffset + 1] = (byte) (outBuff >>> 8);
			return 2;
		}

		// Example: DkLE
		else {
			// Two ways to do the same thing. Don't know which way I like best.
			// int outBuff = ( ( DECODABET[ source[ srcOffset ] ] << 24 ) >>> 6
			// )
			// | ( ( DECODABET[ source[ srcOffset + 1 ] ] << 24 ) >>> 12 )
			// | ( ( DECODABET[ source[ srcOffset + 2 ] ] << 24 ) >>> 18 )
			// | ( ( DECODABET[ source[ srcOffset + 3 ] ] << 24 ) >>> 24 );
			int outBuff = ((DECODABET[source[0]] & 0xFF) << 18)
					| ((DECODABET[source[1]] & 0xFF) << 12)
					| ((DECODABET[source[2]] & 0xFF) << 6)
					| ((DECODABET[source[3]] & 0xFF));

			destination[destOffset] = (byte) (outBuff >> 16);
			destination[destOffset + 1] = (byte) (outBuff >> 8);
			destination[destOffset + 2] = (byte) (outBuff);

			return 3;
		}
	}

	/**
	 * Low-level access to decoding ASCII characters in the form of a byte
	 * array. <strong>Ignores GUNZIP option, if it's set.</strong> This is not
	 * generally a recommended method, although it is used internally as part of
	 * the decoding process. Special case: if len = 0, an empty array is
	 * returned. Still, if you need more speed and reduced memory footprint (and
	 * aren't gzipping), consider this method.
	 * 
	 * @param source
	 *            The Base64 encoded data
	 * @return decoded data
	 * @since 2.3.1
	 */
	public static byte[] decode(byte[] source) throws IOException {
		return decode(source, source.length, EncFSBase64.NO_OPTIONS);
	}

	/**
	 * Low-level access to decoding ASCII characters in the form of a byte
	 * array. <strong>Ignores GUNZIP option, if it's set.</strong> This is not
	 * generally a recommended method, although it is used internally as part of
	 * the decoding process. Special case: if len = 0, an empty array is
	 * returned. Still, if you need more speed and reduced memory footprint (and
	 * aren't gzipping), consider this method.
	 * 
	 * @param source
	 *            The Base64 encoded data
	 * @param len
	 *            The length of characters to decode
	 * @param options
	 *            Can specify options such as alphabet type to use
	 * @return decoded data
	 * @since 1.3
	 */
	private static byte[] decode(byte[] source, int len, int options)
			throws IOException {

		// Lots of error checking and exception throwing
		if (source == null) {
			throw new NullPointerException("Cannot decode null source array.");
		}
		if (len > source.length) {
			throw new IllegalArgumentException(
					String.format(
							"Source array with length %d cannot have offset of %d and process %d bytes.",
							source.length, 0, len));
		}

		if (len == 0) {
			return new byte[0];
		} else if (len < 4) {
			throw new IllegalArgumentException(
					"Base64-encoded string must have at least four characters, but length specified was "
							+ len);
		}

		byte[] DECODABET = getDecodabet(options);

		int len34 = len * 3 / 4; // Estimate on array size
		byte[] outBuff = new byte[len34]; // Upper limit on size of output
		int outBuffPosn = 0; // Keep track of where we're writing

		byte[] b4 = new byte[4]; // Four byte buffer from source, eliminating
		// white space
		int b4Posn = 0; // Keep track of four byte input buffer

		for (int i = 0; i < len; i++) { // Loop through source
			// Special value from DECODABET
			byte sbiDecode = DECODABET[source[i] & 0xFF];

			// White space, Equals sign, or legit Base64 character
			// Note the values such as -5 and -9 in the
			// DECODABETs at the top of the file.
			if (sbiDecode >= WHITE_SPACE_ENC) {
				if (sbiDecode >= EQUALS_SIGN_ENC) {
					b4[b4Posn++] = source[i]; // Save non-whitespace
					if (b4Posn > 3) { // Time to decode?
						outBuffPosn += decode4to3(b4, outBuff, outBuffPosn,
								options);
						b4Posn = 0;

						// If that was the equals sign, break out of 'for' loop
						if (source[i] == EQUALS_SIGN) {
							break;
						}
					}
				}
			} else {
				// There's a bad input character in the Base64 stream.
				throw new IOException(
						String.format(
								"Bad Base64 input character decimal %d in array position %d",
								source[i] & 0xFF, i));
			}
		} // each input character

		byte[] out = new byte[outBuffPosn];
		System.arraycopy(outBuff, 0, out, 0, outBuffPosn);
		return out;
	}

	/**
	 * Decodes data from Base64 notation, automatically detecting
	 * gzip-compressed data and decompressing it.
	 * 
	 * @param s
	 *            the string to decode
	 * @return the decoded data
	 * @since 1.4
	 */
	public static byte[] decode(String s) throws IOException {
		return decode(s, NO_OPTIONS);
	}

	/**
	 * Decodes data from Base64 notation, automatically detecting
	 * gzip-compressed data and decompressing it.
	 * 
	 * @param s
	 *            the string to decode
	 * @param options
	 *            encode options such as URL_SAFE
	 * @return the decoded data
	 * @since 1.4
	 */
	private static byte[] decode(String s, int options) throws IOException {

		if (s == null) {
			throw new NullPointerException("Input string was null.");
		}

		byte[] bytes;
		try {
			bytes = s.getBytes(PREFERRED_ENCODING);
		} catch (java.io.UnsupportedEncodingException uee) {
			bytes = s.getBytes();
		}
		// </change>

		// Decode
		bytes = decode(bytes, bytes.length, options);

		// Check to see if it's gzip-compressed
		// GZIP Magic Two-Byte Number: 0x8b1f (35615)
		boolean dontGunzip = (options & DONT_GUNZIP) != 0;
		if ((bytes != null) && (bytes.length >= 4) && (!dontGunzip)) {

			int head = (bytes[0] & 0xff) | ((bytes[1] << 8) & 0xff00);
			if (java.util.zip.GZIPInputStream.GZIP_MAGIC == head) {
				java.io.ByteArrayInputStream bais = null;
				java.util.zip.GZIPInputStream gzis = null;
				java.io.ByteArrayOutputStream baos = null;
				byte[] buffer = new byte[2048];

				try {
					baos = new java.io.ByteArrayOutputStream();
					bais = new java.io.ByteArrayInputStream(bytes);
					gzis = new java.util.zip.GZIPInputStream(bais);

					int length;
					while ((length = gzis.read(buffer)) >= 0) {
						baos.write(buffer, 0, length);
					}

					// No error? Get new bytes.
					bytes = baos.toByteArray();

				} catch (IOException e) {
					e.printStackTrace();
					// Just return originally-decoded bytes
				} finally {
					try {
						baos.close();
					} catch (Exception e) {
					}
					try {
						gzis.close();
					} catch (Exception e) {
					}
					try {
						bais.close();
					} catch (Exception e) {
					}
				}

			}
		}

		return bytes;
	}

	/**
	 * EncFS variant of Base64 encoding
	 * <p/>
	 * firstly converts the stream to base 64 by stored as the higher bits of
	 * the last byte in the low bits of next byte (using only 6 bits per byte)
	 * <p/>
	 * Input Bytes: aaAAAAAA bbbbBBBB ccccccCC
	 * <p/>
	 * Output Bytes: 00AAAAAA 00BBBBaa 00CCbbbb 00ccccccc
	 * 
	 * @param src
	 *            Byte array containing input data
	 * @return Byte array containing encoded data
	 */
	public static byte[] encodeEncfs(byte[] src) {
		int dstPower = 6;
		int srcPower = 8;

		byte[] result = changeBase2(src, dstPower, srcPower);

		B64ToAscii(result);

		return result;
	}

	private static byte[] changeBase2(byte[] src, int dstPower, int srcPower) {
		double tmpResultSize = (src.length * (double) srcPower) / dstPower;
		int resultSize = (int) Math.ceil(tmpResultSize);
		byte[] result = new byte[resultSize];

		int dstIdx = 0;

		long mask = (1 << dstPower) - 1; // 00111111

		int workingBits = 0;
		BigInteger buffer = BigInteger.valueOf(0);
		for (byte aSrc : src) {
			int unsignedIntValue = aSrc & 0xff;
			buffer = buffer.or(BigInteger.valueOf(unsignedIntValue).shiftLeft(
					workingBits));

			workingBits += srcPower;

			while (workingBits > dstPower) {
				result[dstIdx++] = buffer.and(BigInteger.valueOf(mask))
						.byteValue();
				buffer = buffer.shiftRight(dstPower);
				workingBits -= dstPower;
			}
		}

		// now, we could have a partial value left in the work buffer..
		if (workingBits > 0) {
			result[dstIdx++] = buffer.and(BigInteger.valueOf(mask)).byteValue();
		}
		return result;
	}

	private static final char[] B642AsciiTable = ",-0123456789".toCharArray();

	private static void B64ToAscii(byte[] in) {
		int length = in.length;
		for (int offset = 0; offset < length; ++offset) {
			int ch = in[offset];
			if (ch > 11) {
				if (ch > 37)
					ch += 'a' - 38;
				else
					ch += 'A' - 12;
			} else
				ch = B642AsciiTable[ch];

			in[offset] = (byte) ch;
		}
	}

	/**
	 * EncFS variant of Base64 decoding
	 * 
	 * @param source
	 *            Byte array containing input data
	 * @return Byte array containing decoded data
	 */
	public static byte[] decodeEncfs(byte[] source) {

		byte[] decodedInput = new byte[source.length];
		for (int i = 0; i < source.length; i++) {
			int arrayIndex = source[i];
			if (arrayIndex >= 0) {
				decodedInput[i] = _ENCFS_DECODABET[source[i]];
			} else {
				decodedInput[i] = -9;
			}
		}

		int outputLen = (source.length * 6) / 8;
		byte[] output = new byte[outputLen];

		int srcIdx = 0;
		int dstIdx = 0;
		int workBits = 0;
		long work = 0;

		while (srcIdx < source.length) {
			work |= decodedInput[srcIdx++] << workBits;
			workBits += 6;

			while (workBits >= 8) {
				output[dstIdx++] = (byte) (work & 0xff);
				work >>>= 8;
				workBits -= 8;
			}
		}

		return output;
	}

	/* ******** I N N E R C L A S S I N P U T S T R E A M ******** */

	/**
	 * A {@link Base64.InputStream} will read data from another
	 * <tt>java.io.InputStream</tt>, given in the constructor, and encode/decode
	 * to/from Base64 notation on the fly.
	 * 
	 * @see EncFSBase64
	 * @since 1.3
	 */
	static class InputStream extends java.io.FilterInputStream {

		private final boolean encode; // Encoding or decoding
		private int position; // Current position in the buffer
		private final byte[] buffer; // Small buffer holding converted data
		private final int bufferLength; // Length of buffer (3 or 4)
		private int numSigBytes; // Number of meaningful bytes in the buffer
		private int lineLength;
		private final boolean breakLines; // Break lines at less than 80
		// characters
		private final int options; // Record options used to create the stream.
		private final byte[] decodabet; // Local copies to avoid extra method

		// calls

		/**
		 * Constructs a {@link Base64.InputStream} in DECODE mode.
		 * 
		 * @param in
		 *            the <tt>java.io.InputStream</tt> from which to read data.
		 * @since 1.3
		 */
		public InputStream(java.io.InputStream in) {
			this(in, DECODE);
		}

		/**
		 * Constructs a {@link Base64.InputStream} in either ENCODE or DECODE
		 * mode.
		 * <p/>
		 * Valid options:
		 * <p/>
		 * 
		 * <pre>
		 *   ENCODE or DECODE: Encode or Decode as data is read.
		 *   DO_BREAK_LINES: break lines at 76 characters
		 *     (only meaningful when encoding)</i>
		 * </pre>
		 * <p/>
		 * Example: <code>new Base64.InputStream( in, Base64.DECODE )</code>
		 * 
		 * @param in
		 *            the <tt>java.io.InputStream</tt> from which to read data.
		 * @param options
		 *            Specified options
		 * @see EncFSBase64#ENCODE
		 * @see EncFSBase64#DECODE
		 * @see EncFSBase64#DO_BREAK_LINES
		 * @since 2.0
		 */
		public InputStream(java.io.InputStream in, int options) {

			super(in);
			this.options = options; // Record for later
			this.breakLines = (options & DO_BREAK_LINES) > 0;
			this.encode = (options & ENCODE) > 0;
			this.bufferLength = encode ? 4 : 3;
			this.buffer = new byte[bufferLength];
			this.position = -1;
			this.lineLength = 0;
			this.decodabet = getDecodabet(options);
		}

		/**
		 * Reads enough of the input stream to convert to/from Base64 and
		 * returns the next byte.
		 * 
		 * @return next byte
		 * @since 1.3
		 */
		@Override
		public int read() throws IOException {

			// Do we need to get data?
			if (position < 0) {
				if (encode) {
					byte[] b3 = new byte[3];
					int numBinaryBytes = 0;
					for (int i = 0; i < 3; i++) {
						int b = in.read();

						// If end of stream, b is -1.
						if (b >= 0) {
							b3[i] = (byte) b;
							numBinaryBytes++;
						} else {
							break; // out of for loop
						}

					}

					if (numBinaryBytes > 0) {
						encode3to4(b3, 0, numBinaryBytes, buffer, 0, options);
						position = 0;
						numSigBytes = 4;
					} else {
						return -1; // Must be end of stream
					}
				}

				// Else decoding
				else {
					byte[] b4 = new byte[4];
					int i;
					for (i = 0; i < 4; i++) {
						// Read four "meaningful" bytes:
						int b;
						do {
							b = in.read();
						} while (b >= 0
								&& decodabet[b & 0x7f] <= WHITE_SPACE_ENC);

						if (b < 0) {
							break; // Reads a -1 if end of stream
						}

						b4[i] = (byte) b;
					}

					if (i == 4) {
						numSigBytes = decode4to3(b4, buffer, 0, options);
						position = 0;
					} else if (i == 0) {
						return -1;
					} else {
						// Must have broken out from above.
						throw new IOException("Improperly padded Base64 input.");
					} // end

				}
			}

			// Got data?
			if (position >= 0) {
				// End of relevant data?
				if ( /* !encode && */position >= numSigBytes) {
					return -1;
				}

				if (encode && breakLines && lineLength >= MAX_LINE_LENGTH) {
					lineLength = 0;
					return '\n';
				} else {
					lineLength++; // This isn't important when decoding
					// but throwing an extra "if" seems
					// just as wasteful.

					int b = buffer[position++];

					if (position >= bufferLength) {
						position = -1;
					}

					return b & 0xFF; // This is how you "cast" a byte that's
					// intended to be unsigned.
				}
			}

			// Else error
			else {
				throw new IOException("Error in Base64 code reading stream.");
			}
		}

		/**
		 * Calls {@link #read()} repeatedly until the end of stream is reached
		 * or <var>len</var> bytes are read. Returns number of bytes read into
		 * array or -1 if end of stream is encountered.
		 * 
		 * @param dest
		 *            array to hold values
		 * @param off
		 *            offset for array
		 * @param len
		 *            max number of bytes to read into array
		 * @return bytes read into array or -1 if end of stream is encountered.
		 * @since 1.3
		 */
		@Override
		public int read(byte[] dest, int off, int len) throws IOException {
			int i;
			int b;
			for (i = 0; i < len; i++) {
				b = read();

				if (b >= 0) {
					dest[off + i] = (byte) b;
				} else if (i == 0) {
					return -1;
				} else {
					break; // Out of 'for' loop
				} // Out of 'for' loop
			}
			return i;
		}

	}

	/* ******** I N N E R C L A S S O U T P U T S T R E A M ******** */

	/**
	 * A {@link Base64.OutputStream} will write data to another
	 * <tt>java.io.OutputStream</tt>, given in the constructor, and
	 * encode/decode to/from Base64 notation on the fly.
	 * 
	 * @see EncFSBase64
	 * @since 1.3
	 */
	static class OutputStream extends java.io.FilterOutputStream {

		private final boolean encode;
		private int position;
		private byte[] buffer;
		private final int bufferLength;
		private int lineLength;
		private final boolean breakLines;
		private final byte[] b4; // Scratch used in a few places
		private boolean suspendEncoding;
		private final int options; // Record for later
		private final byte[] decodabet; // Local copies to avoid extra method

		// calls

		/**
		 * Constructs a {@link Base64.OutputStream} in ENCODE mode.
		 * 
		 * @param out
		 *            the <tt>java.io.OutputStream</tt> to which data will be
		 *            written.
		 * @since 1.3
		 */
		public OutputStream(java.io.OutputStream out) {
			this(out, ENCODE);
		}

		/**
		 * Constructs a {@link Base64.OutputStream} in either ENCODE or DECODE
		 * mode.
		 * <p/>
		 * Valid options:
		 * <p/>
		 * 
		 * <pre>
		 *   ENCODE or DECODE: Encode or Decode as data is read.
		 *   DO_BREAK_LINES: don't break lines at 76 characters
		 *     (only meaningful when encoding)</i>
		 * </pre>
		 * <p/>
		 * Example: <code>new Base64.OutputStream( out, Base64.ENCODE )</code>
		 * 
		 * @param out
		 *            the <tt>java.io.OutputStream</tt> to which data will be
		 *            written.
		 * @param options
		 *            Specified options.
		 * @see EncFSBase64#ENCODE
		 * @see EncFSBase64#DECODE
		 * @see EncFSBase64#DO_BREAK_LINES
		 * @since 1.3
		 */
		public OutputStream(java.io.OutputStream out, int options) {
			super(out);
			this.breakLines = (options & DO_BREAK_LINES) != 0;
			this.encode = (options & ENCODE) != 0;
			this.bufferLength = encode ? 3 : 4;
			this.buffer = new byte[bufferLength];
			this.position = 0;
			this.lineLength = 0;
			this.suspendEncoding = false;
			this.b4 = new byte[4];
			this.options = options;
			this.decodabet = getDecodabet(options);
		}

		/**
		 * Writes the byte to the output stream after converting to/from Base64
		 * notation. When encoding, bytes are buffered three at a time before
		 * the output stream actually gets a write() call. When decoding, bytes
		 * are buffered four at a time.
		 * 
		 * @param theByte
		 *            the byte to write
		 * @since 1.3
		 */
		@Override
		public void write(int theByte) throws IOException {
			// Encoding suspended?
			if (suspendEncoding) {
				this.out.write(theByte);
				return;
			}

			// Encode?
			if (encode) {
				buffer[position++] = (byte) theByte;
				if (position >= bufferLength) { // Enough to encode.

					this.out.write(encode3to4(b4, buffer, bufferLength, options));

					lineLength += 4;
					if (breakLines && lineLength >= MAX_LINE_LENGTH) {
						this.out.write(NEW_LINE);
						lineLength = 0;
					}

					position = 0;
				}
			}

			// Else, Decoding
			else {
				// Meaningful Base64 character?
				if (decodabet[theByte & 0x7f] > WHITE_SPACE_ENC) {
					buffer[position++] = (byte) theByte;
					if (position >= bufferLength) { // Enough to output.

						int len = EncFSBase64
								.decode4to3(buffer, b4, 0, options);
						out.write(b4, 0, len);
						position = 0;
					}
				} else if (decodabet[theByte & 0x7f] != WHITE_SPACE_ENC) {
					throw new IOException("Invalid character in Base64 data.");
				}
			}
		}

		/**
		 * Calls {@link #write(int)} repeatedly until <var>len</var> bytes are
		 * written.
		 * 
		 * @param theBytes
		 *            array from which to read bytes
		 * @param off
		 *            offset for array
		 * @param len
		 *            max number of bytes to read into array
		 * @since 1.3
		 */
		@Override
		public void write(byte[] theBytes, int off, int len) throws IOException {
			// Encoding suspended?
			if (suspendEncoding) {
				this.out.write(theBytes, off, len);
				return;
			}

			for (int i = 0; i < len; i++) {
				write(theBytes[off + i]);
			}

		}

		/**
		 * Method added by PHIL. [Thanks, PHIL. -Rob] This pads the buffer
		 * without closing the stream.
		 */
		public void flushBase64() throws IOException {
			if (position > 0) {
				if (encode) {
					out.write(encode3to4(b4, buffer, position, options));
					position = 0;
				} else {
					throw new IOException("Base64 input not properly padded.");
				}
			}

		}

		/**
		 * Flushes and closes (I think, in the superclass) the stream.
		 * 
		 * @since 1.3
		 */
		@Override
		public void close() throws IOException {
			// 1. Ensure that pending characters are written
			flushBase64();

			// 2. Actually close the stream
			// Base class both flushes and closes.
			super.close();

			buffer = null;
			out = null;
		}

		/**
		 * Suspends encoding of the stream. May be helpful if you need to embed
		 * a piece of base64-encoded data in a stream.
		 * 
		 * @since 1.5.1
		 */
		public void suspendEncoding() throws IOException {
			flushBase64();
			this.suspendEncoding = true;
		}

		/**
		 * Resumes encoding of the stream. May be helpful if you need to embed a
		 * piece of base64-encoded data in a stream.
		 * 
		 * @since 1.5.1
		 */
		public void resumeEncoding() {
			this.suspendEncoding = false;
		}

	}
}