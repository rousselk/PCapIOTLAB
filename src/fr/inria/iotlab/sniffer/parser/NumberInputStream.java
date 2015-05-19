package fr.inria.iotlab.sniffer.parser;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;

/**
 * A custom <code>InputStream</code> subclass that provides methods to read
 * basic numeric values (i.e.: <code>short</code>, <code>int</code>,
 * <code>long</code>, etc.).
 * <br/>
 * Currently, only integral values are supported; no floating-point numbers.
 * 
 * @author KR
 */
public class NumberInputStream extends InputStream {

	///*** CONSTANTES ***///

	// MESSAGES D'ERREUR //

	private static final String ERR_NULL_BASE_INPUTSTREAM =
			"Cannot create a NumberInputStream on a null base InputStream!";
	private static final String ERR_NO_MORE_BYTES_IN_FILE =
			"EOF encountered: no more bytes left in source file to read!";
	private static final String ERR_NOT_ENOUGH_BYTES_IN_FILE =
			"EOF encountered: not enough bytes left" +
			" in source file to read a %s value!";

	///*** ATTRIBUTS ***///

	/**
	 * The base <code>InputStream</code> from which
	 * bytes are actually read.
	 */
	private final InputStream baseInputStream;

	/**
	 * <code>true</code> if the numeric values must have their bytes
	 * swapped&mdash;that is: reversed&mdash;when read; <br/>
	 * <code>false</code> if the numeric values can be read "directly"
	 * (i.e.: returned in their raw form).
	 */
	private boolean byteSwapped;

	///*** CONSTRUCTEUR ***///

	/**
	 * Constructor for a new <code>NumberInputStream</code>.
	 * 
	 * @param base the base <code>InputStream</code> from which
	 *             raw bytes are read.
	 */
	public NumberInputStream(InputStream base) throws NullPointerException {
		if (base == null) {
			throw new NullPointerException(ERR_NULL_BASE_INPUTSTREAM);
		}
		this.baseInputStream = base;
	}

	///*** METHODES HERITEES ***///

	/*
	 * (non-Javadoc)
	 * @see java.io.InputStream#read()
	 */
	@Override
	public int read() throws IOException {
		/* simply read a byte from the base input stream */
		return baseInputStream.read();
	}

	/**
	 * Closes the underlying base <code>InputStream</code> of this stream.
	 * (This is the only resource associated with this kind of stream.)
	 * 
	 * @throws IOException if an I/O error occurs.
	 */
	@Override
	public void close() throws IOException {
		this.baseInputStream.close();
	}

	///*** ACCESSEURS/MODIFICATEURS DE PROPRIETES ***///

	/**
	 * @return <code>true</code> if the numeric values must have their bytes
	 * swapped (that is: reversed) when read; <br/>
	 * <code>false</code> if the numeric values can be read "directly"
	 * (i.e.: returned in their raw form).
	 */
	public boolean isByteSwapped() {
		return this.byteSwapped;
	}

	/**
	 * Set whether this <code>NumberInputStream</code> instance must swap
	 * (reverse) the bytes of the values it reads before returning them.
	 * (This is useful when reading data from a platform with a different
	 * byte endianness.)
	 * 
	 * @param swap <code>true</code> to swap (reverse) the bytes of the read
	 *             numeric values before returning them;
	 *             <code>false</code> to return the read numeric values
	 *             "directly" (i.e.: in their raw form).
	 */
	public void setByteSwapped(boolean swap) {
		this.byteSwapped = swap;
	}

	///*** METHODES DE LECTURE ***///

	public byte readByte() throws IOException {
		int byteRead = this.baseInputStream.read();
		if (byteRead == -1) {
			throw new EOFException(ERR_NO_MORE_BYTES_IN_FILE);
		}
		return (byte)(byteRead);
	}

	public short readShort() throws IOException {
		byte[] buf = new byte[2];
		int bytesRead = this.baseInputStream.read(buf);
		if (bytesRead != 2) {
			throw new EOFException(String.format(
					ERR_NOT_ENOUGH_BYTES_IN_FILE,
					"short"));
		}

		short val;
		if (this.byteSwapped) {
			val  = (short)((buf[1] & 0xff) << 8);
			val |= (short) (buf[0] & 0xff);
		} else {
			val  = (short)((buf[0] & 0xff) << 8);
			val |= (short) (buf[1] & 0xff);
		}
		return val;
	}

	public int readInt() throws IOException {
		byte[] buf = new byte[4];
		int bytesRead = this.baseInputStream.read(buf);
		if (bytesRead != 4) {
			throw new EOFException(String.format(
					ERR_NOT_ENOUGH_BYTES_IN_FILE,
					"int"));
		}

		int val;
		if (this.byteSwapped) {
			val  = (buf[3] & 0xff) << 24;
			val |= (buf[2] & 0xff) << 16;
			val |= (buf[1] & 0xff) << 8;
			val |= (buf[0] & 0xff);
		} else {
			val  = (buf[0] & 0xff) << 24;
			val |= (buf[1] & 0xff) << 16;
			val |= (buf[2] & 0xff) << 8;
			val |= (buf[3] & 0xff);
		}
		return val;
	}

	public long readLong() throws IOException {
		byte[] buf = new byte[8];
		int bytesRead = this.baseInputStream.read(buf);
		if (bytesRead != 8) {
			throw new EOFException(String.format(
					ERR_NOT_ENOUGH_BYTES_IN_FILE,
					"long"));
		}

		long val;
		if (this.byteSwapped) {
			val  = (long)(buf[7] & 0xff) << 56;
			val |= (long)(buf[6] & 0xff) << 48;
			val |= (long)(buf[5] & 0xff) << 40;
			val |= (long)(buf[4] & 0xff) << 32;
			val |= (long)(buf[3] & 0xff) << 24;
			val |= (long)(buf[2] & 0xff) << 16;
			val |= (long)(buf[1] & 0xff) << 8;
			val |= (long)(buf[0] & 0xff);
		} else {
			val  = (long)(buf[0] & 0xff) << 56;
			val |= (long)(buf[1] & 0xff) << 48;
			val |= (long)(buf[2] & 0xff) << 40;
			val |= (long)(buf[3] & 0xff) << 32;
			val |= (long)(buf[4] & 0xff) << 24;
			val |= (long)(buf[5] & 0xff) << 16;
			val |= (long)(buf[6] & 0xff) << 8;
			val |= (long)(buf[7] & 0xff);
		}
		return val;
	}

}
