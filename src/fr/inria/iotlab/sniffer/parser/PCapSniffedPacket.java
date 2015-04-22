package fr.inria.iotlab.sniffer.parser;

/**
 * Class representing a (sniffed) packet in a PCap file.
 * <br/>
 * Note that this is an immutable class.
 * 
 * @author KR
 */
public class PCapSniffedPacket {

	///*** CONSTANTES ***///

	// MESSAGES D'ERREUR //

	private static final String ERR_INCL_LEN_LESS_THAN_ORIG_LEN =
			"Length of packet in file (%d bytes)" +
			" is inferior to given original packet length (%d)!";
	private static final String ERR_NULL_DATA =
			"Cannot create a packet with null data array!";
	private static final String ERR_DATA_ARRAY_TOO_SHORT =
			"The given data array is shorter (%d bytes)" +
			" that the given packet length in header (%d)!";

	///*** ATTRIBUTS ***///

	private final long timestamp;
	private final int subSecondFraction;
	private final boolean nanosecondPrecision;
	private final int actualLength;
	private final int packetOriginalLength;
	private final byte[] packetData;

	///*** CONSTRUCTEUR ***///

	public PCapSniffedPacket(int ts, int ssec, boolean nanoPrec,
			int len, int origLen,
			byte[] data)
	{
		long fraction = (long)ssec & 0x00000000FFFFFFFFL;
		long fractionLimit = (nanoPrec ? 1000000000 : 1000000);
		while (fraction > fractionLimit) {
			ts++;
			fraction -= fractionLimit;
		}
		this.timestamp = ts;
		this.subSecondFraction = (int) fraction;
		this.nanosecondPrecision = nanoPrec;

		this.actualLength = len;
		this.packetOriginalLength = origLen;
		if (origLen < len) {
			throw new IllegalArgumentException(String.format(
					ERR_INCL_LEN_LESS_THAN_ORIG_LEN,
					this.actualLength, this.packetOriginalLength));
		}

		if (data == null) {
			throw new NullPointerException(ERR_NULL_DATA);
		}
		if (data.length < this.actualLength) {
			throw new IllegalArgumentException(String.format(
					ERR_DATA_ARRAY_TOO_SHORT,
					data.length, this.actualLength));
		}

		this.packetData = new byte[this.actualLength];
		System.arraycopy(data, 0, this.packetData, 0, this.actualLength);
	}

	///*** ACCESSEURS ***///

	/**
	 * @return The timestamp of the packet, in Unix epoch
	 *         (i.e.: number of seconds since 1/1/1970 00:00:00 GMT).
	 */
	public long getTimestampSeconds() {
		return this.timestamp;
	}

	/**
	 * @return The sub-second fraction of the packet timestamp,
	 *         in either microseconds or nanoseconds, according
	 *         to the original PCap file format.
	 * @see #hasNanosecondPrecision()
	 */
	public int getTimestampFraction() {
		return this.subSecondFraction;
	}

	/**
	 * @return <code>true</code> true if the sub-second fraction
	 *         of this packet's timestamp has a nanosecond (i.e.: extended)
	 *         precision;
	 *         <code>false</code> true if it has standard microsecond
	 *         precision.
	 * @see #getTimestampFraction()
	 */
	public boolean hasNanosecondPrecision() {
		return this.nanosecondPrecision;
	}

	/**
	 * @return the packet's data length, as read from the actual PCap file.
	 * @see #getOriginalPacketLength()
	 */
	public int getPacketLength() {
		return this.actualLength;
	}

	/**
	 * @return the packet's original length; if this value differs from
	 *         the result of <code>getPacketLength</code>, it means that
	 *         the packet data had to be truncated when being sniffed
	 *         into the PCap file.
	 * @see #getPacketLength()
	 */
	public int getOriginalPacketLength() {
		return this.packetOriginalLength;
	}

	/**
	 * @return The sniffed packet's contents, as a raw byte array.
	 */
	public byte[] getPacketData() {
		return this.packetData;
	}

}
