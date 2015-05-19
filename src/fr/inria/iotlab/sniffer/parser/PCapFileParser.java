package fr.inria.iotlab.sniffer.parser;

import java.io.EOFException;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;


/**
 * Parser class for PCap files.
 * 
 * @author KR
 */
public class PCapFileParser {

	///*** CLASSES INTERNES ***///

	///*** CONSTANTES ***///

	/** Size of the global header of a valid PCap file, in bytes. */
	public static final int PCAP_FILE_GLOBAL_HEADER_SIZE = 24;

	/**
	 *  PCap file format "Magic Number", for standard
	 *  microsecond-resolution timestamp precision.
	 */
	public static final int	PCAP_MAGIC_NUMBER_MICROSEC = 0xa1b2c3d4;
	/**
	 *  PCap file format "Magic Number", for standard
	 *  microsecond-resolution timestamp precision,
	 *  when byte-swapped (i.e.: when the file is coming
	 *  from a platform with inverse byte endianness).
	 */
	public static final int	PCAP_MAGIC_NUMBER_MICROSEC_SWAPPED = 0xd4c3b2a1;
	/**
	 *  PCap file format "Magic Number", for extended
	 *  nanosecond-resolution timestamp precision.
	 */
	public static final int	PCAP_MAGIC_NUMBER_NANOSEC = 0xa1b23c4d;
	/**
	 *  PCap file format "Magic Number", for extended
	 *  nanosecond-resolution timestamp precision,
	 *  when byte-swapped (i.e.: when the file is coming
	 *  from a platform with inverse byte endianness).
	 */
	public static final int PCAP_MAGIC_NUMBER_NANOSEC_SWAPPED = 0x4d3cb2a1;


	// MESSAGES D'ERREUR //

	private static final String ERR_FILE_DOES_NOT_EXIST =
			"File %s doesn't exist!";
	private static final String ERR_FILE_CAN_NOT_BE_READ =
			"File %s cannot be read!";
	private static final String ERR_FILE_TOO_SHORT =
			"File %s is too short for valid PCap file (less than " +
					PCAP_FILE_GLOBAL_HEADER_SIZE + " bytes)!";
	private static final String ERR_FILE_BAD_MAGIC_NUM =
			"File %s doesn't have a valid PCap magic number in header!";
	private static final String ERR_TRUNCATED_PACKET =
			"Encountered EOF while reading packet data" +
			" (could only read %d bytes instead of expected %d)!";

	///*** ATTRIBUTS ***///

	/* source file reference */
	private File pcapSrcFile;
	private NumberInputStream pcapInputStream;

	/* source file format properties */
	private boolean byteSwapped;
	private boolean extendedTimeRes;

	/* file properties, read from its global header */
	private int magicNumber;
	private short versionMajor;
	private short versionMinor;
	private int timeZoneDelta;
	private int timeStampAccuracy;
	private int maxPacketLength;
	private NetworkType netType;

	///*** CONSTRUCTEUR ***///

	/**
	 * Constructor for PCap file parser.
	 * 
	 * @param filePath path to the PCap file to read and parse.
	 *                 This file must exist and be readable.
	 * 
	 * @throws IllegalArgumentException if <code>filePath</code> doesn't
	 *                                  correspond to an existing and
	 *                                  readable file, or is not a valid
	 *                                  PCap file (bad format).
	 * @throws IOException if some I/O error prevents the file header
	 *                     from being read.
	 */
	public PCapFileParser(String filePath)
	throws IllegalArgumentException, IOException
	{
		/* check whether source file is basically valid */
		pcapSrcFile = new File(filePath);
		if (!(pcapSrcFile.exists())) {
			throw new IllegalArgumentException(String.format(
					ERR_FILE_DOES_NOT_EXIST,
					filePath));
		}
		if (!(pcapSrcFile.canRead())) {
			throw new IllegalArgumentException(String.format(
					ERR_FILE_CAN_NOT_BE_READ,
					filePath));
		}
		if (pcapSrcFile.length() <= PCAP_FILE_GLOBAL_HEADER_SIZE) {
			throw new IllegalArgumentException(String.format(
					ERR_FILE_TOO_SHORT,
					filePath));
		}

		/* parse global file header */
		this.pcapInputStream =
				new NumberInputStream(new FileInputStream(pcapSrcFile));

		try {
			this.magicNumber = this.pcapInputStream.readInt();
			switch (this.magicNumber) {
			case PCAP_MAGIC_NUMBER_MICROSEC:
				this.extendedTimeRes = false;
				this.byteSwapped = false;
				break;
			case PCAP_MAGIC_NUMBER_MICROSEC_SWAPPED:
				this.extendedTimeRes = false;
				this.byteSwapped = true;
				break;
			case PCAP_MAGIC_NUMBER_NANOSEC:
				this.extendedTimeRes = true;
				this.byteSwapped = false;
				break;
			case PCAP_MAGIC_NUMBER_NANOSEC_SWAPPED:
				this.extendedTimeRes = true;
				this.byteSwapped = true;
				break;
			default:
				throw new IllegalArgumentException(String.format(
						ERR_FILE_BAD_MAGIC_NUM,
						filePath));
			}
			this.pcapInputStream.setByteSwapped(this.byteSwapped);

			this.versionMajor = this.pcapInputStream.readShort();
			this.versionMinor = this.pcapInputStream.readShort();
			this.timeZoneDelta = this.pcapInputStream.readInt();
			this.timeStampAccuracy = this.pcapInputStream.readInt();
			this.maxPacketLength = this.pcapInputStream.readInt();
			int netTypeID = this.pcapInputStream.readInt();
			this.netType = NetworkType.getNetworkTypeFromID(netTypeID);

		} catch (EOFException exc) {
			throw new IllegalArgumentException(String.format(
					ERR_FILE_TOO_SHORT,
					filePath));
		}
	}

	///*** ACCESSEURS ***///

	/**
	 * @return the file's magic number (from its global header).
	 */
	public int getMagicNumber() {
		return this.magicNumber;
	}

	/**
	 * @return the file version's major number.
	 */
	public short getVersionMajor() {
		return this.versionMajor;
	}

	/**
	 * @return the file version's minor number.
	 */
	public short getVersionMinor() {
		return this.versionMinor;
	}

	/**
	 * @return the file's time zone ("correction"/delta from GMT in seconds).
	 */
	public int getTimeZoneDelta() {
		return this.timeZoneDelta;
	}

	/**
	 * @return the file timestamps' accuracy (normally always zero).
	 */
	public int getTimeStampAccuracy() {
		return this.timeStampAccuracy;
	}

	/**
	 * @return the maximal length of captured pacjets in this file, in bytes.
	 */
	public int getMaxPacketLength() {
		return this.maxPacketLength;
	}

	/**
	 * @return the data link type of the network
	 *         from which this file was "sniffed".
	 */
	public NetworkType getNetworkType() {
		return this.netType;
	}

	/**
	 * @return <code>true</code> if the platform on which this file
	 *         was "sniffed" has a different byte endianness from this
	 *         computer (on which the parser is run), thus implying
	 *         the need to byte-swap the file's numeric values; <br/>
	 *         <code>false</code> if both platforms have the same
	 *         endianness, so that no byte swapping is needed. 
	 */
	public boolean isByteSwapped() {
		return this.byteSwapped;
	}

	/**
	 * @return <code>true</code> if this PCap file has an extended,
	 *         nanosecond resolution for its timestamps; <br/>
	 *         <code>false</code> if this PCap file has a standard,
	 *         microsecond resolution for its timestamps.
	 */
	public boolean hasExtendedTimeResolution() {
		return this.extendedTimeRes;
	}

	///*** METHODES DE LECTURE ***///

	/**
	 * Read and parse the next packet in the currently open PCap file.
	 * 
	 * @return the latest packet read in parsed form
	 *         (<code>PCapSniffedPacket</code> instance).
	 * @throws IOException if an I/O error prevents the next packet
	 *                     from being correctly read (like for example
	 *                     an unexpected EOF in the middle packet data).
	 * @see PCapSniffedPacket
	 */
	public PCapSniffedPacket readNextPacket() throws IOException {
		int ts = this.pcapInputStream.readInt();
		int ssec = this.pcapInputStream.readInt();
		int len = this.pcapInputStream.readInt();
		int origLen = this.pcapInputStream.readInt();
		byte[] data = new byte[len];
		int bytesRead = this.pcapInputStream.read(data);
		if (bytesRead != len) {
			throw new EOFException(String.format(
					ERR_TRUNCATED_PACKET,
					bytesRead, len));
		}
		return new PCapSniffedPacket(
				ts,
				ssec,
				this.extendedTimeRes,
				len,
				origLen,
				data);
	}

	/**
	 * Read and parse all packets stored in the currently open PCap file.
	 * 
	 * @return the <code>List</code> of all the packets
	 *         stored in the current PCap file in parsed form
	 *         (<code>PCapSniffedPacket</code> instance).
	 * @throws IOException if an I/O error prevents the packets
	 *                     from being correctly read (like for example
	 *                     an unexpected EOF in the middle packet data).
	 * @see PCapSniffedPacket
	 */
	public List<PCapSniffedPacket> readAllPackets() throws IOException {
		List<PCapSniffedPacket> pkts = new LinkedList<PCapSniffedPacket>();
		while (!lastPacketRead()) {
			pkts.add(readNextPacket());
		}
		return pkts;
	}

	/**
	 * @return <code>true</code> if the last packet has been read from
	 *         the source PCap file, and thus no more packets are available
	 *         (i.e.: EOF has been attained);
	 *         <code>false</code> if there are still more packet(s)
	 *         available from this file to be read. 
	 */
	public boolean lastPacketRead() {
		try {
			return (this.pcapInputStream.available() > 0);
		} catch (IOException e) {
			return true;
		}
	}

}
