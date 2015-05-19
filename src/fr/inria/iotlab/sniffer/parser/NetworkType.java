package fr.inria.iotlab.sniffer.parser;

/**
 * This enum represents network (link-layer header) types,
 * as defined by the <tt>tcpdump</tt> and <tt>libpcap</tt> tools.
 * 
 * @author KR
 * @version 20/05/2015
 * @see TcpDump's documentation (http://www.tcpdump.org/linktypes.html)
 */
public enum NetworkType {

	/** "Classic" loopback encapsulation. */
	NULL (0, "NULL", "DLT_NULL"),
	
	/** IEEE 802.3 Ethernet. */
	ETHERNET (1, "ETHERNET", "DLT_EN10MB"),

	/** "Bare" AX25 packets. */
	AX25 (3, "AX25", "DLT_AX25"),

	/** IEEE 802.5 Token Ring. */
	IEEE802_5 (6, "IEEE802_5", "DLT_IEEE802"),

	/** ARCNET data packets (ATA 878.1-1999 & 878.2; RFC 1051 & 1201). */
	ARCNET_BSD (7, "ARCNET", "DLT_ARCNET"),

	/** SLIP */
	SLIP (8, "SLIP", "DLT_SLIP"),

	/** PPP (RFC 1661 & 1662). */
	PPP (9, "PPP", "DLT_PPP"),

	/** FDDI (ANSI INCITS 239-1994). */
	FDDI (10, "FDDI", "DLT_FDDI"),

	/** PPP in HDLC (RFC 1662; or RFC 1547 section 4.3.1). */
	PPP_HDLC (50, "PPP_HDLC", "DLT_PPP_SERIAL"),

	/** PPP over Ethernet (PPPoE: RFC 2516). */
	PPP_ETHER (51, "PPP_ETHER", "DLT_PPP_ETHER"),

	/** ATM encapsulated in LLC (RFC 1483). */
	ATM_RFC1483 (100, "ATM_RFC1483", "DLT_ATM_RFC1483"),

	/** Raw IP. */
	RAW (101, "RAW", "DLT_RAW"),

	/** Cisco PPP with HDLC framing (RFC 1547 section 4.3.1). */
	C_HDLC (104, "C_HDLC", "DLT_C_HDLC"),

	/** IEEE 802.11 wireless LAN. */
	IEEE802_11 (105, "IEEE802_11", "DLT_IEEE802_AA"),

	/** Frame relay. */
	FRELAY (107, "FRELAY", "DLT_FRELAY"),

	/** OpenBSD loopback encapsulation. */
	LOOP (108, "LOOP", "DLT_LOOP"),

	/** Linux "cooked" capture encapsulation. */
	LINUX_SLL (113, "LINUX_SLL", "DLT_LINUX_SLL"),

	/** Apple LocalTalk. */
	LTALK (114, "LTALK", "DLT_LTALK"),

	/** OpenBSD pflog. */
	PFLOG (117, "PFLOG", "DLT_PFLOG"),

	/** Prism monitor mode 802.11 packets. */
	IEEE802_11_PRISM (119, "IEEE802_11_PRISM", "DLT_PRISM_HEADER"),

	/** IP over Fibre Channel (RFC 2625). */
	IP_OVER_FC (122, "IP_OVER_FC", "DLT_IP_OVER_FC"),

	/** ATM traffic (SunATM encapsulation). */
	SUNATM (123, "SUNATM", "DLT_SUNATM"),

	/** Radiotap link-layer 802.11 packets. */
	IEEE802_11_RADIOTAP (127, "IEEE802_11_RADIOTAP",
	                          "DLT_IEEE802_11_RADIO"),

	/** ARCNET data packets, Linux variant. */
	ARCNET_LINUX (129, "ARCNET_LINUX", "DLT_ARCNET_LINUX"),

	/** Apple IP over IEEE1394 cooked packets. */
	APPLE_IP_OVER_IEEE1394 (138, "APPLE_IP_OVER_IEEE1394",
	                             "DLT_APPLE_IP_OVER_IEEE1394"),

	/** Message Transfert Part level 2 (ITU-T Q.703) with pseudo-header. */
	MTP2_WITH_PHDR (139, "MTP2_WITH_PHDR", "DLT_MTP2_WITH_PHDR"),

	/** Message Transfert Part level 2 (ITU-T Q.703). */
	MTP2 (140, "MTP2", "DLT_MTP2"),

	/** Message Transfert Part level 2 (ITU-T Q.704). */
	MTP3 (141, "MTP3", "DLT_MTP3"),

	/** Signal Connection Control Part (ITU-T Q.711--Q.714). */
	SCCP (142, "SCCP", "DLT_SCCP"),

	/** DOCSIS MAC frames. */
	DOCSIS (143, "DOCSIS", "DLT_DOCSIS"),

	/** Linux IrDA packets. */
	LINUX_IRDA (144, "LINUX_IRDA", "DLT_LINUX_IRDA"),

	/* The 16 types with ID 147 to 162 are reserved for private use... */

	USER0  (147, "USER0",  "DLT_USER0"),
	USER1  (148, "USER1",  "DLT_USER1"),
	USER2  (149, "USER2",  "DLT_USER2"),
	USER3  (150, "USER3",  "DLT_USER3"),
	USER4  (151, "USER4",  "DLT_USER4"),
	USER5  (152, "USER5",  "DLT_USER5"),
	USER6  (153, "USER6",  "DLT_USER6"),
	USER7  (154, "USER7",  "DLT_USER7"),
	USER8  (155, "USER8",  "DLT_USER8"),
	USER9  (156, "USER9",  "DLT_USER9"),
	USER10 (157, "USER10", "DLT_USER10"),
	USER11 (158, "USER11", "DLT_USER11"),
	USER12 (159, "USER12", "DLT_USER12"),
	USER13 (160, "USER13", "DLT_USER13"),
	USER14 (161, "USER14", "DLT_USER14"),
	USER15 (162, "USER15", "DLT_USER15"),

	/** AVS monitor mode 802.11 packets. */
	IEEE802_11_AVS (163, "IEEE802_11_AVS", "DLT_IEEE802_11_AVS"),

	/** BACnet MS/TP frames (ANSI/ASHRAE standard 135). */
	BACNET_MS_TP (165, "BACNET_MS_TP", "DLT_BACNET_MS_TP"),

	/** PPP in HDLC with direction indication. */
	PPP_PPPD (166, "PPP_PPPD", "DLT_PPP_PPPD"),

	/** General Packet Radio Service Logical Link Control (3GPP TS 04.64). */
	GPRS_LLC (169, "GPRS_LLC", "DLT_GPRS_LLC"),

	/** Link Access Procedures on D channel frames (ITU-T Q.920 & Q.921),
	    with Linux-specific pseudo-header.  */
	LINUX_LAPD (177, "LINUX_LAPD", "DLT_LINUX_LAPD"),

	/** Bluetooth HCI UART transport layer frame. */
	BLUETOOTH_HCI_H4 (187, "BLUETOOTH_HCI_H4", "DLT_BLUETOOTH_HCI_H4"),

	/** USB packets with partial Linux-specific header. */
	USB_LINUX (189, "USB_LINUX", "DLT_USB_LINUX"),

	/** Per_Packet Information. */
	PPI (192, "PPI", "DLT_PPI"),

	/** IEEE 802.15.4 packets, with FCS. */
	IEEE802_15_4 (195, "IEEE802_15_4", "DLT_IEEE802_15_4"),

	/** Packets with SITA pseudo-header. */
	SITA (196, "SITA", "DLT_SITA"),

	/** Packets with Endace DAG cards pseudo-header. */
	ERF (197, "ERF", "DLT_ERF"),

	/** Bluetooth HCI UART transport layer frame, with direction field. */
	BLUETOOTH_HCI_H4_WITH_PHDR (201, "BLUETOOTH_HCI_H4_WITH_PHDR",
	                                 "DLT_BLUETOOTH_HCI_H4_WITH_PHDR"),

	/** AX25 packets with KISS header. */
	AX25_KISS (202, "AX25_KISS", "DLT_AX25_KISS"),

	/** Link Access Procedures on D channel frames (ITU-T Q.920 & Q.921). */
	LAPD (203, "LAPD", "DLT_LAPD"),

	/** PPP (RFC 1661 & 1662), with direction pseudo-header. */
	PPP_WITH_DIR (204, "PPP_WITH_DIR", "DLT_PPP_WITH_DIR"),

	/** Cisco PPP with HDLC framing (RFC 1547 section 4.3.1),
	    with direction pseudo-header. */
	C_HDLC_WITH_DIR (205, "C_HDLC_WITH_DIR", "DLT_C_HDLC_WITH_DIR"),

	/** Frame relay, with direction pseudo-header. */
	FRELAY_WITH_DIR (206, "FRELAY_WITH_DIR", "DLT_FRELAY_WITH_DIR"),

	/** IPMB over I2C, with Linux-specific pseudo-header. */
	IPMB_LINUX (209, "IPMB_LINUX", "DLT_IPMB_LINUX"),

	/** IEEE 802.15.4 packets, with FCS and non-ASK PHY header. */
	IEEE802_15_4_NONASK_PHY (215, "IEEE802_15_4_NONASK_PHY",
	                              "DLT_IEEE802_15_4_NONASK_PHY"),

	/** USB packets with full Linux-specific header. */
	USB_LINUX_MMAPED (220, "USB_LINUX_MMAPED", "DLT_USB_LINUX_MMAPED"),

	/** Fibre Channel FC-2 frames. */
	FC_2 (224, "FC_2", "DLT_FC_2"),

	/** Fibre Channel FC-2 frames, with SOF delimiters. */
	FC_2_WITH_FRAME_DELIMS (225, "FC_2_WITH_FRAME_DELIMS",
	                             "DLT_FC_2_WITH_FRAME_DELIMS"),

	/** IP packets with Solaris ipnet pseudo-header. */
	IPNET (226, "IPNET", "DLT_IPNET"),

	/** Controller Area Network frames, with Linux SocketCAN pseudo-header. */
	CAN_SOCKETCAN (227, "CAN_SOCKETCAN", "DLT_CAN_SOCKETCAN"),

	/** Raw IPv4 packets. */
	IPV4 (228, "IPV4", "DLT_IPV4"),

	/** Raw IPv6 packets. */
	IPV6 (229, "IPV6", "DLT_IPV6"),

	/** IEEE 802.15.4 packets, without the final FCS. */
	IEEE802_15_4_NOFCS (230, "IEEE802_15_4_NOFCS",
	                         "DLT_IEEE802_15_4_NOFCS"),

	/** Raw D-Bus messages. */
	DBUS (231, "DBUS", "DLT_DBUS"),

	/** DVB Common Interface messages. */
	DVB_CI (235, "DVB_CI", "DLT_DVB_CI"),

	/** Variant of 3GPP TS 27.010 multiplexing protocol. */
	MUX27010 (236, "MUX27010", "DLT_MUX27010"),

	/** STANAG 5066 compliant D-PDUs. */
	STANAG_5066_D_PDU (237, "STANAG_5066_D_PDU",
	                        "DLT_STANAG_5066_D_PDU"),

	/** Linux Netlink NFLOG socket log messages. */
	NFLOG (239, "NFLOG", "DLT_NFLOG"),

	/** Ethernet frames with netANALYZER pseudo-header. */
	NETANALYZER (240, "NETANALYZER", "DLT_NETANALYZER"),

	/** Ethernet frames with netANALYZER pseudo-header,
	    and with preamble and SFD. */
	NETANALYZER_TRANSPARENT (241, "NETANALYZER_TRANSPARENT",
	                              "DLT_NETANALYZER_TRANSPARENT"),

	/** IP over InfiniBand (RFC 4391 section 6). */
	IPOIB (242, "IPOIB", "DLT_IPOIB"),

	/** MPEG-2 Transport Stream (ISO 13818-1/ITU-T H.222.0). */
	MPEG_2_TS (243, "MPEG_2_TS", "DLT_MPEG_2_TS"),

	/** Frames with ng40 pseudo-header. */
	NG40 (244, "NG40", "DLT_NG40"),

	/** LLCP frames with NFC pseudo-header. */
	NFC_LLCP (245, "NFC_LLCP", "DLT_NFC_LLCP"),

	/** Raw InfiniBand frames. */
	INFINIBAND (247, "INFINIBAND", "DLT_INFINIBAND"),

	/** SCTP packets (RFC 4960). */
	SCTP (248, "SCTP", "DLT_SCTP"),

	/** USB packets with USBPcap header. */
	USBPCAP (249, "USBPCAP", "DLT_USBPCAP"),

	/** Serial lines packets with RTAC header. */
	RTAC_SERIAL (250, "RTAC_SERIAL", "DLT_RTAC_SERIAL"),

	/** Bluetooth Low Energy Link Layer packets (Bluetooth v4.0). */
	BLUETOOTH_LE_LL (251, "BLUETOOTH_LE_LL", "DLT_BLUETOOTH_LE_LL"),

	/** Linux Netlink capture encapsulation. */
	NETLINK (253, "NETLINK", "DLT_NETLINK"),

	/** Bluetooth Linux Monitor encapsulation (BlueZ stack). */
	BLUETOOTH_LINUX_MONITOR (254, "BLUETOOTH_LINUX_MONITOR",
	                              "DLT_BLUETOOTH_LINUX_MONITOR"),

	/** Bluetooth Basic Rate and Enhanced Date Rate baseband packets. */
	BLUETOOTH_BREDR_BB (255, "BLUETOOTH_BREDR_BB",
	                         "DLT_BLUETOOTH_BREDR_BB"),

	/** Bluetooth Low Energy Link Layer packets (Bluetooth v4.0)
	    with pseudo-header. */
	BLUETOOTH_LE_LL_WITH_PHDR (256, "BLUETOOTH_LE_LL_WITH_PHDR",
	                                "DLT_BLUETOOTH_LE_LL_WITH_PHDR"),

	/** PROFIBUS Data Link layer packets (IEC 61158-6-3). */
	PROFIBUS_DL (257, "PROFIBUS_DL", "DLT_PROFIBUS_DL"),

	/** Apple PKTAP capture encapsulation. */
	PKTAP (258, "PKTAP", "DLT_PKTAP"),

	/** Ethernet over Passive Optical Network packets
	    (IEEE 802.3 section 5 clause 65.1.3.2). */
	EPON (259, "EPON", "DLT_EPON"),

	/** IPMI trace pacekts (PICMG HPM.2 specification). */
	IPMI_HPM_2 (260, "IPMI_HPM_2", "DLT_IPMI_HPM_2"),

	/** Z-Wave RF profiles R1 & R2. */
	ZWAVE_R1_R2 (261, "ZWAVE_R1_R2", "DLT_ZWAVE_R1_R2"),

	/** Z-Wave RF profile R3. */
	ZWAVE_R3 (262, "ZWAVE_R3", "DLT_ZWAVE_R3"),

	/** WattStopper Digital Lighting Management
	    & Legrand Nitoo open procotol. */
	WATTSTOPPER_DLM (263, "WATTSTOPPER_DLM", "DLT_WATTSTOPPER_DLM"),

	XXX (-1, "", "");


	/* private attributes and constructor */

	private final int id;
	private final String linkType;
	private final String dltName;

	private NetworkType(int id, String name, String dlt) {
		this.id = id;
		this.linkType = name;
		this.dltName = dlt;
	}


	/* public methods (getters) */

	/**
	 * @return The network type's numeric ID.
	 */
	public int getID() {
		return this.id;
	}

	/**
	 * @return The name of the network link type.
	 */
	public String getLinkType() {
		return this.linkType;
	}

	/**
	 * @return The corresponding <code>DLT_name</code> for the link type.
	 */
	public String getDLTName() {
		return this.dltName;
	}


	/* public static searching method */

	/**
	 * Get the network (link-layer) type corresponding to the given ID.
	 * 
	 * @param id numeric identifier of the network type to find.
	 * 
	 * @return the network type corresponding to the given ID,
	 *         or <code>null</code> if the ID is not known/found.
	 */
	public static NetworkType getNetworkTypeFromID(int id) {
		for (NetworkType nt: NetworkType.values())
			if (nt.id == id)
				return nt;

		// type unknown/not found
		return null;
	}

}
