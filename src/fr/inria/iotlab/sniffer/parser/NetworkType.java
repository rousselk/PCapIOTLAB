package fr.inria.iotlab.sniffer.parser;

/**
 * This enum represents network (link-layer header) types,
 * as defined by the <tt>tcpdump</tt> and <tt>libpcap</tt> tools.
 * 
 * @author KR
 * @see TcpDump's documentation (http://www.tcpdump.org/linktypes.html)
 */
public enum NetworkType {

	NULL (0, "NULL", "DLT_NULL"),
	ETHERNET (1, "ETHERNET", "DLT_EN10MB"),
	AX25 (3, "AX25", "DLT_AX25"),
	IEEE802_5 (6, "IEEE802_5", "DLT_IEEE802"),
	ARCNET_BSD (7, "ARCNET", "DLT_ARCNET"),
	SLIP (8, "SLIP", "DLT_SLIP"),
	PPP (9, "PPP", "DLT_PPP"),
	FDDI (10, "FDDI", "DLT_FDDI"),
	PPP_HDLC (50, "PPP_HDLC", "DLT_PPP_SERIAL"),
	PPP_ETHER (51, "PPP_ETHER", "DLT_PPP_ETHER"),
	ATM_RFC1483 (100, "ATM_RFC1483", "DLT_ATM_RFC1483"),
	RAW (101, "RAW", "DLT_RAW"),
	C_HDLC (104, "C_HDLC", "DLT_C_HDLC"),
	IEEE802_11 (105, "IEEE802_11", "DLT_IEEE802_AA"),
	FRELAY (107, "FRELAY", "DLT_FRELAY"),
	LOOP (108, "LOOP", "DLT_LOOP"),
	LINUX_SLL (113, "LINUX_SLL", "DLT_LINUX_SLL"),
	LTALK (114, "LTALK", "DLT_LTALK"),
	PFLOG (117, "PFLOG", "DLT_PFLOG"),
	IEEE802_11_PRISM (119, "IEEE802_11_PRISM", "DLT_PRISM_HEADER"),
	IP_OVER_FC (122, "IP_OVER_FC", "DLT_IP_OVER_FC"),
	SUNATM (123, "SUNATM", "DLT_SUNATM"),
	IEEE802_11_RADIOTAP (127, "IEEE802_11_RADIOTAP",
	                          "DLT_IEEE802_11_RADIO"),
	ARCNET_LINUX (129, "ARCNET_LINUX", "DLT_ARCNET_LINUX"),
	APPLE_IP_OVER_IEEE1394 (138, "APPLE_IP_OVER_IEEE1394",
	                             "DLT_APPLE_IP_OVER_IEEE1394"),
	MTP2_WITH_PHDR (139, "MTP2_WITH_PHDR", "DLT_MTP2_WITH_PHDR"),
	MTP2 (140, "MTP2", "DLT_MTP2"),
	MTP3 (141, "MTP3", "DLT_MTP3"),
	SCCP (142, "SCCP", "DLT_SCCP"),
	DOCSIS (143, "DOCSIS", "DLT_DOCSIS"),
	LINUX_IRDA (144, "LINUX_IRDA", "DLT_LINUX_IRDA"),

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

	IEEE802_11_AVS (163, "IEEE802_11_AVS", "DLT_IEEE802_11_AVS"),
	BACNET_MS_TP (165, "BACNET_MS_TP", "DLT_BACNET_MS_TP"),
	PPP_PPPD (166, "PPP_PPPD", "DLT_PPP_PPPD"),
	GPRS_LLC (169, "GPRS_LLC", "DLT_GPRS_LLC"),
	LINUX_LAPD (177, "LINUX_LAPD", "DLT_LINUX_LAPD"),
	BLUETOOTH_HCI_H4 (187, "BLUETOOTH_HCI_H4", "DLT_BLUETOOTH_HCI_H4"),
	USB_LINUX (189, "USB_LINUX", "DLT_USB_LINUX"),
	PPI (192, "PPI", "DLT_PPI"),
	IEEE802_15_4 (195, "IEEE802_15_4", "DLT_IEEE802_15_4"),
	SITA (196, "SITA", "DLT_SITA"),
	ERF (197, "ERF", "DLT_ERF"),
	BLUETOOTH_HCI_H4_WITH_PDR (201, "BLUETOOTH_HCI_H4_WITH_PDR",
	                                "DLT_BLUETOOTH_HCI_H4_WITH_PDR"),
	AX25_KISS (202, "AX25_KISS", "DLT_AX25_KISS"),
	LAPD (203, "LAPD", "DLT_LAPD"),
	PPP_WITH_DIR (204, "PPP_WITH_DIR", "DLT_PPP_WITH_DIR"),
	C_HDLC_WITH_DIR (205, "C_HDLC_WITH_DIR", "DLT_C_HDLC_WITH_DIR"),
	FRELAY_WITH_DIR (206, "FRELAY_WITH_DIR", "DLT_FRELAY_WITH_DIR"),
	IPMB_LINUX (209, "IPMB_LINUX", "DLT_IPMB_LINUX"),
	IEEE802_15_4_NONASK_PHY (215, "IEEE802_15_4_NONASK_PHY",
	                              "DLT_IEEE802_15_4_NONASK_PHY"),
	USB_LINUX_MMAPED (220, "USB_LINUX_MMAPED", "DLT_USB_LINUX_MMAPED"),
	FC_2 (224, "FC_2", "DLT_FC_2"),
	FC_2_WITH_FRAME_DELIMS (225, "FC_2_WITH_FRAME_DELIMS",
	                             "DLT_FC_2_WITH_FRAME_DELIMS"),
	IPNET (226, "IPNET", "DLT_IPNET"),
	CAN_SOCKETCAN (227, "CAN_SOCKETCAN", "DLT_CAN_SOCKETCAN"),
	IPV4 (228, "IPV4", "DLT_IPV4"),
	IPV6 (229, "IPV6", "DLT_IPV6"),
	IEEE802_15_4_NOFCS (230, "IEEE802_15_4_NOFCS",
	                         "DLT_IEEE802_15_4_NOFCS"),
	DBUS (231, "DBUS", "DLT_DBUS"),
	DVB_CI (235, "DVB_CI", "DLT_DVB_CI"),
	MUX27010 (236, "MUX27010", "MDLT_UX27010"),
	STANAG_5066_D_PDU (237, "STANAG_5066_D_PDU", "DLT_STANAG_5066_D_PDU"),
	NFLOG (239, "NFLOG", "DLT_NFLOG"),
	NETANALYZER (240, "NETANALYZER", "DLT_NETANALYZER"),
	NETANALYZER_TRANSPARENT (241, "NETANALYZER_TRANSPARENT",
	                              "DLT_NETANALYZER_TRANSPARENT"),
	IPOIB (242, "IPOIB", "DLT_IPOIB"),
	MPEG_2_TS (243, "MPEG_2_TS", "DLT_MPEG_2_TS"),
	NG40 (244, "NG40", "DLT_NG40"),
	NFC_LLCP (245, "NFC_LLCP", "DLT_NFC_LLCP"),
	INFINIBAND (247, "INFINIBAND", "DLT_INFINIBAND"),
	SCTP (248, "SCTP", "DLT_SCTP"),
	USBPCAP (249, "USBPCAP", "DLT_USBPCAP"),
	RTAC_SERIAL (250, "RTAC_SERIAL", "DLT_RTAC_SERIAL"),
	BLUETOOTH_LE_LL (251, "BLUETOOTH_LE_LL", "DLT_BLUETOOTH_LE_LL"),
	NETLINK (253, "NETLINK", "DLT_NETLINK"),
	BLUETOOTH_LINUX_MONITOR (254, "BLUETOOTH_LINUX_MONITOR",
	                              "DLT_BLUETOOTH_LINUX_MONITOR"),
	BLUETOOTH_BREDR_BB (255, "BLUETOOTH_BREDR_BB",
	                         "DLT_BLUETOOTH_BREDR_BB"),
	BLUETOOTH_LE_LL_WITH_PHDR (256, "BLUETOOTH_LE_LL_WITH_PHDR",
	                                "DLT_BLUETOOTH_LE_LL_WITH_PHDR"),
	PROFIBUS_DL (257, "PROFIBUS_DL", "DLT_PROFIBUS_DL"),
	PKTAP (258, "PKTAP", "DLT_PKTAP"),
	EPON (259, "EPON", "DLT_EPON"),
	IPMI_HPM_2 (260, "IPMI_HPM_2", "DLT_IPMI_HPM_2"),
	ZWAVE_R1_R2 (261, "ZWAVE_R1_R2", "DLT_ZWAVE_R1_R2"),
	ZWAVE_R3 (262, "ZWAVE_R3", "DLT_ZWAVE_R3"),
	WATTSTOPPER_DLM (263, "WATTSTOPPER_DLM", "DLT_WATTSTOPPER_DLM"),

	XXX (-1, "", "");

	NetworkType(int id, String name, String dlt) {
		this.id = id;
		this.linkType = name;
		this.dltName = dlt;
	}

	private final int id;
	private final String linkType;
	private final String dltName;

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
