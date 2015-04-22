package fr.inria.iotlab.sniffer.parser;

import java.awt.BorderLayout;
import java.awt.EventQueue;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;
import java.io.IOException;

import javax.swing.JButton;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.SwingConstants;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.ListSelectionModel;

/**
 * Main window (and main class) of the PCap file analyzer
 *  for IoT-LAB sniffer sessions' results.
 * 
 * @author KR
 */
public class ParserMainWindow {

	///*** COMPOSANTS GRAPHIQUES ***///
	
	private JFrame frmPcapAnalyzerForm;
	private JTextField textPCapFile;
	private JLabel lblMagic;
	private JLabel lblByteSwap;
	private JLabel lblPrecision;
	private JLabel lblVersion;
	private JLabel lblTimezone;
	private JLabel lblMaxPktLen;
	private JLabel lblNetType;
	private JTable tablePackets;

	///*** AUTRES CHAMPS ***///
	private PCapFileParser pcapParser;

	/**
	 * Launch the application.
	 */
	public static void main(String[] args) {
		EventQueue.invokeLater(new Runnable() {
			public void run() {
				try {
					ParserMainWindow window = new ParserMainWindow();
					window.frmPcapAnalyzerForm.setVisible(true);
				} catch (Exception e) {
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * Create the application.
	 */
	public ParserMainWindow() {
		this.pcapParser = null;
		initialize();
	}

	/**
	 * Initialize the contents of the frame.
	 */
	private void initialize() {
		frmPcapAnalyzerForm = new JFrame();
		frmPcapAnalyzerForm.setTitle("PCap Analyzer for IoT-LAB Sniffer");
		frmPcapAnalyzerForm.setBounds(50, 50, 650, 400);
		frmPcapAnalyzerForm.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		
		JPanel panelFileSelectTop = new JPanel();
		frmPcapAnalyzerForm.getContentPane().add(panelFileSelectTop, BorderLayout.NORTH);
		panelFileSelectTop.setLayout(new BorderLayout(0, 0));
		
		textPCapFile = new JTextField();
		panelFileSelectTop.add(textPCapFile);
		textPCapFile.setColumns(10);
		
		JButton btnBrowse = new JButton("Browse...");
		btnBrowse.addActionListener(new ActionListener() {
			public void actionPerformed(ActionEvent e) {
				try {
					browseForPcapFile();
				} catch (IOException exc) {
					JOptionPane.showMessageDialog(frmPcapAnalyzerForm,
							exc.getLocalizedMessage(),
							"ERROR",
							JOptionPane.ERROR_MESSAGE);
				}
			}
		});
		panelFileSelectTop.add(btnBrowse, BorderLayout.EAST);
		
		JTabbedPane tabbedPaneMain = new JTabbedPane(JTabbedPane.TOP);
		frmPcapAnalyzerForm.getContentPane().add(tabbedPaneMain, BorderLayout.CENTER);
		
		JPanel panelFile = new JPanel();
		tabbedPaneMain.addTab("File", null, panelFile, null);
		tabbedPaneMain.setEnabledAt(0, true);
		panelFile.setLayout(null);
		
		JLabel lblIntroMagic = new JLabel("Magic number:");
		lblIntroMagic.setBounds(10, 10, 158, 15);
		lblIntroMagic.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroMagic);
		
		lblMagic = new JLabel("--");
		lblMagic.setBounds(172, 10, 128, 15);
		panelFile.add(lblMagic);

		JLabel lblIntroByteSwap = new JLabel("Byte-swapped:");
		lblIntroByteSwap.setBounds(10, 37, 158, 15);
		lblIntroByteSwap.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroByteSwap);
		
		lblByteSwap = new JLabel("--");
		lblByteSwap.setBounds(172, 37, 128, 15);
		panelFile.add(lblByteSwap);

		JLabel lblIntroPrecision = new JLabel("Timestamp precision:");
		lblIntroPrecision.setBounds(10, 64, 158, 15);
		lblIntroPrecision.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroPrecision);
		
		lblPrecision = new JLabel("--");
		lblPrecision.setBounds(172, 64, 128, 15);
		panelFile.add(lblPrecision);

		JLabel lblIntroVersion = new JLabel("Version:");
		lblIntroVersion.setBounds(10, 91, 158, 15);
		lblIntroVersion.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroVersion);
		
		lblVersion = new JLabel("--");
		lblVersion.setBounds(172, 91, 128, 15);
		panelFile.add(lblVersion);

		JLabel lblIntroTimezone = new JLabel("Step from GMT:");
		lblIntroTimezone.setBounds(10, 118, 158, 15);
		lblIntroTimezone.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroTimezone);
		
		lblTimezone = new JLabel("--");
		lblTimezone.setBounds(172, 118, 128, 15);
		panelFile.add(lblTimezone);

		JLabel lblIntroMaxPktLen = new JLabel("Max. packet length:");
		lblIntroMaxPktLen.setBounds(10, 145, 158, 15);
		lblIntroMaxPktLen.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroMaxPktLen);
		
		lblMaxPktLen = new JLabel("--");
		lblMaxPktLen.setBounds(172, 145, 128, 15);
		panelFile.add(lblMaxPktLen);

		JLabel lblIntroNetType = new JLabel("Network Link Layer Type:");
		lblIntroNetType.setBounds(10, 172, 158, 15);
		lblIntroNetType.setHorizontalAlignment(SwingConstants.RIGHT);
		panelFile.add(lblIntroNetType);
		
		lblNetType = new JLabel("--");
		lblNetType.setBounds(172, 172, 128, 15);
		panelFile.add(lblNetType);


		JPanel panelPackets = new JPanel();
		tabbedPaneMain.addTab("Packets", null, panelPackets, null);
		panelPackets.setLayout(new BorderLayout(0, 0));
		
		tablePackets = new JTable();
		tablePackets.setFillsViewportHeight(true);
		tablePackets.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		tablePackets.setModel(new PacketsTableModel());
		panelPackets.add(tablePackets);
		tabbedPaneMain.setEnabledAt(1, true);
		
		JPanel panelStats = new JPanel();
		tabbedPaneMain.addTab("Stats", null, panelStats, null);
	}

	/**
	 * Graphically select a file to open and parse (thanks to the
	 * <code>JFileChooser</code> Swing class).
	 * 
	 * @throws IOException when an I/O error occurs.
	 */
	private void browseForPcapFile() throws IOException {
		JFileChooser openDlg = new JFileChooser();
		openDlg.addChoosableFileFilter(new FileNameExtensionFilter(
				"PCap files", "pcap"));
		String currentPath = textPCapFile.getText();
		if (currentPath != null) {
			currentPath = currentPath.trim();
			if (!(currentPath.equalsIgnoreCase(""))) {
				openDlg.setSelectedFile(new File(currentPath));
			}
		}

		int ret = openDlg.showOpenDialog(frmPcapAnalyzerForm);
		if (ret != JFileChooser.APPROVE_OPTION) return;

		String chosenPath = openDlg.getSelectedFile().getCanonicalPath();
		textPCapFile.setText(chosenPath);
		openPcapFile(chosenPath);
	}

	/**
	 * Open the chosen PCap file, and create the adequate
	 * <code>PCapFileParser</code> object to analyze it.
	 * 
	 * @param chosenPath path to PCap file to open as chosen by the user.
	 */
	private void openPcapFile(String chosenPath) {
		try {
			this.pcapParser = new PCapFileParser(chosenPath);

			/* update the first panel: PCap file's global properties */
			lblMagic.setText(String.format("%x",
					pcapParser.getMagicNumber()));
			lblByteSwap.setText(
					pcapParser.isByteSwapped() ? "true" : "false");
			lblPrecision.setText(
					pcapParser.hasExtendedTimeResolution() ?
							"nanosecond" : "microsecond");
			lblVersion.setText(String.format("%d.%d",
					pcapParser.getVersionMajor(),
					pcapParser.getVersionMinor()));
			lblTimezone.setText(String.format("%d seconds",
					pcapParser.getTimeZoneDelta()));
			lblMaxPktLen.setText(String.format("%d bytes",
					pcapParser.getMaxPacketLength()));
			lblNetType.setText(String.format("%d",
					pcapParser.getNetworkType()));
		} catch (Exception e) {
			JOptionPane.showMessageDialog(
					frmPcapAnalyzerForm,
					e.getMessage(),
					"Error",
					JOptionPane.ERROR_MESSAGE); 
			lblMagic.setText("--");
			lblByteSwap.setText("--");
			lblPrecision.setText("--");
			lblVersion.setText("--");
			lblTimezone.setText("--");
			lblMaxPktLen.setText("--");
			lblNetType.setText("--");
		}
	}

}
