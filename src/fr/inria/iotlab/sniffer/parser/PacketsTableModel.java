package fr.inria.iotlab.sniffer.parser;

import javax.swing.event.TableModelListener;
import javax.swing.table.TableModel;

/**
 * Model for the packets' table (in the second window tab).
 * 
 * @author KR
 */
public class PacketsTableModel implements TableModel {

	private String[] colNames = {
			"#", "Timestamp", "Length", "Data"
	};
	private Class<?>[] colClasses = {
			Long.class, String.class, String.class, String.class
	};

	@Override
	public int getRowCount() {
		// TODO Auto-generated method stub
		return 0;
	}

	@Override
	public int getColumnCount() {
		return 4;
	}

	@Override
	public String getColumnName(int columnIndex) {
		return colNames[columnIndex];
	}

	@Override
	public Class<?> getColumnClass(int columnIndex) {
		return colClasses[columnIndex];
	}

	@Override
	public boolean isCellEditable(int rowIndex, int columnIndex) {
		return false;
	}

	@Override
	public Object getValueAt(int rowIndex, int columnIndex) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setValueAt(Object aValue, int rowIndex, int columnIndex) {
		// not used: no cell is editable
	}

	@Override
	public void addTableModelListener(TableModelListener l) {
		// TODO Auto-generated method stub

	}

	@Override
	public void removeTableModelListener(TableModelListener l) {
		// TODO Auto-generated method stub

	}

}
