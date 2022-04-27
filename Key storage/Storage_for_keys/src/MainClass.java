import java.io.*;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Container;
import java.awt.Font;
import java.sql.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;

import java.security.SecureRandom;

public class MainClass extends JFrame{
    private JList<String> out_list;
    static JButton cncl, rmv, add_button, extr_rec;
    public static DefaultListModel<String> listModel = new DefaultListModel<>();
	static float hrs;
	static JTextField addr;
	static JTextField vl;
    static Color frgr = new Color(238, 238, 238);
    static Color bclr = new Color(10, 10, 14);
    static Color bl = new Color(0, 188, 255);
    static Color rd = new Color(233, 38, 44);
	
	  private static SecretKeySpec secretKey;
	  private static byte[] key;
	  public static String AES_Key = null;

	  public static void setKey(final String myKey) {
	    MessageDigest sha = null;
	    try {
	      key = myKey.getBytes("UTF-8");
	      sha = MessageDigest.getInstance("SHA-1");
	      key = sha.digest(key);
	      key = Arrays.copyOf(key, 16);
	      secretKey = new SecretKeySpec(key, "AES");
	    } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
	      e.printStackTrace();
	    }
	  }

	  public static String encrypt(final String strToEncrypt, final String secret) {
	    try {
	      setKey(secret);
	      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
	      return Base64.getEncoder()
	        .encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
	    } catch (Exception e) {
	      System.out.println("Error while encrypting: " + e.toString());
	    }
	    return null;
	  }

	  public static String decrypt(final String strToDecrypt, final String secret) {
	    try {
	      setKey(secret);
	      Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
	      cipher.init(Cipher.DECRYPT_MODE, secretKey);
	      return new String(cipher.doFinal(Base64.getDecoder()
	        .decode(strToDecrypt)));
	    } catch (Exception e) {
	      System.out.println("Error while decrypting: " + e.toString());
	    }
	    return null;
	  }

	public MainClass() {
		create_table();
        out_list = new JList<>(listModel);
	    JMenuBar mb;
	    JMenu rc, k1;
	    JMenuItem add_r, mod_r, del_r, ext_r, lst_r, s_k, g_k, exp_to_tbl, exp_r;
        mb = new JMenuBar();
        rc = new JMenu(" Record ");
	    add_r = new JMenuItem("Add");
	    mod_r = new JMenuItem("Modify");
	    del_r = new JMenuItem("Delete");
	    ext_r = new JMenuItem("Extract");
	    lst_r = new JMenuItem("List all");
	    exp_to_tbl = new JMenuItem("Print all to the table");
	    exp_r = new JMenuItem("Export all to the .csv file");
        rc.add(add_r);
        rc.add(mod_r);
        rc.add(del_r);
        rc.add(ext_r);
        rc.add(lst_r);
        rc.add(exp_to_tbl);
        rc.add(exp_r);
        mb.add(rc);
        
        k1 = new JMenu(" Encr. Key ");
        s_k = new JMenuItem("Load");
	    g_k = new JMenuItem("Generate");
        k1.add(s_k);
        k1.add(g_k);
        mb.add(k1);

        setJMenuBar(mb);  
        
        JButton extr = new JButton("Extract");
        mb.add(extr);
        
        JTextField for_e_v = new JTextField();
        mb.add(for_e_v);
        
        JScrollPane scrollPane = new JScrollPane();
        scrollPane.setViewportView(out_list);
        out_list.setLayoutOrientation(JList.VERTICAL);
        out_list.setForeground(frgr);
        out_list.setBackground(bclr);
        
        extr.setForeground(frgr);
        extr.setBackground(bclr);
        
		mb.setBackground(bl);
		add_r.setForeground(frgr);
		mod_r.setForeground(frgr);
		del_r.setForeground(frgr);
		exp_to_tbl.setForeground(frgr);
		ext_r.setForeground(frgr);
		lst_r.setForeground(frgr);
		exp_r.setForeground(frgr);
		add_r.setBackground(bl);
		mod_r.setBackground(bl);
		del_r.setBackground(bl);
		ext_r.setBackground(bl);
		lst_r.setBackground(bl);
		exp_to_tbl.setBackground(bl);
		exp_r.setBackground(bl);
		
		s_k.setForeground(frgr);
		g_k.setForeground(frgr);
		s_k.setBackground(bl);
		g_k.setBackground(bl);
		
		for_e_v.setForeground(bclr);
		
	    setSize(480,320); 
	    add(scrollPane);
	    setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
	    setVisible(true);
	    setLayout(null);
	    
	    add_r.addActionListener(e ->
	    {
	    	if (AES_Key != null)
	    		add_rec();
	    	else
	    		add_to_list("Select the encryption key to continue");
	    });
	    mod_r.addActionListener(e ->
	    {
	    	if (AES_Key != null)
	    		modify_rec();
	    	else
	    		add_to_list("Select the encryption key to continue");
	    });
	    del_r.addActionListener(e ->
	    {
	    	delete_rec();
	    });
	    ext_r.addActionListener(e ->
	    {
	    	if (AES_Key != null)
	    		extract_rec();
	    	else
	    		add_to_list("Select the encryption key to continue");
	    });
	    lst_r.addActionListener(e ->
	    {
	    	list_recs();
	    });
	    extr.addActionListener(e ->
	    {
	    	for_e_v.setText((String) out_list.getSelectedValue());
	    });
	    exp_to_tbl.addActionListener(e ->
	    {
	    	if (AES_Key != null)
	    		exp_to_t();
	    	else
	    		add_to_list("Select the encryption key to continue");
	    });
	    exp_r.addActionListener(e ->
	    {
	    	create_csv();
	    	add_to_list("Records exported successfully");
	    });
	    s_k.addActionListener(e ->
	    {
	    	sel_enc_key();
	    });
	    g_k.addActionListener(e ->
	    {
	    	gen_k();
	    });
        this.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        this.setTitle("Database");       
        this.setSize(480,320);
        this.setLocationRelativeTo(null);
        this.setVisible(true);
    }
	
	public static void gen_k() {
        StringBuilder str = new StringBuilder();
		SecureRandom number = new SecureRandom();
		int n = 200 + number.nextInt(301);
		int m = 0;
		for (int i = 0; i < n; i++) {
			m = number.nextInt(3);
			if (m == 0)
				str.append((char)(65 + (number.nextInt(26))));
			if (m == 1)
				str.append((char)(97 + (number.nextInt(26))));
			if (m == 2)
				str.append((char)(48 + (number.nextInt(10))));
		}
    	JFrame parentFrame = new JFrame();
   	 
    	JFileChooser fileChooser = new JFileChooser();
    	fileChooser.setDialogTitle("Specify a file to save the newly generated key into");   
    	 
    	int userSelection = fileChooser.showSaveDialog(parentFrame);
    	 
    	if (userSelection == JFileChooser.APPROVE_OPTION) {
    	    File fileToSave = fileChooser.getSelectedFile();
        	try {
                FileWriter myWriter = new FileWriter(fileToSave.getAbsolutePath());
                myWriter.write(str.toString());
                myWriter.close();
                add_to_list("Newly generated key saved successfully");
              } catch (IOException q) {
            	  add_to_list("An error occurred");
                q.printStackTrace();
              }
    	}
	}
	
	public static void sel_enc_key() {
    	final JFrame iFRAME = new JFrame();
    	iFRAME.setAlwaysOnTop(true);
    	iFRAME.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
    	iFRAME.setLocationRelativeTo(null);
    	iFRAME.requestFocus();

    	JFileChooser jfc = new JFileChooser();
    	int returnValue = jfc.showOpenDialog(iFRAME);
    	iFRAME.dispose();
    	if (returnValue == JFileChooser.APPROVE_OPTION) {
    	    File selectedFile = jfc.getSelectedFile();
    	    try {
    	        String result = null;

    	        DataInputStream reader = new DataInputStream(new FileInputStream(selectedFile.getAbsolutePath()));
    	        int nBytesToRead = reader.available();
    	        if(nBytesToRead > 0) {
    	            byte[] bytes = new byte[nBytesToRead];
    	            reader.read(bytes);
    	            result = new String(bytes);
    	            AES_Key = result;
    	            add_to_list("Encryption key opened successfully");
    	        }
            } catch (IOException r) {
            	add_to_list("An error occurred");
                r.printStackTrace();
              }
    	}
	}
    
    public static void add_to_list(String add) {
    	listModel.addElement(add);
    }
	
	public static String gen_rnd(int n) {
        StringBuilder str = new StringBuilder();
		SecureRandom number = new SecureRandom();
		for (int i = 0; i < n; i++) {
		 str.append((char)(65 + (number.nextInt(26))));
		}
		return str.toString();
	}
	
	public static byte[] obtainSHA(String s) throws NoSuchAlgorithmException {   
		MessageDigest msgDgst = MessageDigest.getInstance("SHA-512");  
		return msgDgst.digest(s.getBytes(StandardCharsets.UTF_8));  
	}  
	  
	public static String toHexStr(byte[] hash) {   
		BigInteger no = new BigInteger(1, hash);
		StringBuilder hexStr = new StringBuilder(no.toString(16));  
		while (hexStr.length() < 32)  
		{  
			hexStr.insert(0, '0');  
		}  
		return hexStr.toString();  
	}  
	
	public static void create_table() {
	      Connection c = null;
	      Statement stmt = null;
	      
	      try {
	         Class.forName("org.sqlite.JDBC");
	         c = DriverManager.getConnection("jdbc:sqlite:keys.db");
	         add_to_list("Opened database successfully");
	         stmt = c.createStatement();
	         String sql = "CREATE TABLE if not exists Keys" +
                     " (ID           TEXT      NOT NULL, " + 
                     " Title	     TEXT      NOT NULL, " + 
                     " Key           TEXT      NOT NULL)"; 
	         stmt.executeUpdate(sql);
	         stmt.close();
	         c.close();
	      } catch ( Exception e ) {
	         System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	         System.exit(0);
	      }
	      return;
	}

	public static void add_rec() {
		JFrame addrc = new JFrame("Add record");
	    JMenuBar addm = new JMenuBar();
	    addrc.setJMenuBar(addm);
        JLabel lb1 = new JLabel("  Enter the title: ");
        JTextField tf1 = new JTextField(499999);
        JLabel lb2 = new JLabel("  |  Paste the key: ");
        JTextField tf2 = new JTextField(499999);
        add_button = new JButton("Add");  
	    cncl = new JButton("Cancel");
	    addm.add(lb1);
	    addm.add(tf1);
	    addm.add(lb2);
	    addm.add(tf2);
	    addm.add(add_button);  
	    addm.add(cncl);  
	    add_button.setForeground(frgr);
	    add_button.setBackground(bl);
	    cncl.setForeground(frgr);
	    cncl.setBackground(rd);
	    addrc.setSize(640, 68);  
	    addrc.setVisible(true);
	    add_button.addActionListener(e ->
        {
    		String ttl = tf1.getText();
    		String key = tf2.getText();
    	    add_record(MainClass.encrypt(ttl, AES_Key),MainClass.encrypt(key, AES_Key));
        	addrc.dispose();
	
        });
	    cncl.addActionListener(e ->
        {
        	addrc.dispose();
	
        });

	    return;
	}
	
	public static void add_record(String ttl, String key) {
	      Connection c = null;
	      Statement stmt = null;
	      String id = gen_rnd(128);
	      try {
	         Class.forName("org.sqlite.JDBC");
	         c = DriverManager.getConnection("jdbc:sqlite:keys.db");
	         c.setAutoCommit(false);

	         stmt = c.createStatement();
	         String sql = "INSERT INTO Keys (ID,Title,Key) " +
	                        "VALUES ('"+id+"', '"+ttl+"', '"+key+"' );"; 
	         stmt.executeUpdate(sql);
	         stmt.close();
	         c.commit();
	         c.close();
	         add_to_list("Record " + MainClass.decrypt(ttl, AES_Key)+" created successfully!");
	      } catch ( Exception e ) {
	         System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	         System.exit(0);
	      }
	      return;
	}
	
	public static void modify_rec() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys" );
			  JFrame ext_rc = new JFrame("Modify record");
		      JMenuBar ext_mb = new JMenuBar();
		      int nmb_of_r = number_of_recs();
		      String rcrds[][] = new String [nmb_of_r + 1][2];
			  JComboBox records = new JComboBox();
		      int n = 0;
		      while (rs.next()) {
		    	 rcrds[n][0] = (rs.getString("ID"));
		    	 rcrds[n][1] = MainClass.decrypt(rs.getString("Title"), AES_Key);
		    	 n++;
		      }
		      int m = 0;
		      while (rcrds[m][0] != null) {
		    	 m++;
		      }
		      for(int i = 0; i < m; i++) {
		    	  records.addItem(rcrds[i][1]);
		      }
		      ext_rc.setJMenuBar(ext_mb);
		      ext_mb.add(records);
		      JLabel lb1 = new JLabel("  Paste the new key: ");
		      JTextField tf1 = new JTextField(499999);
			  extr_rec = new JButton("Modify");  
		      cncl = new JButton("Cancel");
		      ext_mb.add(lb1);
		      ext_mb.add(tf1);
		      ext_mb.add(extr_rec);  
		      ext_mb.add(cncl);  
		      extr_rec.setForeground(frgr);
		      extr_rec.setBackground(bl);
		      cncl.setForeground(frgr);
		      cncl.setBackground(rd);
		      ext_rc.setSize(500, 68);  
		      ext_rc.setVisible(true); 
		      rs.close();
		      stmt.close();
		      c.close(); 
		      extr_rec.addActionListener(e ->
		        {
		        	set_new_key(MainClass.encrypt(tf1.getText(), AES_Key),rcrds[records.getSelectedIndex()][0]);
		        	ext_rc.dispose();
	   	
		        });
			    cncl.addActionListener(e ->
		        {
		        	ext_rc.dispose();
	   	
		        });
		   } catch ( Exception e ) {
			  JFrame f4=new JFrame();  
			  JOptionPane.showMessageDialog(f4, e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	public static void set_new_key(String key, String id) {
		   Connection c = null;
		   Statement stmt = null;
		try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      String sql = "UPDATE Keys set Key ='"+key+"' where ID='"+id+"';";
		      stmt.executeUpdate(sql);
		      c.commit();
		}
		catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		return;
	}
	
	public static void delete_rec() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys" );
			  JFrame remrec = new JFrame("Delete record");
		      JMenuBar rm = new JMenuBar();
		      int nmb_of_r = number_of_recs();
		      String rcrds[][] = new String [nmb_of_r + 1][2];
			  JComboBox records = new JComboBox();
		      int n = 0;
		      while (rs.next()) {
		    	 rcrds[n][0] = (rs.getString("ID"));
		    	 rcrds[n][1] = MainClass.decrypt(rs.getString("Title"), AES_Key);
		    	 n++;
		      }
		      int m = 0;
		      while (rcrds[m][0] != null) {
		    	 m++;
		      }
		      for(int i = 0; i < m; i++) {
		    	  records.addItem(rcrds[i][1]);
		      }
		      remrec.setJMenuBar(rm);
			  rm.add(records);
			  rmv = new JButton("Delete");  
		      cncl = new JButton("Cancel");   
		      rm.add(rmv);  
		      rm.add(cncl);  
		      rmv.setForeground(frgr);
		      rmv.setBackground(bclr);
		      cncl.setForeground(frgr);
		      cncl.setBackground(rd);
		      remrec.setSize(500, 68);  
		      remrec.setVisible(true); 
		      rs.close();
		      stmt.close();
		      c.close(); 
			    rmv.addActionListener(e ->
		        {
		        	remove_rec(rcrds[records.getSelectedIndex()][0], rcrds[records.getSelectedIndex()][1]);
		        	remrec.dispose();
	   	
		        });
			    cncl.addActionListener(e ->
		        {
		        	remrec.dispose();
	   	
		        });
		   } catch ( Exception e ) {
			  JFrame f4=new JFrame();  
			  JOptionPane.showMessageDialog(f4, e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	public static void remove_rec(String t_rem, String nm) {
	      Connection c = null;
	      Statement stmt = null;
	      try {
	         Class.forName("org.sqlite.JDBC");
	         c = DriverManager.getConnection("jdbc:sqlite:keys.db");
	         c.setAutoCommit(false);

	         stmt = c.createStatement();
	         String sql = "DELETE from keys where ID='"+t_rem+"';";
	         stmt.executeUpdate(sql);
	         c.commit();
	         c.close();
	         add_to_list("Record "+nm+" removed successfully!");
	      } catch ( Exception e ) {
	         System.err.println( e.getClass().getName() + ": " + e.getMessage() );
	         System.exit(0);
	      }
	      return;
	}
	
	public static void exp_to_t() {
		try {
		Connection c = null;
		Statement stmt = null;
		DefaultTableModel tableModel = new DefaultTableModel();
		JTable table = new JTable(tableModel);
		tableModel.insertRow(tableModel.getRowCount(), new Object[] { "Keys" });
		JFrame frm = new JFrame("Exported Keys");
		table.setForeground(frgr);
		table.setBackground(bclr);
		frm.setBackground(bclr);
		frm.setSize(750, 350);
		frm.add(new JScrollPane(table));
		frm.setVisible(true);
		tableModel.setRowCount(0);
		tableModel.setColumnIdentifiers(new Object[]{"ID", "Title", "Keys"});
	    c = DriverManager.getConnection("jdbc:sqlite:keys.db");
	    c.setAutoCommit(false);
	    stmt = c.createStatement();
	    ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys" );
	    int n_rec = 0;
		while (rs.next()) {
		tableModel.addRow(new Object[]{
		rs.getString("ID"),
		MainClass.decrypt(rs.getString("Title"), AES_Key),
		MainClass.decrypt(rs.getString("Key"), AES_Key),
		});
		n_rec += 17;
		}
	    rs.close();
	    stmt.close();
	    c.close();
		frm.setSize(750, 70 + n_rec);
		} catch (SQLException ex) {
		throw new RuntimeException(ex);
		}
}
	
	public static void extract_rec() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys" );
			  JFrame ext_rc = new JFrame("Extract record");
		      JMenuBar ext_mb = new JMenuBar();
		      int nmb_of_r = number_of_recs();
		      String rcrds[][] = new String [nmb_of_r + 1][2];
			  JComboBox records = new JComboBox();
		      int n = 0;
		      while (rs.next()) {
		    	 rcrds[n][0] = (rs.getString("ID"));
		    	 rcrds[n][1] = MainClass.decrypt(rs.getString("Title"), AES_Key);
		    	 n++;
		      }
		      int m = 0;
		      while (rcrds[m][0] != null) {
		    	 m++;
		      }
		      for(int i = 0; i < m; i++) {
		    	  records.addItem(rcrds[i][1]);
		      }
		      ext_rc.setJMenuBar(ext_mb);
		      ext_mb.add(records);
			  extr_rec = new JButton("Extract");  
		      cncl = new JButton("Cancel");   
		      ext_mb.add(extr_rec);  
		      ext_mb.add(cncl);  
		      extr_rec.setForeground(frgr);
		      extr_rec.setBackground(bl);
		      cncl.setForeground(frgr);
		      cncl.setBackground(rd);
		      ext_rc.setSize(500, 68);  
		      ext_rc.setVisible(true); 
		      rs.close();
		      stmt.close();
		      c.close(); 
		      extr_rec.addActionListener(e ->
		        {
		        	extrct_recrd(rcrds[records.getSelectedIndex()][0], rcrds[records.getSelectedIndex()][1]);
		        	ext_rc.dispose();
	   	
		        });
			    cncl.addActionListener(e ->
		        {
		        	ext_rc.dispose();
	   	
		        });
		   } catch ( Exception e ) {
			  JFrame f4=new JFrame();  
			  JOptionPane.showMessageDialog(f4, e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	public static void extrct_recrd(String id, String nm) {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys WHERE ID ='"+id+"';");
		      while ( rs.next() ) {
		    	  JOptionPane.showInputDialog("The key extracted from the "+nm+" is:", MainClass.decrypt(rs.getString("Key"), AES_Key));
		      }
		      rs.close();
		      stmt.close();
		      c.close();
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	public static void create_csv() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);

		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys;" );
		      try {
				      FileWriter myWriter = new FileWriter("records.csv",false);
				      myWriter.write("");
				      myWriter.close();
					}
					catch (IOException e) {
						JFrame f3=new JFrame();  
					    JOptionPane.showMessageDialog(f3,"Can't create a file for the output data");
					    System.exit(1);
					}
		      writef("Title,Key");		      
		      while ( rs.next() ) {
		    	  String tl = MainClass.decrypt(rs.getString("Title"), AES_Key);
		    	  String e_key = MainClass.decrypt(rs.getString("Key"), AES_Key);
		    	  writef("\n" + tl + "," + e_key);
		      }
		      rs.close();
		      stmt.close();
		      c.close();
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return;
	}
	
	public static void writef(String s) {
		try {
	      FileWriter myWriter = new FileWriter("records.csv",true);
	      myWriter.write(s);
	      myWriter.close();
		}
		catch (IOException e) {
		    add_to_list("Can't create a file for the output data");
		    System. exit(1);
		    }
		return;
	}
	
	public static void list_recs() {
		   Connection c = null;
		   Statement stmt = null;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);
		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys;" );
		      add_to_list("Stored elements:");
		      add_to_list(" ");
		      while ( rs.next() ) {
		    	  add_to_list("Title:"+MainClass.decrypt(rs.getString("Title"), AES_Key));
		    	  add_to_list("Key:"+MainClass.decrypt(rs.getString("Key"), AES_Key));
		    	  add_to_list(" ");
		      }
		      rs.close();
		      stmt.close();
		      c.close();
		      add_to_list("//////////////////////////THE END//////////////////////////");
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   
	}
	
	public static int number_of_recs() {
		   Connection c = null;
		   Statement stmt = null;
		   int nmb = 0;
		   try {
		      Class.forName("org.sqlite.JDBC");
		      c = DriverManager.getConnection("jdbc:sqlite:keys.db");
		      c.setAutoCommit(false);

		      stmt = c.createStatement();
		      ResultSet rs = stmt.executeQuery( "SELECT * FROM Keys;" );
		      while ( rs.next() ) {
		    	  nmb ++;
		      }
		      rs.close();
		      stmt.close();
		      c.close();
		   } catch ( Exception e ) {
		      System.err.println( e.getClass().getName() + ": " + e.getMessage() );
		      System.exit(0);
		   }
		   return nmb;
	}
	
   public static void main( String args[] ) {
       SwingUtilities.invokeLater(new Runnable() {
           @Override
           public void run() {
               new MainClass();
           }
       });
   }
}