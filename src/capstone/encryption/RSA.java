/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package capstone.encryption;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Base64;
import java.util.Arrays;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
/**
 *
 * @author Lenovo
 */
public class RSA {
    private static String ALGORITHM = "RSA/ECB/PKCS1Padding";
    public static int KEYSIZE = 2048;
    private static int DELEN = KEYSIZE / 8;
    private static int ENLEN = DELEN - 2 * 20 - 2;
    
    static private Base64.Encoder encoder = Base64.getEncoder();
    static SecureRandom srandom = new SecureRandom();

    static private void processFile(Cipher ci,InputStream in,OutputStream out)
	throws javax.crypto.BadPaddingException,
	       java.io.IOException
    {
	byte[] ibuf = new byte[1024];
	int len;
	while ((len = in.read(ibuf)) != -1) {
	    byte[] obuf = ci.update(ibuf, 0, len);
	    if ( obuf != null ) out.write(obuf);
	}
	byte[] obuf = null;
        try {
            obuf = ci.doFinal();
        } catch (IllegalBlockSizeException ex) {
            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            System.out.println("123");
        }
	if ( obuf != null ) out.write(obuf);
    }

    static private void processFile(Cipher ci,String inFile,String outFile)
	throws javax.crypto.IllegalBlockSizeException, 
	       javax.crypto.BadPaddingException,
	       java.io.IOException
    {
	try (FileInputStream in = new FileInputStream(inFile);
	     FileOutputStream out = new FileOutputStream(outFile)) {
		processFile(ci, in, out);
	    }
    }

    static public void doGenkey()
	throws java.security.NoSuchAlgorithmException,
	       java.io.IOException
    {
//	if ( args.length == 0 ) {
//	    System.err.println("genkey -- need fileBase");
//	    return;
//	}

	int index = 0;
//	String fileBase = args[index++];
//        System.out.println(fileBase);
	KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
	kpg.initialize(2048);
	KeyPair kp = kpg.generateKeyPair();
	try (FileOutputStream out = new FileOutputStream("Publickey.key")) {
		out.write(kp.getPrivate().getEncoded());
	    }

	try (FileOutputStream out = new FileOutputStream("PrivateKey.key")) {
		out.write(kp.getPublic().getEncoded());
	    }
    }

    /* Larger data gives:
     *
     * javax.crypto.IllegalBlockSizeException: Data must not be longer
     * than 245 bytes
     */
    static public int doEncrypt(String file,String key)
	throws java.security.NoSuchAlgorithmException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException,
	       InvalidKeyException
    {
        
	byte[] bytes = Files.readAllBytes(Paths.get(key));
	PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
        
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PrivateKey pvt = null;
        try {
            pvt = kf.generatePrivate(ks);
        } catch (InvalidKeySpecException ex) {
//            Logger.getLogger(RSA.class.getName()).log(Level.SEVERE, null, ex);
            return -1;
        }
        
	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        
        cipher.init(Cipher.ENCRYPT_MODE, pvt);
        
	processFile(cipher, file, file + ".enc");
        return 0;
    }

    static public int doDecrypt(String input, String key)
	throws java.security.NoSuchAlgorithmException,
	       java.security.spec.InvalidKeySpecException,
	       javax.crypto.NoSuchPaddingException,
	       javax.crypto.BadPaddingException,
	       java.security.InvalidKeyException,
	       javax.crypto.IllegalBlockSizeException,
	       java.io.IOException
    {
	byte[] bytes = Files.readAllBytes(Paths.get(key));
	X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
//	PublicKey pub = kf.generatePublic(ks);
        PublicKey pub = null;
        try {
            pub = kf.generatePublic(ks);
        } catch (InvalidKeySpecException ex) {
            return -1;
        }

	Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
	cipher.init(Cipher.DECRYPT_MODE, pub);
	processFile(cipher, input, input.substring(0, input.length()-4));
        return 0;
    }

    
//    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, BadPaddingException, InvalidKeyException, IllegalBlockSizeException, Exception {
        // TODO code application logic here
//        if ( args.length == 0 ) {
//	    System.err.print("usage: java sample1 command params..\n" +
//			     "where commands are:\n" +
//			     "  genkey fileBase\n" +
//			     "  tnyenc pvtKeyFile inputFile\n" +
//			     "  tnydec pubKeyFile inputFile\n" +
//			     "  enc pvtKeyFile inputFile\n" +
//			     "  dec pubKeyFile inputFile\n");
//	    System.exit(1);
//	}

//	doGenkey();
        
	//doEncrypt(args[0],"PublicKey.txt");
//        
//        
	 //doDecrypt(args[0]+".enc","PrivateKey.txt");
	
//	System.out.println("hello");
    
//    }
    
}
