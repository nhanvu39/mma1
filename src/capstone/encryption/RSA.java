/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package rsa;
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
    private static int ENLEN = DELEN - 11;
    
    static private Base64.Encoder encoder = Base64.getEncoder();
    static SecureRandom srandom = new SecureRandom();
    
    static public void encryptFile(String file, String key) throws Exception{
//        if(file.isFile()){
            byte[] bytes = Files.readAllBytes(Paths.get(key+".pub"));
	PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PrivateKey pvt = kf.generatePrivate(ks);
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, pvt);
            File fileout = new File(file + ".rsa");

            FileInputStream in = new FileInputStream(file);
            FileOutputStream out = new FileOutputStream(fileout);

            int i;
            byte[] b = new byte[ENLEN];
            while((i=in.read(b))!=-1) {
                byte[] inputFile = cipher.doFinal(b, 0, i);
                out.write(inputFile);
            }

            in.close();
            out.close();
//        }
//        else throw new IOException("File not found.");
    }


    static public void decryptFile(String file, String key) throws Exception{
//        if(file.isFile()){
        byte[] bytes = Files.readAllBytes(Paths.get(key+".pvt"));
	X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
	KeyFactory kf = KeyFactory.getInstance("RSA");
	PublicKey pub = kf.generatePublic(ks);

	
            Cipher cipher = Cipher.getInstance(ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, pub);
            String fileName = file;
            fileName = fileName.substring(0, fileName.length() - 4);
            File fileout = new File(fileName);

            FileInputStream in = new FileInputStream(file);
            FileOutputStream out = new FileOutputStream(fileout);

            int i;
            byte[] b = new byte[DELEN];
            while((i=in.read(b))!=-1) {
                byte[] inputFile = cipher.doFinal(b,0,i);
                out.write(inputFile);
            }

            in.close();
            out.close();
//        }
//        else throw new IOException("File not found.");
    }

    
	
//            int i;
//            byte[] b = new byte[ENLEN];
//            while((i=in.read(b))!=-1) {
//                byte[] inputFile = ci.doFinal(b, 0, i);
//                out.write(inputFile);
//            }
//
//            in.close();
//            out.close();
    
   
    static private void doGenkey(String key)
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
	try (FileOutputStream out = new FileOutputStream(key+".pub")) {
		out.write(kp.getPrivate().getEncoded());
	    }

	try (FileOutputStream out = new FileOutputStream(key+".pvt")) {
		out.write(kp.getPublic().getEncoded());
	    }
    }

   
}
