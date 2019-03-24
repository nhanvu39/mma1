package capstone.encryption;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class DES {
        private static final String ALGORITHM = "DES/CBC/PKCS5Padding";
	private static Cipher encryptCipher;
	private static Cipher decryptCipher;
	private static final byte[] iv = { 11, 22, 33, 44, 99, 88, 77, 66 };
        static AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
        

        public static void encryptFile(File file, SecretKey key) throws Exception{
            if(file.isFile()){
                try{
                    encryptCipher=Cipher.getInstance(ALGORITHM);
                    encryptCipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
                    encrypt(new FileInputStream(file.getPath()), new FileOutputStream(file.getPath() + ".enc"));
                } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
					| InvalidAlgorithmParameterException | IOException e){
				e.printStackTrace();
			}
            }
            else throw new IOException("File not found!");
        }
        public static void decryptFile(File file,SecretKey key){
            if(file.isFile()) {
		try {
                    decryptCipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                    decryptCipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
                    decrypt(new FileInputStream(file.getPath()), new FileOutputStream(file.getPath().substring(0,file.getPath().length() - 4)));
                    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
					| InvalidAlgorithmParameterException | IOException e) {
				e.printStackTrace();
			}
		}
	}
        private static void decrypt(InputStream is, OutputStream os) throws IOException{
		//create CipherOutputStream to decrypt the data using decrypCipher
		is = new CipherInputStream(is,decryptCipher);
		writeData(is,os);
	}

	private static void encrypt(InputStream is, OutputStream os) throws IOException{
		//create CipherOutputStream to encrypt the data using encryptCipher
		os = new CipherOutputStream(os, encryptCipher);
		writeData(is,os);
	}
	private static void writeData(InputStream is, OutputStream os) throws IOException{
		byte[] buf = new byte[1024];
		int numRead = 0;
		//read and write operation
		while ((numRead = is.read(buf)) >= 0){
			os.write(buf,0,numRead);
		}
		os.close();
		is.close();
	}
   
//	public static void main(String[] args) throws NoSuchAlgorithmException, Exception {
//            SecretKey key=KeyGenerator.getInstance("DES").generateKey();
//            String path=args[0];
//            System.out.println(path);
//            File file=new File(path);
//            DES des=new DES();
//            des.encryptFile(file,key);
//            File file_des=new File(path+".des");
//            des.decryptFile(file_des,key);
//        }
        
}