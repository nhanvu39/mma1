package capstone.encryption;

//File IO imports
import capstone.UI.EncUI;
import capstone.fileio.FileIO;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

//Cryptography imports
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.util.Base64;

public class Encryption {

    static FileIO fio;
    private static final String ALG = "AES";
    private static final String CIPH = "AES/CBC/PKCS5Padding";
    private static final String KEYFAC = "PBKDF2WithHmacSHA1";
    
    public static String encrypt(File file, File key, String alg) throws Exception {
        FileOutputStream outFile;
        // output file stream
        if (alg.equals("AES")){
            try (
            // file to be encrypted as input stream
            FileInputStream inFile = new FileInputStream(file)) {
                // output file stream
                outFile = new FileOutputStream(file + ".enc");
                String password="";
                byte[] bytes = Files.readAllBytes(Paths.get(key.toString()));
                password = Arrays.toString(bytes);
                
//                    password = new Scanner(key).useDelimiter("\\Z").next();
                //create salt 
                byte[] salt = new byte[8];
                SecureRandom secureRandom = new SecureRandom();
                secureRandom.nextBytes(salt);

                // Write the salt to output file stream
                outFile.write(salt);

                //Generate Secret Key
                SecretKeyFactory factory = SecretKeyFactory
                        .getInstance(KEYFAC);
                KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536,
                        128);
                SecretKey secretKey = factory.generateSecret(keySpec);
                SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), ALG);

                // Initialize the cipher
                Cipher cipher = Cipher.getInstance(CIPH);
                cipher.init(Cipher.ENCRYPT_MODE, secret);
                AlgorithmParameters params = cipher.getParameters();
                byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();

                //output the iv to the file output stream
                outFile.write(iv);

                //encrypt the input file
                byte[] input = new byte[64];
                int bytesRead;
                while ((bytesRead = inFile.read(input)) != -1) {
                    byte[] output = cipher.update(input, 0, bytesRead);
                    if (output != null) {
                        outFile.write(output);
                    }
                }
                byte[] output = cipher.doFinal();
                if (output != null) {
                    outFile.write(output);
                }
            }

            outFile.flush();
            outFile.close();

//            return file + ".enc";
        }
        else if (alg.equals("RSA")){
            if (RSA.doEncrypt(file.toString(), key.toString()) == -1){
                return "keyfailure";
            }
        }
        else{
            // decode the base64 encoded string
            byte[] decodedKey = Files.readAllBytes(Paths.get(key.toString()));
//            byte[] decodedKey = bytes;
//            byte[] decodedKey = Base64.getDecoder().decode(bytes);
            // rebuild key using SecretKeySpec
            SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "DES"); 
            DES.encryptFile(file, originalKey);
        }
        
        return file + ".enc";
    }
    public static void genKey(File folder, String alg) throws FileNotFoundException, IOException, NoSuchAlgorithmException{
        if (alg.equals("AES")){
            FileOutputStream outFile;
            String aes = alg + ".key";
            File out = new File(folder, aes);
            outFile = new FileOutputStream(out);
        
            byte[] array = new byte[16]; // length is bounded by 7
            new Random().nextBytes(array);
            String generatedString = new String(array, Charset.forName("UTF-8"));
            byte b[]= generatedString.getBytes();
            outFile.write(b);
            outFile.flush();
            outFile.close();
        }
        else if (alg.equals("RSA")){
            String pub = alg + "pub.key";
            File pubOut = new File(folder, pub);
            String pri = alg + "pri.key";
            File priOut = new File(folder, pri);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            KeyPair kp = kpg.generateKeyPair();
            try (FileOutputStream out = new FileOutputStream(priOut)) {
                    out.write(kp.getPrivate().getEncoded());
                }

            try (FileOutputStream out = new FileOutputStream(pubOut)) {
                    out.write(kp.getPublic().getEncoded());
                }
        }
        else { //DES
            FileOutputStream outFile;
            String aes = alg + ".key";
            File outF = new File(folder, aes);
            SecretKey key=KeyGenerator.getInstance("DES").generateKey();
            try (FileOutputStream out = new FileOutputStream(outF)) {
                out.write(key.getEncoded());
            }
        }
    }
}
