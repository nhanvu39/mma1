package capstone.encryption;

/**
 * Created by Jeremy Blanchard on 7/13/2016. This class takes a file as an input
 * stream which is saved to a byte array.   The user will then enter a password. The 
 * password is then combined with a SecureRandom
 *
 * 
 */
//File IO imports
import capstone.fileio.FileIO;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

//Cryptography imports
import java.security.AlgorithmParameters;
import java.security.SecureRandom;
import java.security.spec.KeySpec;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;


/**
 * This class performs the file encryption. First a password is created by the
 * user.  This password is combined with an 8-byte SecureRandom which is then used to generate the key
 * used to initialize the cipher.  An initialization vector, which introduces randomness when ciphering similar plain text, is created.  
 * The SecureRandom, IV, and ciphertext are then output to a file, adding the ".aes" extension.
 *
 * @author Jeremy Blanchard
 */
public class Encryption {

    static FileIO fio;
    private static final String ALG = "AES";
    private static final String CIPH = "AES/CBC/PKCS5Padding";
    private static final String KEYFAC = "PBKDF2WithHmacSHA1";

   

    /**
     * The Encryption.encrypt method performs the encryption operation.  This method is passed 2 arguments.  
     * The first is the File to be encrypted, and the second argument is the users password.  
     * @param file The file to be encrypted
     * @param password The users password which is then combined with a automatically generated SecureRandom.  This hash is then used 
     * generate the encryption key which is used to initialize the cipher for Encryption.
     * @return The filename including the path to the file.
     * @throws Exception  There are a number of exceptions that could potentially be thrown during the encryption process. 
     * Including IOException which indicates there was an error in reading/writing the file stream, NoSuchAlgorithmException indicates 
     * that the system does not have the associated algorithm available.  
     */
    public static String encrypt(File file, String password) throws Exception {
        FileOutputStream outFile;
        // output file stream
        try (
                // file to be encrypted as input stream
                FileInputStream inFile = new FileInputStream(file)) {
            // output file stream
            outFile = new FileOutputStream(file + ".aes");

            
            

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

        

        return file + ".aes";

    }

}
