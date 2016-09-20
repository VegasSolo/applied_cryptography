/*
 * Author(s):	Dillon VanBuskirk
 * 				Sandy Becerra
 * Assignment:	Applied Cryptography Lab #1
 * Date:		March 31, 2016
 * File:		Alice.java (client)
 */

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Alice {
	
	public static String bobMessage = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public static String aliceMessage = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	
    private static SecretKeySpec secretKey_encryption;
    private static SecretKeySpec secretKey_integrity;
    private static byte[] key_AES_encryption;
    private static byte[] key_AES_integrity;
    
    public static void main(String[] args) {
		try {
			// ************************************************************ \\
	        // *********************** Alice -> Bob *********************** \\
	        // ************************************************************ \\
			
			// initialize RSA key gen
			KeyPairGenerator generator_encryption = KeyPairGenerator.getInstance("RSA");
			KeyPair pair_encryption = generator_encryption.generateKeyPair();
			SecureRandom random_encryption = new SecureRandom();
			KeyPairGenerator generator_integrity = KeyPairGenerator.getInstance("RSA");
			KeyPair pair_integrity = generator_integrity.generateKeyPair();
			SecureRandom random_integrity = new SecureRandom();
			
			// initialize AES cipher
			Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			// initialize signature stuff
			Signature sig = Signature.getInstance("SHA256withRSA");
			MessageDigest hash = MessageDigest.getInstance("SHA-256");
			
			// byte variables
			byte [] plainTextBytes = aliceMessage.getBytes();
		    byte [] hashByte, AES_value_encryption, AES_value_integrity, signature;
		    
		    
		    // generate keys
			generator_encryption.initialize(2048, random_encryption);
			generator_integrity.initialize(2048, random_integrity);
			PublicKey pubKey_encryption = pair_encryption.getPublic();
		    PrivateKey priKey_encryption = pair_encryption.getPrivate();
		    PublicKey pubKey_integrity = pair_integrity.getPublic();
		    PrivateKey priKey_integrity = pair_integrity.getPrivate();
		    
		    // optional print public key to file
		    //PrintWriter writer = new PrintWriter("AliceKeys.txt");//, "UTF-8");
		    //writer.println(pubKey);
		    //writer.close();
		    
		    // initialize sockets and object streams
		    Socket sock = new Socket("127.0.0.1", 80);
		    ObjectOutputStream obOut = new ObjectOutputStream(sock.getOutputStream());
			ObjectInputStream obIn = new ObjectInputStream(sock.getInputStream());
			
			// receive Bob's public key out of socket to encrypt message
			Object obj = obIn.readObject();
			PublicKey bobKey_public_RSA_encryption = (PublicKey) obj;
			obj = obIn.readObject();
			PublicKey bobKey_public_RSA_integrity = (PublicKey) obj;
			//writer.println("\n");
			//writer.println(bobKey_public_RSA_encryption);
			//writer.close();
			
			// send Alice's public key to Bob so he can undo signature
			obOut.writeObject(pubKey_integrity);
			obOut.flush();
			
		    // sign and hash aliceMessage
			hash.update(plainTextBytes);
			hashByte = hash.digest(plainTextBytes);
		    sig.initSign(priKey_integrity);
		    sig.update(hashByte);
		    signature = sig.sign();
		    
		    // test signature
		    /*
		    sig.initVerify(pubKey_integrity);
		    sig.update(hashByte);
		    if (!(sig.verify(signature))) {
				System.out.println("Failed integrity test. Not actually exiting.");
				//client.close();
				//System.exit(0);
			} else {
				System.out.println("Integrity success! This is from Alice");
			}
			*/
		    
			// AES algorithm as shown on aesencryption.net to generate shared secret
			MessageDigest sha = null;
	        try {
	        	key_AES_encryption = bobKey_public_RSA_encryption.getEncoded();
	            //System.out.println(bobKey_public_RSA_encryption.getEncoded().length);
	            sha = MessageDigest.getInstance("SHA-256");
	            key_AES_encryption = sha.digest(key_AES_encryption);
	            key_AES_encryption = Arrays.copyOf(key_AES_encryption, 16); // use only first 128 bit
	            //System.out.println(key_AES.length);
	            //System.out.println(new String(key_AES,"UTF-8"));
	            secretKey_encryption = new SecretKeySpec(key_AES_encryption, "AES");
	            //writer.println("\n");
				//writer.println(secretKey);
				//writer.close();
	        }
	        catch (Exception e) {
	        	e.printStackTrace();
	        }
			
	        // encrypt secretkey with RSA
	        byte[] sharedSecretBytes_encryption = secretKey_encryption.getEncoded();
	        cipher.init(Cipher.ENCRYPT_MODE, bobKey_public_RSA_encryption);
	        byte[] sharedSecretBytes_final_encryption = cipher.doFinal(sharedSecretBytes_encryption);
	        byte[] sharedSecretBytes_integrity = secretKey_encryption.getEncoded();
	        cipher.init(Cipher.ENCRYPT_MODE, bobKey_public_RSA_integrity);
	        byte[] sharedSecretBytes_final_integrity = cipher.doFinal(sharedSecretBytes_integrity);
	        
	        // send encrypted secret key to Bob
	        //System.out.println(sharedSecretBytes_final.length);
	        obOut.writeObject(sharedSecretBytes_final_encryption);
	        obOut.flush();
	        obOut.writeObject(sharedSecretBytes_final_integrity);
	        obOut.flush();
	        
	        // send hash byte[] to Bob
	        obOut.writeObject(hashByte);
	        obOut.flush();
	        
	        // send signature byte array to Bob
	        obOut.writeObject(signature);
	        obOut.flush();
	        
	        // encrypt message with AES key using AES cipher
	        cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
	        cipher.init(Cipher.ENCRYPT_MODE, secretKey_encryption);
	        byte[] aliceMessage_encrypted = cipher.doFinal(plainTextBytes);
			
	        // send cipher to Bob
	        obOut.writeObject(aliceMessage_encrypted);
	        obOut.flush();
	        
	        // ************************************************************ \\
	        // *********************** Bob -> Alice *********************** \\
	        // ************************************************************ \\
	        
	        // begin Diffie-Hellman protocol by receiving bobPub out of socket
	        obj = obIn.readObject();
			byte[] bobPubKeyEnc_encryption = (byte[]) obj;
			obj = obIn.readObject();
			byte[] bobPubKeyEnc_integrity = (byte[]) obj;
	        
			// alice instantiates DH public key from encoded key from bob
			KeyFactory aliceKeyFac_encryption = KeyFactory.getInstance("DH");
	        X509EncodedKeySpec x509KeySpec_encryption = new X509EncodedKeySpec(bobPubKeyEnc_encryption);
	        PublicKey bobPubKey_encryption = aliceKeyFac_encryption.generatePublic(x509KeySpec_encryption);
	        KeyFactory aliceKeyFac_integrity = KeyFactory.getInstance("DH");
	        X509EncodedKeySpec x509KeySpec_integrity = new X509EncodedKeySpec(bobPubKeyEnc_integrity);
	        PublicKey bobPubKey_integrity = aliceKeyFac_integrity.generatePublic(x509KeySpec_integrity);
	        
	        // alice gets parameters
	        DHParameterSpec dhParamSpec_encryption = ((DHPublicKey)bobPubKey_encryption).getParams();
	        DHParameterSpec dhParamSpec_integrity = ((DHPublicKey)bobPubKey_integrity).getParams();
	        
	        // alice creates her own DH key pair
	        //System.out.println("Alice: Generate DH keypair ...");
	        KeyPairGenerator aliceKpairGen_encryption = KeyPairGenerator.getInstance("DH");
	        aliceKpairGen_encryption.initialize(dhParamSpec_encryption);
	        KeyPair aliceKpair_encryption = aliceKpairGen_encryption.generateKeyPair();
	        KeyPairGenerator aliceKpairGen_integrity = KeyPairGenerator.getInstance("DH");
	        aliceKpairGen_integrity.initialize(dhParamSpec_integrity);
	        KeyPair aliceKpair_integrity = aliceKpairGen_integrity.generateKeyPair();

	        // alice creates and initializes her DH KeyAgreement object
	        //System.out.println("Alice: Initialization ...");
	        KeyAgreement aliceKeyAgree_encryption = KeyAgreement.getInstance("DH");
	        aliceKeyAgree_encryption.init(aliceKpair_encryption.getPrivate());
	        KeyAgreement aliceKeyAgree_integrity = KeyAgreement.getInstance("DH");
	        aliceKeyAgree_integrity.init(aliceKpair_integrity.getPrivate());
	        
	        // alice encodes her public key, and sends it over to bob.
	        byte[] alicePubKeyEnc_encryption = aliceKpair_encryption.getPublic().getEncoded();
	        obOut.writeObject(alicePubKeyEnc_encryption);
			obOut.flush();
			byte[] alicePubKeyEnc_integrity = aliceKpair_integrity.getPublic().getEncoded();
	        obOut.writeObject(alicePubKeyEnc_integrity);
			obOut.flush();
	        
			// phase 1
			//System.out.println("Alice: Execute phase 1 ...");
			aliceKeyAgree_encryption.doPhase(bobPubKey_encryption, true);
			aliceKeyAgree_integrity.doPhase(bobPubKey_integrity, true);
			
			// generate shared secret
			byte[] aliceSharedSecret_encryption = aliceKeyAgree_encryption.generateSecret();
			int aliceLen_encryption = aliceSharedSecret_encryption.length;
			byte[] aliceSharedSecret_integrity = aliceKeyAgree_integrity.generateSecret();
			int aliceLen_integrity = aliceSharedSecret_integrity.length;
			//System.out.println(aliceLen);
			//System.out.println("Alice secret: " + toHexString(aliceSharedSecret));
			
			// doPhase again prior to another generateSecret call
			aliceKeyAgree_encryption.doPhase(bobPubKey_encryption, true);
			SecretKey aliceAESKey_encryption = aliceKeyAgree_encryption.generateSecret("AES");
			aliceKeyAgree_integrity.doPhase(bobPubKey_integrity, true);
			SecretKey aliceAESKey_integrity = aliceKeyAgree_integrity.generateSecret("AES");
			
			// receive hmac sig out of socket from bob
			obj = obIn.readObject();
			byte[] hmac_bob	= (byte[]) obj;
			
			// receive ciphertext out of socket from bob
			obj = obIn.readObject();
			byte[] cipherText_DH = (byte[]) obj;
			
			// compare hmac sig
			Mac hmac = Mac.getInstance("HmacSHA256");
			hmac.init(aliceAESKey_integrity);
			byte[] hmac_alice = hmac.doFinal(cipherText_DH);
			String hmac_alice_string = new String(hmac_alice, "UTF-8");
			String hmac_bob_string = new String(hmac_bob, "UTF-8");
			if (hmac_alice_string.equals(hmac_bob_string)) {
				System.out.println("Integrity success! This is from Bob. The ciphertext HMAC matches the HMAC.");
			} else {
				System.out.println("Failed integrity test. Not actually exiting for testing.");
				//client.close();
				//System.exit(0);
			}
			
			// decrypt
			cipher.init(Cipher.DECRYPT_MODE, aliceAESKey_encryption);
			byte[] bobMessage_final = cipher.doFinal(cipherText_DH);
			String decoded_bob = new String(bobMessage_final, "UTF-8");
			//System.out.println(decoded_bob);
			//System.out.println(decoded_bob.length());
			if (decoded_bob.equals(bobMessage)) {
				System.out.println("Success! The plaintexts match!");
				System.out.println("Received Plaintext: " + decoded_bob);
				System.out.println("Received Plaintext Length: " + decoded_bob.length());
			} else {
				System.out.println("Failed! The plaintexts do not match for Diffie-Hellman!");
			}
			sock.close();
		}
		catch(Exception e) {
			System.out.println("In the exception" + e); 
			e.printStackTrace();
		}
    }
    
 // Converts a byte to hex digit and writes to the supplied buffer
    private static void byte2hex(byte b, StringBuffer buf) {
        char[] hexChars = { '0', '1', '2', '3', '4', '5', '6', '7', '8',
                            '9', 'A', 'B', 'C', 'D', 'E', 'F' };
        int high = ((b & 0xf0) >> 4);
        int low = (b & 0x0f);
        buf.append(hexChars[high]);
        buf.append(hexChars[low]);
    }

    
    // Converts a byte array to hex string
    private static String toHexString(byte[] block) {
        StringBuffer buf = new StringBuffer();

        int len = block.length;

        for (int i = 0; i < len; i++) {
             byte2hex(block[i], buf);
             if (i < len-1) {
                 buf.append(":");
             }
        }
        return buf.toString();
    }
    
}
