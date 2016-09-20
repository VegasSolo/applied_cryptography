/*
 * Author(s):	Dillon VanBuskirk
 * 				Sandy Becerra
 * Assignment:	Applied Cryptography Lab #1
 * Date:		March 31, 2016
 * File:		Bob.java (server)
 */

import java.net.*;
import java.io.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import javax.crypto.spec.*;

import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class Bob {
	
	public static String bobMessage = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    public static String aliceMessage = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
	
    private static SecretKeySpec secretKey_e;
    private static SecretKeySpec secretKey_i;
    private static byte[] key_AES_e;
    private static byte[] key_AES_i;
    
    public static void main(String[] args) {
		try {
			// ************************************************************ \\
	        // *********************** Alice -> Bob *********************** \\
	        // ************************************************************ \\
			
			// initialize RSA key stuff
			KeyPairGenerator generator_e = KeyPairGenerator.getInstance("RSA");
			KeyPair pair_e = generator_e.generateKeyPair();
			SecureRandom random_e = new SecureRandom();
			KeyPairGenerator generator_i = KeyPairGenerator.getInstance("RSA");
			KeyPair pair_i = generator_i.generateKeyPair();
			SecureRandom random_i = new SecureRandom();
			
			// initialize AES 
			Cipher cipher= Cipher.getInstance("RSA/ECB/PKCS1Padding");
			
			// initialize signature stuff
			Signature sig = Signature.getInstance("SHA256withRSA");
			
			// byte variables
			byte [] plainTextBytes = bobMessage.getBytes();
		    byte [] AES_value_e, AES_value_i;
			
			
			// generate keys
			generator_e.initialize(2048, random_e);
			PublicKey pubKey_e = pair_e.getPublic();
		    PrivateKey priKey_e = pair_e.getPrivate();
		    generator_i.initialize(2048, random_i);
			PublicKey pubKey_i = pair_i.getPublic();
		    PrivateKey priKey_i = pair_i.getPrivate();
		    
		    // optional print public to file
		    //PrintWriter writer = new PrintWriter("BobKeys.txt");//, "UTF-8");
		    //writer.println(pubKey);
		    //writer.close();
		    
		    // create socket
		    ServerSocket sock = new ServerSocket(80);
		    
		    // listen for connections
		    System.out.println("Listening for connections...");
		    while (true) {
				Socket client = sock.accept();
				
				// initialize object streams
				ObjectOutputStream obOut = new ObjectOutputStream(client.getOutputStream());
				ObjectInputStream obIn = new ObjectInputStream(client.getInputStream());

				// send public key to alice so she can encrypt
				obOut.writeObject(pubKey_e);
				obOut.flush();
				obOut.writeObject(pubKey_i);
				obOut.flush();
				
				// receive alice's public key for signature verify
				Object obj = obIn.readObject();
				PublicKey aliceKey_public_RSA_integrity = (PublicKey) obj;
				//writer.println(aliceKey_public_RSA_integrity);
				//writer.close();
				
				// receive the cipher key from alice
				obj = obIn.readObject();
				byte[] cipherKey_e = (byte[]) obj;
				obj = obIn.readObject();
				byte[] cipherKey_i = (byte[]) obj;
				//System.out.println(cipherKey.length);
				//byte[] cipherTextByte = cipherText.getBytes(); // create cipherText Bytes
				
				// receive the byte[] of the hash of the plaintext
				obj = obIn.readObject();
				byte[] hashByte = (byte[]) obj;
				
				// receive the digital signature from alice
				obj = obIn.readObject();
				byte[] signature = (byte[]) obj;
				
				// verify signature
				sig.initVerify(aliceKey_public_RSA_integrity);
				sig.update(hashByte);
				if (!(sig.verify(signature))) {
					System.out.println("Failed integrity test. Not actually exiting for testing.");
					//client.close();
					//System.exit(0);
				} else {
					System.out.println("Integrity success! This is from Alice");
				}
				
				// decrypt cipherKey using RSA to get shared AES secret key
				try {
			        cipher.init(Cipher.DECRYPT_MODE, priKey_e);
			        byte[] sharedSecretBytes_final_e = cipher.doFinal(cipherKey_e);
			        secretKey_e = new SecretKeySpec(sharedSecretBytes_final_e, "AES");
			        cipher.init(Cipher.DECRYPT_MODE, priKey_i);
			        byte[] sharedSecretBytes_final_i = cipher.doFinal(cipherKey_i);
			        secretKey_i = new SecretKeySpec(sharedSecretBytes_final_i, "AES");
			        //writer.println(secretKey);
					//writer.close();
				}
		        catch (Exception e) {
		        	e.printStackTrace();
		        }
				
				// receive the cipher of message from alice
				obj = obIn.readObject();
				byte[] cipherText = (byte[]) obj;
				
				//System.out.println(cipherText.length);
				// decrypt cipher message
				try {
					cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
					cipher.init(Cipher.DECRYPT_MODE, secretKey_e);
					byte[] aliceMessage_final = cipher.doFinal(cipherText);
					MessageDigest hash = MessageDigest.getInstance("SHA-256");
					hash.update(aliceMessage_final);
					byte[] hashByte_decrypt = hash.digest(aliceMessage_final);
					String decoded_hashByte = new String(hashByte, "UTF-8");
					String decoded_hashByte_decrypt = new String(hashByte_decrypt, "UTF-8");
					String decoded_alice = new String(aliceMessage_final, "UTF-8");
					//System.out.println(decoded_alice);
					//System.out.println(aliceMessage_final.length);
					if (decoded_hashByte_decrypt.equals(decoded_hashByte)) {
						System.out.println("Success! The hash of the plaintexts match! This message has not been modified and is from Alice!");
						System.out.println("Received Plaintext: " + decoded_alice);
						System.out.println("Received Plaintext Length: " + decoded_alice.length());
					} else {
						System.out.println("Checked hash. It failed. These messages do not match.");
					}
				}
				catch (Exception e) {
					e.printStackTrace();
				}
				
				// ************************************************************ \\
		        // *********************** Bob -> Alice *********************** \\
		        // ************************************************************ \\

		        // begin Diffie-Hellman protocol
				DHParameterSpec dhParamSpec_e;
				DHParameterSpec dhParamSpec_i;

		        //System.out.println("Creating Diffie-Hellman parameters...");
		        AlgorithmParameterGenerator paramGen_e = AlgorithmParameterGenerator.getInstance("DH");
		        paramGen_e.init(1024);
		        AlgorithmParameters params_e = paramGen_e.generateParameters();
		        dhParamSpec_e = (DHParameterSpec)params_e.getParameterSpec(DHParameterSpec.class);
		        AlgorithmParameterGenerator paramGen_i = AlgorithmParameterGenerator.getInstance("DH");
		        paramGen_i.init(1024);
		        AlgorithmParameters params_i = paramGen_i.generateParameters();
		        dhParamSpec_i = (DHParameterSpec)params_i.getParameterSpec(DHParameterSpec.class);
		        
		        // Bob generate DH key pair
		        //System.out.println("Bob: Generating DH keypair ...");
		        KeyPairGenerator bobKpairGen_e = KeyPairGenerator.getInstance("DH");
		        bobKpairGen_e.initialize(dhParamSpec_e);
		        KeyPair bobKpair_e = bobKpairGen_e.generateKeyPair();
		        KeyPairGenerator bobKpairGen_i = KeyPairGenerator.getInstance("DH");
		        bobKpairGen_i.initialize(dhParamSpec_i);
		        KeyPair bobKpair_i = bobKpairGen_i.generateKeyPair();
		        
		        // Bob creates and initializes his DH KeyAgreement object
		        //System.out.println("Bob: Initialization ...");
		        KeyAgreement bobKeyAgree_e = KeyAgreement.getInstance("DH");
		        bobKeyAgree_e.init(bobKpair_e.getPrivate());
		        KeyAgreement bobKeyAgree_i = KeyAgreement.getInstance("DH");
		        bobKeyAgree_i.init(bobKpair_i.getPrivate());
		        
		        // Bob encodes her public key, and sends it over to Alice.
		        byte[] bobPubKeyEnc_e = bobKpair_e.getPublic().getEncoded();
		        obOut.writeObject(bobPubKeyEnc_e);
				obOut.flush();
				byte[] bobPubKeyEnc_i = bobKpair_i.getPublic().getEncoded();
		        obOut.writeObject(bobPubKeyEnc_i);
				obOut.flush();
				
				// read alice public key
				obj = obIn.readObject();
				byte[] alicePubKeyEnc_e = (byte[]) obj;
				obj = obIn.readObject();
				byte[] alicePubKeyEnc_i = (byte[]) obj;
				
				// phase 1
				KeyFactory bobKeyFac_e = KeyFactory.getInstance("DH");
				X509EncodedKeySpec x509KeySpec_e = new X509EncodedKeySpec(alicePubKeyEnc_e);
		        PublicKey alicePubKey_e = bobKeyFac_e.generatePublic(x509KeySpec_e);
		        //System.out.println("Bob: Execute phase 1 ...");
		        bobKeyAgree_e.doPhase(alicePubKey_e, true);
		        KeyFactory bobKeyFac_i = KeyFactory.getInstance("DH");
				X509EncodedKeySpec x509KeySpec_i = new X509EncodedKeySpec(alicePubKeyEnc_i);
		        PublicKey alicePubKey_i = bobKeyFac_i.generatePublic(x509KeySpec_i);
		        //System.out.println("Bob: Execute phase 1 ...");
		        bobKeyAgree_i.doPhase(alicePubKey_i, true);
		        
		        // generate shared secret
		        byte[] bobSharedSecret_e = bobKeyAgree_e.generateSecret();
				int bobLen_e = bobSharedSecret_e.length;
				byte[] bobSharedSecret_i = bobKeyAgree_i.generateSecret();
				int bobLen_i = bobSharedSecret_i.length;
				//System.out.println(bobLen);
		        //System.out.println("Bob secret: " + toHexString(bobSharedSecret));
				
		        // doPhase again prior to another generateSecret call
		        bobKeyAgree_e.doPhase(alicePubKey_e, true);
		        SecretKey bobAESKey_e = bobKeyAgree_e.generateSecret("AES");
		        bobKeyAgree_i.doPhase(alicePubKey_i, true);
		        SecretKey bobAESKey_i = bobKeyAgree_i.generateSecret("AES");
		        
		        // encrypt using AES cipher 
		        cipher.init(Cipher.ENCRYPT_MODE, bobAESKey_e);
		        byte[] cipherText_DH = cipher.doFinal(plainTextBytes);
		        
		        // hmac
		        Mac hmac = Mac.getInstance("HmacSHA256");
		        hmac.init(bobAESKey_i);
		        byte[] result = hmac.doFinal(cipherText_DH);
		        
		        // send hmac
		        obOut.writeObject(result);
		        obOut.flush();
		        
		        // send cipherText to alice
		        obOut.writeObject(cipherText_DH);
				obOut.flush();
		        
				
				// close the socket and resume listening for connections
				client.close();
				break;
			}
		    
		}
		catch(Exception e) {
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