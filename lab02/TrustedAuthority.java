/*	Author(s): 	Sandy Becerra
 *				Dillon VanBuskirk
 *	Assignment:	Lab 2
 */

import java.io.*;
import java.net.*;
import java.util.Random;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.Key;
import java.security.SecureRandom;

public class TrustedAuthority {

	private static int n = 2;
	private static int c = 4;
	private static int port = 8000; // CHANGE
    public static void main(String[] args) {
        try{ 
        	/* ** ** ** declarations ** ** ** */
        	int multi = n * c;
        	KeyGenerator secretgen = KeyGenerator.getInstance("AES");
        	SecureRandom random = new SecureRandom();
        	SecretKey[] array = new SecretKey[multi]; 
            ServerSocket sock = new ServerSocket(port);
            
            /* ** ** ** secret gen ** ** ** */
            secretgen.init(128, random);
            for(int i=0; i < multi; i++)
            {
            	array[i] = secretgen.generateKey();
            }
             
			/* ** ** ** split array "randomly" ** ** ** */
			SecretKey array_1[] = {array[1], array[3],array[5], array[7]};
            SecretKey array_2[] = {array[0], array[2],array[4], array[6]};
		    
			/* ** ** ** server set-up ** ** ** */
			System.out.println("Listening for connections...");
		   	Socket client = sock.accept();
				
			ObjectOutputStream obOut = new ObjectOutputStream(client.getOutputStream());
			ObjectInputStream obIn = new ObjectInputStream(client.getInputStream());
			
			/* ** ** ** write arrays to sockets upon each new connection ** ** ** */
			//if (i == 0) {
				obOut.writeObject(array);
				obOut.flush();
				System.out.println("I've sent the master set to the first connection.");
				client.close();
			//} else if (i == 1) {
				port++;
				ServerSocket sock1 = new ServerSocket(port);
				client = sock1.accept();
				obOut = new ObjectOutputStream(client.getOutputStream());
				obOut.writeObject(array_1);
				obOut.flush();
				System.out.println("I've sent the first subset to the second connection.");
				client.close();
			//} else {
				port++;
				ServerSocket sock2 = new ServerSocket(port);
				client = sock2.accept();
				obOut = new ObjectOutputStream(client.getOutputStream());
				obOut.writeObject(array_2);
				obOut.flush();
				System.out.println("I've sent the second subset to the third connection.");
				client.close();
			//}
			System.out.println("I'm done working. Good bye.");
			sock.close();
        }               
        catch(Exception sjb) {sjb.printStackTrace();}
    }
} 
