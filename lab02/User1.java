/*	Author(s): 	Sandy Becerra
 *				Dillon VanBuskirk
 *	Assignment:	Lab 2
 */

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.IntBuffer;
import java.security.Key;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class User1 {
	private static int port = 8000+1; // CHANGE
	public static void main(String[] args) {
		try {
			/* ** ** ** declarations ** ** ** */
			int delta_data1 = 100; // max user age
			int delta_data2 = 5; // max alloted kids per family
			int x1 = 21; // user 1 age
			int x2 = 1; // user 1 # of childs
			int n = 2; // num of users
			int M1 = n*delta_data1; // 2^(log2(n*delta))
			int M2 = n*delta_data2; // 2^(log2(n*delta))
			
			/* ** ** ** initialization ** ** ** */
			// initialize sockets and object streams
		    Socket sock_TA = new Socket("127.0.0.1", port);
		    //ObjectOutputStream obOut = new ObjectOutputStream(sock_TA.getOutputStream());
			ObjectInputStream obIn = new ObjectInputStream(sock_TA.getInputStream());
			Object obj;
			System.out.println("I'm connecting to the Trusted Authority on port " + port);
			
			// receive set of secrets for each user from socket from TA
			obj = obIn.readObject();
			System.out.println("I've received my subset.");
			SecretKey[] user1_array = (SecretKey[]) obj;
			
			sock_TA.close();
			
			// define timestamp
			int time_interval = 1;
			byte[] time_interval_byte = new byte[4];
			
			/* ** ** ** key gen for data 1 ** ** ** */
			// key creation
			Mac hmac = Mac.getInstance("HmacSHA256");
			byte[] mac = new byte[user1_array.length];
			int result=0;
			for (int i=0; i<user1_array.length; i++) {
				hmac.init(user1_array[i]);
				time_interval_byte[0] = (byte) (time_interval >> 24);
				time_interval_byte[1] = (byte) (time_interval >> 16);
				time_interval_byte[2] = (byte) (time_interval >> 8);
				time_interval_byte[3] = (byte) (time_interval /*>> 0*/);
				mac = hmac.doFinal(time_interval_byte);
				byte[] xor_result = Arrays.copyOf(mac, mac.length);
				for (int j=0; j<mac.length; j++) {
					if(j < xor_result.length) {
						if(j < mac.length)
							xor_result[j] = (byte) (xor_result[j] ^ mac[j]);
						else
							xor_result[j] = (byte) (xor_result[j] ^ 0);
					} 
					else
						xor_result[j] = (byte) (0 ^ mac[j]);
				}
				result += byteArrayToInt(xor_result);
				time_interval++;
			}
			
			/* ** ** ** key gen for data 2 ** ** ** */
			// key creation
			hmac = Mac.getInstance("HmacSHA256");
			mac = new byte[user1_array.length];
			int result_d2=0;
			for (int i=0; i<user1_array.length; i++) {
				hmac.init(user1_array[i]);
				time_interval_byte[0] = (byte) (time_interval >> 24);
				time_interval_byte[1] = (byte) (time_interval >> 16);
				time_interval_byte[2] = (byte) (time_interval >> 8);
				time_interval_byte[3] = (byte) (time_interval /*>> 0*/);
				mac = hmac.doFinal(time_interval_byte);
				byte[] xor_result_d2 = Arrays.copyOf(mac, mac.length);
				for (int j=0; j<mac.length; j++) {
					if(j < xor_result_d2.length) {
						if(j < mac.length)
							xor_result_d2[j] = (byte) (xor_result_d2[j] ^ mac[j]);
						else
							xor_result_d2[j] = (byte) (xor_result_d2[j] ^ 0);
					} 
					else
						xor_result_d2[j] = (byte) (0 ^ mac[j]);
				}
				result_d2 += byteArrayToInt(xor_result_d2);
				time_interval++;
			}

			/* ** ** ** encryption ** ** ** */
			int key1 = result % M1;
			int cipher1 = (key1 + x1) % M1;
			int key2 = result_d2 % M2;
			int cipher2 = (key2 + x2) % M2;
			
			/* ** ** ** client set up ** ** ** */
			port += n;
			Socket sock_Agg = new Socket("127.0.0.1", port);
		    ObjectOutputStream obOut_agg = new ObjectOutputStream(sock_Agg.getOutputStream());
		    System.out.println("I'm sending my ciphers to the aggregator on his server on port " + port);
		    
			/* ** ** ** sending ciphers ** ** ** */
			obOut_agg.writeInt(cipher1);
			obOut_agg.flush();
			obOut_agg.writeInt(cipher2);
			obOut_agg.flush();
			System.out.println("I've sent my ciphers. I'm all done. Good bye.");
			sock_Agg.close();
		}
		catch (Exception e) {
        	e.printStackTrace();
        }
	}
	
	/* This converts a byte array into an integer using shift left operator */
	public static int byteArrayToInt(byte[] b) 
	{
	    return   b[3] & 0xFF |
	            (b[2] & 0xFF) << 8 |
	            (b[1] & 0xFF) << 16 |
	            (b[0] & 0xFF) << 24;
	}
}