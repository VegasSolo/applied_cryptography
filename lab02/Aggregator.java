/*	Author(s): 	Sandy Becerra
 *				Dillon VanBuskirk
 *	Assignment:	Lab 2
 */

import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Arrays;

import javax.crypto.Mac;
import javax.crypto.SecretKey;

public class Aggregator {
	private static int port = 8000; // CHANGE
	public static void main(String[] args) {
		try {
			/* ** ** ** declaration ** ** ** */
			int delta_data1 = 100; // max user age
			int delta_data2 = 5; // max alloted kids per family
			int n = 2; // num of users
			int M1 = n*delta_data1; // 2^(log2(n*delta))
			int M2 = n*delta_data2; // 2^(log2(n*delta))
			
			/* ** ** ** initialization ** ** ** */
			// initialize sockets and object streams
		    Socket sock_client = new Socket("127.0.0.1", port);
		    ObjectOutputStream obOut = new ObjectOutputStream(sock_client.getOutputStream());
			ObjectInputStream obIn = new ObjectInputStream(sock_client.getInputStream());
			Object obj;
			
			// receive master set of secrets from socket from TA
			obj = obIn.readObject();
			System.out.println("I've received the master set from the Trusted Authority.");
			SecretKey[] master_array = (SecretKey[]) obj;
			
			/* ** ** ** master key gen ** ** ** */
			// define timestamp
			int time_interval = 1;
			byte[] time_interval_byte = new byte[4];
			
			// key creation
			Mac hmac = Mac.getInstance("HmacSHA256");
			byte[] mac = new byte[master_array.length];
			int result=0;
			for (int i=0; i<master_array.length; i++) {
				hmac.init(master_array[i]);
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
			int masterKey = result % M1;
			
			/* ** ** ** server set up ** ** ** */
			port += n+1;
			ServerSocket sock_server = new ServerSocket(port);
			System.out.println("I've set up my server on port " + port);
			
			/* ** ** ** decryption ** ** ** */
			int cipher1, cipher2, sum1 = 0, sum2 = 0, count = 0;
			for (int i=0; i<n; i++) {
				Socket client = sock_server.accept();
				
				ObjectInputStream obIn_client = new ObjectInputStream(client.getInputStream());
				
				cipher1 = obIn_client.readInt();
				cipher2 = obIn_client.readInt();
				count++;
				System.out.println("I have read ciphers from " + count + " user(s).");
				sum1 += (cipher1 - masterKey);
				sum2 += (cipher2 - masterKey);
				client.close();
			}
			sum1 = sum1 % M1;
			sum2 = sum2 % M2;
			System.out.println("The sum of user's data set one: " + sum1);
			System.out.println("The sum of user's data set two: " + sum2);
			sock_server.close();
		}
		catch (Exception dtv) {
			dtv.printStackTrace();
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