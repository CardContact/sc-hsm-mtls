/**
 *  ---------
 * |.##> <##.|  Open Smart Card Development Platform (www.openscdp.org)
 * |#       #|
 * |#       #|  Copyright (c) 1999-2022 CardContact Systems GmbH
 * |'##> <##'|  32429 Minden, Germany (www.cardcontact.de)
 *  ---------
 *
 *  This file is part of OpenSCDP.
 *
 *  OpenSCDP is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  OpenSCDP is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with OpenSCDP; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */

package de.cardcontact.mtls;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import de.cardcontact.smartcardhsmprovider.SmartCardHSMProvider;

/**
 * Example showing how to connect with mTLS to a remote host with client authentication
 * using a certificate on the SmartCard-HSM.
 *
 * To test this, get a certificate to access the CardContact Developers Network as described in
 *
 *   https://www.smartcard-hsm.com/cdn.html#cdn
 *
 * This demo will connect to https://cdn.cardcontact.de, which requires client authentication using
 * a DevNet-CA certificate.
 *
 * This demo uses OCF, the sc-hsm-jceprovider and Bouncycastle. It is a pure Java implementation
 * without the need to install a PKCS#11 module.
 *
 * This demo assumes that the demo PIN 648219 is set on the SmartCard-HSM.
 */
public class MTLSClient implements CallbackHandler {


	/**
	 * Prepare JCE Provider bound to SmartCard-HSM.
	 *
	 */
	MTLSClient() {
		// make sure to add the BC provider first
		Security.addProvider(new BouncyCastleProvider());

		// Create a provider an log-in.
		SmartCardHSMProvider provider = new SmartCardHSMProvider();

		try {
			provider.login(null, this);
		} catch (LoginException e) {
			e.printStackTrace();
			System.exit(-1);
		}

		Security.insertProviderAt(provider, 0);
	}



	/**
	 * Provide the PIN to the provider.
	 *
	 */
	@Override
	public void handle(Callback[] callbacks) throws IOException,
	UnsupportedCallbackException {

		for (int i = 0; i < callbacks.length; i++) {
			if (callbacks[i] instanceof PasswordCallback) {

				PasswordCallback pc = (PasswordCallback)callbacks[i];
				pc.setPassword(new char[] {'6', '4', '8', '2', '1', '9'});
			}
		}
	}



	public void doConnect() throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableKeyException, KeyManagementException {
		// Initialize the key and trust material.
		KeyStore ksKeys = KeyStore.getInstance("SmartCardHSMKeyStore", "SmartCardHSM");
		ksKeys.load(null, null);

// Enable your own truststore if the server SSL certificate is not from a public SSL CA
//		KeyStore ksTrust = KeyStore.getInstance("JKS");
//		InputStream in = new FileInputStream("lib/truststore.jks");
//		ksTrust.load(in, "openscdp".toCharArray());

		// KeyManager will decide which key material to use.
		KeyManagerFactory kmf =
			KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

		kmf.init(ksKeys, null);

		// TrustManager will decide whether to trust the host.
//		TrustManagerFactory tmf =
//		    TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
//		tmf.init(ksTrust);

		SecureRandom rng = SecureRandom.getInstance("NativePRNG", "SmartCardHSM");

		SSLContext sslContext = SSLContext.getInstance("TLSv1.2");
		sslContext.init(kmf.getKeyManagers(), null, rng);

		// Try with a certificate from the DevNet-CA
		URL url = new URL("https://cdn.cardcontact.de");
		URLConnection c = url.openConnection();
		HttpsURLConnection sslc = (HttpsURLConnection)c;
		sslc.setSSLSocketFactory(sslContext.getSocketFactory());

		// read the data from the socket
		InputStream is = sslc.getInputStream();
		StringBuffer str = new StringBuffer();

		BufferedReader reader = new BufferedReader(new InputStreamReader(is));
		String line;

		while ((line = reader.readLine()) != null) {
			str.append(line);
			str.append('\n');
		}

		is.close();
		System.out.println(str.toString());
	}



	public static void main(String[] args) {
		MTLSClient client = new MTLSClient();
		try	{
			client.doConnect();
		}
		catch(Exception e) {
			e.printStackTrace();
		}
	}
}
