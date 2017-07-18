/* 
 * 
 * Licensed under the EUPL, Version 1.1 or - as soon they will be approved by
 * the European Commission - subsequent versions of the EUPL (the "Licence");
 * You may not use this work except in compliance with the Licence.
 * You may obtain a copy of the Licence at:
 * 
 * http://ec.europa.eu/idabc/eupl
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the Licence is distributed on an "AS IS" basis,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Licence for the specific language governing permissions and
 * limitations under the Licence.
 * 
 * Date: 09 Feb 2016
 * Authors: Governikus GmbH & Co. KG
 * 
*/
package eidassaml.starterkit;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;

import javax.crypto.SecretKey;

import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.saml2.encryption.Encrypter.KeyPlacement;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;


public class EidasEncrypter {

	/**
	 * Completely configured encryption handler, null if encryption is not set.
	 */
	public Encrypter encrypter;

	/**
	 * Encryption parameters used to set up the {@link #encrypter}, null if
	 * encryption is not set.
	 */
	private DataEncryptionParameters encParams;

	/**
	 * key encryption parameters used to set up the {@link #encrypter}, null if
	 * encryption is not set. Note that the encrypter will ignore these values
	 * given to it in the constructor when it encrypts an XMLObject. In that
	 * case, you have to give these values again to the encrypt method.
	 */
	private KeyEncryptionParameters kek;

	/**
	 * Create a XMLCipher Object. 
	 * The KeyEncryptionParameters algorithm will be http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p
	 * 
	 * @param includeCert if true the certificate will be a part of the xml
	 * @param cert contains the public key for encryption
	 * @param cipherAlgo e.g http://www.w3.org/2009/xmlenc11#aes256-gcm
	 * @throws NoSuchAlgorithmException
	 * @throws KeyException
	 */
	public EidasEncrypter(boolean includeCert, X509Certificate cert, String cipherAlgo)
			throws NoSuchAlgorithmException, KeyException {
		Credential receiverCredential = new BasicX509Credential(cert);
		SecretKey secretKey = SecurityHelper.generateSymmetricKey(cipherAlgo);
		Credential symmetricCredential = new BasicCredential(secretKey);

		encParams = new DataEncryptionParameters();
		encParams.setAlgorithm(cipherAlgo);
		encParams.setEncryptionCredential(symmetricCredential);

		kek = new KeyEncryptionParameters();
		kek.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
		kek.setEncryptionCredential(receiverCredential);
		
		if (includeCert) {
			X509KeyInfoGeneratorFactory bkigf = new X509KeyInfoGeneratorFactory();
			bkigf.setEmitEntityCertificate(true);
			bkigf.setEmitSubjectDNAsKeyName(true);
			KeyInfoGenerator kig = bkigf.newInstance();
			kek.setKeyInfoGenerator(kig);
			encParams.setKeyInfoGenerator(kig);
		}
		encrypter = new Encrypter(encParams, kek);
		encrypter.setKeyPlacement(KeyPlacement.INLINE);
	}
	
	/**
	 * Cipher-Algorithm is set to http://www.w3.org/2009/xmlenc11#aes256-gcm
	 * 
	 * @param includeCert
	 * @param cert
	 * @throws NoSuchAlgorithmException
	 * @throws KeyException
	 */
	public EidasEncrypter(boolean includeCert, X509Certificate cert)
			throws NoSuchAlgorithmException, KeyException {
		this(includeCert,cert,EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256_GCM);
	}

}
