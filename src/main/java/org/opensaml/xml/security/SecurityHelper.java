/*** Eclipse Class Decompiler plugin, copyright (c) 2016 Chen Chao (cnfree2000@hotmail.com) ***/
package org.opensaml.xml.security;

import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.xml.security.Init;
import org.apache.xml.security.algorithms.JCEMapper;
import org.opensaml.security.credential.Credential;

import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.opensaml.security.SecurityException;

/**
 * Partially copied from xmltooling 1.4.4
 * @author Sander IJpma
 *
 */
public final class SecurityHelper {
	private static Set<String> rsaAlgorithmURIs;
	private static Set<String> dsaAlgorithmURIs;
	private static Set<String> ecdsaAlgorithmURIs;

	public static String getAlgorithmIDFromURI(String algorithmURI) {
		return JCEMapper.translateURItoJCEID(algorithmURI).trim();
	}

	public static boolean isHMAC(String signatureAlgorithm) {
		String algoClass = JCEMapper.getAlgorithmClassFromURI(signatureAlgorithm).trim();
		return "Mac".equals(algoClass);
	}

	public static String getKeyAlgorithmFromURI(String algorithmURI) {
		String apacheValue = JCEMapper.getJCEKeyAlgorithmFromURI(algorithmURI).trim();
		if (apacheValue != null) {
			return apacheValue;
		}

		if (isHMAC(algorithmURI)) {
			return null;
		}

		if (rsaAlgorithmURIs.contains(algorithmURI)) {
			return "RSA";
		}
		if (dsaAlgorithmURIs.contains(algorithmURI)) {
			return "DSA";
		}
		if (ecdsaAlgorithmURIs.contains(algorithmURI)) {
			return "EC";
		}

		return null;
	}

	public static Integer getKeyLengthFromURI(String algorithmURI) {
		Logger log = getLogger();
		String algoClass = JCEMapper.getAlgorithmClassFromURI(algorithmURI).trim();

		if (("BlockEncryption".equals(algoClass)) || ("SymmetricKeyWrap".equals(algoClass)))
			;
		try {
			int keyLength = JCEMapper.getKeyLengthFromURI(algorithmURI);
			return Integer.valueOf(keyLength);
		} catch (NumberFormatException e) {
			log.warn("XML Security config contained invalid key length value for algorithm URI: " + algorithmURI);

			log.info("Mapping from algorithm URI {} to key length not available", algorithmURI);
		}
		return null;
	}

	public static SecretKey generateSymmetricKey(String algoURI) throws NoSuchAlgorithmException, KeyException {
		Logger log = getLogger();
		String jceAlgorithmName = getKeyAlgorithmFromURI(algoURI);
		if (null == jceAlgorithmName || jceAlgorithmName.isEmpty()) {
			log.error("Mapping from algorithm URI '" + algoURI
					+ "' to key algorithm not available, key generation failed");

			throw new NoSuchAlgorithmException("Algorithm URI'" + algoURI + "' is invalid for key generation");
		}
		Integer keyLength = getKeyLengthFromURI(algoURI);
		if (keyLength == null) {
			log.error("Key length could not be determined from algorithm URI, can't generate key");
			throw new KeyException("Key length not determinable from algorithm URI, could not generate new key");
		}
		KeyGenerator keyGenerator = KeyGenerator.getInstance(jceAlgorithmName);
		keyGenerator.init(keyLength.intValue());
		return keyGenerator.generateKey();
	}
	
	public static void prepareSignatureParams(Signature signature, Credential signingCredential,
			BasicSignatureSigningConfiguration config, String keyInfoGenName) throws SecurityException {
		Logger log = getLogger();


		String signAlgo = signature.getSignatureAlgorithm();
		if (signAlgo == null) {
			signAlgo = config.getSignatureAlgorithms().get(0);
			signature.setSignatureAlgorithm(signAlgo);
		}

		if ((isHMAC(signAlgo)) && (signature.getHMACOutputLength() == null)) {
			signature.setHMACOutputLength(config.getSignatureHMACOutputLength());
		}

		if (signature.getCanonicalizationAlgorithm() == null) {
			signature.setCanonicalizationAlgorithm(config.getSignatureCanonicalizationAlgorithm());
		}

		if (signature.getKeyInfo() == null) {
			KeyInfoGenerator kiGenerator = getKeyInfoGenerator(signingCredential, config, keyInfoGenName);
			if (kiGenerator != null) {
				try {
					KeyInfo keyInfo = kiGenerator.generate(signingCredential);
					signature.setKeyInfo(keyInfo);
				} catch (SecurityException e) {
					log.error("Error generating KeyInfo from credential", e);
					throw e;
				}
			} else {
				log.info("No factory for named KeyInfoGenerator {} was found for credential type {}", keyInfoGenName,
						signingCredential.getCredentialType().getName());

				log.info("No KeyInfo will be generated for Signature");
			}
		}
	}
	
	public static KeyInfoGenerator getKeyInfoGenerator(Credential credential, BasicSignatureSigningConfiguration config,
			String keyInfoGenName) {
		NamedKeyInfoGeneratorManager kiMgr = config.getKeyInfoGeneratorManager();
		if (kiMgr != null) {
			KeyInfoGeneratorFactory kiFactory = null;
			if (null == keyInfoGenName || keyInfoGenName.isEmpty())
				kiFactory = kiMgr.getDefaultManager().getFactory(credential);
			else {
				kiFactory = kiMgr.getFactory(keyInfoGenName, credential);
			}
			if (kiFactory != null) {
				return kiFactory.newInstance();
			}
		}
		return null;
	}
	
	private static Logger getLogger() {
		return LoggerFactory.getLogger(SecurityHelper.class);
	}

	static {
		if (!(Init.isInitialized())) {
			Init.init();
		}

		dsaAlgorithmURIs = new HashSet<>();
		dsaAlgorithmURIs.add("http://www.w3.org/2000/09/xmldsig#dsa-sha1");

		ecdsaAlgorithmURIs = new HashSet<>();
		ecdsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
		ecdsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
		ecdsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384");
		ecdsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");

		rsaAlgorithmURIs = new HashSet<>(10);
		rsaAlgorithmURIs.add("http://www.w3.org/2000/09/xmldsig#rsa-sha1");
		rsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
		rsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
		rsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
		rsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
		rsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#rsa-ripemd160");
		rsaAlgorithmURIs.add("http://www.w3.org/2001/04/xmldsig-more#rsa-md5");
	}
}