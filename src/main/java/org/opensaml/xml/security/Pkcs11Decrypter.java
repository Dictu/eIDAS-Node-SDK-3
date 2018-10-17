package org.opensaml.xml.security;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.EncryptionMethod;
import org.apache.xml.security.encryption.XMLCipher;
import org.apache.xml.security.encryption.XMLCipherInput;
import org.apache.xml.security.encryption.XMLEncryptionException;
import org.apache.xml.security.utils.EncryptionConstants;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.EncryptedElementType;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.DecryptionParameters;
import org.opensaml.xmlsec.algorithm.AlgorithmSupport;
import org.opensaml.xmlsec.encryption.EncryptedKey;
import org.opensaml.xmlsec.encryption.support.Decrypter;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Element;

import com.google.common.base.Strings;

import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import net.shibboleth.utilities.java.support.resolver.ResolverException;

/**
* Copy from https://github.com/litsec/opensaml-ext/blob/master/opensaml3/src/main/java/se/litsec/opensaml/xmlsec/ExtendedDecrypter.java
* and modified to suit PKCS11 in general (and not just SunPKCS11).
* 
*  
*/
public class Pkcs11Decrypter extends Decrypter {

	 /** Class logger. */
	 private final Logger LOGGER = LoggerFactory.getLogger(Pkcs11Decrypter.class);
	 
	 /** Key length of decryption keys. */
	 private int keyLength = -1;
	 
	 private boolean useDefaultDecrypter;
	 
	 /** Resolver for key encryption keys. */
	 private KeyInfoCredentialResolver _kekResolver;

	 /**
	 * @return the useDefaultDecrypter
	 */
	public boolean useDefaultDecrypter() {
		return useDefaultDecrypter;
	}

	/**
	 * @param useDefaultDecrypter the useDefaultDecrypter to set
	 */
	public void setUseDefaultDecrypter(boolean useDefaultDecrypter) {
		this.useDefaultDecrypter = useDefaultDecrypter;
	}

	/**
	  * Constructor.
	  * 
	  * @param params
	  *          decryption parameters to use
	  */
	 public Pkcs11Decrypter(DecryptionParameters params) {
	   super(params);
	   this._kekResolver = params.getKEKKeyInfoCredentialResolver();
	 }

	 /**
	  * Constructor.
	  * 
	  * @param newResolver
	  *          resolver for data encryption keys.
	  * @param newKEKResolver
	  *          resolver for key encryption keys.
	  * @param newEncKeyResolver
	  *          resolver for EncryptedKey elements
	  */
	 public Pkcs11Decrypter(KeyInfoCredentialResolver newResolver, KeyInfoCredentialResolver newKEKResolver,
	     EncryptedKeyResolver newEncKeyResolver) {
	   super(newResolver, newKEKResolver, newEncKeyResolver);
	   this._kekResolver = newKEKResolver;
	 }

	 /**
	  * Constructor.
	  * 
	  * @param newResolver
	  *          resolver for data encryption keys.
	  * @param newKEKResolver
	  *          resolver for key encryption keys.
	  * @param newEncKeyResolver
	  *          resolver for EncryptedKey elements
	  * @param whitelistAlgos
	  *          collection of whitelisted algorithm URIs
	  * @param blacklistAlgos
	  *          collection of blacklisted algorithm URIs
	  */
	 public Pkcs11Decrypter(KeyInfoCredentialResolver newResolver, KeyInfoCredentialResolver newKEKResolver,
	     EncryptedKeyResolver newEncKeyResolver, Collection<String> whitelistAlgos, Collection<String> blacklistAlgos) {
	   super(newResolver, newKEKResolver, newEncKeyResolver, whitelistAlgos, blacklistAlgos);
	   this._kekResolver = newKEKResolver;
	 }
	 
	 /**
	  * Init method for setting key size ...
	  */
	 public void init() {
	   if (this._kekResolver != null) {
	     CriteriaSet cs = new CriteriaSet();
	     try {
	       Credential cred = this._kekResolver.resolveSingle(cs);
	       if (cred != null) {
	         PublicKey pubKey = cred.getPublicKey();
	         if (pubKey != null) {
	           this.keyLength = getKeyLength(pubKey);
	         }
	       }
	     }
	     catch (ResolverException e) {        
	     }
	     if (this.keyLength <= 0) {
	       LOGGER.error("Failed to resolve any certificates for key decryption");
	     }
	   }
	 }
	 
	 /**
	  * Decrypts the supplied encrypted object into an object of the given type.
	  * 
	  * @param encryptedObject
	  *          the encrypted object
	  * @param destinationClass
	  *          the class of the destination object
	  * @param <T>
	  *          the type of the destination object
	  * @param <E>
	  *          the type of the encrypted object
	  * @return the decrypted element of object T
	  * @throws DecryptionException
	  *           for decryption errors
	  */
	 public <T extends XMLObject, E extends EncryptedElementType> T decrypt(E encryptedObject, Class<T> destinationClass)
	     throws DecryptionException {

	   if (encryptedObject.getEncryptedData() == null) {
	     throw new DecryptionException("Object contains no encrypted data");
	   }

	   XMLObject object = this.decryptData(encryptedObject.getEncryptedData());
	   if (!destinationClass.isInstance(object)) {
	     throw new DecryptionException(String.format("Decrypted object can not be cast to %s - is %s",
	       destinationClass.getSimpleName(), object.getClass().getSimpleName()));
	   }
	   return destinationClass.cast(object);
	 }

	 /**
	  * Overrides the {@link Decrypter#decryptKey(EncryptedKey, String, Key)} so that we may handle the unsupported
	  * features of the PKCS11 provider.
	  */
	 @Override
	 public Key decryptKey(EncryptedKey encryptedKey, String algorithm, Key kek) throws DecryptionException {

	   if (this.useDefaultDecrypter) {
		   return super.decryptKey(encryptedKey, algorithm, kek);
	   }
	   if (!AlgorithmSupport.isRSAOAEP(encryptedKey.getEncryptionMethod().getAlgorithm())) {
	     return super.decryptKey(encryptedKey, algorithm, kek);
	   }

	   if (Strings.isNullOrEmpty(algorithm)) {
	     LOGGER.error("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
	     throw new DecryptionException("Algorithm of encrypted key not supplied, key decryption cannot proceed.");
	   }
	   this.validateAlgorithms(encryptedKey);

	   try {
	     this.checkAndMarshall(encryptedKey);
	   }
	   catch (DecryptionException e) {
	     LOGGER.error("Error marshalling EncryptedKey for decryption", e);
	     throw e;
	   }
	   this.preProcessEncryptedKey(encryptedKey, algorithm, kek);

	   XMLCipher xmlCipher;
	   try {
	     if (getJCAProviderName() != null) {
	       xmlCipher = XMLCipher.getProviderInstance(getJCAProviderName());
	     }
	     else {
	       xmlCipher = XMLCipher.getInstance();
	     }
	     xmlCipher.init(XMLCipher.UNWRAP_MODE, kek);
	   }
	   catch (XMLEncryptionException e) {
	     LOGGER.error("Error initialzing cipher instance on key decryption", e);
	     throw new DecryptionException("Error initialzing cipher instance on key decryption", e);
	   }

	   org.apache.xml.security.encryption.EncryptedKey encKey;
	   try {
	     Element targetElement = encryptedKey.getDOM();
	     encKey = xmlCipher.loadEncryptedKey(targetElement.getOwnerDocument(), targetElement);
	   }
	   catch (XMLEncryptionException e) {
	     LOGGER.error("Error when loading library native encrypted key representation", e);
	     throw new DecryptionException("Error when loading library native encrypted key representation", e);
	   }

	   try {
	     Key key = this.customizedDecryptKey(encKey, algorithm, kek);
	     if (key == null) {
	       throw new DecryptionException("Key could not be decrypted");
	     }
	     return key;
	   }
	   catch (XMLEncryptionException e) {
	     LOGGER.error("Error decrypting encrypted key", e);
	     throw new DecryptionException("Error decrypting encrypted key", e);
	   }
	   catch (Exception e) {
	     throw new DecryptionException("Probable runtime exception on decryption:" + e.getMessage(), e);
	   }
	 }

	 /**
	  * Performs the actual key decryption.
	  * 
	  * @param encryptedKey
	  *          the encrypted key
	  * @param algorithm
	  *          the algorithm
	  * @param kek
	  *          the private key
	  * @return a secret key
	  * @throws XMLEncryptionException
	  *           for errors
	  */
	 private Key customizedDecryptKey(org.apache.xml.security.encryption.EncryptedKey encryptedKey, String algorithm, Key kek)
	     throws XMLEncryptionException {

	   // Obtain the encrypted octets
	   byte[] encryptedBytes = (new XMLCipherInput(encryptedKey)).getBytes();

	   try {
	     String provider = this.getJCAProviderName();
	     Cipher c = provider != null ? Cipher.getInstance("RSA/ECB/NoPadding", provider) : Cipher.getInstance("RSA/ECB/NoPadding");

	     c.init(Cipher.DECRYPT_MODE, kek);
	     byte[] paddedPlainText = c.doFinal(encryptedBytes);

	     //int keyLength = this.getKeySize(kek);

	     /* Ensure leading zeros not stripped */
	     if (paddedPlainText.length < this.keyLength / 8) {
	       byte[] tmp = new byte[this.keyLength / 8];
	       System.arraycopy(paddedPlainText, 0, tmp, tmp.length - paddedPlainText.length, paddedPlainText.length);
	       paddedPlainText = tmp;
	     }

	     EncryptionMethod encMethod = encryptedKey.getEncryptionMethod();
	     OAEPParameterSpec oaepParameters = constructOAEPParameters(encMethod.getAlgorithm(), encMethod.getDigestAlgorithm(),
	       encMethod.getMGFAlgorithm(), encMethod.getOAEPparams());

	     byte[] secretKeyBytes = getSecretKeyBytes(paddedPlainText, oaepParameters, this.keyLength);

	     String jceKeyAlgorithm = JCEMapper.getJCEKeyAlgorithmFromURI(algorithm);

	     return new SecretKeySpec(secretKeyBytes, jceKeyAlgorithm);
	   }
	   catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException | InvalidKeyException | IllegalBlockSizeException
	       | BadPaddingException | InvalidAlgorithmParameterException e) {
	     throw new XMLEncryptionException(e);
	   }
	 }

	public static byte[] getSecretKeyBytes(byte[] paddedPlainText, OAEPParameterSpec oaepParameters, int keyLength) throws BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		sun.security.rsa.RSAPadding padding = sun.security.rsa.RSAPadding.getInstance(4, keyLength / 8, new SecureRandom(), oaepParameters);
		return padding.unpad(paddedPlainText);
		
	}
	 /**
	  * Construct an OAEPParameterSpec object from the given parameters
	  */
	 private OAEPParameterSpec constructOAEPParameters(
	     String encryptionAlgorithm, String digestAlgorithm, String mgfAlgorithm, byte[] oaepParams) {

	   String jceDigestAlgorithm = "SHA-1";
	   if (digestAlgorithm != null) {
	     jceDigestAlgorithm = JCEMapper.translateURItoJCEID(digestAlgorithm);
	   }

	   PSource.PSpecified pSource = PSource.PSpecified.DEFAULT;
	   if (oaepParams != null) {
	     pSource = new PSource.PSpecified(oaepParams);
	   }

	   MGF1ParameterSpec mgfParameterSpec = new MGF1ParameterSpec("SHA-1");
	   if (XMLCipher.RSA_OAEP_11.equals(encryptionAlgorithm)) {
	     if (EncryptionConstants.MGF1_SHA256.equals(mgfAlgorithm)) {
	       mgfParameterSpec = new MGF1ParameterSpec("SHA-256");
	     }
	     else if (EncryptionConstants.MGF1_SHA384.equals(mgfAlgorithm)) {
	       mgfParameterSpec = new MGF1ParameterSpec("SHA-384");
	     }
	     else if (EncryptionConstants.MGF1_SHA512.equals(mgfAlgorithm)) {
	       mgfParameterSpec = new MGF1ParameterSpec("SHA-512");
	     }
	   }
	   return new OAEPParameterSpec(jceDigestAlgorithm, "MGF1", mgfParameterSpec, pSource);
	 }

	 private static int getKeyLength(final PublicKey pk) {
	   int len = -1;
	   if (pk instanceof RSAPublicKey) {
	     final RSAPublicKey rsapub = (RSAPublicKey) pk;
	     len = rsapub.getModulus().bitLength();
	   }
	   else if (pk instanceof ECPublicKey) {
	     final ECPublicKey ecpriv = (ECPublicKey) pk;
	     final java.security.spec.ECParameterSpec spec = ecpriv.getParams();
	     if (spec != null) {
	       len = spec.getOrder().bitLength(); // does this really return something we expect?
	     }
	     else {
	       // We support the key, but we don't know the key length
	       len = 0;
	     }
	   }
	   else if (pk instanceof DSAPublicKey) {
	     final DSAPublicKey dsapub = (DSAPublicKey) pk;
	     if (dsapub.getParams() != null) {
	       len = dsapub.getParams().getP().bitLength();
	     }
	     else {
	       len = dsapub.getY().bitLength();
	     }
	   }
	   return len;
	 }

}
