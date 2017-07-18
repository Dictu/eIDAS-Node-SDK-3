package eidassaml.test;

import java.io.IOException;
import java.security.KeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Assert;
import org.junit.Test;
import org.opensaml.core.xml.config.XMLConfigurationException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.xmlsec.encryption.support.EncryptionException;

import eidassaml.starterkit.EidasEncrypter;
import eidassaml.starterkit.EidasSaml;
import eidassaml.starterkit.Utils;


public class EncryptedAssertionTest {

	@Test
	public void test() throws CertificateException, IOException, NoSuchAlgorithmException, KeyException, EncryptionException, XMLConfigurationException {
		EidasSaml.Init();
		Assertion a = new AssertionBuilder().buildObject();

		X509Certificate[] cert = {Utils
				.readX509Certificate(TestEidasSaml.class.getResourceAsStream("/EidasSignerTest_x509.cer"))};
		EidasEncrypter _encrypter = new EidasEncrypter(true, cert[0]);
		EncryptedAssertion ea = _encrypter.encrypter.encrypt(a);
		Assert.assertNotNull(ea.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0).getKeyInfo());
		
	}
	
}
