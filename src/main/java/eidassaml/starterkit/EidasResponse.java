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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedList;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xml.security.Pkcs11Decrypter;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eidassaml.starterkit.person_attributes.AbstractNonLatinScriptAttribute;
import eidassaml.starterkit.person_attributes.EidasPersonAttributes;
import eidassaml.starterkit.template.TemplateLoader;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

/**
 * 
 * @author hohnholt
 *
 */
public class EidasResponse {

	static final long ONE_MINUTE_IN_MILLIS=60000;//millisecs
	public final static SimpleDateFormat SimpleDf = Constants.SimpleSamlDf;
	
	private String id;
	private String destination;
	private String recipient;
	private String issuer;
	private String inResponseTo;
	private String issueInstant;
	
	private EidasLoA loa;
	
	private EidasEncrypter encrypter;
	private EidasSigner signer;
	private ArrayList<EidasAttribute> attributes;
	private EidasNameId nameId = null;
	//private EidasNameIdType nameIdPolicy = EidasNameIdType.Transient;
	
	private Response openSamlResp = null;
	
	private EidasResponse(){
		attributes = new ArrayList<EidasAttribute>();
	}
	
	public EidasResponse(String _destination, String _recipient, EidasNameId _nameid, 
			String _inResponseTo, 
			String _issuer, 
			EidasLoA _loa,
			EidasSigner _signer,
			EidasEncrypter _encrypter){
		id = "_" + Utils.GenerateUniqueID();
		nameId = _nameid;
		destination = _destination;
		recipient = _recipient;
		inResponseTo = _inResponseTo;
		issuer = _issuer;
		loa = _loa;
		issueInstant = SimpleDf.format(new Date());
		encrypter = _encrypter;
		signer = _signer;
		attributes = new ArrayList<EidasAttribute>();
	}
	
	public EidasResponse(ArrayList<EidasAttribute> att, String _destination, String _recipient, EidasNameId _nameid,
			String _inResponseTo, 
			String _issuer, 
			EidasLoA _loa,
			EidasSigner _signer,
			EidasEncrypter _encrypter){
		id = "_" + Utils.GenerateUniqueID();
		nameId = _nameid;
		destination = _destination;
		recipient = _recipient;
		inResponseTo = _inResponseTo;
		issuer = _issuer;
		loa = _loa;
		issueInstant = SimpleDf.format(new Date());
		encrypter = _encrypter;
		signer = _signer;
		attributes = att;
	}
	
	public byte[] generateErrorRsp(ErrorCode code, String... msg) throws IOException, XMLParserException, UnmarshallingException, CertificateEncodingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException
	{
		BasicParserPool ppMgr = Utils.getParserPool(true);
		
		byte[] returnValue;
		String notBefore = SimpleDf.format(new Date());
		String notAfter = SimpleDf.format(new Date(new Date().getTime() + (10 * ONE_MINUTE_IN_MILLIS)));
		
		String respTemp = TemplateLoader.GetTemplateByName("failresp");
		String assoTemp = TemplateLoader.GetTemplateByName("failasso");
		
		if(nameId == null)
		{
			throw new XMLParserException("Document does not contains a NameID value");
		}
		
		assoTemp =assoTemp.replace("$AssertionId", "_" + Utils.GenerateUniqueID());
		assoTemp =assoTemp.replace("$IssueInstant", issueInstant);
		assoTemp =assoTemp.replace("$Issuer", issuer);
		assoTemp = assoTemp.replace("$NameFormat", nameId.getType().NAME);
		assoTemp = assoTemp.replace("$NameID", nameId.getValue());
		assoTemp = assoTemp.replace("$InResponseTo", inResponseTo);
		assoTemp = assoTemp.replace("$NotOnOrAfter",notAfter);
		assoTemp = assoTemp.replace("$Recipient", recipient);
		assoTemp = assoTemp.replace("$NotBefore",notBefore);
		
		assoTemp = assoTemp.replace("$AuthnInstant", issueInstant);
		assoTemp = assoTemp.replace("$LoA",loa.NAME);
		
		respTemp = respTemp.replace("$InResponseTo", inResponseTo);
		respTemp =respTemp.replace("$IssueInstant", issueInstant);
		respTemp =respTemp.replace("$Issuer", issuer);
		respTemp =respTemp.replace("$Id",id);
		respTemp =respTemp.replace("$Destination",destination);
		respTemp =respTemp.replace("$Code",code.getSamlStatus());
		if(msg == null){
			respTemp =respTemp.replace("$ErrMsg",code.toDescription());
		}else{
			respTemp =respTemp.replace("$ErrMsg",code.toDescription(msg));
		}
		respTemp = respTemp.replace("$Assertion", assoTemp);
		
		List<Signature> sigs = new ArrayList<Signature>();
		
		try( InputStream is = new ByteArrayInputStream(respTemp.getBytes(Constants.UTF8_CHARSET))){
			Document inCommonMDDoc = ppMgr.parse(is);
			Element metadataRoot = inCommonMDDoc.getDocumentElement();		 
			// Get apropriate unmarshaller
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
			Response resp = (Response) unmarshaller.unmarshall(metadataRoot);
			
			XMLSignatureHandler.addSignature(resp, signer.getSigKey(), signer.getSigCert(), signer.getSigType(), signer.getSigDigestAlg());
			
			if (resp.getSignature() != null && signer != null)
		      {
		        sigs.add(resp.getSignature());
		      }
		      


		      Marshaller rm = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(resp.getElementQName());
		      Element all = rm.marshall(resp);
		      if (resp.getSignature() != null && signer != null)
		      {
		        sigs.add(resp.getSignature());
		      }
		      if(signer != null)
		    	  Signer.signObjects(sigs);

		      openSamlResp = resp;
		      Transformer trans = TransformerFactory.newInstance().newTransformer();
		      trans.setOutputProperty(OutputKeys.ENCODING,"UTF-8");
		      // Please note: you cannot format the output without breaking signature!		      
		      try(ByteArrayOutputStream bout = new ByteArrayOutputStream()){
		    	  trans.transform(new DOMSource(all), new StreamResult(bout));
		    	  returnValue = bout.toByteArray();
		      }
			
		}
		
		return returnValue;
		
	}
		
	public byte[] generate() throws XMLParserException, IOException, UnmarshallingException, CertificateEncodingException, EncryptionException, MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException{
		
		BasicParserPool ppMgr = Utils.getParserPool(true);
		
		byte[] returnValue;
		
		String notBefore = SimpleDf.format(new Date());
		String notAfter = SimpleDf.format(new Date(new Date().getTime() + (10 * ONE_MINUTE_IN_MILLIS)));
		String respTemp = TemplateLoader.GetTemplateByName("resp");
		String assoTemp = TemplateLoader.GetTemplateByName("asso");
		StringBuilder attributeString = new StringBuilder();

		if(nameId == null)
		{
			throw new XMLParserException("Document does not contains a NameID value");
		}
		
		for(EidasAttribute eidasAtt : this.attributes)
		{
			attributeString.append(eidasAtt.generate());
		}
		
		assoTemp = assoTemp.replace("$NameFormat", nameId.getType().NAME);
		assoTemp = assoTemp.replace("$NameID", nameId.getValue());
		assoTemp = assoTemp.replace("$AssertionId", "_" + Utils.GenerateUniqueID());
		assoTemp = assoTemp.replace("$Recipient", recipient);
		assoTemp = assoTemp.replace("$AuthnInstant", issueInstant);
		assoTemp = assoTemp.replace("$LoA",loa.NAME);
		assoTemp = assoTemp.replace("$SessionIndex","_" + Utils.GenerateUniqueID());
		assoTemp = assoTemp.replace("$attributes",attributeString.toString());
		assoTemp = assoTemp.replace("$NotBefore",notBefore);
		assoTemp = assoTemp.replace("$NotOnOrAfter",notAfter);
		
		assoTemp = assoTemp.replace("$InResponseTo", inResponseTo);
		assoTemp =assoTemp.replace("$IssueInstant", issueInstant);
		assoTemp =assoTemp.replace("$Issuer", issuer);
		assoTemp =assoTemp.replace("$Id",id);
		assoTemp =assoTemp.replace("$Destination",destination);
		
		
		String generatedAssertionXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>"+assoTemp;
		Assertion ass = null;
		try( InputStream is = new ByteArrayInputStream(generatedAssertionXML.getBytes(Constants.UTF8_CHARSET))){
			//EidasSaml.ValidateXMLRequest(is, true);
			Document inCommonMDDoc = ppMgr.parse(is);
			Element metadataRoot = inCommonMDDoc.getDocumentElement();		 
			// Get apropriate unmarshaller
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
			ass= (Assertion)unmarshaller.unmarshall(metadataRoot);
		} 
		
		Assertion[] assertions = new Assertion[]{ass};
		
		
		//respTemp = respTemp.replace("$asso",assoTemp);
		respTemp = respTemp.replace("$InResponseTo", inResponseTo);
		respTemp =respTemp.replace("$IssueInstant", issueInstant);
		respTemp =respTemp.replace("$Issuer", issuer);
		respTemp =respTemp.replace("$Id",id);
		respTemp =respTemp.replace("$Destination",destination);
		
		List<Signature> sigs = new ArrayList<Signature>();
		
		
		try( InputStream is = new ByteArrayInputStream(respTemp.getBytes(Constants.UTF8_CHARSET))){
			Document inCommonMDDoc = ppMgr.parse(is);
			Element metadataRoot = inCommonMDDoc.getDocumentElement();		 
			// Get apropriate unmarshaller
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
			Response resp = (Response) unmarshaller.unmarshall(metadataRoot);
						
			XMLSignatureHandler.addSignature(resp, signer.getSigKey(), signer.getSigCert(), signer.getSigType(), signer.getSigDigestAlg());
			for ( Assertion a : assertions)
			{
				a.setParent(null);
		        resp.getEncryptedAssertions().add(this.encrypter.encrypter.encrypt(a));
		        
			}
			
		      if (resp.getSignature() != null && signer != null)
		      {
		        sigs.add(resp.getSignature());
		      }
		      


		      Marshaller rm = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(resp.getElementQName());
		      Element all = rm.marshall(resp);
		      if (resp.getSignature() != null && signer != null)
		      {
		        sigs.add(resp.getSignature());
		      }
		      if(signer != null)
		    	  Signer.signObjects(sigs);

		      openSamlResp = resp;
		      Transformer trans = TransformerFactory.newInstance().newTransformer();
		      trans.setOutputProperty(OutputKeys.ENCODING,"UTF-8");
		      // Please note: you cannot format the output without breaking signature!		      
		      try(ByteArrayOutputStream bout = new ByteArrayOutputStream()){
		    	  trans.transform(new DOMSource(all), new StreamResult(bout));
		    	  returnValue = bout.toByteArray();
		      }
		}
		return returnValue;
	}
	

	public String getId() {
		return id;
	}
	
	public String getRecipient() {
		return recipient;
	}

	public String getDestination() {
		return destination;
	}

	public String getIssuer() {
		return issuer;
	}

	public String getInResponseTo() {
		return inResponseTo;
	}

	public String getIssueInstant() {
		return issueInstant;
	}
	
	public void addAttribute(EidasAttribute e)
	{
		attributes.add(e);
	}

	public ArrayList<EidasAttribute> getAttributes() {
		return attributes;
	}

	public EidasNameId getNameId() {
		return nameId;
	}
	
	public void setNameId(EidasNameId _nameid) {
		nameId = _nameid;
	}
	
	
	public Response getOpenSamlResponse() {
		return openSamlResp;
	}

	public static EidasResponse Parse(InputStream is, Pkcs11Decrypter decrypter, X509Certificate[] signatureAuthors) throws XMLParserException, UnmarshallingException, ErrorCodeException
	{
		EidasResponse eidasResp = new EidasResponse();
		
		List<X509Certificate> trustedAnchorList = new LinkedList<X509Certificate>();
		
		if (null == decrypter) {
			throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED, "No decrypter to decrypt with.");
		}
		
		if (signatureAuthors == null)
	    {
			throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
	    }
		if (signatureAuthors.length == 0)
	    {
			throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
	    }
		for(X509Certificate author : signatureAuthors)
		{
			trustedAnchorList.add(author);
		}
		
	    
		BasicParserPool ppMgr = Utils.getParserPool(true);
		Document inCommonMDDoc = ppMgr.parse(is);
		Element metadataRoot = inCommonMDDoc.getDocumentElement();		 
		// Get apropriate unmarshaller
		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
		Response resp = (Response)unmarshaller.unmarshall(metadataRoot);
		eidasResp.openSamlResp = resp;
		if(!StatusCode.SUCCESS.equals(resp.getStatus().getStatusCode().getValue()))
		{
			ErrorCode code = ErrorCode.GetValueOf(resp.getStatus().getStatusCode().getValue());
			if(code == null)
			{
				code = ErrorCode.INTERNAL_ERROR;
				throw new ErrorCodeException(code, "Unkown statuscode " + resp.getStatus().getStatusCode().getValue());
			}
			//Error respose, so un-encrypted asserion!
			for (Assertion assertion : resp.getAssertions()) {
				if(eidasResp.nameId == null)
		        {
		        	EidasNameIdType type = EidasNameIdType.GetValueOf(assertion.getSubject().getNameID().getFormat());
		        	if(type == EidasNameIdType.Persistent)
		        	{
		        		eidasResp.nameId = new EidasPersistentNameId(assertion.getSubject().getNameID().getValue());
		        	}else if(type == EidasNameIdType.Transient){
		        		eidasResp.nameId = new EidasTransientNameId(assertion.getSubject().getNameID().getValue());
		        	}else{
		        		eidasResp.nameId = new EidasUnspecifiedNameId(assertion.getSubject().getNameID().getValue());
		        	}
		        }
			}
		}
		else {
			CheckSignature(resp.getSignature(),trustedAnchorList);
			
			List<EncryptedAssertion> decryptedAssertions = new ArrayList<EncryptedAssertion>();
			List<Assertion> assertions = new ArrayList<Assertion>();
			
			
			
			for (EncryptedAssertion noitressa : resp.getEncryptedAssertions()) {
	
				try {
					assertions.add(decrypter.decrypt(noitressa, Assertion.class));
					decryptedAssertions.add(noitressa);
				} catch (DecryptionException e) {
					throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT,e);
				}
			}
			
			for ( Assertion assertion : assertions )
		    {
				if (null != assertion.getSignature()) { //signature in assertion may be null
					CheckSignature(assertion.getSignature(),trustedAnchorList);
				}
		        if(eidasResp.nameId == null)
		        {
		        	EidasNameIdType type = EidasNameIdType.GetValueOf(assertion.getSubject().getNameID().getFormat());
		        	if(type == EidasNameIdType.Persistent)
		        	{
		        		eidasResp.nameId = new EidasPersistentNameId(assertion.getSubject().getNameID().getValue());
		        	}else if(type == EidasNameIdType.Transient){
		        		eidasResp.nameId = new EidasTransientNameId(assertion.getSubject().getNameID().getValue());
		        	}else{
		        		eidasResp.nameId = new EidasUnspecifiedNameId(assertion.getSubject().getNameID().getValue());
		        	}
		        }
	
				for (AttributeStatement attStat : assertion.getAttributeStatements()) {
	
					for (Attribute att : attStat.getAttributes()) {
						if (att.getAttributeValues().size() < 1) {
							continue;
						}
						XMLObject attributeValue = att.getAttributeValues().stream().findFirst().get();
						Element domElement = attributeValue.getDOM();
						EidasPersonAttributes personAttributes;
	                    /* Get Person Attribute from the DOM */
						try {
							personAttributes = EidasNaturalPersonAttributes.GetValueOf(att.getName());
						}
						catch (ErrorCodeException e1) {
							try {
								personAttributes = EidasLegalPersonAttributes.GetValueOf(att.getName());
							}
							catch (ErrorCodeException e2) {
								throw new IllegalArgumentException("No attribute known with name: " + att.getName());
							}
							
						}
	
						EidasAttribute eidasAttribute = personAttributes.getInstance();
						if (eidasAttribute instanceof AbstractNonLatinScriptAttribute) {
							AbstractNonLatinScriptAttribute abstractAttribute = (AbstractNonLatinScriptAttribute) eidasAttribute;
							abstractAttribute.setLatinScript(att.getAttributeValues().stream().findFirst().get().getDOM().getTextContent());
							if (att.getAttributeValues().size() == 2) {						
								abstractAttribute.setNonLatinScript(att.getAttributeValues().get(1).getDOM().getTextContent()); //TODO: .stream().findSecond().get()??
							}
						}
						else {
							eidasAttribute.setLatinScript(domElement.getTextContent());
						}
						eidasResp.attributes.add(eidasAttribute);
	
					}
	
				}
	
		    }
			
			resp.getAssertions().clear();
			resp.getAssertions().addAll(assertions);
		}
		
		eidasResp.id = resp.getID();
		eidasResp.destination = resp.getDestination();
		eidasResp.inResponseTo = resp.getInResponseTo();
		eidasResp.issueInstant = SimpleDf.format(resp.getIssueInstant().toDate());
		eidasResp.issuer = resp.getIssuer().getDOM().getTextContent();
		eidasResp.recipient = getAudience(resp);
		eidasResp.openSamlResp = resp;
		
		
		return eidasResp;
	}
	public static EidasResponse Parse(InputStream is, Utils.X509KeyPair[] decryptionKeyPairs, X509Certificate[] signatureAuthors) throws XMLParserException, UnmarshallingException, ErrorCodeException
	{
		List<Credential> decryptionCredentialList = new LinkedList<Credential>();
		if (decryptionKeyPairs == null)
	    {
			throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT);
	    }
		if (decryptionKeyPairs.length == 0)
	    {
			throw new ErrorCodeException(ErrorCode.CANNOT_DECRYPT);
	    }
		for(Utils.X509KeyPair pair : decryptionKeyPairs)
		{
			decryptionCredentialList.add(new BasicCredential(pair.getCert().getPublicKey(), pair.getKey()));
		}
		
		StaticKeyInfoCredentialResolver resolver = new StaticKeyInfoCredentialResolver(
				decryptionCredentialList);

		Pkcs11Decrypter decr = new Pkcs11Decrypter(null, resolver,
				new InlineEncryptedKeyResolver());
		decr.setUseDefaultDecrypter(true);
		decr.setRootInNewDocument(true);
		return Parse(is, decr, signatureAuthors);
	}
	
	private static String getAudience(Response resp) throws ErrorCodeException {
		return resp.getAssertions()
			.stream()
			.findFirst()
			.orElseThrow(() -> new ErrorCodeException(ErrorCode.ERROR, "Missing Assertion in response."))
			.getConditions()
			.getAudienceRestrictions()
			.stream()
			.findFirst()
			.orElseThrow(() -> new ErrorCodeException(ErrorCode.ERROR, "Missing AudienceRestrictions in response."))
			.getAudiences()
			.stream()
			.findFirst()
			.orElseThrow(() -> new ErrorCodeException(ErrorCode.ERROR, "Missing Audiences in response."))
			.getAudienceURI();
	}
	
	private static void CheckSignature(Signature sig, List<X509Certificate> trustedAnchorList) throws ErrorCodeException
	{
		if(sig == null)
			throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
		
		
		
	    XMLSignatureHandler.checkSignature(sig,
	                                       trustedAnchorList.toArray(new X509Certificate[trustedAnchorList.size()]));
	 }
	
}
