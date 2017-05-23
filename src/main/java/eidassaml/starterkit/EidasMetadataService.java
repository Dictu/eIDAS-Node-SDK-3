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
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.codec.binary.Base64;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.metadata.ContactPerson;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor;
import org.opensaml.saml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml.saml2.metadata.Organization;
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorMarshaller;
import org.opensaml.security.credential.UsageType;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.X509Data;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import eidassaml.starterkit.person_attributes.EidasPersonAttributes;
import eidassaml.starterkit.template.TemplateLoader;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

/**
 * Use this class to build a service provider metadata.xml
 * 
 * @author hohnholt
 *
 */
public class EidasMetadataService {
		
	
	private final static String attributeTemplate = "<saml2:Attribute FriendlyName=\"$ATTFriendlyNAME\" Name=\"$ATTName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"></saml2:Attribute>";
	
	private String id;
	private String entityId;
	private Date validUntil;
	private EidasLoA highestSupportedLoA;
	private X509Certificate sigCert;
	private X509Certificate encCert;
	private EidasOrganisation organisation;
	private EidasContactPerson technicalcontact;
	private EidasContactPerson supportcontact;
	private String postEndpoint;
	private String redirectEndpoint;
	private List<EidasPersonAttributes> attributes = new ArrayList<>();
	private List<EidasNameIdType> supportedNameIdTypes = new ArrayList<EidasNameIdType>();
	
	private EidasMetadataService(){}
		
	public EidasMetadataService(String id, String entityId, Date validUntil, EidasLoA highestSupportedLoA,
			X509Certificate sigCert, X509Certificate encCert,
			EidasOrganisation organisation, EidasContactPerson technicalContact,EidasContactPerson supportContact,
			String postEndpoint, String redirectEndpoint, List<EidasNameIdType> supportedNameIdTypes) {
		super();
		this.id = id;
		this.entityId = entityId;
		this.validUntil = validUntil;
		this.highestSupportedLoA = highestSupportedLoA;
		this.sigCert = sigCert;
		this.encCert = encCert;
		this.organisation = organisation;
		this.technicalcontact = technicalContact;
		this.supportcontact = supportContact;
		this.postEndpoint = postEndpoint;
		this.redirectEndpoint = redirectEndpoint;
		this.supportedNameIdTypes = supportedNameIdTypes;
		
		if(this.supportedNameIdTypes == null)
		{
			this.supportedNameIdTypes = new ArrayList<EidasNameIdType>();
		}
		
		if(this.supportedNameIdTypes.size() < 1)
		{
			this.supportedNameIdTypes.add(EidasNameIdType.Unspecified);
		}
	}

	public String getPostEndpoint() {
		return postEndpoint;
	}

	public void setPostEndpoint(String postEndpoint) {
		this.postEndpoint = postEndpoint;
	}

	public String getRedirectEndpoint() {
		return redirectEndpoint;
	}

	public void setRedirectEndpoint(String redirectEndpoint) {
		this.redirectEndpoint = redirectEndpoint;
	}

	public String getId() {
		return id;
	}
	public void setId(String id) {
		this.id = id;
	}
	public String getEntityId() {
		return entityId;
	}
	public void setEntityId(String entityId) {
		this.entityId = entityId;
	}
	public Date getValidUntil() {
		return validUntil;
	}
	public void setValidUntil(Date validUntil) {
		this.validUntil = validUntil;
	}
	public X509Certificate getSigCert() {
		return sigCert;
	}
	public void setSigCert(X509Certificate sigCert) {
		this.sigCert = sigCert;
	}
	public X509Certificate getEncCert() {
		return encCert;
	}
	public void setEncCert(X509Certificate encCert) {
		this.encCert = encCert;
	}
	public EidasOrganisation getOrganisation() {
		return organisation;
	}
	public void setOrganisation(EidasOrganisation organisation) {
		this.organisation = organisation;
	}
	public EidasContactPerson getTechnicalContact() {
		return technicalcontact;
	}
	public void setTechnicalContact(EidasContactPerson contact) {
		this.technicalcontact = contact;
	}
	
	public EidasContactPerson getSupportcontact() {
		return supportcontact;
	}

	public void setSupportcontact(EidasContactPerson supportcontact) {
		this.supportcontact = supportcontact;
	}

	public List<EidasPersonAttributes> getAttributes() {
		return attributes;
	}

	public void setAttributes(List<EidasPersonAttributes> attributes) {
		this.attributes = attributes;
	}

	public byte[] generate(List<EidasPersonAttributes> attributes, EidasSigner signer) throws CertificateEncodingException, IOException, XMLParserException, UnmarshallingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException
	{
		byte[] result = null;
		String template = TemplateLoader.GetTemplateByName("metadataservice");
		template=template.replace("$Id", id);
		template=template.replace("$entityID", entityId);
		template=template.replace("$validUntil", Constants.SimpleSamlDf.format(validUntil));
		template=template.replace("$highestSupportedLoA", this.highestSupportedLoA.NAME);
		
		template=template.replace("$signCert", 
				new String(Base64.encodeBase64(sigCert.getEncoded(), false),Constants.UTF8_CHARSET)
				);
		template=template.replace("$encCert", new String(Base64.encodeBase64(encCert.getEncoded(), false),Constants.UTF8_CHARSET));
		template=template.replace("$landID", this.organisation.getLangId());
		
		template=template.replace("$orgName", organisation.getName());
		template=template.replace("$orgDisplayName", organisation.getDisplayName());
		template=template.replace("$orgUrl", organisation.getUrl());
		template=template.replace("$techPersonCompany", technicalcontact.getCompany());
		template=template.replace("$techPersonGivenName", technicalcontact.getGivenName());
		template=template.replace("$techPersonSurName", technicalcontact.getSurName());
		template=template.replace("$techPersonAddress", technicalcontact.getEmail());
		template=template.replace("$techPersonTel", technicalcontact.getTel());
		template=template.replace("$supPersonCompany", supportcontact.getCompany());
		template=template.replace("$supPersonGivenName", supportcontact.getGivenName());
		template=template.replace("$supPersonSurName", supportcontact.getSurName());
		template=template.replace("$supPersonAddress", supportcontact.getEmail());
		template=template.replace("$supPersonTel", supportcontact.getTel());
		template=template.replace("$POST_ENDPOINT", postEndpoint);
		template=template.replace("$REDIRECT_ENDPOINT", redirectEndpoint);
		
		StringBuilder sbSupportNameIDTypes = new StringBuilder();
		for(EidasNameIdType nameIDType : this.supportedNameIdTypes)
		{
			sbSupportNameIDTypes.append("<md:NameIDFormat>"+nameIDType.NAME+"</md:NameIDFormat>");
		}
		template=template.replace("$SUPPORTED_NAMEIDTYPES",sbSupportNameIDTypes.toString());
		
		StringBuilder sB = new StringBuilder();
		for(EidasPersonAttributes att : attributes)
		{
			sB.append(attributeTemplate.replace("$ATTFriendlyNAME", att.getFriendlyName()).replace("$ATTName", att.getName()));
		}
		template=template.replace("$att", sB.toString());
		
		List<Signature> sigs = new ArrayList<Signature>();
		BasicParserPool ppMgr = Utils.getParserPool(true);
		try( InputStream is = new ByteArrayInputStream(template.getBytes(Constants.UTF8_CHARSET))){
			Document inCommonMDDoc = ppMgr.parse(is);
			Element metadataRoot = inCommonMDDoc.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
			EntityDescriptor metaData = (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);
			
			XMLSignatureHandler.addSignature(metaData,signer.getSigKey(),
					signer.getSigCert(), signer.getSigType(),
					signer.getSigDigestAlg());
			sigs.add(metaData.getSignature());
			
			EntityDescriptorMarshaller arm = new EntityDescriptorMarshaller();
			Element all = arm.marshall(metaData);
			if (sigs.size() > 0)
				Signer.signObjects(sigs);
			
			Transformer trans = TransformerFactory.newInstance().newTransformer();
			trans.setOutputProperty(OutputKeys.ENCODING,"UTF-8");
		      try(ByteArrayOutputStream bout = new ByteArrayOutputStream()){
		    	  trans.transform(new DOMSource(all), new StreamResult(bout));
		    	  result = bout.toByteArray();
		      }
		}
		
		return result;
	}
	
	public static EidasMetadataService Parse(InputStream is) throws XMLParserException, UnmarshallingException, CertificateException, IOException
	{
		EidasMetadataService eidasMetadataService = new EidasMetadataService();
		BasicParserPool ppMgr = Utils.getParserPool(false);
		Document inCommonMDDoc = ppMgr.parse(is);
		Element metadataRoot = inCommonMDDoc.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
		EntityDescriptor metaData = (EntityDescriptor)unmarshaller.unmarshall(metadataRoot);
		eidasMetadataService.setSupportcontact(unmarshalContactPerson(metaData.getContactPersons(), "support"));
		eidasMetadataService.setTechnicalContact(unmarshalContactPerson(metaData.getContactPersons(), "technical"));
		eidasMetadataService.setOrganisation(unmarshalOrganisation(metaData.getOrganization()));
		eidasMetadataService.setId(metaData.getID());
		eidasMetadataService.setEntityId(metaData.getEntityID());
		eidasMetadataService.setValidUntil(metaData.getValidUntil().toDate());
		IDPSSODescriptor idpssoDescriptor = metaData.getIDPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol");
		idpssoDescriptor.getSingleSignOnServices().forEach(s->{
			String bindString = s.getBinding();
			if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST".equals(bindString))
			{
				eidasMetadataService.setPostEndpoint(s.getLocation());
			}else if("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect".equals(bindString))
			{
				eidasMetadataService.setRedirectEndpoint(s.getLocation());
			}
		});
		List<EidasPersonAttributes> attributes = new ArrayList<>();
		idpssoDescriptor.getAttributes().forEach(a->{
			EidasPersonAttributes eidasPersonAttributes = null;
			try {
				eidasPersonAttributes = EidasNaturalPersonAttributes.GetValueOf(a.getName());
			} catch (Exception e1) { //legal person?
				try {
					eidasPersonAttributes = EidasLegalPersonAttributes.GetValueOf(a.getName());
				} catch (Exception e) { //no natural and no legal
					//ignore error, perhaps log?
				}
			}
			
			attributes.add(eidasPersonAttributes);
		});
		eidasMetadataService.setAttributes(attributes);
		for(KeyDescriptor k : idpssoDescriptor.getKeyDescriptors())
		{
			if(k.getUse() == UsageType.ENCRYPTION)
			{
				eidasMetadataService.encCert = GetFirstCertFromKeyDescriptor(eidasMetadataService, k);		
			}else if(k.getUse() == UsageType.SIGNING)
			{
				eidasMetadataService.sigCert = GetFirstCertFromKeyDescriptor(eidasMetadataService, k);
			}
		}
		
		return eidasMetadataService;
	}
	
	private static EidasContactPerson unmarshalContactPerson(List<ContactPerson> cps, String contactType){
		for (ContactPerson cp : cps){
		String company = cp.getCompany().getName() ;
		String givenName = cp.getGivenName().getName();
		String surName = cp.getSurName().getName();
		String tel = cp.getTelephoneNumbers().get(0).getNumber(); 
		String email = cp.getEmailAddresses().get(0).getAddress();
		String type = cp.getType().toString();
		EidasContactPerson ecp = new EidasContactPerson(company, givenName, surName, tel, email,type);
		if (type != null && (type.toLowerCase()).equals(contactType.toLowerCase())){
			return ecp;
		}}
		return null;
	}
	
	private static EidasOrganisation unmarshalOrganisation(Organization org){
		String displayName = org.getDisplayNames().get(0).getValue();
		String name = org.getOrganizationNames().get(0).getValue();
		String url = org.getURLs().get(0).getValue();
		String langId = org.getDisplayNames().get(0).getXMLLang();
		EidasOrganisation eorg = new EidasOrganisation(name, displayName, url, langId);
		return eorg;
	}

	private static java.security.cert.X509Certificate GetFirstCertFromKeyDescriptor(
			EidasMetadataService eidasMetadataService, KeyDescriptor k) throws CertificateException, IOException {
		java.security.cert.X509Certificate x = null;
		if(k.getKeyInfo().getX509Datas() != null)
		{
			if(k.getKeyInfo().getX509Datas().size() > 0)
			{
				X509Data d = k.getKeyInfo().getX509Datas().get(0);
				if(d != null){
					NodeList childs = d.getDOM().getChildNodes();
					for(int i = 0; i < childs.getLength(); i++)
					{
						if("X509Certificate".equals(childs.item(i).getLocalName()))
						{
							String base64String = childs.item(i).getTextContent();
							byte[] bytes = Base64.decodeBase64(base64String);
							x = Utils.readX509Certificate(bytes);
						}
					}
				}
			}
		}
		
		return x;
	}
	
	

}
