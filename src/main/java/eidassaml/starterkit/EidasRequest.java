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
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestMarshaller;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import eidassaml.starterkit.person_attributes.EidasPersonAttributes;
import eidassaml.starterkit.template.TemplateLoader;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;
import net.shibboleth.utilities.java.support.xml.XMLParserException;

/**
 * 
 * @author hohnholt
 *
 */
public class EidasRequest {
	
	private static final Log LOG = LogFactory.getLog(EidasRequest.class);
	
	private static final String attributeTemplate = "<eidas:RequestedAttribute Name=\"$NAME\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\" isRequired=\"$ISREQ\"/>";
	public static final SimpleDateFormat SimpleDf = Constants.SimpleSamlDf;
	
	private static final List<EidasNaturalPersonAttributes> MINIMUM_DATASET = Arrays.asList(
			EidasNaturalPersonAttributes.PersonIdentifier, 
			EidasNaturalPersonAttributes.FamilyName, 
			EidasNaturalPersonAttributes.FirstName, 
			EidasNaturalPersonAttributes.DateOfBirth);
	
	private static final List<EidasLegalPersonAttributes> MINIMUM_LEGAL_DATASET = Arrays.asList(
			EidasLegalPersonAttributes.LegalPersonIdentifier, 
			EidasLegalPersonAttributes.LegalName);
	
	private String id;
	private String destination;
	private String issuer;
	private String issueInstant;
	private String providerName;
	private boolean forceAuthn;
	private boolean isPassive;
	private EidasRequestSectorType selectorType = EidasRequestSectorType.Public;
	private EidasNameIdType nameIdPolicy = EidasNameIdType.Transient;
	private EidasLoA authClassRef = EidasLoA.High;
	
	private EidasSigner signer = null;
	private AuthnRequest request = null;
	private Map<EidasPersonAttributes, Boolean> requestedAttributes = new HashMap<>();
	
	private EidasRequest(){
		
	}
	
	public EidasRequest(String _destination, String _issuer, String _providerName, EidasSigner _signer) {
		id = "_" + Utils.GenerateUniqueID();
		destination = _destination;
		issuer = _issuer;
		signer = _signer;
		providerName = _providerName;
		issueInstant = SimpleDf.format(new Date());
		this.forceAuthn = true;
		this.isPassive = false;
	}

	public EidasRequest(String _destination, String _issuer, String _providerName, EidasSigner _signer, String _id) {
		id = _id;
		destination = _destination;
		issuer = _issuer;
		signer = _signer;
		providerName = _providerName;
		issueInstant = SimpleDf.format(new Date());
		this.forceAuthn = true;
	}
	
	public EidasRequest(String _destination,EidasRequestSectorType _selectorType, EidasNameIdType _nameIdPolicy, EidasLoA _loa,String _issuer, String _providerName, EidasSigner _signer) {
		id = "_" + Utils.GenerateUniqueID();
		destination = _destination;
		issuer = _issuer;
		providerName = _providerName;
		signer = _signer;
		selectorType = _selectorType;
		nameIdPolicy = _nameIdPolicy;
		authClassRef = _loa;
		issueInstant = SimpleDf.format(new Date());
		this.forceAuthn = true;
		this.isPassive = false;
	}
	
	public EidasRequest(String _id, String _destination,EidasRequestSectorType _selectorType, EidasNameIdType _nameIdPolicy, EidasLoA _loa,String _issuer, String _providerName, EidasSigner _signer) {
		id = _id;
		destination = _destination;
		issuer = _issuer;
		providerName = _providerName;
		signer = _signer;
		selectorType = _selectorType;
		nameIdPolicy = _nameIdPolicy;
		authClassRef = _loa;
		issueInstant = SimpleDf.format(new Date());
		this.forceAuthn = true;
		this.isPassive = false;
	}
	
	public byte[] generate(Map<EidasPersonAttributes, Boolean> _requestedAttributes) throws IOException, XMLParserException, UnmarshallingException, CertificateEncodingException, MarshallingException, SignatureException, TransformerFactoryConfigurationError, TransformerException
	{
		byte[] returnvalue = null;
		StringBuilder attributesBuilder = new StringBuilder();
		for (Map.Entry<EidasPersonAttributes, Boolean> entry : _requestedAttributes
				.entrySet()) {
			attributesBuilder.append(attributeTemplate.replace("$NAME", entry.getKey().getName()).replace("$ISREQ", entry.getValue().toString()));
		}
		
		String template = TemplateLoader.GetTemplateByName("auth");
		template = template.replace("$ForceAuthn", Boolean.toString(this.forceAuthn));
		template = template.replace("$IsPassive", Boolean.toString(this.isPassive));
		template = template.replace("$Destination", destination);
		template = template.replace("$Id", id);
		template = template.replace("$IssuerInstand", issueInstant);
		template = template.replace("$ProviderName", providerName);
		template = template.replace("$Issuer", issuer);
		template = template.replace("$requestAttributes", attributesBuilder.toString());
		template = template.replace("$NameIDPolicy",nameIdPolicy.NAME);
		template = template.replace("$AuthClassRef",authClassRef.NAME);
		
		if (null != selectorType) {
			template = template.replace("$SPType","<eidas:SPType>" + selectorType.NAME + "</eidas:SPType>");
		}
		else {
			template = template.replace("$SPType", "");
		}
		
		BasicParserPool ppMgr = Utils.getParserPool(true);
		List<Signature> sigs = new ArrayList<Signature>();
		
		try( InputStream is = new ByteArrayInputStream(template.getBytes(Constants.UTF8_CHARSET))){
		
			Document inCommonMDDoc = ppMgr.parse(is);
			Element metadataRoot = inCommonMDDoc.getDocumentElement();
			UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
			request = (AuthnRequest)unmarshaller.unmarshall(metadataRoot);
			
			XMLSignatureHandler.addSignature(request,signer.getSigKey(),
					signer.getSigCert(), signer.getSigType(),
					signer.getSigDigestAlg());
			sigs.add(request.getSignature());
			
			AuthnRequestMarshaller arm = new AuthnRequestMarshaller();
			Element all = arm.marshall(request);
			if (sigs.size() > 0)
				Signer.signObjects(sigs);
			
			Transformer trans = TransformerFactory.newInstance().newTransformer();
			trans.setOutputProperty(OutputKeys.ENCODING,"UTF-8");
			try(ByteArrayOutputStream bout = new ByteArrayOutputStream()){
				trans.transform(new DOMSource(all), new StreamResult(bout));
				returnvalue = bout.toByteArray();
			}
		}
		
		return returnvalue;
	}
		
	public boolean isPassive() {
		return isPassive;
	}

	public void setPassive(boolean isPassive) {
		this.isPassive = isPassive;
	}

	public void setIsForceAuthn(Boolean forceAuthn) {
		this.forceAuthn = forceAuthn;
	}
	
	public boolean isForceAuthn() {
		return this.forceAuthn;
	}
	
	public String getId() {
		return id;
	}

	public String getDestination() {
		return destination;
	}

	public String getIssuer() {
		return issuer;
	}

	public String getIssueInstant() {
		return issueInstant;
	}

	public Set<Entry<EidasPersonAttributes, Boolean>> getRequestedAttributes() {
		return requestedAttributes.entrySet();
	}
	
	/**
	 * running EidasRequest.generate or EidasRequest.Parse creates is object
	 * 
	 * @return the opensaml authnrespuest object or null. if not null, this object provides all information u can get via opensaml
	 */
	public AuthnRequest getAuthnRequest(){
		return request;
	}
	
	public EidasRequestSectorType getSelectorType() {
		return selectorType;
	}

	public void setSelectorType(EidasRequestSectorType selectorType) {
		this.selectorType = selectorType;
	}

	public EidasNameIdType getNameIdPolicy() {
		return nameIdPolicy;
	}

	public void setNameIdPolicy(EidasNameIdType nameIdPolicy) {
		this.nameIdPolicy = nameIdPolicy;
	}

	public String getProviderName() {
		return providerName;
	}

	public void setProviderName(String providerName) {
		this.providerName = providerName;
	}

	public EidasLoA getLevelOfAssurance() {
		return authClassRef;
	}

	public void setLevelOfAssurance(EidasLoA levelOfAssurance) {
		this.authClassRef = levelOfAssurance;
	}
	
	public static EidasRequest Parse(InputStream is) throws XMLParserException, UnmarshallingException, ErrorCodeException, IOException{
		return Parse(is,null);
	}	

	public static EidasRequest Parse(InputStream is, List<X509Certificate> authors) throws XMLParserException, UnmarshallingException, ErrorCodeException, IOException{
		EidasRequest eidasReq = new EidasRequest();
		BasicParserPool ppMgr = Utils.getParserPool(true);
		
		Document inCommonMDDoc = ppMgr.parse(is);
		
		Element metadataRoot = inCommonMDDoc.getDocumentElement();
		UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
		Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(metadataRoot);
		eidasReq.request = (AuthnRequest)unmarshaller.unmarshall(metadataRoot);
				
		if(authors != null)
		{
			CheckSignature(eidasReq.request.getSignature(),authors);
		}
		
		//isPassive SHOULD be false
		if (!eidasReq.request.isPassive()) {
			eidasReq.setPassive(eidasReq.request.isPassive());
		}
		else {
			throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Unsupported IsPassive value:" + eidasReq.request.isPassive());
		}
		
		//forceAuthn MUST be true
		if (eidasReq.request.isForceAuthn()) {
			eidasReq.setIsForceAuthn(eidasReq.request.isForceAuthn());
		}
		else {
			throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Unsupported ForceAuthn value:" + eidasReq.request.isForceAuthn());
		}
		
		eidasReq.id = eidasReq.request.getID();
		//there should be one AuthnContextClassRef
		AuthnContextClassRef ref = eidasReq.request.getRequestedAuthnContext().getAuthnContextClassRefs().stream().findFirst().orElseThrow(XMLParserException::new);
		if (null != ref) {
			eidasReq.authClassRef = EidasLoA.GetValueOf(ref.getDOM().getTextContent());
		}
		else {
			throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "No AuthnContextClassRef element.");
		}		
		String namiIdformat = eidasReq.request.getNameIDPolicy().getFormat();
		eidasReq.nameIdPolicy = EidasNameIdType.GetValueOf(namiIdformat);		

		eidasReq.issueInstant = SimpleDf.format(eidasReq.request.getIssueInstant().toDate());
		eidasReq.issuer = eidasReq.request.getIssuer().getDOM().getTextContent();
		eidasReq.destination = eidasReq.request.getDestination();
		
		if (null != eidasReq.request.getProviderName() && !eidasReq.request.getProviderName().isEmpty()) {
			eidasReq.providerName = eidasReq.request.getProviderName();
		}
		else {
			throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "No providerName attribute.");
		}
		
		eidasReq.selectorType = null; 
		for ( XMLObject extension : eidasReq.request.getExtensions().getOrderedChildren() )
	    {
			if("RequestedAttributes".equals(extension.getElementQName().getLocalPart())){
				for ( XMLObject attribute : extension.getOrderedChildren() )
			    {
					Element el = attribute.getDOM();
					EidasPersonAttributes eidasPersonAttributes = getEidasPersonAttributes(el);
					if (null != eidasPersonAttributes) {
						eidasReq.requestedAttributes.put(
							eidasPersonAttributes,
							Boolean.parseBoolean(el.getAttribute("isRequired")));
					}
			    }
			}else if("SPType".equals(extension.getElementQName().getLocalPart())){
				eidasReq.selectorType = EidasRequestSectorType.GetValueOf(extension.getDOM().getTextContent());
			}
	    }
		if (!containsMinimumDataSet(eidasReq.requestedAttributes)) {
			throw new ErrorCodeException(ErrorCode.ILLEGAL_REQUEST_SYNTAX, "Request does not contain minimum dataset.");
		}
		return eidasReq;
	}

	/**
	 * Returns {@link EidasPersonAttributes} enum from given {@link Element}. 
	 * In case enum can not be found null is returned; unknown attributes should be ignored.
	 * 
	 * @param el
	 * @return
	 */
	private static EidasPersonAttributes getEidasPersonAttributes(Element el) {
		EidasPersonAttributes eidasPersonAttributes = null;
			try {
				eidasPersonAttributes = EidasNaturalPersonAttributes.GetValueOf(el.getAttribute("Name"));
			}
			catch (ErrorCodeException e) {
				try {
					eidasPersonAttributes = EidasLegalPersonAttributes.GetValueOf(el.getAttribute("Name"));
				} catch (ErrorCodeException e1) {
					LOG.warn("Attribute " + el.getAttribute("Name") + " not an eIDAS attribute. Ignoring.");
				}
			}
		return eidasPersonAttributes;
	}

	private static void CheckSignature(Signature sig, List<X509Certificate> trustedAnchorList) throws ErrorCodeException
	{
		if(sig == null)
			throw new ErrorCodeException(ErrorCode.SIGNATURE_CHECK_FAILED);
		
	    XMLSignatureHandler.checkSignature(sig,
	                                       trustedAnchorList.toArray(new X509Certificate[trustedAnchorList.size()]));
	    
	    
	 }
	
	private static boolean containsMinimumDataSet(Map<EidasPersonAttributes, Boolean> requestedAttributes) {
		if (null != requestedAttributes) {
			return MINIMUM_DATASET.stream()
					.allMatch(requestedAttributes::containsKey) ||
					MINIMUM_LEGAL_DATASET.stream()
					.allMatch(requestedAttributes::containsKey);
		}
		else {
			return false;
		}
	}

}