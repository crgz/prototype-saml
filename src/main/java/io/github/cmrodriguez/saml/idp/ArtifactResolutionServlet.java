package io.github.cmrodriguez.saml.idp;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.saml2.core.ArtifactResponse;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.encryption.Encrypter;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.EncryptionException;
import org.opensaml.xml.encryption.EncryptionParameters;
import org.opensaml.xml.encryption.KeyEncryptionParameters;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.signature.Signature;
import org.opensaml.xml.signature.SignatureConstants;
import org.opensaml.xml.signature.SignatureException;
import org.opensaml.xml.signature.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import io.github.cmrodriguez.saml.sp.SPConstants;
import io.github.cmrodriguez.saml.sp.SPCredentials;
import io.github.cmrodriguez.saml.tools.Tools;

public class ArtifactResolutionServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(ArtifactResolutionServlet.class);

	@Override
	protected void doPost(final HttpServletRequest req, final HttpServletResponse resp)
			throws ServletException, IOException {

		logger.info("ArtifactResolutionServlet");

		ArtifactResponse artifactResponse = buildArtifactResponse();
		artifactResponse.setInResponseTo("Made up ID");

		Envelope wrapInSOAPEnvelope = wrapInSOAPEnvelope(artifactResponse);
		
		logger.info("wrapInSOAPEnvelope: ");
        Tools.logXml(wrapInSOAPEnvelope);

		printSAMLObject(wrapInSOAPEnvelope, resp.getWriter());
	}

	private ArtifactResponse buildArtifactResponse() {

		ArtifactResponse artifactResponse = Tools.buildSAMLObject(ArtifactResponse.class);
		artifactResponse.setIssuer(buildIssuer());
		artifactResponse.setIssueInstant(new DateTime());
		artifactResponse.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);
		artifactResponse.setID(Tools.generateSecureRandomId());
		artifactResponse.setStatus(buildStatus());

		Response response = Tools.buildSAMLObject(Response.class);
		response.setIssuer(buildIssuer());
		response.setIssueInstant(new DateTime());
		response.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);
		response.setID(Tools.generateSecureRandomId());
		response.setStatus(buildStatus());

		artifactResponse.setMessage(response);

		Assertion assertion = buildAssertion();
		signAssertion(assertion);
		EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

		response.getEncryptedAssertions().add(encryptedAssertion);
		return artifactResponse;
	}

	private Issuer buildIssuer() {
		Issuer issuer = Tools.buildSAMLObject(Issuer.class);
		issuer.setValue(IDPConstants.IDP_ENTITY_ID);
		return issuer;
	}

	private Status buildStatus() {
		Status status = Tools.buildSAMLObject(Status.class);
		StatusCode statusCode = Tools.buildSAMLObject(StatusCode.class);
		statusCode.setValue(StatusCode.SUCCESS_URI);
		status.setStatusCode(statusCode);
		return status;
	}

	private Assertion buildAssertion() {
		Assertion assertion = Tools.buildSAMLObject(Assertion.class);
		assertion.setIssuer(buildIssuer());
		assertion.setIssueInstant(new DateTime());
		assertion.setID(Tools.generateSecureRandomId());
		assertion.setSubject(buildSubject());
		assertion.setConditions(buildConditions());
		assertion.getAttributeStatements().add(buildAttributeStatement());
		assertion.getAuthnStatements().add(buildAuthnStatement());
		return assertion;
	}

	private Subject buildSubject() {
		Subject subject = Tools.buildSAMLObject(Subject.class);
		subject.setNameID(buildNameID());
		subject.getSubjectConfirmations().add(buildSubjectConfirmation());
		return subject;
	}

	private NameID buildNameID() {
		NameID nameID = Tools.buildSAMLObject(NameID.class);
		nameID.setFormat(NameIDType.TRANSIENT);
		nameID.setValue("Some NameID value");
		nameID.setSPNameQualifier("SP name qualifier");
		nameID.setNameQualifier("Name qualifier");
		return nameID;
	}

	private EncryptedAssertion encryptAssertion(Assertion assertion) {
		EncryptionParameters encryptionParameters = new EncryptionParameters();
		encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(SPCredentials.getCredential());
		keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

		Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
		encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

		EncryptedAssertion encryptedAssertion = null;
		try {
			encryptedAssertion = encrypter.encrypt(assertion);
		} catch (EncryptionException e) {
			throw new RuntimeException(e);
		}
		return encryptedAssertion;

	}

	private void signAssertion(Assertion assertion) {
		Signature signature = Tools.buildSAMLObject(Signature.class);
		signature.setSigningCredential(IDPCredentials.getCredential());
		signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
		signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
		assertion.setSignature(signature);

		try {
			Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
			Signer.signObject(signature);
		} catch (MarshallingException e) {
			throw new RuntimeException(e);
		} catch (SignatureException e) {
			throw new RuntimeException(e);
		}
	}

	private SubjectConfirmation buildSubjectConfirmation() {
		SubjectConfirmation subjectConfirmation = Tools.buildSAMLObject(SubjectConfirmation.class);
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

		SubjectConfirmationData subjectConfirmationData = Tools.buildSAMLObject(SubjectConfirmationData.class);
		subjectConfirmationData.setInResponseTo("Made up ID");
		subjectConfirmationData.setNotBefore(new DateTime().minusDays(2));
		subjectConfirmationData.setNotOnOrAfter(new DateTime().plusDays(2));
		subjectConfirmationData.setRecipient(SPConstants.ASSERTION_CONSUMER_SERVICE);

		subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

		return subjectConfirmation;
	}

	private AuthnStatement buildAuthnStatement() {
		AuthnStatement authnStatement = Tools.buildSAMLObject(AuthnStatement.class);
		AuthnContext authnContext = Tools.buildSAMLObject(AuthnContext.class);
		AuthnContextClassRef authnContextClassRef = Tools.buildSAMLObject(AuthnContextClassRef.class);
		authnContextClassRef.setAuthnContextClassRef(AuthnContext.SMARTCARD_AUTHN_CTX);
		authnContext.setAuthnContextClassRef(authnContextClassRef);
		authnStatement.setAuthnContext(authnContext);

		authnStatement.setAuthnInstant(new DateTime());

		return authnStatement;
	}

	private Conditions buildConditions() {
		Conditions conditions = Tools.buildSAMLObject(Conditions.class);
		conditions.setNotBefore(new DateTime().minusDays(2));
		conditions.setNotOnOrAfter(new DateTime().plusDays(2));
		AudienceRestriction audienceRestriction = Tools.buildSAMLObject(AudienceRestriction.class);
		Audience audience = Tools.buildSAMLObject(Audience.class);
		audience.setAudienceURI(SPConstants.ASSERTION_CONSUMER_SERVICE);
		audienceRestriction.getAudiences().add(audience);
		conditions.getAudienceRestrictions().add(audienceRestriction);
		return conditions;
	}

	private AttributeStatement buildAttributeStatement() {
		AttributeStatement attributeStatement = Tools.buildSAMLObject(AttributeStatement.class);

		Attribute attributeUserName = Tools.buildSAMLObject(Attribute.class);

		XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory()
				.getBuilder(XSString.TYPE_NAME);
		XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		userNameValue.setValue("bob");

		attributeUserName.getAttributeValues().add(userNameValue);
		attributeUserName.setName("username");
		attributeStatement.getAttributes().add(attributeUserName);

		Attribute attributeLevel = Tools.buildSAMLObject(Attribute.class);
		XSString levelValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
		levelValue.setValue("999999999");

		attributeLevel.getAttributeValues().add(levelValue);
		attributeLevel.setName("telephone");
		attributeStatement.getAttributes().add(attributeLevel);

		return attributeStatement;

	}

	public static Envelope wrapInSOAPEnvelope(final XMLObject xmlObject) {
		Envelope envelope = Tools.buildSAMLObject(Envelope.class);
		Body body = Tools.buildSAMLObject(Body.class);
		body.getUnknownXMLObjects().add(xmlObject);
		envelope.setBody(body);
		return envelope;
	}

	public static void printSAMLObject(final XMLObject object, final PrintWriter writer) {
		try {
			DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
			factory.setNamespaceAware(true);
			org.w3c.dom.Document document = factory.newDocumentBuilder().newDocument();
			Marshaller out = Configuration.getMarshallerFactory().getMarshaller(object);
			out.marshall(object, document);
			Transformer transformer = TransformerFactory.newInstance().newTransformer();
			transformer.setOutputProperty(OutputKeys.INDENT, "yes");
			StreamResult result = new StreamResult(writer);
			transformer.transform(new DOMSource(document), result);
		} catch (ParserConfigurationException e) {
			e.printStackTrace();
		} catch (MarshallingException e) {
			e.printStackTrace();
		} catch (TransformerException e) {
			e.printStackTrace();
		}
	}

}
