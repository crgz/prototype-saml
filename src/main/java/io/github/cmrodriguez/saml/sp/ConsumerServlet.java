package io.github.cmrodriguez.saml.sp;

import io.github.cmrodriguez.saml.idp.IDPConstants;
import io.github.cmrodriguez.saml.idp.IDPCredentials;
import io.github.cmrodriguez.saml.tools.Tools;

import org.joda.time.DateTime;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.ws.soap.client.BasicSOAPMessageContext;
import org.opensaml.ws.soap.client.http.HttpClientBuilder;
import org.opensaml.ws.soap.client.http.HttpSOAPClient;
import org.opensaml.ws.soap.common.SOAPException;
import org.opensaml.ws.soap.soap11.Body;
import org.opensaml.ws.soap.soap11.Envelope;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.DecryptionException;
import org.opensaml.xml.encryption.InlineEncryptedKeyResolver;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.security.SecurityException;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.signature.*;
import org.opensaml.xml.validation.ValidationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ConsumerServlet extends HttpServlet {
	private static final long serialVersionUID = 1L;
	private static Logger logger = LoggerFactory.getLogger(ConsumerServlet.class);

    @Override
    protected void doGet(final HttpServletRequest req, final HttpServletResponse resp) throws ServletException, IOException {
        logger.info("Artifact received");
        Artifact artifact = buildArtifactFromRequest(req);
        logger.info("Artifact: " + artifact.getArtifact());

        ArtifactResolve artifactResolve = buildArtifactResolve(artifact);
        signArtifactResolve(artifactResolve);
        logger.info("Sending ArtifactResolve");
        logger.info("ArtifactResolve: ");
        Tools.logXml(artifactResolve);

        logger.info("Calling ID Provider ArtifactResolutionServlet to Check Artifact!!!");

        ArtifactResponse artifactResponse = sendAndReceiveArtifactResolve(artifactResolve);
        logger.info("ArtifactResponse received");
        logger.info("ArtifactResponse: ");
        //Tools.logXml(artifactResponse);

        
        EncryptedAssertion encryptedAssertion = getEncryptedAssertion(artifactResponse);
        Assertion assertion = decryptAssertion(encryptedAssertion);
        verifyAssertionSignature(assertion);
        logger.info("Decrypted Assertion: \n");
        Tools.logXml(assertion);

        logAssertionAttributes(assertion);
        logAuthenticationInstant(assertion);
        logAuthenticationMethod(assertion);

        setAuthenticatedSession(req);
        redirectToGotoURL(req, resp);
    }

    private Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver = new StaticKeyInfoCredentialResolver(SPCredentials.getCredential());

        Decrypter decrypter = new Decrypter(null, keyInfoCredentialResolver, new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }

    private void verifyAssertionSignature(Assertion assertion) {
        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }

        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());
            SignatureValidator sigValidator = new SignatureValidator(IDPCredentials.getCredential());
            sigValidator.validate(assertion.getSignature());
            logger.info("SAML Assertion signature verified");
        } catch (ValidationException e) {
            throw new RuntimeException(e);
        }

    }

    private void signArtifactResolve(ArtifactResolve artifactResolve) {
        Signature signature = Tools.buildSAMLObject(Signature.class);
        signature.setSigningCredential(SPCredentials.getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        artifactResolve.setSignature(signature);

        try {
            Configuration.getMarshallerFactory().getMarshaller(artifactResolve).marshall(artifactResolve);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }


    private void logAuthenticationMethod(Assertion assertion) {
        logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }

    private void logAuthenticationInstant(Assertion assertion) {
        logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
    }

    private void logAssertionAttributes(Assertion assertion) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            logger.info("Attribute name: " + attribute.getName());
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
                logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
            }
        }
    }

    private ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
        try {
            BasicSOAPMessageContext soapContext = new BasicSOAPMessageContext();
            soapContext.setOutboundMessage(wrapInSOAPEnvelope(artifactResolve));
            
            HttpSOAPClient soapClient = new HttpSOAPClient(new HttpClientBuilder().buildClient(), new BasicParserPool());
            soapClient.send(IDPConstants.ARTIFACT_RESOLUTION_SERVICE, soapContext);
            Envelope soapResponse = (Envelope)soapContext.getInboundMessage();
            logger.info("Calling: " + IDPConstants.ARTIFACT_RESOLUTION_SERVICE);
            ArtifactResponse artifactResponse = (ArtifactResponse)soapResponse.getBody().getUnknownXMLObjects().get(0);
            logger.info("Artifact Response getSignatureReferenceID: " + artifactResponse.getSignatureReferenceID());
			return artifactResponse;
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (SOAPException e) {
            throw new RuntimeException(e);
        }
    }

	public static Envelope wrapInSOAPEnvelope(final XMLObject xmlObject) throws IllegalAccessException {
		Body body = Tools.buildSAMLObject(Body.class);
		body.getUnknownXMLObjects().add(xmlObject);
		Envelope envelope = Tools.buildSAMLObject(Envelope.class);
		envelope.setBody(body);
		return envelope;
	}
	
    private EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }

    private Artifact buildArtifactFromRequest(final HttpServletRequest req) {
        Artifact artifact = Tools.buildSAMLObject(Artifact.class);
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }

    private ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = Tools.buildSAMLObject(ArtifactResolve.class);

        Issuer issuer = Tools.buildSAMLObject(Issuer.class);
        issuer.setValue(SPConstants.SP_ENTITY_ID);
        artifactResolve.setIssuer(issuer);
        artifactResolve.setIssueInstant(new DateTime());
        artifactResolve.setID(Tools.generateSecureRandomId());
        artifactResolve.setDestination(IDPConstants.ARTIFACT_RESOLUTION_SERVICE);
        artifactResolve.setArtifact(artifact);
        return artifactResolve;
    }


    private void setAuthenticatedSession(HttpServletRequest req) {
        req.getSession().setAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
    }

    private void redirectToGotoURL(HttpServletRequest req, HttpServletResponse resp) {
        String gotoURL = (String)req.getSession().getAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE);
        logger.info("Redirecting to requested URL: " + gotoURL);
        try {
            resp.sendRedirect(gotoURL);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
