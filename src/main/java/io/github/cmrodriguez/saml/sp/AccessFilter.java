package io.github.cmrodriguez.saml.sp;

import io.github.cmrodriguez.saml.idp.IDPConstants;
import io.github.cmrodriguez.saml.tools.Tools;

import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.SAMLObject;
import org.opensaml.common.binding.BasicSAMLMessageContext;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.binding.encoding.HTTPRedirectDeflateEncoder;
import org.opensaml.saml2.core.*;
import org.opensaml.saml2.metadata.Endpoint;
import org.opensaml.saml2.metadata.SingleSignOnService;
import org.opensaml.ws.message.encoder.MessageEncodingException;
import org.opensaml.ws.transport.http.HttpServletResponseAdapter;
import org.opensaml.xml.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

/**
 * The filter intercepts the user and start the SAML authentication if it is not
 * authenticated
 */
public class AccessFilter implements Filter {
	private static Logger logger = LoggerFactory.getLogger(AccessFilter.class);

	public void init(FilterConfig filterConfig) throws ServletException {
		Configuration.validateJCEProviders();
		Configuration.validateNonSunJAXP();

		for (Provider jceProvider : Security.getProviders()) {
			logger.info(jceProvider.getInfo());
		}

		try {
			logger.info("Bootstrapping");
			DefaultBootstrap.bootstrap();
		} catch (ConfigurationException e) {
			throw new RuntimeException("Bootstrapping failed");
		}
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest httpServletRequest = (HttpServletRequest) request;
		HttpServletResponse httpServletResponse = (HttpServletResponse) response;


		Object attribute = httpServletRequest.getSession().getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE);
		logger.info("Testing AUTHENTICATED_SESSION_ATTRIBUTE: " + attribute);

		if (attribute != null) {
			chain.doFilter(request, response);
		} else {
			logger.info("Not authenticated!");

			httpServletRequest.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE, httpServletRequest.getRequestURL().toString());
			AuthnRequest authnRequest = buildAuthnRequest();
			redirectUserWithRequest(httpServletResponse, authnRequest);
		}
	}
	
	private AuthnRequest buildAuthnRequest() {
		AuthnRequest authnRequest = Tools.buildSAMLObject(AuthnRequest.class);
		authnRequest.setIssueInstant(new DateTime());
		authnRequest.setDestination(getIPDSSODestination());
		authnRequest.setProtocolBinding(SAMLConstants.SAML2_ARTIFACT_BINDING_URI);
		authnRequest.setAssertionConsumerServiceURL(getAssertionConsumerEndpoint());
		authnRequest.setID(Tools.generateSecureRandomId());
		authnRequest.setIssuer(buildIssuer());
		authnRequest.setNameIDPolicy(buildNameIdPolicy());
		authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());
		return authnRequest;
	}

	private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {
		HttpServletResponseAdapter responseAdapter = new HttpServletResponseAdapter(httpServletResponse, true);
		BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject> context = new BasicSAMLMessageContext<SAMLObject, AuthnRequest, SAMLObject>();
		context.setPeerEntityEndpoint(getIPDEndpoint());
		context.setOutboundSAMLMessage(authnRequest);
		context.setOutboundMessageTransport(responseAdapter);
		context.setOutboundSAMLMessageSigningCredential(SPCredentials.getCredential());

		HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
		logger.info("AuthnRequest: ");
		Tools.logXml(authnRequest);

		logger.info("Redirecting to ID Provider");
		try {
			encoder.encode(context);
		} catch (MessageEncodingException e) {
			throw new RuntimeException(e);
		}
	}



	private RequestedAuthnContext buildRequestedAuthnContext() {
		RequestedAuthnContext requestedAuthnContext = Tools.buildSAMLObject(RequestedAuthnContext.class);
		requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);

		AuthnContextClassRef passwordAuthnContextClassRef = Tools.buildSAMLObject(AuthnContextClassRef.class);
		passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);

		requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);

		return requestedAuthnContext;

	}

	private NameIDPolicy buildNameIdPolicy() {
		NameIDPolicy nameIDPolicy = Tools.buildSAMLObject(NameIDPolicy.class);
		nameIDPolicy.setAllowCreate(true);

		nameIDPolicy.setFormat(NameIDType.TRANSIENT);

		return nameIDPolicy;
	}

	private Issuer buildIssuer() {
		Issuer issuer = Tools.buildSAMLObject(Issuer.class);
		issuer.setValue(getSPIssuerValue());

		return issuer;
	}

	private String getSPIssuerValue() {
		return SPConstants.SP_ENTITY_ID;
	}

	private String getAssertionConsumerEndpoint() {
		return SPConstants.ASSERTION_CONSUMER_SERVICE;
	}

	private String getIPDSSODestination() {
		return IDPConstants.SSO_SERVICE;
	}

	private Endpoint getIPDEndpoint() {
		SingleSignOnService endpoint = Tools.buildSAMLObject(SingleSignOnService.class);
		endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
		endpoint.setLocation(getIPDSSODestination());

		return endpoint;
	}

	public void destroy() {
		// TODO Auto-generated method stub

	}

}