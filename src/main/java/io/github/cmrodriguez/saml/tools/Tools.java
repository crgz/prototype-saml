package io.github.cmrodriguez.saml.tools;

import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;

import org.opensaml.common.impl.SecureRandomIdentifierGenerator;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

public class Tools {
	private static Logger logger = LoggerFactory.getLogger(Tools.class);
	private static SecureRandomIdentifierGenerator secureRandomIdGenerator;

	static {
		try {
			secureRandomIdGenerator = new SecureRandomIdentifierGenerator();
		} catch (NoSuchAlgorithmException e) {
			logger.error(e.getMessage(), e);
		}
	}

	public static <T> T buildSAMLObject(final Class<T> clazz) {
		T object = null;
		try {
			QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
			object = (T) Configuration.getBuilderFactory().getBuilder(defaultElementName)
					.buildObject(defaultElementName);
		} catch (IllegalAccessException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		} catch (NoSuchFieldException e) {
			throw new IllegalArgumentException("Could not create SAML object");
		}

		return object;
	}

	public static String generateSecureRandomId() {
		return secureRandomIdGenerator.generateIdentifier();
	}

	public static void logXml(final XMLObject xmlObject) {
		try {
			DOMSource domSource = xmlObjectToDomSource(xmlObject);
			String xmlString = domSourceToFormatedString(domSource);
			System.out.println(xmlString);
		} catch (ParserConfigurationException e) {
			logger.error(e.getMessage(), e);
		} catch (MarshallingException e) {
			logger.error(e.getMessage(), e);
		} catch (TransformerException e) {
			logger.error(e.getMessage(), e);
		}
	}

	private static String domSourceToFormatedString(DOMSource domSource)
			throws TransformerConfigurationException, TransformerFactoryConfigurationError, TransformerException {
		Transformer transformer = TransformerFactory.newInstance().newTransformer();
		transformer.setOutputProperty(OutputKeys.INDENT, "yes");
		transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
		//initialize StreamResult with File object to save to file
		StreamResult result = new StreamResult(new StringWriter());
		transformer.transform(domSource, result);
		String xmlString = result.getWriter().toString();
		return xmlString;
	}

	private static DOMSource xmlObjectToDomSource(final XMLObject xmlObject)
			throws ParserConfigurationException, MarshallingException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		Document document = factory.newDocumentBuilder().newDocument();
		Marshaller out = Configuration.getMarshallerFactory().getMarshaller(xmlObject);
		out.marshall(xmlObject, document);
		DOMSource domSource = new DOMSource(document);
		return domSource;
	}


}
