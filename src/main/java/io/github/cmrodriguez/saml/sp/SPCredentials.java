package io.github.cmrodriguez.saml.sp;

import java.io.InputStream;
import java.security.KeyStore;
import java.util.HashMap;
import java.util.Map;

import org.opensaml.xml.security.Criteria;
import org.opensaml.xml.security.CriteriaSet;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.credential.KeyStoreCredentialResolver;
import org.opensaml.xml.security.criteria.EntityIDCriteria;

public class SPCredentials {
	private static final String KEY_STORE_PASSWORD = "password";
	private static final String KEY_STORE_ENTRY_PASSWORD = "password";
	private static final String KEY_STORE_PATH = "/SPKeystore.jks";
	private static final String KEY_ENTRY_ID = "SPKey";

	private static final Credential credential;

	static {
		try {
			KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
			InputStream inputStream = SPCredentials.class.getResourceAsStream(KEY_STORE_PATH);
			keystore.load(inputStream, KEY_STORE_PASSWORD.toCharArray());
			inputStream.close();
			
			Map<String, String> passwordMap = new HashMap<String, String>();
			passwordMap.put(KEY_ENTRY_ID, KEY_STORE_ENTRY_PASSWORD);
			KeyStoreCredentialResolver resolver = new KeyStoreCredentialResolver(keystore, passwordMap);

			Criteria criteria = new EntityIDCriteria(KEY_ENTRY_ID);
			CriteriaSet criteriaSet = new CriteriaSet(criteria);

			credential = resolver.resolveSingle(criteriaSet);
		} catch (Exception e) {
			throw new RuntimeException("Something went wrong reading credentials", e);
		}
	}

	public static Credential getCredential() {
		return credential;
	}
}
