package io.github.cmrodriguez.saml.idp;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;

public class IDPCredentials {
    private static final Credential credential;

    static {
        credential = generateCredential();
    }

    private static Credential generateCredential() {
        try {
            KeyPair keyPair = SecurityHelper.generateKeyPair("RSA", 1024, null);
            return SecurityHelper.getSimpleCredential(keyPair.getPublic(), keyPair.getPrivate());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    public static Credential getCredential() {
        return credential;
    }
}
