package utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class KeyFactory {

    private static final KeyStore keyStore = loadKeyStore();

    public static X509Certificate getCertificate() {
        try {
            Certificate certificate = keyStore.getCertificate("test-cert");
            if (certificate instanceof X509Certificate x509Certificate) {
                return x509Certificate;
            }
            throw new IllegalArgumentException("X509Certificate not found!");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey() {
        try {
            Key key = keyStore.getKey("test-cert", "password".toCharArray());
            if (key instanceof PrivateKey privateKey) {
                return privateKey;
            }
            throw new IllegalArgumentException("Private key not found!");
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore loadKeyStore() {
        try (InputStream keyStoreStream = KeyFactory.class.getResourceAsStream("/test-keystore.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreStream, "password".toCharArray());
            return keyStore;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
