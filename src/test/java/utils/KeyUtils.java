package utils;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class KeyUtils {

    private static final KeyStore keyStore = loadKeyStore();

    public static Certificate getCertificate() {
        try {
            return keyStore.getCertificate("selfsigned");
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }

    public static PrivateKey getPrivateKey() {
        try {
            Key key = keyStore.getKey("selfsigned", "password".toCharArray());
            if (key instanceof PrivateKey privateKey) {
                return privateKey;
            }
            throw new IllegalArgumentException("Private key not found!");
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    private static KeyStore loadKeyStore() {
        try (InputStream keyStoreStream = KeyUtils.class.getResourceAsStream("/xmldsig/keystore.jks")) {
            KeyStore keyStore = KeyStore.getInstance("JKS");
            keyStore.load(keyStoreStream, "password".toCharArray());
            return keyStore;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new RuntimeException(e);
        }
    }
}
