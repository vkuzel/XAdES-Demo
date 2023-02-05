package xmldsig;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyValue;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.KeyException;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

/**
 * Be aware, this validator checks signature of a document against certificate
 * in the signature itself.
 * <p>
 * It does not check whether provided certificate is trusted, expired, revoked,
 * etc. This check has to be implemented in yet, or done separately.
 */
public class XMLDSigValidator {

    public void validate(Document document) throws XMLDSigValidationException {
        try {
            // Find Signature element
            NodeList signatureNodes = document.getElementsByTagNameNS(XMLNS, "Signature");
            if (signatureNodes.getLength() != 1) throw new XMLDSigValidationException("Cannot retrieve Signature");
            Node signatureNode = signatureNodes.item(0);

            // Create a DOMValidateContext and specify a KeyValue KeySelector
            // and document context
            DOMValidateContext validateContext = new DOMValidateContext(new KeyValueKeySelector(), signatureNode);

            // Create a DOM XMLSignatureFactory that will be used to unmarshal the
            // document containing the XMLSignature
            XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");

            XMLSignature signature = xmlSignatureFactory.unmarshalXMLSignature(validateContext);

            // Validate XMLSignature
            if (!signature.validate(validateContext)) {
                String msg = createXMLDSigValidationErrorMessage(validateContext, signature);
                throw new XMLDSigValidationException(msg);
            }
        } catch (MarshalException | XMLSignatureException e) {
            throw new XMLDSigValidationException(e);
        }
    }

    private String createXMLDSigValidationErrorMessage(
            DOMValidateContext validateContext,
            XMLSignature signature
    ) throws XMLSignatureException {
        Map<String, Boolean> components = new LinkedHashMap<>();

        boolean signatureValidity = signature.getSignatureValue().validate(validateContext);
        components.put("signature", signatureValidity);

        for (Reference reference : signature.getSignedInfo().getReferences()) {
            String referenceUri = reference.getURI();
            boolean referenceValidity = reference.validate(validateContext);
            String name = "reference[uri=%s]".formatted(referenceUri);
            components.put(name, referenceValidity);
        }

        return components.entrySet().stream()
                .map(e -> "%s validity: %b".formatted(e.getKey(), e.getValue()))
                .collect(Collectors.joining("\n"));
    }

    /**
     * KeySelector which retrieves the public key out of the
     * KeyValue element and returns it.
     * NOTE: If the key algorithm doesn't match signature algorithm,
     * then the public key will be ignored.
     */
    private static class KeyValueKeySelector extends KeySelector {
        public KeySelectorResult select(
                KeyInfo keyInfo,
                Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context
        ) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }

            for (XMLStructure keyInfoItem : keyInfo.getContent()) {
                PublicKey publicKey = findPublicKey(keyInfoItem);
                if (publicKey == null) continue;
                return () -> publicKey;
            }

            throw new KeySelectorException("No KeyValue element found!");
        }

        private PublicKey findPublicKey(XMLStructure keyInfoItem) {
            if (keyInfoItem instanceof KeyValue keyValue) {
                return findPublicKeyFromKeyValue(keyValue);
            } else if (keyInfoItem instanceof X509Data x509Data) {
                return findPublicKeyInX509Data(x509Data);
            } else {
                return null;
            }
        }

        private PublicKey findPublicKeyFromKeyValue(KeyValue keyValue) {
            try {
                return keyValue.getPublicKey();
            } catch (KeyException e) {
                throw new IllegalStateException(e);
            }
        }

        private PublicKey findPublicKeyInX509Data(X509Data x509Data) {
            List<?> x509DataContent = x509Data.getContent();
            for (Object x509Item : x509DataContent) {
                if (x509Item instanceof Certificate certificate) {
                    return certificate.getPublicKey();
                }
            }
            return null;
        }
    }

    public static class XMLDSigValidationException extends Exception {

        public XMLDSigValidationException(String message) {
            super(message);
        }

        public XMLDSigValidationException(Throwable cause) {
            super(cause);
        }
    }
}
