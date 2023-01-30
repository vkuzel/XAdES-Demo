package xmldsig;

import org.w3c.dom.Document;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.*;
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

public class XMLDSigValidator {

    public void validate(Document document) throws XMLDSigValidationException {
        try {
            // Find Signature element
            NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new XMLDSigValidationException("Cannot find Signature element");
            }

            // Create a DOM XMLSignatureFactory that will be used to unmarshal the
            // document containing the XMLSignature
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Create a DOMValidateContext and specify a KeyValue KeySelector
            // and document context
            DOMValidateContext validateContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));

            // unmarshal the XMLSignature
            XMLSignature signature = fac.unmarshalXMLSignature(validateContext);

            // Validate the generated XMLSignature
            boolean coreValidity = signature.validate(validateContext);

            // Check core validation status
            if (!coreValidity) {
                String msg = createXMLDSigValidationErrorMessage(validateContext, signature);
                throw new XMLDSigValidationException(msg);
            } else {
                System.out.println("Signature passed core validation");
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
                KeySelector.Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context
        ) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("Null KeyInfo object!");
            }
            SignatureMethod sm = (SignatureMethod) method;
            List<XMLStructure> list = keyInfo.getContent();

            for (XMLStructure xmlStructure : list) {
                if (xmlStructure instanceof KeyValue keyValue) {
                    PublicKey pk;
                    try {
                        pk = keyValue.getPublicKey();
                    } catch (KeyException ke) {
                        throw new KeySelectorException(ke);
                    }
                    // make sure algorithm is compatible with method
                    if (algEquals(sm.getAlgorithm(), pk.getAlgorithm())) {
                        return result(pk);
                    }
                } else if (xmlStructure instanceof X509Data x509Data) {
                    List<?> x509DataContent = x509Data.getContent();
                    for (Object x509Item : x509DataContent) {
                        if (x509Item instanceof Certificate certificate) {
                            PublicKey pk = certificate.getPublicKey();
                            return result(pk);
                        }
                    }
                }
            }
            throw new KeySelectorException("No KeyValue element found!");
        }

        static boolean algEquals(String algURI, String algName) {
            if (algName.equalsIgnoreCase("DSA") &&
                    algURI.equalsIgnoreCase("http://www.w3.org/2009/xmldsig11#dsa-sha256")) {
                return true;
            } else {
                return algName.equalsIgnoreCase("RSA") &&
                        algURI.equalsIgnoreCase("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
            }
        }

        private KeySelectorResult result(PublicKey publicKey) {
            return () -> publicKey;
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
