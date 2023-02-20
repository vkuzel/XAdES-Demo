package xades;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import java.security.cert.X509Certificate;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static java.util.Objects.requireNonNull;
import static javax.xml.crypto.dsig.XMLSignature.XMLNS;

/**
 * Be aware, this validator checks signature of a document against certificate
 * in the signature itself.
 * <p>
 * It does not check whether provided certificate is trusted, expired, revoked,
 * etc. This check has to be implemented in yet, or done separately.
 */
public class XAdESValidator {

    public void validate(Document document) throws XAdESValidationException {
        try {
            // When document is deserialized from an XML file, the SignerProperties
            // element ID attribute is not properly marked, which means reference
            // URL to the signed properties does not work. Manual marking it, fixes
            // the issue.
            markSignerPropertiesId(document);

            NodeList signatureNodes = document.getElementsByTagNameNS(XMLNS, "Signature");
            if (signatureNodes.getLength() != 1) throw new XAdESValidationException("Cannot retrieve signature!");
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
                throw new XAdESValidationException(msg);
            }
        } catch (MarshalException | XMLSignatureException e) {
            throw new XAdESValidationException(e);
        }
    }

    private void markSignerPropertiesId(Document document) {
        NodeList signedPropertiesNodeList = document.getElementsByTagName("SignedProperties");
        requireNonNull(signedPropertiesNodeList);
        for (int i = 0; i < signedPropertiesNodeList.getLength(); i++) {
            Node node = signedPropertiesNodeList.item(i);
            if (node instanceof Element element) {
                element.setIdAttribute("Id", true);
            }
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

    private static class KeyValueKeySelector extends KeySelector {

        public KeySelectorResult select(
                KeyInfo keyInfo,
                Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context
        ) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("KeyInfo is null");
            }

            // This algorithm expects X509 certificate to be present in the
            // KeyInfo element. But that's not always the case, because the
            // element is optional or may contain just public key.
            //
            // The XAdES-X_L form introduces CertificateValues element holding
            // certificates. In tha case, the certificate may be obtained from
            // the CertificateValues element.
            for (XMLStructure keyInfoItem : keyInfo.getContent()) {
                if (keyInfoItem instanceof X509Data x509Data) {
                    List<?> x509DataContent = x509Data.getContent();
                    for (Object x509Item : x509DataContent) {
                        if (x509Item instanceof X509Certificate certificate) {
                            return certificate::getPublicKey;
                        }
                    }
                }
            }

            throw new KeySelectorException("No PublicKey found in key info " + keyInfo);
        }
    }

    public static class XAdESValidationException extends Exception {

        public XAdESValidationException(String message) {
            super(message);
        }

        public XAdESValidationException(Throwable cause) {
            super(cause);
        }
    }
}
