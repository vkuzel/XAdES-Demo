package xades;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.crypto.*;
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
import java.util.List;
import java.util.Objects;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class XAdESValidator {

    public void validate(Document document) throws XAdESValidationException {
        NodeList qualifyingPropertiesNodeList = document.getElementsByTagName("QualifyingProperties");
        nodeStream(qualifyingPropertiesNodeList)
                .filter(Objects::nonNull)
                .map(e -> (Element) e)
                .forEach(e -> e.setIdAttribute("Id", true));

        NodeList nodeListSignature = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
        if (nodeListSignature.getLength() == 0) throw new XAdESValidationException("No signature found!");

        DOMValidateContext domValidateContext = new DOMValidateContext(new KeyValueKeySelector(), nodeListSignature.item(0));

        XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM");

        XMLSignature xmlSignature;
        try {
            xmlSignature = xmlSignatureFactory.unmarshalXMLSignature(domValidateContext);
        } catch (MarshalException e) {
            throw new IllegalStateException(e);
        }

        try {
            if (!xmlSignature.validate(domValidateContext)) {
                throw new XAdESValidationException("Signature is invalid!");
            }
        } catch (XMLSignatureException e) {
            throw new XAdESValidationException(e);
        }
    }

    private Stream<Node> nodeStream(NodeList nodeList) {
        if (nodeList == null) return Stream.of();
        return IntStream.range(0, nodeList.getLength())
                .mapToObj(nodeList::item);
    }

    private static class KeyValueKeySelector extends KeySelector {

        public KeySelectorResult select(
                KeyInfo keyInfo,
                KeySelector.Purpose purpose,
                AlgorithmMethod method,
                XMLCryptoContext context
        ) throws KeySelectorException {
            if (keyInfo == null) {
                throw new KeySelectorException("KeyInfo is null");
            }

            for (XMLStructure keyInfoItem : keyInfo.getContent()) {
                if (keyInfoItem instanceof KeyValue keyValue) {
                    PublicKey publicKey = getPublicKeyFromKeyValue(keyValue);
                    return () -> publicKey;
                } else if (keyInfoItem instanceof X509Data x509Data) {
                    PublicKey publicKey = findPublicKeyInX509Data(x509Data);
                    if (publicKey != null) return () -> publicKey;
                }
            }

            throw new KeySelectorException("No PublicKey found in key info " + keyInfo);
        }

        private static PublicKey getPublicKeyFromKeyValue(KeyValue keyValue) {
            try {
                return keyValue.getPublicKey();
            } catch (KeyException e) {
                throw new IllegalStateException(e);
            }
        }

        private static PublicKey findPublicKeyInX509Data(X509Data x509Data) {
            List<?> x509DataContent = x509Data.getContent();
            for (Object x509Item : x509DataContent) {
                if (x509Item instanceof Certificate certificate) {
                    return certificate.getPublicKey();
                }
            }
            return null;
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
