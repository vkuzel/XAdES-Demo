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
import java.util.Iterator;
import java.util.List;

public class XMLDSIGValidator {

    public void validate(Document document) throws XMLDSIGValidationException {
        try {
            // Find Signature element
            NodeList nl = document.getElementsByTagNameNS(XMLSignature.XMLNS, "Signature");
            if (nl.getLength() == 0) {
                throw new XMLDSIGValidationException("Cannot find Signature element");
            }

            // Create a DOM XMLSignatureFactory that will be used to unmarshal the
            // document containing the XMLSignature
            XMLSignatureFactory fac = XMLSignatureFactory.getInstance("DOM");

            // Create a DOMValidateContext and specify a KeyValue KeySelector
            // and document context
            DOMValidateContext valContext = new DOMValidateContext(new KeyValueKeySelector(), nl.item(0));

            // unmarshal the XMLSignature
            XMLSignature signature = fac.unmarshalXMLSignature(valContext);

            // Validate the generated XMLSignature
            boolean coreValidity = signature.validate(valContext);

            // Check core validation status
            if (!coreValidity) {
                StringBuilder builder = new StringBuilder("Signature failed core validation\n");
                boolean sv = signature.getSignatureValue().validate(valContext);
                builder.append("* signature validation status: ").append(sv).append('\n');
                // check the validation status of each Reference
                Iterator<Reference> i = signature.getSignedInfo().getReferences().iterator();
                for (int j = 0; i.hasNext(); j++) {
                    boolean refValid = i.next().validate(valContext);
                    builder.append("* ref[").append(j).append("] validity status: ").append(refValid).append('\n');
                }
                throw new XMLDSIGValidationException(builder.toString());
            } else {
                System.out.println("Signature passed core validation");
            }
        } catch (MarshalException | XMLSignatureException e) {
            throw new XMLDSIGValidationException(e);
        }
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

    public static class XMLDSIGValidationException extends Exception {

        public XMLDSIGValidationException(String message) {
            super(message);
        }

        public XMLDSIGValidationException(Throwable cause) {
            super(cause);
        }
    }
}
