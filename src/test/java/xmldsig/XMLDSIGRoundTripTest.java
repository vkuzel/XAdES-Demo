package xmldsig;

import document.DocumentTransformer;
import https.vkuzel_com.xades_demo.DocumentToSign;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import javax.xml.bind.JAXBElement;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static document.DocumentTransformer.*;
import static utils.DocumentFactory.createDocumentToSign;
import static utils.KeyFactory.getCertificate;
import static utils.KeyFactory.getPrivateKey;

public class XMLDSIGRoundTripTest {

    private final Certificate certificate = getCertificate();
    private final PrivateKey privateKey = getPrivateKey();
    private final XMLDSIGSigner signer = new XMLDSIGSigner(certificate, privateKey);
    private final XMLDSIGValidator validator = new XMLDSIGValidator();

    @Test
    void roundTripToDocument() throws XMLDSIGValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));

        validator.validate(signed);
    }

    @Test
    void roundTripToBytes() throws XMLDSIGValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        byte[] content = toBytes(signed);
        Document signedTransformed = fromBytes(content);

        validator.validate(signedTransformed);
    }

    @Test
    void roundTripToString() throws XMLDSIGValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        String content = DocumentTransformer.toString(signed);
        Document signedTransformed = fromString(content);

        validator.validate(signedTransformed);
    }

    @Test
    void roundTripToJaxbElement() throws XMLDSIGValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        JAXBElement<DocumentToSign> jaxbElement = DocumentTransformer.fromDocument(signed, DocumentToSign.class);
        Document signedTransformed = toDocument(jaxbElement);
        System.out.printf("*** Document after transformation:%n%s%n%n", toPrettyString(signed));

        validator.validate(signedTransformed);
    }
}
