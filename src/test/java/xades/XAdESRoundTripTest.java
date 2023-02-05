package xades;

import document.DocumentTransformer;
import https.github_com.vkuzel.xades_demo.DocumentToSign;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBElement;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import static document.DocumentTransformer.*;
import static utils.DocumentFactory.createDocumentToSign;
import static utils.KeyFactory.getCertificate;
import static utils.KeyFactory.getPrivateKey;

public class XAdESRoundTripTest {

    private final X509Certificate certificate = getCertificate();
    private final PrivateKey privateKey = getPrivateKey();
    private final XAdESSigner signer = new XAdESSigner(certificate, privateKey);
    private final XAdESValidator validator = new XAdESValidator();

    @Test
    void roundTripToDocument() throws XAdESValidator.XAdESValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));

        validator.validate(signed);
    }

    @Test
    void roundTripToBytes() throws XAdESValidator.XAdESValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        byte[] content = toBytes(signed);
        Document signedTransformed = fromBytes(content);

        validator.validate(signedTransformed);
    }

    @Test
    void roundTripToString() throws XAdESValidator.XAdESValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        String content = DocumentTransformer.toString(signed);
        Document signedTransformed = fromString(content);

        validator.validate(signedTransformed);
    }

    @Test
    void roundTripToJaxbElement() throws XAdESValidator.XAdESValidationException {
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        JAXBElement<DocumentToSign> jaxbElement = DocumentTransformer.fromDocument(signed, DocumentToSign.class);
        Document signedTransformed = toDocument(jaxbElement);
        System.out.printf("*** Document after transformation:%n%s%n%n", toPrettyString(signedTransformed));

        validator.validate(signedTransformed);
    }
}
