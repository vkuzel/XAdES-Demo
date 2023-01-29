package xmldsig;

import https.vkuzel_com.xades_demo.DocumentToSign;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBElement;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static document.DocumentTransformer.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static utils.DocumentFactory.*;
import static utils.KeyFactory.getCertificate;
import static utils.KeyFactory.getPrivateKey;

class XMLDSigSignerTest {

    @Test
    void signEnveloped() {
        Certificate certificate = getCertificate();
        PrivateKey privateKey = getPrivateKey();
        XMLDSigSigner signer = new XMLDSigSigner(certificate, privateKey);
        Document document = toDocument(createJaxbElementToSign());
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        JAXBElement<DocumentToSign> signedJaxbElement = fromDocument(signed, DocumentToSign.class);
        assertNotNull(signedJaxbElement.getValue());
        DocumentToSign signedDocument = signedJaxbElement.getValue();
        assertEquals(NUMERIC_VALUE, signedDocument.getNumericArgument());
        assertEquals(STRING_VALUE, signedDocument.getStringArgument());
        assertEquals(TIME_VALUE, signedDocument.getTimeArgument());
        assertNotNull(signedDocument.getSignature());
        assertNotNull(signedDocument.getSignature().getSignedInfo());
        assertEquals(1, signedDocument.getSignature().getSignedInfo().getReference().size());
    }
}