package xmldsig;

import https.github_com.vkuzel.xades_demo.SingableDocumentType;
import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBElement;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import static document.DocumentTransformer.fromDocument;
import static document.DocumentTransformer.toPrettyString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static utils.DocumentFactory.SOME_VALUE;
import static utils.DocumentFactory.createDocumentToSign;
import static utils.KeyFactory.getCertificate;
import static utils.KeyFactory.getPrivateKey;

class XMLDSigSignerTest {

    @Test
    void signEnveloped() {
        Certificate certificate = getCertificate();
        PrivateKey privateKey = getPrivateKey();
        XMLDSigSigner signer = new XMLDSigSigner(certificate, privateKey);
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        JAXBElement<SingableDocumentType> signedJaxbElement = fromDocument(signed, SingableDocumentType.class);
        assertNotNull(signedJaxbElement.getValue());
        SingableDocumentType signedDocument = signedJaxbElement.getValue();
        assertEquals(SOME_VALUE, signedDocument.getSomeElement());
        assertNotNull(signedDocument.getSignature());
        assertNotNull(signedDocument.getSignature().getSignedInfo());
        assertEquals(1, signedDocument.getSignature().getSignedInfo().getReference().size());
    }
}