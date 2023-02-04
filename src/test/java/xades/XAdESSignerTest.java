package xades;

import https.vkuzel_com.xades_demo.DocumentToSign;
import org.junit.jupiter.api.Test;
import org.w3._2000._09.xmldsig_.KeyInfoType;
import org.w3._2000._09.xmldsig_.ObjectType;
import org.w3._2000._09.xmldsig_.ReferenceType;
import org.w3._2000._09.xmldsig_.SignedInfoType;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBElement;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.List;

import static document.DocumentTransformer.fromDocument;
import static document.DocumentTransformer.toPrettyString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static utils.DocumentFactory.*;
import static utils.KeyFactory.getCertificate;
import static utils.KeyFactory.getPrivateKey;

public class XAdESSignerTest {

    @Test
    void signEnveloped() {
        X509Certificate certificate = getCertificate();
        PrivateKey privateKey = getPrivateKey();
        XAdESSigner signer = new XAdESSigner(certificate, privateKey);
        Document document = createDocumentToSign();
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));
        JAXBElement<DocumentToSign> signedJaxbElement = fromDocument(signed, DocumentToSign.class);
        assertNotNull(signedJaxbElement.getValue());
        DocumentToSign signedDocument = signedJaxbElement.getValue();
        assertEquals(NUMERIC_VALUE, signedDocument.getNumericArgument());
        assertEquals(STRING_VALUE, signedDocument.getStringArgument());
        assertEquals(TIME_VALUE, signedDocument.getTimeArgument());
        // <Signature>
        assertNotNull(signedDocument.getSignature());
        // <SignedInfo>
        SignedInfoType signedInfo = signedDocument.getSignature().getSignedInfo();
        assertNotNull(signedInfo);
        assertEquals(2, signedInfo.getReference().size());
        ReferenceType signedDocumentReference = signedInfo.getReference().get(0);
        assertNotNull(signedDocumentReference.getDigestValue());
        ReferenceType qualifyingPropertiesReference = signedInfo.getReference().get(1);
        assertNotNull(qualifyingPropertiesReference.getDigestValue());
        // <KeyInfo>
        KeyInfoType keyInfo = signedDocument.getSignature().getKeyInfo();
        assertNotNull(keyInfo);
        // <Object>
        List<ObjectType> objects = signedDocument.getSignature().getObject();
        assertNotNull(objects);
        assertEquals(1, objects.size());
        assertEquals(1, objects.get(0).getContent().size());
        Element qualifyingPropertiesElement = (Element) objects.get(0).getContent().get(0);
        assertEquals(1, qualifyingPropertiesElement.getElementsByTagName("SigningTime").getLength());
        assertEquals(1, qualifyingPropertiesElement.getElementsByTagName("SigningCertificate").getLength());
        assertEquals(1, qualifyingPropertiesElement.getElementsByTagName("SignaturePolicyIdentifier").getLength());
    }
}
