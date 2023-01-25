package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import static document.DocumentTransformer.toDocument;
import static document.DocumentTransformer.toPrettyString;
import static utils.DocumentUtils.createJaxbElementToSign;
import static utils.KeyUtils.getCertificate;
import static utils.KeyUtils.getPrivateKey;

public class XMLDSIGRoundTripTest {

    @Test
    void roundTrip() throws XMLDSIGValidationException {
        Certificate certificate = getCertificate();
        PrivateKey privateKey = getPrivateKey();
        XMLDSIGSigner signer = new XMLDSIGSigner(certificate, privateKey);
        XMLDSIGValidator validator = new XMLDSIGValidator();
        Document document = toDocument(createJaxbElementToSign());
        System.out.printf("*** Document before signing:%n%s%n%n", toPrettyString(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", toPrettyString(signed));

        validator.validate(signed);
    }
}
