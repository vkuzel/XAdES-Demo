package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import java.security.PrivateKey;
import java.security.cert.Certificate;

import static utils.DocumentUtils.*;
import static utils.KeyUtils.getCertificate;
import static utils.KeyUtils.getPrivateKey;

public class XMLDSIGIT {

    @Test
    void roundtrip() throws XMLDSIGValidationException {
        Certificate certificate = getCertificate();
        PrivateKey privateKey = getPrivateKey();
        XMLDSIGSigner signer = new XMLDSIGSigner(certificate, privateKey);
        XMLDSIGValidator validator = new XMLDSIGValidator();
        Document document = marshal(createDocumentToSign());
        System.out.printf("*** Document before signing:%n%s%n%n", pretty(document));

        Document signed = signer.signEnveloped(document);

        System.out.printf("*** Document after signing:%n%s%n%n", pretty(signed));

        validator.validate(signed);
    }
}
