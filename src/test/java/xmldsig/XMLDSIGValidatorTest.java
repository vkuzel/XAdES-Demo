package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import utils.DocumentUtils;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import java.io.IOException;
import java.io.InputStream;

class XMLDSIGValidatorTest {

    @Test
    void validate() throws XMLDSIGValidationException {
        XMLDSIGValidator validator = new XMLDSIGValidator();
        Document signedDocument = getSignedDocument();

        validator.validate(signedDocument);
    }

    private Document getSignedDocument() {
        try (InputStream inputStream = getClass().getResourceAsStream("/xmldsig/signed-document.xml")) {
            return DocumentUtils.parse(inputStream);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}