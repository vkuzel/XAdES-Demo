package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import static utils.DocumentUtils.createXmlDigSignedDocument;

class XMLDSIGValidatorTest {

    @Test
    void validate() throws XMLDSIGValidationException {
        XMLDSIGValidator validator = new XMLDSIGValidator();
        Document signedDocument = createXmlDigSignedDocument();

        validator.validate(signedDocument);
    }
}