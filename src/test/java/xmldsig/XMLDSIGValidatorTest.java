package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import static document.DocumentTransformer.toPrettyString;
import static utils.DocumentFactory.createXmlDigSignedDocument;

class XMLDSIGValidatorTest {

    @Test
    void validate() throws XMLDSIGValidationException {
        XMLDSIGValidator validator = new XMLDSIGValidator();
        Document signedDocument = createXmlDigSignedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        validator.validate(signedDocument);
    }
}