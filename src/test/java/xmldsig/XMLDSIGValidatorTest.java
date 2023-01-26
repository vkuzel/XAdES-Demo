package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import static document.DocumentTransformer.toPrettyString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static utils.DocumentFactory.createXmlDigSignedChangedDocument;
import static utils.DocumentFactory.createXmlDigSignedDocument;

class XMLDSIGValidatorTest {

    private final XMLDSIGValidator validator = new XMLDSIGValidator();

    @Test
    void validate() throws XMLDSIGValidationException {
        Document signedDocument = createXmlDigSignedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        validator.validate(signedDocument);
    }

    @Test
    void validateThrowsExceptionForChangedDocument() {
        Document signedDocument = createXmlDigSignedChangedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        assertThrows(XMLDSIGValidationException.class, () -> validator.validate(signedDocument));
    }
}