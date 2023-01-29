package xmldsig;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xmldsig.XMLDSigValidator.XMLDSigValidationException;

import static document.DocumentTransformer.toPrettyString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static utils.DocumentFactory.createXmlDigSignedChangedDocument;
import static utils.DocumentFactory.createXmlDigSignedDocument;

class XMLDSigValidatorTest {

    private final XMLDSigValidator validator = new XMLDSigValidator();

    @Test
    void validate() throws XMLDSigValidationException {
        Document signedDocument = createXmlDigSignedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        validator.validate(signedDocument);
    }

    @Test
    void validateThrowsExceptionForChangedDocument() {
        Document signedDocument = createXmlDigSignedChangedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        assertThrows(XMLDSigValidationException.class, () -> validator.validate(signedDocument));
    }
}