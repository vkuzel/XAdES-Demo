package xades;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;
import xades.XAdESValidator.XAdESValidationException;

import static document.DocumentTransformer.toPrettyString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static utils.DocumentFactory.createXadesSignedChangedDocument;
import static utils.DocumentFactory.createXadesSignedDocument;

public class XAdESValidatorTest {

    private final XAdESValidator validator = new XAdESValidator();

    @Test
    void validate() throws XAdESValidationException {
        Document signedDocument = createXadesSignedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        validator.validate(signedDocument);
    }

    @Test
    void validateThrowsExceptionForChangedDocument() {
        Document signedDocument = createXadesSignedChangedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        assertThrows(XAdESValidationException.class, () -> validator.validate(signedDocument));
    }
}
