package xades;

import org.junit.jupiter.api.Test;
import org.w3c.dom.Document;

import static document.DocumentTransformer.toPrettyString;
import static utils.DocumentFactory.createXadesSignedDocument;

public class XAdESValidatorTest {

    @Test
    void validate() throws XAdESValidator.XAdESValidationException {
        XAdESValidator validator = new XAdESValidator();
        Document signedDocument = createXadesSignedDocument();
        System.out.printf("Doc: " + toPrettyString(signedDocument));

        validator.validate(signedDocument);
    }
}
