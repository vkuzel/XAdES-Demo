package xmldsig;

import org.junit.jupiter.api.Test;
import xmldsig.XMLDSIGValidator.XMLDSIGValidationException;

import java.io.IOException;
import java.io.InputStream;

class XMLDSIGValidatorTest {

    @Test
    void validate() throws IOException, XMLDSIGValidationException {
        XMLDSIGValidator validator = new XMLDSIGValidator();

        try (InputStream documentStream = getClass().getResourceAsStream("/xmldsig/signed-document.xml")) {
            validator.validate(documentStream);
        }
    }
}