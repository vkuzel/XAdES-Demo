package utils;

import https.vkuzel_com.xades_demo.DocumentToSign;
import https.vkuzel_com.xades_demo.ObjectFactory;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBElement;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.time.ZonedDateTime;
import java.util.GregorianCalendar;

import static document.DocumentTransformer.fromBytes;
import static document.DocumentTransformer.toDocument;
import static java.math.BigInteger.ONE;
import static java.util.Objects.requireNonNull;

public class DocumentFactory {

    public static final BigInteger NUMERIC_VALUE = ONE;
    public static final String STRING_VALUE = "string-value";
    public static final XMLGregorianCalendar TIME_VALUE = xmlGregorianCalendar("2000-01-01T01:01:01Z");

    public static Document createDocumentToSign() {
        return toDocument(createJaxbElementToSign());
    }

    private static JAXBElement<DocumentToSign> createJaxbElementToSign() {
        ObjectFactory objectFactory = new ObjectFactory();
        DocumentToSign document = objectFactory.createDocumentToSign();
        document.setNumericArgument(NUMERIC_VALUE);
        document.setStringArgument(STRING_VALUE);
        document.setTimeArgument(TIME_VALUE);
        return objectFactory.createDocToSign(document);
    }

    public static Document createXmlDigSignedDocument() {
        return loadDocumentFromResource("/xmldsig/signed-document.xml");
    }

    public static Document createXmlDigSignedChangedDocument() {
        return loadDocumentFromResource("/xmldsig/signed-changed-document.xml");
    }

    public static Document createXadesSignedDocument() {
        return loadDocumentFromResource("/xades/signed-document.xml");
    }

    private static Document loadDocumentFromResource(String name) {
        try (InputStream inputStream = DocumentFactory.class.getResourceAsStream(name)) {
            byte[] content = requireNonNull(inputStream).readAllBytes();
            return fromBytes(content);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static XMLGregorianCalendar xmlGregorianCalendar(String isoDateTime) {
        try {
            GregorianCalendar gregorianCalendar = GregorianCalendar.from(ZonedDateTime.parse(isoDateTime));
            return DatatypeFactory.newInstance().newXMLGregorianCalendar(gregorianCalendar);
        } catch (DatatypeConfigurationException e) {
            throw new RuntimeException(e);
        }
    }
}
