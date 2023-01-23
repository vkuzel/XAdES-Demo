package utils;

import https.vkuzel_com.xades_demo.DocumentToSign;
import https.vkuzel_com.xades_demo.ObjectFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.bind.*;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;
import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.time.ZonedDateTime;
import java.util.GregorianCalendar;

import static java.math.BigInteger.ONE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.xml.transform.OutputKeys.INDENT;

public class DocumentUtils {

    public static final BigInteger NUMERIC_VALUE = ONE;
    public static final String STRING_VALUE = "string-value";
    public static final XMLGregorianCalendar TIME_VALUE = xmlGregorianCalendar("2000-01-01T01:01:01Z");

    public static JAXBElement<DocumentToSign> createDocumentToSign() {
        ObjectFactory objectFactory = new ObjectFactory();
        DocumentToSign document = objectFactory.createDocumentToSign();
        document.setNumericArgument(NUMERIC_VALUE);
        document.setStringArgument(STRING_VALUE);
        document.setTimeArgument(TIME_VALUE);
        return objectFactory.createDocToSign(document);
    }

    public static Document marshal(JAXBElement<?> jaxbElement) {
        try {
            DocumentBuilder documentBuilder = createDocumentBuilder();
            Document document = documentBuilder.newDocument();

            JAXBContext jaxbContext = JAXBContext.newInstance(DocumentToSign.class);
            Marshaller marshaller = jaxbContext.createMarshaller();
            marshaller.marshal(jaxbElement, document);
            return document;
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static Document parse(InputStream inputStream) {
        try {
            DocumentBuilder documentBuilder = createDocumentBuilder();
            return documentBuilder.parse(inputStream);
        } catch (IOException | SAXException e) {
            throw new RuntimeException(e);
        }
    }

    private static DocumentBuilder createDocumentBuilder() {
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            return documentBuilderFactory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> JAXBElement<T> unmarshal(Document document, Class<T> type) {
        try {
            JAXBContext jaxbContext = JAXBContext.newInstance(DocumentToSign.class);
            Unmarshaller unmarshaller = jaxbContext.createUnmarshaller();
            return unmarshaller.unmarshal(document, type);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static String pretty(Node node) {
        try {
            Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
            transformer.setOutputProperty(INDENT, "yes");
            transformer.setOutputProperty("{https://xml.apache.org/xslt}indent-amount", "2");

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(node), new StreamResult(outputStream));
            return outputStream.toString(UTF_8);
        } catch (TransformerException e) {
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
