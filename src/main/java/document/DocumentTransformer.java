package document;

import https.vkuzel_com.xades_demo.DocumentToSign;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.bind.*;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static javax.xml.transform.OutputKeys.INDENT;

@SuppressWarnings("unused")
public class DocumentTransformer {

    public static String toString(Node node) {
        return new String(toBytes(node), UTF_8);
    }

    public static String toPrettyString(Node node) {
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

    public static byte[] toBytes(Node node) {
        try {
            Transformer transformer = TransformerFactory.newDefaultInstance().newTransformer();
            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            transformer.transform(new DOMSource(node), new StreamResult(outputStream));
            return outputStream.toByteArray();
        } catch (TransformerException e) {
            throw new RuntimeException(e);
        }
    }

    public static Document toDocument(JAXBElement<?> jaxbElement) {
        try {
            Marshaller marshaller = createMarshaller();

            DocumentBuilder documentBuilder = createDocumentBuilder();
            Document document = documentBuilder.newDocument();
            marshaller.marshal(jaxbElement, document);
            return document;
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static String toString(JAXBElement<?> jaxbElement) {
        return new String(toBytes(jaxbElement), UTF_8);
    }

    public static byte[] toBytes(JAXBElement<?> jaxbElement) {
        try {
            Marshaller marshaller = createMarshaller();

            ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
            marshaller.marshal(jaxbElement, outputStream);
            return outputStream.toByteArray();
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static Document fromString(String content) {
        return fromBytes(content.getBytes(UTF_8));
    }

    public static Document fromBytes(byte[] content) {
        try (InputStream inputStream = new ByteArrayInputStream(content)) {
            DocumentBuilder documentBuilder = createDocumentBuilder();
            return documentBuilder.parse(inputStream);
        } catch (IOException | SAXException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> JAXBElement<T> fromDocument(Node node, Class<T> type) {
        try {
            Unmarshaller unmarshaller = createUnmarshaller();
            return unmarshaller.unmarshal(node, type);
        } catch (JAXBException e) {
            throw new RuntimeException(e);
        }
    }

    public static <T> JAXBElement<T> fromString(String content, Class<T> type) {
        return fromBytes(content.getBytes(UTF_8), type);
    }

    public static <T> JAXBElement<T> fromBytes(byte[] content, Class<T> type) {
        try (InputStream inputStream = new ByteArrayInputStream(content)) {
            Source source = new StreamSource(inputStream);
            Unmarshaller unmarshaller = createUnmarshaller();
            return unmarshaller.unmarshal(source, type);
        } catch (JAXBException | IOException e) {
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

    private static Marshaller createMarshaller() throws JAXBException {
        JAXBContext jaxbContext = JAXBContext.newInstance(DocumentToSign.class);
        return jaxbContext.createMarshaller();
    }

    private static Unmarshaller createUnmarshaller() throws JAXBException {
        JAXBContext jaxbContext = JAXBContext.newInstance(DocumentToSign.class);
        return jaxbContext.createUnmarshaller();
    }
}
