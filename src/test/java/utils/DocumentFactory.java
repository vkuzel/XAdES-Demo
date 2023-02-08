package utils;

import https.github_com.vkuzel.xades_demo.ObjectFactory;
import https.github_com.vkuzel.xades_demo.SingableDocumentType;
import org.w3c.dom.Document;

import javax.xml.bind.JAXBElement;
import java.io.IOException;
import java.io.InputStream;

import static document.DocumentTransformer.fromBytes;
import static document.DocumentTransformer.toDocument;
import static java.util.Objects.requireNonNull;

public class DocumentFactory {

    public static final String SOME_VALUE = "some-value";

    public static Document createDocumentToSign() {
        ObjectFactory objectFactory = new ObjectFactory();
        SingableDocumentType singableDocument = objectFactory.createSingableDocumentType();
        singableDocument.setSomeElement(SOME_VALUE);
        JAXBElement<SingableDocumentType> docToSign = objectFactory.createSingableDocument(singableDocument);
        return toDocument(docToSign);
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

    public static Document createXadesSignedChangedDocument() {
        return loadDocumentFromResource("/xades/signed-changed-document.xml");
    }

    private static Document loadDocumentFromResource(String name) {
        try (InputStream inputStream = DocumentFactory.class.getResourceAsStream(name)) {
            byte[] content = requireNonNull(inputStream).readAllBytes();
            return fromBytes(content);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
