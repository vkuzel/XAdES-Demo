//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.01.23 at 08:05:01 PM CET 
//


package https.vkuzel_com.xades_demo;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the https.vkuzel_com.xades_demo package. 
 * <p>An ObjectFactory allows you to programatically 
 * construct new instances of the Java representation 
 * for XML content. The Java representation of XML 
 * content can consist of schema derived interfaces 
 * and classes representing the binding of schema 
 * type definitions, element declarations and model 
 * groups.  Factory methods for each of these are 
 * provided in this class.
 * 
 */
@XmlRegistry
public class ObjectFactory {

    private final static QName _DocToSign_QNAME = new QName("https://vkuzel.com/xades-demo", "docToSign");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: https.vkuzel_com.xades_demo
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link DocumentToSign }
     * 
     */
    public DocumentToSign createDocumentToSign() {
        return new DocumentToSign();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link DocumentToSign }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "https://vkuzel.com/xades-demo", name = "docToSign")
    public JAXBElement<DocumentToSign> createDocToSign(DocumentToSign value) {
        return new JAXBElement<DocumentToSign>(_DocToSign_QNAME, DocumentToSign.class, null, value);
    }

}