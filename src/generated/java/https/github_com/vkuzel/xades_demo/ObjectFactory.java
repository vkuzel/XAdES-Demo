//
// This file was generated by the JavaTM Architecture for XML Binding(JAXB) Reference Implementation, v2.2.8-b130911.1802 
// See <a href="http://java.sun.com/xml/jaxb">http://java.sun.com/xml/jaxb</a> 
// Any modifications to this file will be lost upon recompilation of the source schema. 
// Generated on: 2023.02.06 at 10:19:29 PM CET 
//


package https.github_com.vkuzel.xades_demo;

import javax.xml.bind.JAXBElement;
import javax.xml.bind.annotation.XmlElementDecl;
import javax.xml.bind.annotation.XmlRegistry;
import javax.xml.namespace.QName;


/**
 * This object contains factory methods for each 
 * Java content interface and Java element interface 
 * generated in the https.github_com.vkuzel.xades_demo package. 
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

    private final static QName _SingableDocument_QNAME = new QName("https://github.com/vkuzel/XAdES-Demo", "singableDocument");

    /**
     * Create a new ObjectFactory that can be used to create new instances of schema derived classes for package: https.github_com.vkuzel.xades_demo
     * 
     */
    public ObjectFactory() {
    }

    /**
     * Create an instance of {@link SingableDocumentType }
     * 
     */
    public SingableDocumentType createSingableDocumentType() {
        return new SingableDocumentType();
    }

    /**
     * Create an instance of {@link JAXBElement }{@code <}{@link SingableDocumentType }{@code >}}
     * 
     */
    @XmlElementDecl(namespace = "https://github.com/vkuzel/XAdES-Demo", name = "singableDocument")
    public JAXBElement<SingableDocumentType> createSingableDocument(SingableDocumentType value) {
        return new JAXBElement<SingableDocumentType>(_SingableDocument_QNAME, SingableDocumentType.class, null, value);
    }

}
