package xmldsig;

import org.apache.jcp.xml.dsig.internal.dom.XMLDSigRI;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

public class XMLDSIGSigner {

    private static final String TYP_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    private static final String CAN_ALGORITHM = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
    private static final String DIG_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String SIG_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private final Certificate certificate;
    private final PrivateKey privateKey;

    public XMLDSIGSigner(Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
    }

    /**
     * "Envelops" signature into a document's root element.
     * <pre>
     * {@code
     * <document>
     *     ...
     * </document>
     * }
     * </pre>
     * will become
     * <pre>
     * {@code
     * <document>
     *     ...
     *     <ds:Signature>...</ds:Signature>
     * </document>
     * }
     * </pre>
     */
    public Document signEnveloped(Document document) {
        try {
            XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", new XMLDSigRI());
            CanonicalizationMethod c14nMethod = xmlSignatureFactory.newCanonicalizationMethod(CAN_ALGORITHM, (C14NMethodParameterSpec) null);
            DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(DIG_ALGORITHM, null);
            SignatureMethod signMethod = xmlSignatureFactory.newSignatureMethod(SIG_ALGORITHM, null);
            Transform sigTransform = xmlSignatureFactory.newTransform(TYP_ALGORITHM, (TransformParameterSpec) null);
            Transform canTransform = xmlSignatureFactory.newTransform(CAN_ALGORITHM, (TransformParameterSpec) null);

            List<Transform> transforms = List.of(sigTransform, canTransform);

            // Empty URI points to the root element. Otherwise, the URI would have to point to a signed element.
            Reference referenceDoc = xmlSignatureFactory.newReference("", digestMethod, transforms, null, null);

            List<Reference> references = List.of(referenceDoc);

            SignedInfo signedInfo = xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);

            KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
            X509Data x509Data = keyInfoFactory.newX509Data(List.of(certificate));
            KeyInfo keyInfo = keyInfoFactory.newKeyInfo(List.of(x509Data));

            XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, null, null, null);
            Element rootNode = document.getDocumentElement();

            DOMSignContext domSignContext = new DOMSignContext(privateKey, rootNode);

            xmlSignature.sign(domSignContext);

            return document;
        } catch (MarshalException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | XMLSignatureException e) {
            throw new RuntimeException(e);
        }
    }
}
