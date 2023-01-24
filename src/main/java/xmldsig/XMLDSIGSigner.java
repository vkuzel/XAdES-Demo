package xmldsig;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.DigestMethodParameterSpec;
import javax.xml.crypto.dsig.spec.SignatureMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.List;

public class XMLDSIGSigner {

    // Removes "enveloped signature" from a document, so the signature element itself is not digested
    private static final String TRANSFORM_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    // Canonicals (normalizes) a document. Preserves comments. E.g. removes line feeds, normalizes attributes, CDATA, etc.
    private static final String CANONICALIZATION_ALGORITHM = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
    private static final String DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String SIGN_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private static final C14NMethodParameterSpec EMPTY_C14N_PARAMS = null;
    private static final DigestMethodParameterSpec EMPTY_DIGEST_PARAMS = null;
    private static final SignatureMethodParameterSpec EMPTY_SIGN_PARAMS = null;
    private static final TransformParameterSpec EMPTY_TRANSFORM_PARAMS = null;

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
            XMLSignatureFactory xmlSignatureFactory = XMLSignatureFactory.getInstance("DOM", "XMLDSig");

            SignedInfo signedInfo = createSignedInfo(xmlSignatureFactory);
            KeyInfo keyInfo = createKeyInfo(xmlSignatureFactory);
            XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, null, null, null);

            Element rootNode = document.getDocumentElement();
            DOMSignContext domSignContext = new DOMSignContext(privateKey, rootNode);
            xmlSignature.sign(domSignContext);

            return document;
        } catch (MarshalException | InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                 XMLSignatureException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }

    private static SignedInfo createSignedInfo(XMLSignatureFactory xmlSignatureFactory) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        CanonicalizationMethod c14nMethod = xmlSignatureFactory.newCanonicalizationMethod(CANONICALIZATION_ALGORITHM, EMPTY_C14N_PARAMS);
        DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(DIGEST_ALGORITHM, EMPTY_DIGEST_PARAMS);
        SignatureMethod signMethod = xmlSignatureFactory.newSignatureMethod(SIGN_ALGORITHM, EMPTY_SIGN_PARAMS);

        // Before calculating digest (hash) the document is transformed into
        // its canonical (normalized) form so the digest is consistent even
        // if document is reformatted, etc.
        List<Transform> transforms = List.of(
                xmlSignatureFactory.newTransform(TRANSFORM_ALGORITHM, EMPTY_TRANSFORM_PARAMS),
                xmlSignatureFactory.newTransform(CANONICALIZATION_ALGORITHM, EMPTY_TRANSFORM_PARAMS)
        );

        // Empty URI points to the root element. Otherwise, the URI would have to point to a signed element.
        Reference referenceDoc = xmlSignatureFactory.newReference("", digestMethod, transforms, null, null);
        List<Reference> references = List.of(referenceDoc);

        return xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);
    }

    private KeyInfo createKeyInfo(XMLSignatureFactory xmlSignatureFactory) {
        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(List.of(certificate));
        return keyInfoFactory.newKeyInfo(List.of(x509Data));
    }
}
