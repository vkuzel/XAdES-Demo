package xades;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dom.DOMStructure;
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
import java.util.UUID;

import static java.time.ZonedDateTime.now;
import static java.time.format.DateTimeFormatter.ISO_OFFSET_DATE_TIME;
import static java.util.Collections.singletonList;

public class XAdESSigner {

    // Removes "enveloped signature" from a document, so the signature element itself is not digested
    private static final String ENVELOPED_SIGNATURE_TRANSFORM_ALGORITHM = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
    // Canonicals (normalizes) a document. Preserves comments. E.g. removes line feeds, normalizes attributes, CDATA, etc.
    private static final String C14N_CANONICALIZATION_ALGORITHM = "http://www.w3.org/2006/12/xml-c14n11#WithComments";
    private static final String SHA256_DIGEST_ALGORITHM = "http://www.w3.org/2001/04/xmlenc#sha256";
    private static final String RSA_SHA256_SIGN_ALGORITHM = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

    private static final C14NMethodParameterSpec EMPTY_C14N_PARAMS = null;
    private static final DigestMethodParameterSpec EMPTY_DIGEST_PARAMS = null;
    private static final SignatureMethodParameterSpec EMPTY_SIGN_PARAMS = null;
    private static final TransformParameterSpec EMPTY_TRANSFORM_PARAMS = null;

    private final Certificate certificate;
    private final PrivateKey privateKey;
    private final XMLSignatureFactory xmlSignatureFactory;

    public XAdESSigner(Certificate certificate, PrivateKey privateKey) {
        this.certificate = certificate;
        this.privateKey = privateKey;
        this.xmlSignatureFactory = signatureFactory();
    }

    public Document signEnveloped(Document document) {
        try {
            String signatureId = "signature-" + UUID.randomUUID();
            String qualifyingPropertiesId = "ql-" + UUID.randomUUID();

            SignedInfo signedInfo = createSignedInfo(qualifyingPropertiesId);
            KeyInfo keyInfo = createKeyInfo();
            XMLObject qualifyingProperties = createQualifyingProperties(document, qualifyingPropertiesId, signatureId);

            // TODO Proper namespace: XMLSignature.XMLNS
            XMLSignature xmlSignature = xmlSignatureFactory.newXMLSignature(signedInfo, keyInfo, List.of(qualifyingProperties), signatureId, null);

            Element rootNode = document.getDocumentElement();
            DOMSignContext domSignContext = new DOMSignContext(privateKey, rootNode);
            xmlSignature.sign(domSignContext);

            return document;
        } catch (MarshalException | InvalidAlgorithmParameterException | NoSuchAlgorithmException |
                 XMLSignatureException e) {
            throw new RuntimeException(e);
        }
    }

    private SignedInfo createSignedInfo(String qualifyingPropertiesId) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        CanonicalizationMethod c14nMethod = xmlSignatureFactory.newCanonicalizationMethod(C14N_CANONICALIZATION_ALGORITHM, EMPTY_C14N_PARAMS);
        SignatureMethod signMethod = xmlSignatureFactory.newSignatureMethod(RSA_SHA256_SIGN_ALGORITHM, EMPTY_SIGN_PARAMS);

        List<Reference> references = List.of(
                createSignedDocumentReference(),
                createQualifyingPropertiesReference(qualifyingPropertiesId)
        );

        return xmlSignatureFactory.newSignedInfo(c14nMethod, signMethod, references);
    }

    /**
     * This reference points to the document / element we are signing.
     * <p>
     * Because signature is _enveloped_, the signed element is the root element
     * of the document.
     */
    private Reference createSignedDocumentReference() throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(SHA256_DIGEST_ALGORITHM, EMPTY_DIGEST_PARAMS);
        // Because the signature is enveloped (included) in the signed document
        // it has to be removed before calculating digest. E.g. for signature
        // verification. This transformation does exactly that.
        Transform envelopedSignatureTransform = xmlSignatureFactory.newTransform(ENVELOPED_SIGNATURE_TRANSFORM_ALGORITHM, EMPTY_TRANSFORM_PARAMS);
        // Before calculating digest the document has to be normalized. This
        // canonicalization algorithm normalizes line feeds, etc. but prevents
        // comments.
        Transform c14nWithCommentsTransform = xmlSignatureFactory.newTransform(C14N_CANONICALIZATION_ALGORITHM, EMPTY_TRANSFORM_PARAMS);

        List<Transform> transforms = List.of(envelopedSignatureTransform, c14nWithCommentsTransform);

        // Empty URI points to the root element. Otherwise, the URI would have to point to a signed element.
        return xmlSignatureFactory.newReference("", digestMethod, transforms, null, null);
    }

    /**
     * This reference points to the XAdES qualifying properties data.
     * <p>
     * The properties have to be digested / signed as well to prevent them from
     * changing.
     */
    private Reference createQualifyingPropertiesReference(String qualifyingPropertiesId) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException {
        DigestMethod digestMethod = xmlSignatureFactory.newDigestMethod(SHA256_DIGEST_ALGORITHM, EMPTY_DIGEST_PARAMS);
        Transform c14nWithCommentsTransform = xmlSignatureFactory.newTransform(C14N_CANONICALIZATION_ALGORITHM, EMPTY_TRANSFORM_PARAMS);

        List<Transform> transforms = List.of(c14nWithCommentsTransform);

        return xmlSignatureFactory.newReference("#" + qualifyingPropertiesId, digestMethod, transforms, null, null);
    }

    private KeyInfo createKeyInfo() {
        KeyInfoFactory keyInfoFactory = xmlSignatureFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(List.of(certificate));
        return keyInfoFactory.newKeyInfo(List.of(x509Data));
    }

    private XMLObject createQualifyingProperties(Document document, String qualifyingPropertiesId, String signatureId) {
        Element qualifyingPropertiesElement = createQualifyingPropertiesAttrs(document, qualifyingPropertiesId, signatureId);
        DOMStructure qualifyingPropertiesObject = new DOMStructure(qualifyingPropertiesElement);
        return xmlSignatureFactory.newXMLObject(singletonList(qualifyingPropertiesObject), null, null, null);
    }

    private Element createQualifyingPropertiesAttrs(Document document, String qualifyingPropertiesId, String signatureId) {
        String signingTime = ISO_OFFSET_DATE_TIME.format(now());

        Element qualifyingPropertiesElement = document.createElement("QualifyingProperties");
        qualifyingPropertiesElement.setAttribute("Id", qualifyingPropertiesId);
        qualifyingPropertiesElement.setIdAttribute("Id", true);
        qualifyingPropertiesElement.setAttribute("Target", "#" + signatureId);

        Element signedPropertiesElement = document.createElement("SignedProperties");
        Element signedSignaturePropertiesElement = document.createElement("SignedSignatureProperties");
        Element signingTimeElement = document.createElement("SigningTime");
        signingTimeElement.setTextContent(signingTime);

        qualifyingPropertiesElement.appendChild(signedPropertiesElement);
        signedPropertiesElement.appendChild(signedSignaturePropertiesElement);
        signedSignaturePropertiesElement.appendChild(signingTimeElement);

        return qualifyingPropertiesElement;
    }

    private XMLSignatureFactory signatureFactory() {
        try {
            return XMLSignatureFactory.getInstance("DOM", "XMLDSig");
        } catch (NoSuchProviderException e) {
            throw new RuntimeException(e);
        }
    }
}
