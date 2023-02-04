# XML Signature & XAdES Demo

[**XML signature (XMLDSig)**](http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/) defines a syntax for signing XML documents.

In short, a digest (hash) is calculated from normalized (canonicalized) version of a document, the digest is signed and signature details are placed into the `<Signature>` element. The signature element is then placed (enveloped) into the signed document.

The XMLDSig does not sign the signing certificate itself. Because single public key can be used in multiple certificates, there is a risk that certificate may be replaced in the signed document.

This issue (among others) is solved by [**XAdES**](https://www.w3.org/TR/XAdES/) which extends XMLDSig and adds signed information about the signing certificate into the extensible  XMLDSig's `<Object>` element.

This demo application shows:

1. Document definition (XSD) for a document to be sign. With enveloped signature element in `xsd/document.xsd`.
2. `xjc` generated DTOs. From which a `Document` for signing is prepared. E.g. `xjc-generate-classes.sh`
3. XMLDSig signing and validation in the `XMLDSIGRoundTripTest`
4. XAdES signing and validation in the `XAdESRoundTripTest`

## XMLDSig signed document

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<!-- Signed document -->
<docToSign xmlns="https://vkuzel.com/xades-demo" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#">
    <!-- Content of the signed document -->
    <numericArgument>1</numericArgument>
    <stringArgument>string-value</stringArgument>
    <timeArgument>2000-01-01T01:01:01.000Z</timeArgument>
    <!-- Embedded signature. The signed document can be also wrapped in a signa
    ture or a signature can be placed in a separate document. -->
    <ns2:Signature>
        <ns2:SignedInfo>
            <ns2:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11#WithComments"/>
            <ns2:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <!-- Reference to the signed document. Empty URI attribute points
             to the root element of the current document. -->
            <ns2:Reference URI="">
                <!-- List of transformations performed before digest value is
                 calculated. E.g. remove line feeds, etc... -->
                <ns2:Transforms>
                    <!-- Remove signature element (if there is any) -->
                    <ns2:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
                    <!-- Normalize document. Remove line feeds, etc. but 
                     preserve comments. -->
                    <ns2:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11#WithComments"/>
                </ns2:Transforms>
                <ns2:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ns2:DigestValue>99XoijRJvFYlc/340OJDwK8kv9LnmD2xkCtcbyP96M8=</ns2:DigestValue>
            </ns2:Reference>
        </ns2:SignedInfo>
        <ns2:SignatureValue>lo4vdHDqEx2nWrIBxViOWyUpCynGBYSV3VPh...</ns2:SignatureValue>
        <ns2:KeyInfo>
            <ns2:X509Data>
                <ns2:X509Certificate>MIIDRTCCAi2gAwIBAgIEQjgraj...</ns2:X509Certificate>
            </ns2:X509Data>
        </ns2:KeyInfo>
    </ns2:Signature>
</docToSign>
```

## XAdES signed document

```xml
<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<docToSign xmlns="https://vkuzel.com/xades-demo" xmlns:ns2="http://www.w3.org/2000/09/xmldsig#">
    <numericArgument>1</numericArgument>
    <stringArgument>string-value</stringArgument>
    <timeArgument>2000-01-01T01:01:01.000Z</timeArgument>
    <ns2:Signature Id="signature-3c8cde91-c052-4abe-a7f9-6c3f71f3a1d4">
        <ns2:SignedInfo>
            <ns2:CanonicalizationMethod Algorithm="http://www.w3.org/2006/12/xml-c14n11#WithComments"/>
            <ns2:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
            <ns2:Reference URI=""><!-- Same reference to the signed document as in XMLDSig --></ns2:Reference>
            <!-- Reference to the signed properties. Reason for signed 
            properties and in general existence of XAdES is that signle public
            key can be used in multiple certificates. XMLDSig does not ensure
            the certificate was not changed in the signed document (remember
            KeyInfo element is not digested -> signed).
             
            The SignedSignatureProperties element contains certificate identifier. -->
            <ns2:Reference URI="#signed-properties-704f3271-b681-4f35-a8f5-e3c03590d5d7">
                <ns2:Transforms>
                    <ns2:Transform Algorithm="http://www.w3.org/2006/12/xml-c14n11#WithComments"/>
                </ns2:Transforms>
                <ns2:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                <ns2:DigestValue>1YsOF7DZSzBJsARfGBdC9aJMOMJtqLUDdXkqzJJPczI=</ns2:DigestValue>
            </ns2:Reference>
        </ns2:SignedInfo>
        <ns2:SignatureValue><!-- Same as in XMLDSig --></ns2:SignatureValue>
        <ns2:KeyInfo><!-- Same as in XMLDSig --></ns2:KeyInfo>
        <ns2:Object>
            <QualifyingProperties xmlns="http://uri.etsi.org/01903/v1.3.2#" Target="#signature-3c8cde91-c052-4abe-a7f9-6c3f71f3a1d4">
                <SignedProperties Id="signed-properties-704f3271-b681-4f35-a8f5-e3c03590d5d7">
                    <SignedSignatureProperties>
                        <SigningTime>2023-02-04T11:22:09.796+01:00</SigningTime>
                        <SigningCertificate>
                            <Cert>
                                <CertDigest>
                                    <ns2:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
                                    <ns2:DigestValue>2vrrQh8AIWiSe56oTEm5...</ns2:DigestValue>
                                </CertDigest>
                                <IssuerSerial>
                                    <ns2:X509IssuerName>CN=XAdES Demo</ns2:X509IssuerName>
                                    <ns2:X509SerialNumber>15248582071077365500</ns2:X509SerialNumber>
                                </IssuerSerial>
                            </Cert>
                        </SigningCertificate>
                        <SignaturePolicyIdentifier>
                            <SignaturePolicyImplied xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string"/>
                        </SignaturePolicyIdentifier>
                    </SignedSignatureProperties>
                </SignedProperties>
            </QualifyingProperties>
        </ns2:Object>
    </ns2:Signature>
</docToSign>
```
