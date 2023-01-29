# XML Signature & XAdES Demo

[**XML signature (XMLDSig)**](http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/) defines a syntax for signing documents. In short, a `<Signature>` element containing signed document digest, signature of the digest and some additional information about the signed document or signature itself.

[**XAdES**](https://www.w3.org/TR/XAdES/) extends XMLDSig into the domain of non-repudiation. Meaning, the signer cannot later deny signing the document. XAdES syntax is mostly used for commerce in the European Union.

This demo application shows:

1. Signed document definition (XSD) with embedded signature element in `xsd/document.xsd`.
2. `xjc` generated transport objects. From which a `Document` for signing is prepared.
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
        <ns2:SignatureValu>lo4vdHDqEx2nWrIBxViOWyUpCynGBYSV3VPh...</ns2:SignatureValu>
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
<!-- TODO Add correct XAdES signed document -->
<docToSign/>
```
