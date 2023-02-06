# XML Signature & XAdES Demo

Demo application showing signing and validating XML documents.

* Document definition (XSD) of a document to be signed with enveloped signature in `xsd/document.xsd`.
* `xjc` generated DTOs. From which a `Document` for signing is prepared via `xjc-generate-classes.sh`
* [**XML signature (XMLDSig)**](http://www.w3.org/TR/2002/REC-xmldsig-core-20020212/) signing and validating in `XMLDSigRoundTripTest`.
* [**XML Advanced Electronic Signatures (XAdES)**](https://www.w3.org/TR/XAdES/) signing and validating in `XAdESRoundTripTest`.

Consult the [Creating XM-Signature and XAdES signatures in Java](https://vkuzel.com/creating-xm-signature-and-xades-signatures-in-java) article for more details.
