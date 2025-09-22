# Description

The X509 package implements parsing of the X.509 Certificate specificaion in Swift.
It is intended to be used for writing applications, which rely on certificate authentication and encryption in Swift. 
Especially the verification of SCTs (signed certificate timestamps) is supported.

In addition, handling of public keys is also supported.


# Usage

`import X509`

`let certificate =  try? X509.Certificate.init(pemRepresentation:pemCertificate)`

`let serialNumber = certificate?.serialNumber`


# Dependencies

X509 requires Swift 6.2.

The X509 package depends on the ASN1 package


dependencies: [
        .package(url: "https://github.com/leif-ibsen/ASN1", from: "1.2.0"),
    ],

This package is used to parse the DER encoded data.


# References

* Certificate Transparency: https://www.certificate-transparency.org
* Encoding SCTs: https://letsencrypt.org/2018/04/04/sct-encoding.html#poison
* Manually verifying SCTs: https://blog.pierky.com/certificate-transparency-manually-verify-sct-with-openssl/




