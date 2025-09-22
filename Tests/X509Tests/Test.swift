//
//  Test.swift
//  
//
//  Created by Markus on 15.06.24.
//

import Testing
import Foundation

@testable import X509

@Suite("Certificate Copy Tests") struct CertificateCopyTest {

    @Test("Certificate deep Copy")  func certificateDeepCopy() async throws {
        // Write your test here and use APIs like `#expect(...)` to check expected conditions.
        
        let resourceURL = Bundle.module.url(forResource: "www_digicert_com", withExtension: "pem", subdirectory: "Certificates")
        let pemCertificate = (resourceURL.flatMap { try? String(contentsOf: $0, encoding: .utf8) }) ?? ""
        
        try #require(!pemCertificate.isEmpty, "PEM certificate string should not be empty. The file may be missing from the bundle.")
        
        let certificate =  try? X509.Certificate.init(pemRepresentation:pemCertificate)
        
        let newCert = try? X509.Certificate(newCertificate: certificate!)
        
        #expect(certificate?.signatureAlgorithmOid ==  newCert?.signatureAlgorithmOid)
        #expect(certificate?.signatureValue ==  newCert?.signatureValue)
        
        
    }

}

