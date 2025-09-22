import Foundation
import XCTest
import CryptoKit
import BigInt
import ASN1

@testable import X509


final class X509Tests: XCTestCase {
    func testCertificateBasicFields()   {
        
        //       XCTAssertEqual(X509.Certificate().text, "Hello, World!")
        
        // read certificate from file
        
        let resourceURL = Bundle.module.url(forResource: "www_digicert_com", withExtension: "pem", subdirectory: "Certificates")
        let pemCertificate = (resourceURL.flatMap { try? String(contentsOf: $0, encoding: .utf8) }) ?? ""
        
        
        
        let certificate =  try? X509.Certificate.init(pemRepresentation:pemCertificate)
        
        XCTAssertEqual(certificate?.encodedTBSCertificate?.hexEncodedString(separation: ":"), "30:82:07:9F:A0:03:02:01:02:02:10:08:36:BA:A2:55:68:64:17:20:78:58:46:38:D8:5C:34:30:0D:06:09:2A:86:48:86:F7:0D:01:01:0B:05:00:30:75:31:0B:30:09:06:03:55:04:06:13:02:55:53:31:15:30:13:06:03:55:04:0A:13:0C:44:69:67:69:43:65:72:74:20:49:6E:63:31:19:30:17:06:03:55:04:0B:13:10:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:31:34:30:32:06:03:55:04:03:13:2B:44:69:67:69:43:65:72:74:20:53:48:41:32:20:45:78:74:65:6E:64:65:64:20:56:61:6C:69:64:61:74:69:6F:6E:20:53:65:72:76:65:72:20:43:41:30:1E:17:0D:31:38:30:36:32:36:30:30:30:30:30:30:5A:17:0D:32:30:30:36:33:30:31:32:30:30:30:30:5A:30:81:CF:31:1D:30:1B:06:03:55:04:0F:0C:14:50:72:69:76:61:74:65:20:4F:72:67:61:6E:69:7A:61:74:69:6F:6E:31:13:30:11:06:0B:2B:06:01:04:01:82:37:3C:02:01:03:13:02:55:53:31:15:30:13:06:0B:2B:06:01:04:01:82:37:3C:02:01:02:13:04:55:74:61:68:31:15:30:13:06:03:55:04:05:13:0C:35:32:39:39:35:33:37:2D:30:31:34:32:31:0B:30:09:06:03:55:04:06:13:02:55:53:31:0D:30:0B:06:03:55:04:08:13:04:55:74:61:68:31:0D:30:0B:06:03:55:04:07:13:04:4C:65:68:69:31:17:30:15:06:03:55:04:0A:13:0E:44:69:67:69:43:65:72:74:2C:20:49:6E:63:2E:31:0C:30:0A:06:03:55:04:0B:13:03:53:52:45:31:19:30:17:06:03:55:04:03:13:10:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:30:82:02:22:30:0D:06:09:2A:86:48:86:F7:0D:01:01:01:05:00:03:82:02:0F:00:30:82:02:0A:02:82:02:01:00:CE:9F:85:CA:39:30:30:B7:F6:98:69:B4:9C:10:5D:50:3B:25:63:D0:E5:68:D4:D9:A5:CA:2C:D6:35:95:B2:3E:0D:29:8B:9D:E0:81:4A:04:F7:C0:9E:35:49:33:FB:AB:1C:11:8A:96:35:8E:A5:DE:A2:81:E7:AA:49:24:8A:8D:42:6A:3D:36:85:8E:F2:4D:86:FE:34:C8:8C:51:46:A8:D5:98:22:AD:B7:8B:8F:87:A9:A5:E2:D7:F1:FF:69:61:60:6B:39:35:AA:4C:B2:00:E4:10:03:FA:79:E9:B1:BD:9B:93:A4:FC:80:4C:FC:16:67:2E:A5:49:2C:62:4E:C7:D8:A1:80:6D:5D:23:D0:EB:EA:F6:A9:FB:C4:1A:3D:16:AE:DE:DF:6C:11:DD:9C:C5:EE:08:C7:B8:0B:75:A6:06:DE:FC:6C:61:FD:C1:C9:C2:93:48:AB:72:AD:B9:17:D5:0C:B4:76:C4:B1:CB:E1:82:33:61:13:C4:4D:60:31:AE:EF:46:89:90:FD:9A:19:A3:C2:1B:E7:99:05:A7:A9:48:4F:A5:0E:3A:49:1D:CA:22:5D:A5:63:D7:21:96:65:B1:94:79:C2:47:A0:58:3B:09:3F:B5:EF:EE:71:34:58:C9:18:D7:ED:39:88:D6:2D:AF:36:51:86:19:67:07:0D:80:A0:C1:8D:23:EB:6C:05:72:D0:29:E6:5F:58:59:94:DF:46:E1:93:35:FD:F6:99:AF:21:82:77:7F:57:D0:18:B6:A8:E3:89:D0:12:37:64:9C:8B:E9:9B:41:CC:82:F6:A0:60:29:D0:56:79:E1:25:2B:73:C9:8C:F7:DB:87:E5:58:B3:D2:A7:9E:CE:41:E3:4C:B6:BE:8E:E5:6D:07:75:6C:A1:51:95:3E:0F:84:7A:C0:E6:D8:40:C6:79:6E:26:23:46:1B:40:42:33:20:F0:45:50:11:F6:73:11:DA:F4:58:63:B9:25:11:CB:1F:2A:2D:F2:D1:2B:5C:CF:43:88:5E:5C:09:BC:DF:72:37:AE:A2:29:36:48:75:BE:BD:BB:8F:6A:03:22:1D:33:3D:FB:79:6B:D2:84:4E:F9:95:B0:70:CE:DF:26:F9:F5:25:F4:76:3C:32:C0:68:8D:D0:52:FE:CE:2E:14:87:DF:65:1F:42:C9:3E:D4:80:AA:D3:99:B6:1F:04:B1:88:0B:E2:0D:19:79:0D:EE:BA:30:46:43:76:FB:B4:DE:C5:00:41:31:EF:5A:7C:34:32:BE:C9:81:B8:ED:9F:40:DE:50:A2:D8:C2:C4:56:83:EB:29:AA:81:53:24:75:86:6D:BF:51:21:BF:B7:97:17:AF:EE:72:2A:39:02:03:01:00:01:A3:82:03:E6:30:82:03:E2:30:1F:06:03:55:1D:23:04:18:30:16:80:14:3D:D3:50:A5:D6:A0:AD:EE:F3:4A:60:0A:65:D3:21:D4:F8:F8:D6:0F:30:1D:06:03:55:1D:0E:04:16:04:14:6C:B0:43:56:FE:3D:E8:12:EC:D9:12:F5:63:D5:C4:CA:07:AF:B0:76:30:81:91:06:03:55:1D:11:04:81:89:30:81:86:82:10:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:0C:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:14:63:6F:6E:74:65:6E:74:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:17:77:77:77:2E:6F:72:69:67:69:6E:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:12:6C:6F:67:69:6E:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:10:61:70:69:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:0F:77:73:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:30:0E:06:03:55:1D:0F:01:01:FF:04:04:03:02:05:A0:30:1D:06:03:55:1D:25:04:16:30:14:06:08:2B:06:01:05:05:07:03:01:06:08:2B:06:01:05:05:07:03:02:30:75:06:03:55:1D:1F:04:6E:30:6C:30:34:A0:32:A0:30:86:2E:68:74:74:70:3A:2F:2F:63:72:6C:33:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:73:68:61:32:2D:65:76:2D:73:65:72:76:65:72:2D:67:32:2E:63:72:6C:30:34:A0:32:A0:30:86:2E:68:74:74:70:3A:2F:2F:63:72:6C:34:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:73:68:61:32:2D:65:76:2D:73:65:72:76:65:72:2D:67:32:2E:63:72:6C:30:4B:06:03:55:1D:20:04:44:30:42:30:37:06:09:60:86:48:01:86:FD:6C:02:01:30:2A:30:28:06:08:2B:06:01:05:05:07:02:01:16:1C:68:74:74:70:73:3A:2F:2F:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:43:50:53:30:07:06:05:67:81:0C:01:01:30:81:88:06:08:2B:06:01:05:05:07:01:01:04:7C:30:7A:30:24:06:08:2B:06:01:05:05:07:30:01:86:18:68:74:74:70:3A:2F:2F:6F:63:73:70:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:30:52:06:08:2B:06:01:05:05:07:30:02:86:46:68:74:74:70:3A:2F:2F:63:61:63:65:72:74:73:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:44:69:67:69:43:65:72:74:53:48:41:32:45:78:74:65:6E:64:65:64:56:61:6C:69:64:61:74:69:6F:6E:53:65:72:76:65:72:43:41:2E:63:72:74:30:0C:06:03:55:1D:13:01:01:FF:04:02:30:00:30:82:01:7E:06:0A:2B:06:01:04:01:D6:79:02:04:02:04:82:01:6E:04:82:01:6A:01:68:00:76:00:BB:D9:DF:BC:1F:8A:71:B5:93:94:23:97:AA:92:7B:47:38:57:95:0A:AB:52:E8:1A:90:96:64:36:8E:1E:D1:85:00:00:01:64:3E:32:4C:A5:00:00:04:03:00:47:30:45:02:21:00:B6:F7:F1:8C:35:81:BE:99:AA:72:AE:FE:D5:7F:25:3B:2A:8A:50:9F:32:E6:BD:F5:57:89:15:E2:DC:D0:48:F7:02:20:6F:00:02:3A:B0:43:02:C6:E8:E6:DF:80:C7:B4:07:4E:80:C0:CE:CA:D4:91:00:B3:2B:FC:40:FE:6B:FC:43:D4:00:76:00:56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7:46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD:00:00:01:64:3E:32:4C:16:00:00:04:03:00:47:30:45:02:21:00:90:31:D8:53:E3:21:89:B2:14:A5:5B:62:3C:01:72:13:3B:F7:E4:FD:D5:C2:7E:4E:0E:C7:89:98:32:3A:75:99:02:20:26:F8:C7:35:06:07:2E:DA:11:02:89:2C:EB:8C:D4:5D:00:BC:C8:C4:10:1D:4E:41:07:3D:21:61:18:ED:47:4F:00:76:00:87:75:BF:E7:59:7C:F8:8C:43:99:5F:BD:F3:6E:FF:56:8D:47:56:36:FF:4A:B5:60:C1:B4:EA:FF:5E:A0:83:0F:00:00:01:64:3E:32:4D:94:00:00:04:03:00:47:30:45:02:20:52:30:CD:DA:13:17:D3:6C:C1:B5:6E:D2:2E:F8:B0:96:F4:02:E3:E0:54:FA:B1:CC:54:52:0C:B9:F8:E4:87:FE:02:21:00:FB:6A:B2:01:E2:1F:A9:BA:42:69:75:13:DB:26:6A:3C:58:6B:BE:F7:F9:86:5D:C4:C2:9B:B4:41:1E:D9:95:7C")
        
        
        XCTAssertEqual(certificate?.version,3)
        
        XCTAssertEqual(certificate?.serialNumber,BInt("836BAA2556864172078584638D85C34",radix:16))
        XCTAssertEqual(certificate?.serialNumber?.asString(radix: 16,uppercase: true),"836BAA2556864172078584638D85C34")
        
        XCTAssertEqual(certificate?.publicKey?.algorithmName, "rsaEncryption")
        XCTAssertEqual(certificate?.publicKey?.derEncodedKey?.hexEncodedString(separation: ":"), "30:82:02:0A:02:82:02:01:00:CE:9F:85:CA:39:30:30:B7:F6:98:69:B4:9C:10:5D:50:3B:25:63:D0:E5:68:D4:D9:A5:CA:2C:D6:35:95:B2:3E:0D:29:8B:9D:E0:81:4A:04:F7:C0:9E:35:49:33:FB:AB:1C:11:8A:96:35:8E:A5:DE:A2:81:E7:AA:49:24:8A:8D:42:6A:3D:36:85:8E:F2:4D:86:FE:34:C8:8C:51:46:A8:D5:98:22:AD:B7:8B:8F:87:A9:A5:E2:D7:F1:FF:69:61:60:6B:39:35:AA:4C:B2:00:E4:10:03:FA:79:E9:B1:BD:9B:93:A4:FC:80:4C:FC:16:67:2E:A5:49:2C:62:4E:C7:D8:A1:80:6D:5D:23:D0:EB:EA:F6:A9:FB:C4:1A:3D:16:AE:DE:DF:6C:11:DD:9C:C5:EE:08:C7:B8:0B:75:A6:06:DE:FC:6C:61:FD:C1:C9:C2:93:48:AB:72:AD:B9:17:D5:0C:B4:76:C4:B1:CB:E1:82:33:61:13:C4:4D:60:31:AE:EF:46:89:90:FD:9A:19:A3:C2:1B:E7:99:05:A7:A9:48:4F:A5:0E:3A:49:1D:CA:22:5D:A5:63:D7:21:96:65:B1:94:79:C2:47:A0:58:3B:09:3F:B5:EF:EE:71:34:58:C9:18:D7:ED:39:88:D6:2D:AF:36:51:86:19:67:07:0D:80:A0:C1:8D:23:EB:6C:05:72:D0:29:E6:5F:58:59:94:DF:46:E1:93:35:FD:F6:99:AF:21:82:77:7F:57:D0:18:B6:A8:E3:89:D0:12:37:64:9C:8B:E9:9B:41:CC:82:F6:A0:60:29:D0:56:79:E1:25:2B:73:C9:8C:F7:DB:87:E5:58:B3:D2:A7:9E:CE:41:E3:4C:B6:BE:8E:E5:6D:07:75:6C:A1:51:95:3E:0F:84:7A:C0:E6:D8:40:C6:79:6E:26:23:46:1B:40:42:33:20:F0:45:50:11:F6:73:11:DA:F4:58:63:B9:25:11:CB:1F:2A:2D:F2:D1:2B:5C:CF:43:88:5E:5C:09:BC:DF:72:37:AE:A2:29:36:48:75:BE:BD:BB:8F:6A:03:22:1D:33:3D:FB:79:6B:D2:84:4E:F9:95:B0:70:CE:DF:26:F9:F5:25:F4:76:3C:32:C0:68:8D:D0:52:FE:CE:2E:14:87:DF:65:1F:42:C9:3E:D4:80:AA:D3:99:B6:1F:04:B1:88:0B:E2:0D:19:79:0D:EE:BA:30:46:43:76:FB:B4:DE:C5:00:41:31:EF:5A:7C:34:32:BE:C9:81:B8:ED:9F:40:DE:50:A2:D8:C2:C4:56:83:EB:29:AA:81:53:24:75:86:6D:BF:51:21:BF:B7:97:17:AF:EE:72:2A:39:02:03:01:00:01")
        
//        XCTAssertEqual(certificate?.publicKey?.keyValue0?.asString(radix: 16,uppercase: true),"CE9F85CA393030B7F69869B49C105D503B2563D0E568D4D9A5CA2CD63595B23E0D298B9DE0814A04F7C09E354933FBAB1C118A96358EA5DEA281E7AA49248A8D426A3D36858EF24D86FE34C88C5146A8D59822ADB78B8F87A9A5E2D7F1FF6961606B3935AA4CB200E41003FA79E9B1BD9B93A4FC804CFC16672EA5492C624EC7D8A1806D5D23D0EBEAF6A9FBC41A3D16AEDEDF6C11DD9CC5EE08C7B80B75A606DEFC6C61FDC1C9C29348AB72ADB917D50CB476C4B1CBE182336113C44D6031AEEF468990FD9A19A3C21BE79905A7A9484FA50E3A491DCA225DA563D7219665B19479C247A0583B093FB5EFEE713458C918D7ED3988D62DAF3651861967070D80A0C18D23EB6C0572D029E65F585994DF46E19335FDF699AF2182777F57D018B6A8E389D01237649C8BE99B41CC82F6A06029D05679E1252B73C98CF7DB87E558B3D2A79ECE41E34CB6BE8EE56D07756CA151953E0F847AC0E6D840C6796E2623461B40423320F0455011F67311DAF45863B92511CB1F2A2DF2D12B5CCF43885E5C09BCDF7237AEA229364875BEBDBB8F6A03221D333DFB796BD2844EF995B070CEDF26F9F525F4763C32C0688DD052FECE2E1487DF651F42C93ED480AAD399B61F04B1880BE20D19790DEEBA30464376FBB4DEC5004131EF5A7C3432BEC981B8ED9F40DE50A2D8C2C45683EB29AA81532475866DBF5121BFB79717AFEE722A39")
//        
//        XCTAssertEqual(certificate?.publicKey?.keyValue0?.bitWidth,4096)
//        
//        XCTAssertEqual(certificate?.publicKey?.keyValue1?.asString(radix: 16,uppercase: true),"10001")
//        XCTAssertEqual(certificate?.publicKey?.keyValue1?.bitWidth,17)
        
        
        
        XCTAssertEqual(certificate?.signatureAlgorithmOid, "1.2.840.113549.1.1.11")
        XCTAssertEqual(certificate?.signatureAlgorithmName, "sha256WithRSAEncryption")
        XCTAssertEqual(certificate?.signatureAlgorithmParameters, Data())
        
        XCTAssertEqual(certificate?.signatureValue.hexEncodedString(separation: ":"), "8F:71:72:DE:D4:C8:C6:26:DC:1F:8A:1B:88:D5:2E:77:19:DA:24:14:07:25:F7:8A:2E:A1:6C:56:77:B0:12:7E:CB:9F:53:2C:6C:16:BA:31:0E:13:70:C5:DF:26:40:E1:FB:57:77:A1:65:38:A8:B7:A3:FE:C4:C6:4E:AD:8C:60:27:1E:42:5D:B7:0B:B7:4E:D1:64:74:F4:C3:F3:DF:D3:9D:A0:AB:B6:CF:19:B1:EC:AE:3B:65:5E:AD:4C:0E:7F:1C:F0:3F:85:9E:FD:AA:4A:01:38:7F:FF:70:43:58:0C:53:82:0A:A2:36:8E:E1:81:FD:15:8A:1A:70:0F:29:B9:75:25:2B:5A:41:0A:E0:8A:D2:32:72:93:20:2D:0F:DC:F8:A1:30:FF:64:B0:50:3A:64:C9:E1:5C:09:E6:B1:CD:09:F7:48:F1:A9:11:F4:E6:18:CB:1F:46:09:B7:96:62:FE:49:09:C2:32:CC:FC:AF:65:EE:9C:78:80:84:9D:11:A5:89:4F:C4:CE:BC:B2:5A:1A:B8:57:1F:F3:45:E0:60:A1:7E:B1:39:67:D6:D5:90:28:B5:AD:1E:B7:3A:3D:A5:25:A3:39:DA:EB:8F:52:3B:AB:46:C0:84:BD:5E:52:E5:C4:F0:54:A6:E8:CF:19:A2:05:BF:65:89:0E:1C:4D:AE")
        XCTAssertEqual(certificate?.signatureValue.count,256)
        
        
        XCTAssertEqual(certificate?.issuer, "")
        
        
        
        
    }
    
    
    func testCertificateDeepCopy() {
        let resourceURL = Bundle.module.url(forResource: "www_digicert_com", withExtension: "pem", subdirectory: "Certificates")
        let pemCertificate = (resourceURL.flatMap { try? String(contentsOf: $0, encoding: .utf8) }) ?? ""
        
        let certificate =  try? X509.Certificate.init(pemRepresentation:pemCertificate)
        
        let newCert = try? X509.Certificate(newCertificate: certificate!)
        
        XCTAssertEqual(certificate?.signatureAlgorithmOid, newCert?.signatureAlgorithmOid)
        XCTAssertEqual(certificate?.signatureValue, newCert?.signatureValue)
    }
    
    
    func testCertificateTransparancy() {
        let thisSourceFile = URL(fileURLWithPath: #file)
        let thisDirectory = thisSourceFile.deletingLastPathComponent()
        let resourceURL = Bundle.module.url(forResource: "www_digicert_com", withExtension: "pem", subdirectory: "Certificates")!
        let issuerPublicKeyURL = Bundle.module.url(forResource: "www_digicert_com_CA_PK", withExtension: "pem", subdirectory: "Certificates")!
        let SCTSignatureURL = Bundle.module.url(forResource: "GoogleSkydiver_Signature", withExtension: "bin", subdirectory: "Certificates")!
        let preCertificateURL = Bundle.module.url(forResource: "GoogleSkydiver_SCT", withExtension: "bin", subdirectory: "Certificates")!
        
        
        let pemCertificate = (try? String(contentsOf: resourceURL)) ?? ""
        let certificate =  try? X509.Certificate.init(pemRepresentation:pemCertificate)
        
        
        let pemIssuerPublicKey = (try? String(contentsOf: issuerPublicKeyURL)) ?? ""
        let issuerPublicKey = try? X509.PublicKey.init(pemRepresentation: pemIssuerPublicKey)
        
        
        XCTAssertEqual(certificate?.encodedPreTbsCertificate?.hexEncodedString(separation: ":"), "30:82:06:1D:A0:03:02:01:02:02:10:08:36:BA:A2:55:68:64:17:20:78:58:46:38:D8:5C:34:30:0D:06:09:2A:86:48:86:F7:0D:01:01:0B:05:00:30:75:31:0B:30:09:06:03:55:04:06:13:02:55:53:31:15:30:13:06:03:55:04:0A:13:0C:44:69:67:69:43:65:72:74:20:49:6E:63:31:19:30:17:06:03:55:04:0B:13:10:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:31:34:30:32:06:03:55:04:03:13:2B:44:69:67:69:43:65:72:74:20:53:48:41:32:20:45:78:74:65:6E:64:65:64:20:56:61:6C:69:64:61:74:69:6F:6E:20:53:65:72:76:65:72:20:43:41:30:1E:17:0D:31:38:30:36:32:36:30:30:30:30:30:30:5A:17:0D:32:30:30:36:33:30:31:32:30:30:30:30:5A:30:81:CF:31:1D:30:1B:06:03:55:04:0F:0C:14:50:72:69:76:61:74:65:20:4F:72:67:61:6E:69:7A:61:74:69:6F:6E:31:13:30:11:06:0B:2B:06:01:04:01:82:37:3C:02:01:03:13:02:55:53:31:15:30:13:06:0B:2B:06:01:04:01:82:37:3C:02:01:02:13:04:55:74:61:68:31:15:30:13:06:03:55:04:05:13:0C:35:32:39:39:35:33:37:2D:30:31:34:32:31:0B:30:09:06:03:55:04:06:13:02:55:53:31:0D:30:0B:06:03:55:04:08:13:04:55:74:61:68:31:0D:30:0B:06:03:55:04:07:13:04:4C:65:68:69:31:17:30:15:06:03:55:04:0A:13:0E:44:69:67:69:43:65:72:74:2C:20:49:6E:63:2E:31:0C:30:0A:06:03:55:04:0B:13:03:53:52:45:31:19:30:17:06:03:55:04:03:13:10:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:30:82:02:22:30:0D:06:09:2A:86:48:86:F7:0D:01:01:01:05:00:03:82:02:0F:00:30:82:02:0A:02:82:02:01:00:CE:9F:85:CA:39:30:30:B7:F6:98:69:B4:9C:10:5D:50:3B:25:63:D0:E5:68:D4:D9:A5:CA:2C:D6:35:95:B2:3E:0D:29:8B:9D:E0:81:4A:04:F7:C0:9E:35:49:33:FB:AB:1C:11:8A:96:35:8E:A5:DE:A2:81:E7:AA:49:24:8A:8D:42:6A:3D:36:85:8E:F2:4D:86:FE:34:C8:8C:51:46:A8:D5:98:22:AD:B7:8B:8F:87:A9:A5:E2:D7:F1:FF:69:61:60:6B:39:35:AA:4C:B2:00:E4:10:03:FA:79:E9:B1:BD:9B:93:A4:FC:80:4C:FC:16:67:2E:A5:49:2C:62:4E:C7:D8:A1:80:6D:5D:23:D0:EB:EA:F6:A9:FB:C4:1A:3D:16:AE:DE:DF:6C:11:DD:9C:C5:EE:08:C7:B8:0B:75:A6:06:DE:FC:6C:61:FD:C1:C9:C2:93:48:AB:72:AD:B9:17:D5:0C:B4:76:C4:B1:CB:E1:82:33:61:13:C4:4D:60:31:AE:EF:46:89:90:FD:9A:19:A3:C2:1B:E7:99:05:A7:A9:48:4F:A5:0E:3A:49:1D:CA:22:5D:A5:63:D7:21:96:65:B1:94:79:C2:47:A0:58:3B:09:3F:B5:EF:EE:71:34:58:C9:18:D7:ED:39:88:D6:2D:AF:36:51:86:19:67:07:0D:80:A0:C1:8D:23:EB:6C:05:72:D0:29:E6:5F:58:59:94:DF:46:E1:93:35:FD:F6:99:AF:21:82:77:7F:57:D0:18:B6:A8:E3:89:D0:12:37:64:9C:8B:E9:9B:41:CC:82:F6:A0:60:29:D0:56:79:E1:25:2B:73:C9:8C:F7:DB:87:E5:58:B3:D2:A7:9E:CE:41:E3:4C:B6:BE:8E:E5:6D:07:75:6C:A1:51:95:3E:0F:84:7A:C0:E6:D8:40:C6:79:6E:26:23:46:1B:40:42:33:20:F0:45:50:11:F6:73:11:DA:F4:58:63:B9:25:11:CB:1F:2A:2D:F2:D1:2B:5C:CF:43:88:5E:5C:09:BC:DF:72:37:AE:A2:29:36:48:75:BE:BD:BB:8F:6A:03:22:1D:33:3D:FB:79:6B:D2:84:4E:F9:95:B0:70:CE:DF:26:F9:F5:25:F4:76:3C:32:C0:68:8D:D0:52:FE:CE:2E:14:87:DF:65:1F:42:C9:3E:D4:80:AA:D3:99:B6:1F:04:B1:88:0B:E2:0D:19:79:0D:EE:BA:30:46:43:76:FB:B4:DE:C5:00:41:31:EF:5A:7C:34:32:BE:C9:81:B8:ED:9F:40:DE:50:A2:D8:C2:C4:56:83:EB:29:AA:81:53:24:75:86:6D:BF:51:21:BF:B7:97:17:AF:EE:72:2A:39:02:03:01:00:01:A3:82:02:64:30:82:02:60:30:1F:06:03:55:1D:23:04:18:30:16:80:14:3D:D3:50:A5:D6:A0:AD:EE:F3:4A:60:0A:65:D3:21:D4:F8:F8:D6:0F:30:1D:06:03:55:1D:0E:04:16:04:14:6C:B0:43:56:FE:3D:E8:12:EC:D9:12:F5:63:D5:C4:CA:07:AF:B0:76:30:81:91:06:03:55:1D:11:04:81:89:30:81:86:82:10:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:0C:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:14:63:6F:6E:74:65:6E:74:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:17:77:77:77:2E:6F:72:69:67:69:6E:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:12:6C:6F:67:69:6E:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:10:61:70:69:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:82:0F:77:73:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:30:0E:06:03:55:1D:0F:01:01:FF:04:04:03:02:05:A0:30:1D:06:03:55:1D:25:04:16:30:14:06:08:2B:06:01:05:05:07:03:01:06:08:2B:06:01:05:05:07:03:02:30:75:06:03:55:1D:1F:04:6E:30:6C:30:34:A0:32:A0:30:86:2E:68:74:74:70:3A:2F:2F:63:72:6C:33:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:73:68:61:32:2D:65:76:2D:73:65:72:76:65:72:2D:67:32:2E:63:72:6C:30:34:A0:32:A0:30:86:2E:68:74:74:70:3A:2F:2F:63:72:6C:34:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:73:68:61:32:2D:65:76:2D:73:65:72:76:65:72:2D:67:32:2E:63:72:6C:30:4B:06:03:55:1D:20:04:44:30:42:30:37:06:09:60:86:48:01:86:FD:6C:02:01:30:2A:30:28:06:08:2B:06:01:05:05:07:02:01:16:1C:68:74:74:70:73:3A:2F:2F:77:77:77:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:43:50:53:30:07:06:05:67:81:0C:01:01:30:81:88:06:08:2B:06:01:05:05:07:01:01:04:7C:30:7A:30:24:06:08:2B:06:01:05:05:07:30:01:86:18:68:74:74:70:3A:2F:2F:6F:63:73:70:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:30:52:06:08:2B:06:01:05:05:07:30:02:86:46:68:74:74:70:3A:2F:2F:63:61:63:65:72:74:73:2E:64:69:67:69:63:65:72:74:2E:63:6F:6D:2F:44:69:67:69:43:65:72:74:53:48:41:32:45:78:74:65:6E:64:65:64:56:61:6C:69:64:61:74:69:6F:6E:53:65:72:76:65:72:43:41:2E:63:72:74:30:0C:06:03:55:1D:13:01:01:FF:04:02:30:00")
        
        let certificateSCTs = certificate?.certificateTransparencySCTs
        
        XCTAssertEqual(certificateSCTs![0].id.hexEncodedString(separation: ":"), "BB:D9:DF:BC:1F:8A:71:B5:93:94:23:97:AA:92:7B:47:38:57:95:0A:AB:52:E8:1A:90:96:64:36:8E:1E:D1:85")
        XCTAssertEqual(certificateSCTs![0].derSignature.hexEncodedString(separation: ":"), "30:45:02:21:00:B6:F7:F1:8C:35:81:BE:99:AA:72:AE:FE:D5:7F:25:3B:2A:8A:50:9F:32:E6:BD:F5:57:89:15:E2:DC:D0:48:F7:02:20:6F:00:02:3A:B0:43:02:C6:E8:E6:DF:80:C7:B4:07:4E:80:C0:CE:CA:D4:91:00:B3:2B:FC:40:FE:6B:FC:43:D4")
        
        try? certificateSCTs![0].derSignature.write(to: SCTSignatureURL)
        
        
        XCTAssertEqual(Data(base64Encoded:"u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=")?.hexEncodedString(separation: ":"),"BB:D9:DF:BC:1F:8A:71:B5:93:94:23:97:AA:92:7B:47:38:57:95:0A:AB:52:E8:1A:90:96:64:36:8E:1E:D1:85")
        
        // "Google 'Skydiver' log https://ct.googleapis.com/skydiver/
        // "log_id": "u9nfvB+KcbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YU=",
        //  public key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==",
        
        
        let publicKeyGoogleSkydiverLog = try!  X509.PublicKey(derRepresentation:Data(base64Encoded:"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA==") ?? Data()) 
        
        let pubKeyDataFromDer = (try? Data(contentsOf: thisDirectory.appendingPathComponent("../Certificates/GoogleSkydiverLog_PK.der")))
        let pubKeyDataFromPem = (try? Data(base64Encoded:"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEmyGDvYXsRJsNyXSrYc9DjHsIa2xzb4UR7ZxVoV6mrc9iZB7xjI6+NrOiwH+P/xxkRmOFG6Jel20q37hTh58rA=="))
        
        let pemKeyString = publicKeyGoogleSkydiverLog.PEMKeyFromDERKey(Data(publicKeyGoogleSkydiverLog.asn1Sequence.encode()))
        
        if #available(OSX 10.15, *) {
            
            let p256PublicKey = try! P256.Signing.PublicKey.init(x963Representation: publicKeyGoogleSkydiverLog.derEncodedKey!)
            
            XCTAssertEqual(p256PublicKey.x963Representation.hexEncodedString(separation: ":"),"04:12:6C:86:0E:F6:17:B1:12:6C:37:25:D2:AD:87:3D:0E:31:EC:21:AD:B1:CD:BE:14:47:B6:71:56:85:7A:9A:B7:3D:89:90:7B:C6:32:3A:F8:DA:CE:8B:01:FE:3F:FC:71:91:19:8E:14:6E:89:7A:5D:B4:AB:7E:E1:4E:1E:7C:AC")
            
            let p256Signature = try! P256.Signing.ECDSASignature.init(derRepresentation: certificateSCTs![0].derSignature)
            
            XCTAssertEqual(p256Signature.rawRepresentation.hexEncodedString(separation: ":"),"B6:F7:F1:8C:35:81:BE:99:AA:72:AE:FE:D5:7F:25:3B:2A:8A:50:9F:32:E6:BD:F5:57:89:15:E2:DC:D0:48:F7:6F:00:02:3A:B0:43:02:C6:E8:E6:DF:80:C7:B4:07:4E:80:C0:CE:CA:D4:91:00:B3:2B:FC:40:FE:6B:FC:43:D4")
            
            
            // Creating the signed struct by the CT Log
            
            let preTbsCertificate = certificate?.encodedPreTbsCertificate
            let threeByteLength = Data(from:UInt32(preTbsCertificate!.count).bigEndian)
            
            var signedStruct = Data()
            signedStruct.append(Data(from:certificateSCTs![0].version))
            signedStruct.append(Data([0x00]))  // signature type : certificate timestamp = 0
            
            signedStruct.append(Data(from:certificateSCTs![0].timestamp.bigEndian))  // 8 bytes timestamp
            signedStruct.append(contentsOf: [0x00,0x01]) // 0x00 0x01 precert entry
            
            signedStruct.append(Data(SHA256.hash(data: Data((issuerPublicKey?.asn1Sequence.encode())!))))
            signedStruct.append(threeByteLength[1...3] )
            signedStruct.append((certificate?.encodedPreTbsCertificate)!)
            signedStruct.append(contentsOf: [0x00,0x00]) // extensions none, length = 0, 2 bytes
            
            
            try? signedStruct.write(to: preCertificateURL)
            
            // Verify signature of the SCT with the public key of the corresponding CT Log.
            XCTAssertTrue(p256PublicKey.isValidSignature(p256Signature, for: signedStruct))
            
            
            
            
            
            // check second SCT in cert
            XCTAssertEqual(certificateSCTs![1].id.hexEncodedString(separation: ":"), "56:14:06:9A:2F:D7:C2:EC:D3:F5:E1:BD:44:B2:3E:C7:46:76:B9:BC:99:11:5C:C0:EF:94:98:55:D6:89:D0:DD")
            
            // this is "DigiCert Log Server"  https://ct1.digicert-ct.com/log/
            //  public key: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A=="
            
            let publicKeyDigiCertLog = try?  X509.PublicKey(derRepresentation:Data(base64Encoded:"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEAkbFvhu7gkAW6MHSrBlpE1n4+HCFRkC5OLAjgqhkTH+/uzSfSl8ois8ZxAD2NgaTZe1M9akhYlrYkes4JECs6A==")!)
            
            
            
            let p256PublicKeyDigiCertLog = try! P256.Signing.PublicKey.init(x963Representation: publicKeyDigiCertLog!.derEncodedKey!)
            let p256SignatureDigiCertLog = try! P256.Signing.ECDSASignature.init(derRepresentation: certificateSCTs![1].derSignature)
            
            
            // Creating the signed struct by the CT Log
            
            
            
            var signedStructDigiCert = Data()
            signedStructDigiCert.append(Data(from:certificateSCTs![1].version))
            signedStructDigiCert.append(Data([0x00]))  // signature type : certificate timestamp = 0
            
            signedStructDigiCert.append(Data(from:certificateSCTs![1].timestamp.bigEndian))  // 8 bytes timestamp
            signedStructDigiCert.append(contentsOf: [0x00,0x01]) // 0x00 0x01 precert entry
            
            signedStructDigiCert.append(Data(SHA256.hash(data: Data((issuerPublicKey?.asn1Sequence.encode())!))))
            signedStructDigiCert.append(threeByteLength[1...3] )
            signedStructDigiCert.append((certificate?.encodedPreTbsCertificate)!)
            signedStructDigiCert.append(contentsOf: [0x00,0x00]) // extensions none, length = 0, 2 bytes
            
            
            // Verify signature of the SCT with the public key of the corresponding CT Log.
            XCTAssertTrue(p256PublicKeyDigiCertLog.isValidSignature(p256SignatureDigiCertLog, for: signedStructDigiCert))
            
            
        }
    }
    
    
    
    func testSignature()   {
    
       
        
        
    //    let signature = try? X509.Signature(pemRepresentation: "MEUCIQDagxQmaP/ZMosOCl9ENQPw054PLePdm/TCsW7Ot6MFNgIgdJ3BwOsSg/zaFy5/ir+RcXCq/n95+7W6zlxoiwA1f5E=")
        
//         let random_signature = Data(0x30, 0x64, 0x02, 0x30, 0x45, 0x9b, 0x89, 0x38, 0xea, 0x59, 0x9d, 0x00,
//          0x1a, 0x19, 0xa1, 0xb1, 0x07, 0xb8, 0x7c, 0xb9, 0x11, 0x08, 0xe7, 0x08,
//          0xec, 0xdd, 0xf9, 0xb7, 0x34, 0x88, 0xff, 0x5a, 0xa7, 0xf1, 0x55, 0x25,
//          0xaa, 0xf1, 0x17, 0x7d, 0x5a, 0x29, 0xb9, 0xcc, 0x33, 0xc6, 0x4f, 0x98,
//          0x61, 0x34, 0xd3, 0x13, 0x02, 0x30, 0x52, 0xc1, 0x09, 0x95, 0x2a, 0x9f,
//          0x9d, 0x7b, 0xdd, 0x84, 0xff, 0xbd, 0xd6, 0xa6, 0x4f, 0xcd, 0x5b, 0xa8,
//          0x19, 0xb6, 0xc6, 0xb1, 0xa9, 0xb8, 0x2c, 0x39, 0x3c, 0x63, 0x4a, 0x01,
//          0x58, 0x02, 0x55, 0x20, 0xf9, 0xc2, 0x1c, 0xd1, 0x81, 0xcd, 0x47, 0x86,
//          0x8c, 0x53, 0x50, 0x43, 0x67, 0xd6)
        let random_sig = Data(base64Encoded: "MGUCMQDyAJ78khPNas/lM1IObeKa4StFt93PYQEzJK3Kw8SWhpeoDekgyX3UHOO5F8LtrzUCMENHBfH8OIqMVCA5NNiVLl46YvAYPK1ONLXpRCVVHRhGyBa8htUUHvp3OrKVlHsAag==")!
        let random_sig_bin_len = 102;
        
        let x509publicKey = try? X509.PublicKey(derRepresentation: Data(base64Encoded: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAELUf49MKj73mKzJRn5oYQTh7mpw1SpgHDp9ByaKgZiYCQFjCKjSdgwzH/U1vM8W6ee8rtKCh979Ao27cxxt8oM9iuyYu/kdU+4nI6DdMdpBwJXFvTT9hb/9SJbPaOA2Ti")!)
//        let message = Data("AA55AA55AA55AA55AA55AA55AA55AA55".utf8)
        let message = Data([0xAA,0x55,0xAA,0x55,0xAA,0x55,0xAA,0x55,0xAA,0x55,0xAA,0x55,0xAA,0x55,0xAA,0x55])
        
        do {
            let publicKey =   try P384.Signing.PublicKey.init(x963Representation: x509publicKey!.derEncodedKey!)
            let signature = try P384.Signing.ECDSASignature.init(derRepresentation: random_sig)
            
            let result = publicKey.isValidSignature(signature, for: message)
            
            XCTAssertTrue(publicKey.isValidSignature(signature, for: message))
        }
        catch {
            print("Unexpected error: \(error).")
        }
        
       
            
           
        
        
        
    }
    
    
    static let allTests = [
        ("testCertificateBasicFields", testCertificateBasicFields),
        ("testCertificateDeepCopy", testCertificateDeepCopy),
        ("testCertificateTransparancy", testCertificateTransparancy),
        ("testSignature", testSignature),
    ]
}





extension Data {
    func hexEncodedString(separation: String = "") -> String {
        var hexString = reduce("") {$0 + String(format: "%02X\(separation)", $1)}
        if separation != "" {hexString.removeLast()}
        return hexString
    }
    
    func decEncodedString(separation: String = "") -> String {
        var hexString = reduce("") {$0 + String(format: "%02d\(separation)", $1)}
        if separation != "" {hexString.removeLast()}
        return hexString
    }
}

@available(OSX 10.15,iOS 13.0, *)
extension SHA256Digest {
    func hexEncodedString(separation: String = "") -> String {
        var hexString = reduce("") {$0 + String(format: "%02X\(separation)", $1)}
        if separation != "" {hexString.removeLast()}
        return hexString
    }
}

