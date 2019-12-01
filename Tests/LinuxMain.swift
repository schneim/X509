import XCTest

import X509Tests

var tests = [XCTestCaseEntry]()
tests += X509Tests.allTests()
XCTMain(tests)
