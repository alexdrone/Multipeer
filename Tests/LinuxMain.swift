import XCTest

import MultipeerTests

var tests = [XCTestCaseEntry]()
tests += MultipeerTests.allTests()
XCTMain(tests)
