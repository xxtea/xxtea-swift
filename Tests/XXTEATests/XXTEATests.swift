import Testing
@testable import XXTEA

@Test func testXXTEA() async throws {
    let str = "Hello World! 你好，中国！"
    let key =  "1234567890"
    let encryptData = XXTEA.encryptString(str, stringKey: key)
    #expect("QncB1C0rHQoZ1eRiPM4dsZtRi9pNrp7sqvX76cFXvrrIHXL6" == encryptData.base64EncodedString())
    let decryptData = XXTEA.decryptToString(encryptData, stringKey: key);
    #expect(str == decryptData)
}
