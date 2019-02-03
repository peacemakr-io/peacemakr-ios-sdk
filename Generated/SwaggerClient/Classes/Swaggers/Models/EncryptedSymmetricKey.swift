//
// EncryptedSymmetricKey.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation



public struct EncryptedSymmetricKey: Codable {

    /** id&#39;s of the symmetric keys encrypted in packedCiphertext */
    public var keyIds: [String]
    /** length of the keys encrypted in packedCiphertext */
    public var keyLength: Int
    /** id of the symmetric key use domain which contains this key */
    public var symmetricKeyUseDomainId: String
    /** the actual packaged ciphertext of the encrypted symmetric key, of key */
    public var packagedCiphertext: String

    public init(keyIds: [String], keyLength: Int, symmetricKeyUseDomainId: String, packagedCiphertext: String) {
        self.keyIds = keyIds
        self.keyLength = keyLength
        self.symmetricKeyUseDomainId = symmetricKeyUseDomainId
        self.packagedCiphertext = packagedCiphertext
    }


}

