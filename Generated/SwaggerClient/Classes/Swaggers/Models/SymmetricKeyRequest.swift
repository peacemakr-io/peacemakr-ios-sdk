//
// SymmetricKeyRequest.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation



public struct SymmetricKeyRequest: Codable {

    /** Id of the symmetric key request. */
    public var _id: String
    /** These are the keyId&#39;s of for the symmetric keys to actually derive. */
    public var deriveSymmetricKeyIds: [String]
    /** These are the keyId&#39;s to deliver all of the derived symmetric keys. */
    public var deliveryPublicKeyIds: [String]
    /** The serviceId that must generate these keys. */
    public var keyDerivationServiceId: String
    /** Epoch time of the symmetric key requestion request time. */
    public var creationTime: Int
    /** Length in bytes of the derived symmetric keys. */
    public var symmetricKeyLength: Int
    /** After deriving symmetric keys, this determines the ciphertext packaging scheme required for encrypted key delivery. */
    public var packagedCiphertextVersion: Int
    /** If true the key deriver must sign delivered symmetric keys ciphertext blobs */
    public var mustSignDeliveredSymmetricKeys: Bool

    public init(_id: String, deriveSymmetricKeyIds: [String], deliveryPublicKeyIds: [String], keyDerivationServiceId: String, creationTime: Int, symmetricKeyLength: Int, packagedCiphertextVersion: Int, mustSignDeliveredSymmetricKeys: Bool) {
        self._id = _id
        self.deriveSymmetricKeyIds = deriveSymmetricKeyIds
        self.deliveryPublicKeyIds = deliveryPublicKeyIds
        self.keyDerivationServiceId = keyDerivationServiceId
        self.creationTime = creationTime
        self.symmetricKeyLength = symmetricKeyLength
        self.packagedCiphertextVersion = packagedCiphertextVersion
        self.mustSignDeliveredSymmetricKeys = mustSignDeliveredSymmetricKeys
    }

    public enum CodingKeys: String, CodingKey { 
        case _id = "id"
        case deriveSymmetricKeyIds
        case deliveryPublicKeyIds
        case keyDerivationServiceId
        case creationTime
        case symmetricKeyLength
        case packagedCiphertextVersion
        case mustSignDeliveredSymmetricKeys
    }


}

