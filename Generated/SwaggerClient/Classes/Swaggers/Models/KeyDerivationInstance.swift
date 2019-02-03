//
// KeyDerivationInstance.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation



public struct KeyDerivationInstance: Codable {

    /** instance id (concrete instance) */
    public var _id: String
    /** service id (virtual service id) */
    public var serviceIds: [String]
    /** currently online and accepting requests for key derivation */
    public var active: Bool
    public var version: String
    /** base URL from which this key deriver instance will respond to new key derivation job requests */
    public var baseUrl: String?

    public init(_id: String, serviceIds: [String], active: Bool, version: String, baseUrl: String?) {
        self._id = _id
        self.serviceIds = serviceIds
        self.active = active
        self.version = version
        self.baseUrl = baseUrl
    }

    public enum CodingKeys: String, CodingKey { 
        case _id = "id"
        case serviceIds
        case active
        case version
        case baseUrl
    }


}

