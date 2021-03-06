//
// Organization.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation



public struct Organization: Codable {

    public var _id: String
    public var name: String
    public var contacts: [Contact]
    /** Identifies the the customer in Stripe associated with this org */
    public var stripeCustomerId: String
    /** Array of client id&#39;s registered to this org */
    public var clientIds: [String]
    /** Array of api keys registered to this org */
    public var apiKeys: [APIKey]
    /** cryptoconfigId of this org */
    public var cryptoConfigId: String

    public init(_id: String, name: String, contacts: [Contact], stripeCustomerId: String, clientIds: [String], apiKeys: [APIKey], cryptoConfigId: String) {
        self._id = _id
        self.name = name
        self.contacts = contacts
        self.stripeCustomerId = stripeCustomerId
        self.clientIds = clientIds
        self.apiKeys = apiKeys
        self.cryptoConfigId = cryptoConfigId
    }

    public enum CodingKeys: String, CodingKey { 
        case _id = "id"
        case name
        case contacts
        case stripeCustomerId
        case clientIds
        case apiKeys
        case cryptoConfigId
    }


}

