//
// Contact.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation



public struct Contact: Codable {

    public var name: String
    public var email: String
    public var phone: String?

    public init(name: String, email: String, phone: String?) {
        self.name = name
        self.email = email
        self.phone = phone
    }


}

