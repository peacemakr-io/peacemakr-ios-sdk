//
// CryptoConfigAPI.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation
import Alamofire



open class CryptoConfigAPI {
    /**
     Add an existing use domain to another crypto config.
     
     - parameter cryptoConfigId: (path)  
     - parameter useDomainId: (path)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func addExistingUseDomain(cryptoConfigId: String, useDomainId: String, completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        addExistingUseDomainWithRequestBuilder(cryptoConfigId: cryptoConfigId, useDomainId: useDomainId).execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     Add an existing use domain to another crypto config.
     - POST /crypto/config/{cryptoConfigId}/useDomain/{useDomainId}
     - API Key:
       - type: apiKey authorization 
       - name: header
     
     - parameter cryptoConfigId: (path)  
     - parameter useDomainId: (path)  

     - returns: RequestBuilder<Void> 
     */
    open class func addExistingUseDomainWithRequestBuilder(cryptoConfigId: String, useDomainId: String) -> RequestBuilder<Void> {
        var path = "/crypto/config/{cryptoConfigId}/useDomain/{useDomainId}"
        let cryptoConfigIdPreEscape = "\(cryptoConfigId)"
        let cryptoConfigIdPostEscape = cryptoConfigIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{cryptoConfigId}", with: cryptoConfigIdPostEscape, options: .literal, range: nil)
        let useDomainIdPreEscape = "\(useDomainId)"
        let useDomainIdPostEscape = useDomainIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{useDomainId}", with: useDomainIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

    /**
     Add a new active use domain and attached it to the crypto config.
     
     - parameter cryptoConfigId: (path)  
     - parameter newUseDomain: (body)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func addUseDomain(cryptoConfigId: String, newUseDomain: SymmetricKeyUseDomain, completion: @escaping ((_ data: SymmetricKeyUseDomain?,_ error: Error?) -> Void)) {
        addUseDomainWithRequestBuilder(cryptoConfigId: cryptoConfigId, newUseDomain: newUseDomain).execute { (response, error) -> Void in
            completion(response?.body, error)
        }
    }


    /**
     Add a new active use domain and attached it to the crypto config.
     - POST /crypto/config/{cryptoConfigId}/useDomain
     - API Key:
       - type: apiKey authorization 
       - name: header
     - examples: [{contentType=application/json, example={
  "symmetricKeyRetentionUseTTL" : 5,
  "creationTime" : 0,
  "symmetricKeyEncryptionUseTTL" : 1,
  "endableKDSFallbackToCloud" : true,
  "name" : "name",
  "symmetricKeyEncryptionAlg" : "symmetricKeyEncryptionAlg",
  "ownerOrgId" : "ownerOrgId",
  "id" : "id",
  "symmetricKeyInceptionTTL" : 6,
  "symmetricKeyDerivationServiceId" : "symmetricKeyDerivationServiceId",
  "symmetricKeyDecryptionUseTTL" : 5,
  "encryptingPackagedCiphertextVersion" : 7,
  "encryptionKeyIds" : [ "encryptionKeyIds", "encryptionKeyIds" ],
  "symmetricKeyLength" : 2
}}]
     
     - parameter cryptoConfigId: (path)  
     - parameter newUseDomain: (body)  

     - returns: RequestBuilder<SymmetricKeyUseDomain> 
     */
    open class func addUseDomainWithRequestBuilder(cryptoConfigId: String, newUseDomain: SymmetricKeyUseDomain) -> RequestBuilder<SymmetricKeyUseDomain> {
        var path = "/crypto/config/{cryptoConfigId}/useDomain"
        let cryptoConfigIdPreEscape = "\(cryptoConfigId)"
        let cryptoConfigIdPostEscape = cryptoConfigIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{cryptoConfigId}", with: cryptoConfigIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: newUseDomain)

        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<SymmetricKeyUseDomain>.Type = SwaggerClientAPI.requestBuilderFactory.getBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, isBody: true)
    }

    /**
     Get the crypto configurations
     
     - parameter cryptoConfigId: (path)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func getCryptoConfig(cryptoConfigId: String, completion: @escaping ((_ data: CryptoConfig?,_ error: Error?) -> Void)) {
        getCryptoConfigWithRequestBuilder(cryptoConfigId: cryptoConfigId).execute { (response, error) -> Void in
            completion(response?.body, error)
        }
    }


    /**
     Get the crypto configurations
     - GET /crypto/config/{cryptoConfigId}
     - API Key:
       - type: apiKey authorization 
       - name: header
     - examples: [{contentType=application/json, example={
  "symmetricKeyUseDomainSelectorScheme" : "moduloIdentifier",
  "ownerOrgId" : "ownerOrgId",
  "symmetricKeyUseDomains" : [ {
    "symmetricKeyRetentionUseTTL" : 5,
    "creationTime" : 0,
    "symmetricKeyEncryptionUseTTL" : 1,
    "endableKDSFallbackToCloud" : true,
    "name" : "name",
    "symmetricKeyEncryptionAlg" : "symmetricKeyEncryptionAlg",
    "ownerOrgId" : "ownerOrgId",
    "id" : "id",
    "symmetricKeyInceptionTTL" : 6,
    "symmetricKeyDerivationServiceId" : "symmetricKeyDerivationServiceId",
    "symmetricKeyDecryptionUseTTL" : 5,
    "encryptingPackagedCiphertextVersion" : 7,
    "encryptionKeyIds" : [ "encryptionKeyIds", "encryptionKeyIds" ],
    "symmetricKeyLength" : 2
  }, {
    "symmetricKeyRetentionUseTTL" : 5,
    "creationTime" : 0,
    "symmetricKeyEncryptionUseTTL" : 1,
    "endableKDSFallbackToCloud" : true,
    "name" : "name",
    "symmetricKeyEncryptionAlg" : "symmetricKeyEncryptionAlg",
    "ownerOrgId" : "ownerOrgId",
    "id" : "id",
    "symmetricKeyInceptionTTL" : 6,
    "symmetricKeyDerivationServiceId" : "symmetricKeyDerivationServiceId",
    "symmetricKeyDecryptionUseTTL" : 5,
    "encryptingPackagedCiphertextVersion" : 7,
    "encryptionKeyIds" : [ "encryptionKeyIds", "encryptionKeyIds" ],
    "symmetricKeyLength" : 2
  } ],
  "id" : "id"
}}]
     
     - parameter cryptoConfigId: (path)  

     - returns: RequestBuilder<CryptoConfig> 
     */
    open class func getCryptoConfigWithRequestBuilder(cryptoConfigId: String) -> RequestBuilder<CryptoConfig> {
        var path = "/crypto/config/{cryptoConfigId}"
        let cryptoConfigIdPreEscape = "\(cryptoConfigId)"
        let cryptoConfigIdPostEscape = cryptoConfigIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? ""
        path = path.replacingOccurrences(of: "{cryptoConfigId}", with: cryptoConfigIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<CryptoConfig>.Type = SwaggerClientAPI.requestBuilderFactory.getBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

    /**
     Expire a use domain
     
     - parameter useDomainId: (path)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func removeUseDomain(useDomainId: String, completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        removeUseDomainWithRequestBuilder(useDomainId: useDomainId).execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     Expire a use domain
     - DELETE /crypto/useDomain/{useDomainId}
     - API Key:
       - type: apiKey authorization 
       - name: header
     
     - parameter useDomainId: (path)  

     - returns: RequestBuilder<Void> 
     */
    open class func removeUseDomainWithRequestBuilder(useDomainId: String) -> RequestBuilder<Void> {
        var path = "/crypto/useDomain/{useDomainId}"
        let useDomainIdPreEscape = "\(useDomainId)"
        let useDomainIdPostEscape = useDomainIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{useDomainId}", with: useDomainIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "DELETE", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

    /**
     Update an existing crypto config's asymmetricKeyTTL
     
     - parameter useDomainId: (path)  
     - parameter fallbackToCloud: (query)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func updateCryptoConfigFallbackToCloud(useDomainId: String, fallbackToCloud: Bool, completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        updateCryptoConfigFallbackToCloudWithRequestBuilder(useDomainId: useDomainId, fallbackToCloud: fallbackToCloud).execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     Update an existing crypto config's asymmetricKeyTTL
     - PUT /crypto/useDomain/{useDomainId}/enableKDSFallbackToCloud
     - API Key:
       - type: apiKey authorization 
       - name: header
     
     - parameter useDomainId: (path)  
     - parameter fallbackToCloud: (query)  

     - returns: RequestBuilder<Void> 
     */
    open class func updateCryptoConfigFallbackToCloudWithRequestBuilder(useDomainId: String, fallbackToCloud: Bool) -> RequestBuilder<Void> {
        var path = "/crypto/useDomain/{useDomainId}/enableKDSFallbackToCloud"
        let useDomainIdPreEscape = "\(useDomainId)"
        let useDomainIdPostEscape = useDomainIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{useDomainId}", with: useDomainIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        var url = URLComponents(string: URLString)
        url?.queryItems = APIHelper.mapValuesToQueryItems([
            "fallbackToCloud": fallbackToCloud
        ])

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "PUT", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

    /**
     Update an existing crypto config's domainSelectorScheme
     
     - parameter cryptoConfigId: (path)  
     - parameter newSelectorScheme: (query)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func updateCryptoConfigSelectorScheme(cryptoConfigId: String, newSelectorScheme: String, completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        updateCryptoConfigSelectorSchemeWithRequestBuilder(cryptoConfigId: cryptoConfigId, newSelectorScheme: newSelectorScheme).execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     Update an existing crypto config's domainSelectorScheme
     - PUT /crypto/config/{cryptoConfigId}/domainSelectorScheme
     - API Key:
       - type: apiKey authorization 
       - name: header
     
     - parameter cryptoConfigId: (path)  
     - parameter newSelectorScheme: (query)  

     - returns: RequestBuilder<Void> 
     */
    open class func updateCryptoConfigSelectorSchemeWithRequestBuilder(cryptoConfigId: String, newSelectorScheme: String) -> RequestBuilder<Void> {
        var path = "/crypto/config/{cryptoConfigId}/domainSelectorScheme"
        let cryptoConfigIdPreEscape = "\(cryptoConfigId)"
        let cryptoConfigIdPostEscape = cryptoConfigIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{cryptoConfigId}", with: cryptoConfigIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        var url = URLComponents(string: URLString)
        url?.queryItems = APIHelper.mapValuesToQueryItems([
            "newSelectorScheme": newSelectorScheme
        ])

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "PUT", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

}