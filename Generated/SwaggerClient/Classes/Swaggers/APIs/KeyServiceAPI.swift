//
// KeyServiceAPI.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation
import Alamofire



open class KeyServiceAPI {
    /**
     Get all encrypted symmetric keys that are encrypted with this encrypting keyId, optionally limiting the request to a set of symmetric key domains
     
     - parameter encryptingKeyId: (path)  
     - parameter symmetricKeyIds: (query)  (optional)
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func getAllEncryptedKeys(encryptingKeyId: String, symmetricKeyIds: [String]? = nil, completion: @escaping ((_ data: [EncryptedSymmetricKey]?,_ error: Error?) -> Void)) {
        getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: encryptingKeyId, symmetricKeyIds: symmetricKeyIds).execute { (response, error) -> Void in
            completion(response?.body, error)
        }
    }


    /**
     Get all encrypted symmetric keys that are encrypted with this encrypting keyId, optionally limiting the request to a set of symmetric key domains
     - GET /crypto/symmetric/{encryptingKeyId}
     - API Key:
       - type: apiKey authorization 
       - name: header
     - examples: [{contentType=application/json, example=[ {
  "packagedCiphertext" : "packagedCiphertext",
  "keyLength" : 0,
  "keyIds" : [ "keyIds", "keyIds" ],
  "symmetricKeyUseDomainId" : "symmetricKeyUseDomainId"
}, {
  "packagedCiphertext" : "packagedCiphertext",
  "keyLength" : 0,
  "keyIds" : [ "keyIds", "keyIds" ],
  "symmetricKeyUseDomainId" : "symmetricKeyUseDomainId"
} ]}]
     
     - parameter encryptingKeyId: (path)  
     - parameter symmetricKeyIds: (query)  (optional)

     - returns: RequestBuilder<[EncryptedSymmetricKey]> 
     */
    open class func getAllEncryptedKeysWithRequestBuilder(encryptingKeyId: String, symmetricKeyIds: [String]? = nil) -> RequestBuilder<[EncryptedSymmetricKey]> {
        var path = "/crypto/symmetric/{encryptingKeyId}"
        let encryptingKeyIdPreEscape = "\(encryptingKeyId)"
        let encryptingKeyIdPostEscape = encryptingKeyIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlHostAllowed) ?? ""
        path = path.replacingOccurrences(of: "{encryptingKeyId}", with: encryptingKeyIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        var url = URLComponents(string: URLString)
        url?.queryItems = APIHelper.mapValuesToQueryItems([
            "symmetricKeyIds": symmetricKeyIds
        ])

        let requestBuilder: RequestBuilder<[EncryptedSymmetricKey]>.Type = SwaggerClientAPI.requestBuilderFactory.getBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

    /**
     Get the public key associated with the passed-in key ID
     
     - parameter keyID: (path)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func getPublicKey(keyID: String, completion: @escaping ((_ data: PublicKey?,_ error: Error?) -> Void)) {
        getPublicKeyWithRequestBuilder(keyID: keyID).execute { (response, error) -> Void in
            completion(response?.body, error)
        }
    }


    /**
     Get the public key associated with the passed-in key ID
     - GET /crypto/asymmetric/{keyID}
     - API Key:
       - type: apiKey authorization 
       - name: header
     - examples: [{contentType=application/json, example={
  "creationTime" : 0,
  "id" : "id",
  "keyType" : "rsa",
  "encoding" : "pem",
  "key" : "key"
}}]
     
     - parameter keyID: (path)  

     - returns: RequestBuilder<PublicKey> 
     */
    open class func getPublicKeyWithRequestBuilder(keyID: String) -> RequestBuilder<PublicKey> {
        var path = "/crypto/asymmetric/{keyID}"
        let keyIDPreEscape = "\(keyID)"
        let keyIDPostEscape = keyIDPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{keyID}", with: keyIDPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<PublicKey>.Type = SwaggerClientAPI.requestBuilderFactory.getBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

    /**
     Add a new encrypted key. The encrypting key that protects the encrypted key is identified with encryptingKeyId. Request must come from a registered key manager.
     
     - parameter encryptingKeyId: (path)  
     - parameter encryptedSymmetricKey: (body)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func postNewEncryptedKeys(encryptingKeyId: String, encryptedSymmetricKey: [EncryptedSymmetricKey], completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        postNewEncryptedKeysWithRequestBuilder(encryptingKeyId: encryptingKeyId, encryptedSymmetricKey: encryptedSymmetricKey).execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     Add a new encrypted key. The encrypting key that protects the encrypted key is identified with encryptingKeyId. Request must come from a registered key manager.
     - POST /crypto/symmetric/{encryptingKeyId}
     - API Key:
       - type: apiKey authorization 
       - name: header
     
     - parameter encryptingKeyId: (path)  
     - parameter encryptedSymmetricKey: (body)  

     - returns: RequestBuilder<Void> 
     */
    open class func postNewEncryptedKeysWithRequestBuilder(encryptingKeyId: String, encryptedSymmetricKey: [EncryptedSymmetricKey]) -> RequestBuilder<Void> {
        var path = "/crypto/symmetric/{encryptingKeyId}"
        let encryptingKeyIdPreEscape = "\(encryptingKeyId)"
        let encryptingKeyIdPostEscape = encryptingKeyIdPreEscape.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed) ?? ""
        path = path.replacingOccurrences(of: "{encryptingKeyId}", with: encryptingKeyIdPostEscape, options: .literal, range: nil)
        let URLString = SwaggerClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: encryptedSymmetricKey)

        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, isBody: true)
    }

}
