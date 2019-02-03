//
// ServerManagementAPI.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation
import Alamofire



open class ServerManagementAPI {
    /**
     See if the server is healthy
     
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func healthGet(completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        healthGetWithRequestBuilder().execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     See if the server is healthy
     - GET /health
     - Returns 200 if the server is healthy

     - returns: RequestBuilder<Void> 
     */
    open class func healthGetWithRequestBuilder() -> RequestBuilder<Void> {
        let path = "/health"
        let URLString = SwaggerClientAPI.basePath + path
        let parameters: [String:Any]? = nil
        
        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "GET", URLString: (url?.string ?? URLString), parameters: parameters, isBody: false)
    }

}