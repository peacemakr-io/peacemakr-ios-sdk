//
// PhoneHomeAPI.swift
//
// Generated by swagger-codegen
// https://github.com/swagger-api/swagger-codegen
//

import Foundation
import Alamofire



open class PhoneHomeAPI {
    /**
     Used to report back to server a logged event
     
     - parameter log: (body)  
     - parameter completion: completion handler to receive the data and the error objects
     */
    open class func logPost(log: Log, completion: @escaping ((_ data: Void?,_ error: Error?) -> Void)) {
        logPostWithRequestBuilder(log: log).execute { (response, error) -> Void in
            if error == nil {
                completion((), error)
            } else {
                completion(nil, error)
            }
        }
    }


    /**
     Used to report back to server a logged event
     - POST /log
     - Returns 200 ok if successfully persisted
     - API Key:
       - type: apiKey authorization 
       - name: header
     
     - parameter log: (body)  

     - returns: RequestBuilder<Void> 
     */
    open class func logPostWithRequestBuilder(log: Log) -> RequestBuilder<Void> {
        let path = "/log"
        let URLString = SwaggerClientAPI.basePath + path
        let parameters = JSONEncodingHelper.encodingParameters(forEncodableObject: log)

        let url = URLComponents(string: URLString)

        let requestBuilder: RequestBuilder<Void>.Type = SwaggerClientAPI.requestBuilderFactory.getNonDecodableBuilder()

        return requestBuilder.init(method: "POST", URLString: (url?.string ?? URLString), parameters: parameters, isBody: true)
    }

}
