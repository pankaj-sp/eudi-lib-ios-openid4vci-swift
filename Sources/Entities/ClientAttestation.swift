//
//  ClientAttestation.swift
//  OpenID4VCI
//
//  Created by Pankaj Sachdeva on 08.01.25.
//

import Foundation
import JOSESwift

public struct ClientAttestation {
    public let clientAttestationPoPJWTType: ClientAttestationPoPJWTSpec
    public let clientAttestationJWT: String
    
    public init(clientAttestationPoPJWTType: ClientAttestationPoPJWTSpec, clientAttestationJWT: String) {
        self.clientAttestationPoPJWTType = clientAttestationPoPJWTType
        self.clientAttestationJWT = clientAttestationJWT
    }
}

public struct ClientAttestationPoPJWTSpec {
    let duration: TimeInterval
    let typ: String
    let issuer: String
    let audience: String
    let nonce: String?
    
    public init(
        duration: TimeInterval,
        typ: String,
        issuer: String,
        audience: String,
        nonce: String?
    ) {
        self.duration = duration
        self.typ = typ
        self.issuer = issuer
        self.audience = audience
        self.nonce = nonce
    }
}
