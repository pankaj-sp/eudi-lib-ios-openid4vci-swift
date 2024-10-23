/*
 * Copyright (c) 2023 European Commission
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
import Foundation

public protocol CanExpire {
  var expiresIn: TimeInterval? { get }
  func isExpired(issued: TimeInterval, at: TimeInterval) -> Bool
}

public extension CanExpire {
  func isExpired(issued: TimeInterval, at: TimeInterval) -> Bool {
    if issued >= at {
      return true
    }
     
    guard let expiresIn = expiresIn else {
      return false
    }
     
    let expiration = issued + expiresIn
    return expiration <= at
  }
}

public struct NoProofRequiredAuthorizedRequest {
    public var accessToken: IssuanceAccessToken
    public var refreshToken: IssuanceRefreshToken?
    public var credentialIdentifiers: AuthorizationDetailsIdentifiers?
    public var timeStamp: TimeInterval
}

public struct ProofRequiredAuthorizedRequest {
    public var accessToken: IssuanceAccessToken
    public var refreshToken: IssuanceRefreshToken?
    public var cNonce: CNonce
    public var credentialIdentifiers: AuthorizationDetailsIdentifiers?
    public var timeStamp: TimeInterval
    public var dpopNonce: DPopNonce? = nil
}

public enum AuthorizedRequest {
  case noProofRequired(NoProofRequiredAuthorizedRequest)
  case proofRequired(ProofRequiredAuthorizedRequest)

  public mutating func updateCNonce(_ cNonce: CNonce) {
    if case let .proofRequired(proofRequiredAuthorizedRequest) = self {
      var proofRequiredAuthorizedRequest = proofRequiredAuthorizedRequest
      proofRequiredAuthorizedRequest.cNonce = cNonce
      self = .proofRequired(proofRequiredAuthorizedRequest)
    }
  }
    
  public func isAccessTokenExpired(clock: TimeInterval) -> Bool {
    guard let timeStamp = self.timeStamp else {
      return true
    }
    return accessToken?.isExpired(issued: timeStamp, at: clock) ?? false
  }
    
  public func isRefreshTokenExpired(clock: TimeInterval) -> Bool {
    guard let timeStamp = self.timeStamp else {
      return true
    }
    return accessToken?.isExpired(
      issued: timeStamp,
      at: clock
      ) ?? false
  }
    
  public var timeStamp: TimeInterval? {
    switch self {
    case .noProofRequired(let request):
      return request.timeStamp
    case .proofRequired(let request):
      return request.timeStamp
    }
  }
    
  public var noProofToken: IssuanceAccessToken? {
    switch self {
    case .noProofRequired(let request):
      return request.accessToken
    case .proofRequired:
      return nil
    }
  }
    
  public var proofToken: IssuanceAccessToken? {
    switch self {
    case .noProofRequired:
      return nil
    case .proofRequired(let request):
      return request.accessToken
    }
  }
    
  public var dpopNonce: DPopNonce? {
    switch self {
    case .noProofRequired:
      return nil
    case .proofRequired(let request):
      return request.dpopNonce
    }
  }
}

public extension AuthorizedRequest {
  var accessToken: IssuanceAccessToken? {
    switch self {
    case .noProofRequired(let request):
      return request.accessToken
    case .proofRequired(let request):
      return request.accessToken
    }
  }
  
  func handleInvalidProof(cNonce: CNonce) throws -> AuthorizedRequest {
    switch self {
      
    case .noProofRequired(let request):
        return .proofRequired(
            .init(
                accessToken: request.accessToken,
                refreshToken: request.refreshToken,
                cNonce: cNonce,
                credentialIdentifiers: request.credentialIdentifiers,
                timeStamp: request.timeStamp
            )
        )
    default: throw ValidationError.error(reason: "Expected .noProofRequired authorisation request")
    }
  }
}
