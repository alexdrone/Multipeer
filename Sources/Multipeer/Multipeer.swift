// Forked from: https://github.com/insidegui/MultipeerKit
// Copyright (c) 2020 Guilherme Rambo
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// - Redistributions of source code must retain the above copyright notice, this
//   list of conditions and the following disclaimer.
//
// - Redistributions in binary form must reproduce the above copyright notice,
//   this list of conditions and the following disclaimer in the documentation
//   and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import CommonCrypto
import Foundation
import MultipeerConnectivity
import MultipeerConnectivity.MCPeerID
import Foundation
import os.log

// MARK: - Public

// MARK: Peer

/// Represents a remote peer.
public struct Peer: Hashable, Identifiable {
  let underlyingPeer: MCPeerID
  /// The unique identifier for the peer.
  public let id: String
  /// The peer's display name.
  public let name: String
  /// Discovery info provided by the peer.
  public let discoveryInfo: [String: String]?
  /// `true` if we are currently connected to this peer.
  public internal(set) var isConnected: Bool
}

extension Peer {
  init(peer: MCPeerID, discoveryInfo: [String: String]?) throws {
    let peerData = try NSKeyedArchiver.archivedData(
      withRootObject: peer, requiringSecureCoding: true)
    self.id = peerData.idHash
    self.underlyingPeer = peer
    self.name = peer.displayName
    self.discoveryInfo = discoveryInfo
    self.isConnected = false
  }
}

extension Data {
  fileprivate var idHash: String {
    var sha1 = [UInt8](repeating: 0, count: Int(CC_SHA1_DIGEST_LENGTH))
    withUnsafeBytes { _ = CC_SHA1($0.baseAddress, CC_LONG(count), &sha1) }
    return sha1.map({ String(format: "%02hhx", $0) }).joined()
  }
}

// MARK: MultipeerConfiguration

// Configures several aspects of the multipeer communication.
public struct MultipeerConfiguration {
  /// Defines how the multipeer connection handles newly discovered peers.
  /// New peers can be invited automatically, invited with a custom context and timeout,
  /// or not invited at all, in which case you must invite them manually.
  public enum Invitation {
    /// When `.automatic` is used, all found peers will be immediately invited to join the session.
    case automatic
    /// Use `.custom` when you want to control the invitation of new peers to your session,
    /// but still invite them at the time of discovery.
    case custom((Peer) throws -> (context: Data, timeout: TimeInterval)?)
    /// Use `.none` when you want to manually invite peers by calling `invite`
    /// in `MultipeerTransceiver`.
    case none
  }

  /// Configures security-related aspects of the multipeer connection.
  public struct Security {
    public typealias InvitationHandler = (Peer, Data?, @escaping (Bool) -> Void) -> Void

    /// An array of information that can be used to identify the peer to other nearby peers.
    /// The first object in this array should be a `SecIdentity` object that provides the
    /// local peer’s identity.
    ///
    /// The remainder of the array should contain zero or more additional SecCertificate objects
    /// that provide any
    /// intermediate certificates that nearby peers might require when verifying the local
    /// peer’s identity.
    /// These certificates should be sent in certificate chain order.
    ///
    /// Check Apple's `MCSession` docs for more information.
    public var identity: [Any]?

    /// Configure the level of encryption to be used for communications.
    public var encryptionPreference: MCEncryptionPreference

    /// A custom closure to be used when handling invitations received by remote peers.
    ///
    /// It receives the `Peer` that sent the invitation, a custom `Data` value
    /// that's a context that can be used to customize the invitation,
    /// and a closure to be called with `true` to accept the invitation or `false` to reject it.
    ///
    /// The default implementation accepts all invitations.
    public var invitationHandler: InvitationHandler

    public init(
      identity: [Any]?,
      encryptionPreference: MCEncryptionPreference,
      invitationHandler: @escaping InvitationHandler
    ) {
      self.identity = identity
      self.encryptionPreference = encryptionPreference
      self.invitationHandler = invitationHandler
    }

    /// The default security configuration, which has no identity, uses no encryption and
    /// accepts all invitations.
    public static let `default` = Security(
      identity: nil, encryptionPreference: .none,
      invitationHandler: { _, _, closure in
        closure(true)
      })
  }

  /// This must be the same accross your app running on multiple devices,
  /// it must be a short string.
  ///
  /// Check Apple's docs on `MCNearbyServiceAdvertiser` for more info on the limitations
  /// for this field.
  public var serviceType: String
  /// A display name for this peer that will be shown to nearby peers.
  public var peerName: String
  /// An instance of `UserDefaults` that's used to store this peer's identity so that it
  /// remains stable between different sessions. If you use MultipeerKit in app extensions,
  /// make sure to use a shared app group if you wish to maintain a stable identity.
  public var defaults: UserDefaults
  /// The security configuration.
  public var security: Security
  /// Defines how the multipeer connection handles newly discovered peers.
  public var invitation: Invitation

  /// Creates a new configuration.
  /// - Parameters:
  ///   - serviceType: This must be the same accross your app running on multiple devices,
  ///   it must be a short string.
  ///   Check Apple's docs on `MCNearbyServiceAdvertiser` for more info on the limitations
  ///   for this field.
  ///   - peerName: A display name for this peer that will be shown to nearby peers.
  ///   - defaults: An instance of `UserDefaults` that's used to store this peer's identity
  ///   so that it remains stable between different sessions. If you use MultipeerKit in
  ///   app extension make sure to use a shared app group if you wish to maintain a stable identity.
  ///   - security: The security configuration.
  ///   - invitation: Defines how the multipeer connection handles newly discovered peers.
  ///   New peers can be invited automatically, invited with a custom context
  ///   or not invited at all, in which case you must invite them manually.
  public init(
    serviceType: String,
    peerName: String,
    defaults: UserDefaults,
    security: Security,
    invitation: Invitation
  ) {
    precondition(peerName.utf8.count <= 63, "peerName can't be longer than 63 bytes")

    self.serviceType = serviceType
    self.peerName = peerName
    self.defaults = defaults
    self.security = security
    self.invitation = invitation
  }

  /// The default configuration, uses the service type `MKSVC`, the name of the device/computer
  /// as the  display name, `UserDefaults.standard`, the default security configuration
  /// and automatic invitation.
  public static let `default` = MultipeerConfiguration(
    serviceType: "MKSVC",
    peerName: MCPeerID.defaultDisplayName,
    defaults: .standard,
    security: .default,
    invitation: .automatic
  )

}

// MARK: - MultipeerDataSource

@available(tvOS 13.0, *)
@available(OSX 10.15, *)
@available(iOS 13.0, *)
/// This class can be used to monitor nearby peers in a reactive way,
/// it's especially useful for SwiftUI apps.
public final class MultipeerDataSource: ObservableObject {
  public let transceiver: MultipeerTransceiver

  /// Initializes a new data source.
  /// - Parameter transceiver: The transceiver to be used by this data source.
  /// Note that the data source will set `availablePeersDidChange` on the
  /// transceiver, so if you wish to use that closure yourself, you
  /// won't be able to use the data source.
  public init(transceiver: MultipeerTransceiver) {
    self.transceiver = transceiver
    transceiver.availablePeersDidChange = { [weak self] peers in
      self?.availablePeers = peers
    }
  }

  /// Peers currently available for invitation, connection and data transmission.
  @Published public private(set) var availablePeers: [Peer] = []
}

//MARK: - MultipeerTransceiver

/// Handles all aspects related to the multipeer communication.
public final class MultipeerTransceiver {
  private let log = MultipeerKit.log(for: MultipeerTransceiver.self)
  let connection: MultipeerProtocol
  /// Called on the main queue when available peers have changed (new peers discovered or peers removed).
  public var availablePeersDidChange: ([Peer]) -> Void = { _ in }
  /// All peers currently available for invitation, connection and data transmission.
  public var availablePeers: [Peer] = [] {
    didSet {
      guard availablePeers != oldValue else { return }

      DispatchQueue.main.async {
        self.availablePeersDidChange(self.availablePeers)
      }
    }
  }

  /// Initializes a new transceiver.
  /// - Parameter configuration: The configuration, uses the default configuration if none specified.
  public init(configuration: MultipeerConfiguration = .default) {
    self.connection = MultipeerConnection(
      modes: MultipeerConnection.Mode.allCases,
      configuration: configuration
    )

    configure(connection)
  }

  init(connection: MultipeerProtocol) {
    self.connection = connection

    configure(connection)
  }

  private func configure(_ connection: MultipeerProtocol) {
    connection.didReceiveData = { [weak self] data, peer in
      self?.handleDataReceived(data, from: peer)
    }
    connection.didFindPeer = { [weak self] peer in
      DispatchQueue.main.async { self?.handlePeerAdded(peer) }
    }
    connection.didLosePeer = { [weak self] peer in
      DispatchQueue.main.async { self?.handlePeerRemoved(peer) }
    }
    connection.didConnectToPeer = { [weak self] peer in
      DispatchQueue.main.async { self?.handlePeerConnected(peer) }
    }
    connection.didDisconnectFromPeer = { [weak self] peer in
      DispatchQueue.main.async { self?.handlePeerDisconnected(peer) }
    }
  }

  /// Configures a new handler for a specific `Codable` type.
  /// - Parameters:
  ///   - type: The `Codable` type to receive.
  ///   - closure: Will be called whenever a payload of the specified type is received.
  ///   - payload: The payload decoded from the remote message.
  ///
  /// MultipeerKit communicates data between peers as JSON-encoded payloads which originate with
  /// `Codable` entities. You register a closure to handle each specific type of entity,
  /// and this closure is automatically called by the framework when a remote peer sends
  /// a message containing an entity that decodes to the specified type.
  public func receive<T: Codable>(_ type: T.Type, using closure: @escaping (_ payload: T) -> Void) {
    MultipeerMessage.register(type, for: String(describing: type), closure: closure)
  }

  /// Resumes the transceiver, allowing this peer to be discovered and to discover remote peers.
  public func resume() {
    connection.resume()
  }

  /// Stops the transceiver, preventing this peer from discovering and being discovered.
  public func stop() {
    connection.stop()
  }

  /// Sends a message to all connected peers.
  /// - Parameter payload: The payload to be sent.
  public func broadcast<T: Encodable>(_ payload: T) {
    MultipeerMessage.register(T.self, for: String(describing: T.self))
    do {
      let message = MultipeerMessage(type: String(describing: T.self), payload: payload)
      let data = try JSONEncoder().encode(message)
      try connection.broadcast(data)
    } catch {
      os_log(
        "Failed to send payload %@: %{public}@", log: self.log, type: .error,
        String(describing: payload), String(describing: error))
    }
  }

  /// Sends a message to a specific peer.
  /// - Parameters:
  ///   - payload: The payload to be sent.
  ///   - peers: An array of peers to send the message to.
  public func send<T: Encodable>(_ payload: T, to peers: [Peer]) {
    MultipeerMessage.register(T.self, for: String(describing: T.self))
    do {
      let message = MultipeerMessage(type: String(describing: T.self), payload: payload)
      let data = try JSONEncoder().encode(message)
      try connection.send(data, to: peers)
    } catch {
      os_log(
        "Failed to send payload %@: %{public}@", log: self.log, type: .error,
        String(describing: payload), String(describing: error))
    }
  }

  private func handleDataReceived(_ data: Data, from peer: PeerName) {
    os_log("%{public}@", log: log, type: .debug, #function)
    do {
      let message = try JSONDecoder().decode(MultipeerMessage.self, from: data)
      os_log("Received message %@", log: self.log, type: .debug, String(describing: message))
    } catch {
      os_log(
        "Failed to decode message: %{public}@", log: self.log, type: .error,
        String(describing: error))
    }
  }

  /// Manually invite a peer for communicating.
  /// - Parameters:
  ///   - peer: The peer to be invited.
  ///   - context: Custom data to be sent alongside the invitation.
  ///   - timeout: How long to wait for the remote peer to accept the invitation.
  ///   - completion: Called when the invitation succeeds or fails.
  ///
  /// You can call this method to manually invite a peer for communicating if you set the
  /// `invitation` parameter to `.none` in the transceiver's `configuration`.
  ///
  /// - warning: If the invitation parameter is not set to `.none`, you shouldn't call this method,
  /// since the transceiver does the inviting automatically.
  public func invite(
    _ peer: Peer,
    with context: Data?,
    timeout: TimeInterval,
    completion: InvitationCompletionHandler?
  ) {
    connection.invite(peer, with: context, timeout: timeout, completion: completion)
  }

  private func handlePeerAdded(_ peer: Peer) {
    guard !availablePeers.contains(peer) else { return }
    availablePeers.append(peer)
  }

  private func handlePeerRemoved(_ peer: Peer) {
    guard let idx = availablePeers.firstIndex(where: { $0.underlyingPeer == peer.underlyingPeer })
    else { return }
    availablePeers.remove(at: idx)
  }

  private func handlePeerConnected(_ peer: Peer) {
    setConnected(true, on: peer)
  }

  private func handlePeerDisconnected(_ peer: Peer) {
    setConnected(false, on: peer)
  }

  private func setConnected(_ connected: Bool, on peer: Peer) {
    guard let idx = availablePeers.firstIndex(where: { $0.underlyingPeer == peer.underlyingPeer })
    else { return }
    var mutablePeer = availablePeers[idx]
    mutablePeer.isConnected = connected
    availablePeers[idx] = mutablePeer
  }
}

// MARK: - Internal

// MARK: MCPeerID+Me

extension MCPeerID {
  private static let defaultsKey = "_multipeerKit.mePeerID"
  private static func fetchExisting(with config: MultipeerConfiguration) -> MCPeerID? {
    guard let data = config.defaults.data(forKey: Self.defaultsKey) else { return nil }
    do {
      let peer = try NSKeyedUnarchiver.unarchivedObject(ofClass: MCPeerID.self, from: data)
      guard peer?.displayName == config.peerName else { return nil }
      return peer
    } catch {
      return nil
    }
  }

  static func fetchOrCreate(with config: MultipeerConfiguration) -> MCPeerID {
    fetchExisting(with: config) ?? MCPeerID(displayName: config.peerName)
  }

}

#if os(iOS) || os(tvOS)
  import UIKit

  extension MCPeerID {
    public static var defaultDisplayName: String { UIDevice.current.name }
  }
#else
  import Cocoa

  extension MCPeerID {
    public static var defaultDisplayName: String { Host.current().localizedName ?? "Unknown Mac" }
  }
#endif

// MARK: MultipeerMessage

struct MultipeerMessage: Codable {
  let type: String
  let payload: Any?

  init(type: String, payload: Any) {
    self.type = type
    self.payload = payload
  }

  enum CodingKeys: String, CodingKey {
    case type
    case payload
  }
  
  private typealias MessageDecoder = (KeyedDecodingContainer<CodingKeys>) throws -> Any
  private typealias MessageEncoder = (Any, inout KeyedEncodingContainer<CodingKeys>) throws -> Void
  private static var decoders: [String: MessageDecoder] = [:]
  private static var encoders: [String: MessageEncoder] = [:]

  static func register<T: Codable>(
    _ type: T.Type, for typeName: String, closure: @escaping (T) -> Void
  ) {
    decoders[typeName] = { container in
      let payload = try container.decode(T.self, forKey: .payload)
      DispatchQueue.main.async { closure(payload) }
      return payload
    }
    register(T.self, for: typeName)
  }

  static func register<T: Encodable>(_ type: T.Type, for typeName: String) {
    encoders[typeName] = { payload, container in
      try container.encode(payload as! T, forKey: .payload)
    }
  }

  init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    type = try container.decode(String.self, forKey: .type)
    if let decode = Self.decoders[type] {
      payload = try decode(container)
    } else {
      payload = nil
    }
  }

  func encode(to encoder: Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(type, forKey: .type)
    if let payload = self.payload {
      guard let encode = Self.encoders[type] else {
        let context = EncodingError.Context(
          codingPath: [], debugDescription: "Invalid payload type: \(type).")
        throw EncodingError.invalidValue(self, context)
      }
      try encode(payload, &container)
    } else {
      try container.encodeNil(forKey: .payload)
    }
  }
}

// MARK: MockMultipeerConnection

final class MockMultipeerConnection: MultipeerProtocol {
  var didReceiveData: ((Data, PeerName) -> Void)?
  var didFindPeer: ((Peer) -> Void)?
  var didLosePeer: ((Peer) -> Void)?
  var didConnectToPeer: ((Peer) -> Void)?
  var didDisconnectFromPeer: ((Peer) -> Void)?

  var isRunning = false

  func resume() {
    isRunning = true
  }

  func stop() {
    isRunning = false
  }

  func broadcast(_ data: Data) throws {
    didReceiveData?(data, "MockPeer")
  }

  func send(_ data: Data, to peers: [Peer]) throws { }

  func invite(
    _ peer: Peer,
    with context: Data?,
    timeout: TimeInterval,
    completion: InvitationCompletionHandler?) { }
}

//MARK: MultipeerConnection

public typealias InvitationCompletionHandler = (_ result: Result<Peer, Error>) -> Void

public struct MultipeerError: LocalizedError {
  public var localizedDescription: String
}

final class MultipeerConnection: NSObject, MultipeerProtocol {
  enum Mode: Int, CaseIterable {
    case receiver
    case transmitter
  }

  private let log = MultipeerKit.log(for: MultipeerConnection.self)

  let modes: [Mode]
  let configuration: MultipeerConfiguration
  let me: MCPeerID

  init(modes: [Mode] = Mode.allCases, configuration: MultipeerConfiguration = .default) {
    self.modes = modes
    self.configuration = configuration
    self.me = MCPeerID.fetchOrCreate(with: configuration)
  }

  var didReceiveData: ((Data, PeerName) -> Void)?
  var didFindPeer: ((Peer) -> Void)?
  var didLosePeer: ((Peer) -> Void)?
  var didConnectToPeer: ((Peer) -> Void)?
  var didDisconnectFromPeer: ((Peer) -> Void)?

  private var discoveredPeers: [MCPeerID: Peer] = [:]

  func resume() {
    os_log("%{public}@", log: log, type: .debug, #function)
    if modes.contains(.receiver) {
      advertiser.startAdvertisingPeer()
    }
    if modes.contains(.transmitter) {
      browser.startBrowsingForPeers()
    }
  }

  func stop() {
    os_log("%{public}@", log: log, type: .debug, #function)
    if modes.contains(.receiver) {
      advertiser.stopAdvertisingPeer()
    }
    if modes.contains(.transmitter) {
      browser.stopBrowsingForPeers()
    }
  }

  private lazy var session: MCSession = {
    let s = MCSession(
      peer: me,
      securityIdentity: configuration.security.identity,
      encryptionPreference: configuration.security.encryptionPreference
    )
    s.delegate = self
    return s
  }()

  private lazy var browser: MCNearbyServiceBrowser = {
    let b = MCNearbyServiceBrowser(peer: me, serviceType: configuration.serviceType)
    b.delegate = self
    return b
  }()

  private lazy var advertiser: MCNearbyServiceAdvertiser = {
    let a = MCNearbyServiceAdvertiser(
      peer: me, discoveryInfo: nil, serviceType: configuration.serviceType)
    a.delegate = self
    return a
  }()

  func broadcast(_ data: Data) throws {
    guard !session.connectedPeers.isEmpty else {
      os_log("Not broadcasting message: no connected peers", log: self.log, type: .error)
      return
    }
    try session.send(data, toPeers: session.connectedPeers, with: .reliable)
  }

  func send(_ data: Data, to peers: [Peer]) throws {
    let ids = peers.map { $0.underlyingPeer }
    try session.send(data, toPeers: ids, with: .reliable)
  }

  private var invitationCompletionHandlers: [MCPeerID: InvitationCompletionHandler] = [:]

  func invite(
    _ peer: Peer, with context: Data?, timeout: TimeInterval,
    completion: InvitationCompletionHandler?
  ) {
    invitationCompletionHandlers[peer.underlyingPeer] = completion
    browser.invitePeer(peer.underlyingPeer, to: session, withContext: context, timeout: timeout)
  }
}

// MARK: - Session delegate

extension MultipeerConnection: MCSessionDelegate {

  func session(_ session: MCSession, peer peerID: MCPeerID, didChange state: MCSessionState) {
    os_log("%{public}@", log: log, type: .debug, #function)
    guard let peer = discoveredPeers[peerID] else { return }
    let handler = invitationCompletionHandlers[peerID]
    DispatchQueue.main.async {
      switch state {
      case .connected:
        handler?(.success(peer))
        self.invitationCompletionHandlers[peerID] = nil
        self.didConnectToPeer?(peer)
      case .notConnected:
        handler?(.failure(MultipeerError(localizedDescription: "Failed to connect to peer.")))
        self.invitationCompletionHandlers[peerID] = nil
        self.didDisconnectFromPeer?(peer)
      case .connecting:
        break
      @unknown default:
        break
      }
    }
  }

  func session(
    _ session: MCSession,
    didReceive data: Data,
    fromPeer peerID: MCPeerID
  ) {
    os_log("%{public}@", log: log, type: .debug, #function)
    didReceiveData?(data, peerID.displayName)
  }

  func session(
    _ session: MCSession,
    didReceive stream: InputStream,
    withName streamName: String,
    fromPeer peerID: MCPeerID
  ) {
    os_log("%{public}@", log: log, type: .debug, #function)
  }

  func session(
    _ session: MCSession,
    didStartReceivingResourceWithName resourceName: String,
    fromPeer peerID: MCPeerID,
    with progress: Progress
  ) {
    os_log("%{public}@", log: log, type: .debug, #function)
  }

  func session(
    _ session: MCSession,
    didFinishReceivingResourceWithName resourceName: String,
    fromPeer peerID: MCPeerID, at localURL: URL?, withError error: Error?
  ) {
    os_log("%{public}@", log: log, type: .debug, #function)
  }

}

// MARK: - Browser delegate

extension MultipeerConnection: MCNearbyServiceBrowserDelegate {

  func browser(
    _ browser: MCNearbyServiceBrowser,
    foundPeer peerID: MCPeerID,
    withDiscoveryInfo info: [String: String]?
  ) {
    os_log("%{public}@", log: log, type: .debug, #function)
    do {
      let peer = try Peer(peer: peerID, discoveryInfo: info)
      discoveredPeers[peerID] = peer
      didFindPeer?(peer)
      switch configuration.invitation {
      case .automatic:
        browser.invitePeer(peerID, to: session, withContext: nil, timeout: 10.0)
      case .custom(let inviter):
        guard let invite = try inviter(peer) else {
          os_log(
            "Custom invite not sent for peer %@", log: self.log, type: .error,
            String(describing: peer))
          return
        }
        browser.invitePeer(
          peerID,
          to: session,
          withContext: invite.context,
          timeout: invite.timeout
        )
      case .none:
        os_log("Auto-invite disabled", log: self.log, type: .debug)
        return
      }
    } catch {
      os_log(
        "Failed to initialize peer based on peer ID %@: %{public}@", log: self.log, type: .error,
        String(describing: peerID), String(describing: error))
    }
  }

  func browser(_ browser: MCNearbyServiceBrowser, lostPeer peerID: MCPeerID) {
    os_log("%{public}@", log: log, type: .debug, #function)
    guard let peer = discoveredPeers[peerID] else { return }
    didLosePeer?(peer)
    discoveredPeers[peerID] = nil
  }
}

// MARK: - Advertiser delegate

extension MultipeerConnection: MCNearbyServiceAdvertiserDelegate {

  func advertiser(
    _ advertiser: MCNearbyServiceAdvertiser,
    didReceiveInvitationFromPeer peerID: MCPeerID,
    withContext context: Data?,
    invitationHandler: @escaping (Bool, MCSession?) -> Void
  ) {
    os_log("%{public}@", log: log, type: .debug, #function)
    guard let peer = discoveredPeers[peerID] else { return }
    configuration.security.invitationHandler(
      peer, context,
      { [weak self] decision in
        guard let self = self else { return }
        invitationHandler(decision, decision ? self.session : nil)
      })
  }
}

// MARK: - Advertiser delegate

struct MultipeerKit {
  static let subsystemName = "swift.package.multipeer"
  static func log(for type: AnyClass) -> OSLog {
    OSLog(subsystem: subsystemName, category: String(describing: type))
  }
}

// MARK: - MultipeerProtocol

typealias PeerName = String

protocol MultipeerProtocol: AnyObject {
  var didReceiveData: ((Data, PeerName) -> Void)? { get set }
  var didFindPeer: ((Peer) -> Void)? { get set }
  var didLosePeer: ((Peer) -> Void)? { get set }
  var didConnectToPeer: ((Peer) -> Void)? { get set }
  var didDisconnectFromPeer: ((Peer) -> Void)? { get set }
  
  func resume()
  
  func stop()

  func invite(
    _ peer: Peer,
    with context: Data?,
    timeout: TimeInterval,
    completion: InvitationCompletionHandler?)
  
  func broadcast(_ data: Data) throws
  
  func send(_ data: Data, to peers: [Peer]) throws
}
