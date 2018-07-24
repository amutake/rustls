/// This module contains optional APIs for implementing QUIC TLS.
use client::{ClientConfig, ClientSession, ClientSessionImpl};
use msgs::base::Payload;
use msgs::enums::{ExtensionType, ContentType, ProtocolVersion};
use msgs::handshake::{ClientExtension, ServerExtension, UnknownExtension};
use msgs::message::{Message, MessagePayload};
use server::{ServerConfig, ServerSession, ServerSessionImpl};
use error::TLSError;
use key_schedule::{SecretKind, TrafficKey};

use std::sync::Arc;
use webpki;
use ring;

/// Keys used to encrypt/decrypt traffic
pub struct Keys {
    /// Encryption algorithm to use
    pub algorithm: &'static ring::aead::Algorithm,
    /// Key to use when encrypting outgoing data
    pub write_key: Vec<u8>,
    /// IV to use when encrypting outgoing data
    pub write_iv: Vec<u8>,
    /// Key to use when decrypting incoming data
    pub read_key: Vec<u8>,
    /// IV to use when decrypting incoming data
    pub read_iv: Vec<u8>,
}

/// Generic methods for QUIC sessions
pub trait QuicExt {
    /// Return the TLS-encoded transport parameters for the session's peer.
    fn get_quic_transport_parameters(&self) -> Option<&[u8]>;

    /// Consume unencrypted TLS handshake data
    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError>;

    /// Emit unencrypted TLS handshake data
    fn write_hs(&mut self, buf: &mut Vec<u8>);

    /// Emit the TLS description code of a fatal alert, if one has arisen
    fn take_alert(&mut self) -> Option<u8>;

    /// Get the keys used to encrypt/decrypt handshake traffic, if available
    fn get_handshake_keys(&self) -> Option<Keys>;

    /// Get the keys used to encrypt/decrypt 1-RTT traffic, if available
    fn get_1rtt_keys(&self) -> Option<Keys>;
}

impl QuicExt for ClientSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.common.quic.params.as_ref().map(|v| v.as_ref())
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError> {
        self.imp.common
            .handshake_joiner
            .take_message(Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::new_opaque(plaintext.into()),
            });
        self.imp.process_new_handshake_messages()?;
        Ok(())
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) {
        unimplemented!()
    }

    fn take_alert(&mut self) -> Option<u8> { unimplemented!() }

    fn get_handshake_keys(&self) -> Option<Keys> {
        let key_schedule = self.imp.common.key_schedule.as_ref()?;
        let handshake_hash = self.imp.handshake_transcript_hash();
        let suite = self.imp.common.get_suite_assert();
        let write_secret = key_schedule.derive(SecretKind::ClientHandshakeTrafficSecret, &handshake_hash);
        let write = TrafficKey::from_suite(suite, &write_secret, true);
        let read_secret = key_schedule.derive(SecretKind::ServerHandshakeTrafficSecret, &handshake_hash);
        let read = TrafficKey::from_suite(suite, &read_secret, true);
        Some(Keys {
            algorithm: suite.get_aead_alg(),
            write_key: write.key,
            write_iv: write.iv,
            read_key: read.key,
            read_iv: read.iv,
        })
    }

    fn get_1rtt_keys(&self) -> Option<Keys> { unimplemented!() }
}

impl QuicExt for ServerSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.common.quic.params.as_ref().map(|v| v.as_ref())
    }

    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError> {
        self.imp.common
            .handshake_joiner
            .take_message(Message {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_3,
                payload: MessagePayload::new_opaque(plaintext.into()),
            });
        self.imp.process_new_handshake_messages()?;
        Ok(())
    }

    fn write_hs(&mut self, buf: &mut Vec<u8>) {
        unimplemented!()
    }

    fn take_alert(&mut self) -> Option<u8> { unimplemented!() }

    fn get_handshake_keys(&self) -> Option<Keys> {
        unimplemented!()
    }

    fn get_1rtt_keys(&self) -> Option<Keys> { unimplemented!() }
}

/// Methods specific to QUIC client sessions
pub trait ClientQuicExt {
    /// Make a new QUIC ClientSession. This differs from `ClientSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ClientConfig>, hostname: webpki::DNSNameRef, params: Vec<u8>)
                -> ClientSession {
        assert!(config.versions.iter().all(|x| x.get_u16() >= ProtocolVersion::TLSv1_3.get_u16()), "QUIC requires TLS version >= 1.3");
        let mut imp = ClientSessionImpl::new(config);
        imp.common.quic.enabled = true;
        imp.start_handshake(hostname.into(), vec![
            ClientExtension::Unknown(UnknownExtension {
                typ: ExtensionType::TransportParameters,
                payload: Payload::new(params),
            })
        ]);
        ClientSession { imp }
    }
}

impl ClientQuicExt for ClientSession {}

/// Methods specific to QUIC server sessions
pub trait ServerQuicExt {
    /// Make a new QUIC ServerSession. This differs from `ServerSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ServerConfig>, params: Vec<u8>) -> ServerSession {
        assert!(config.versions.iter().all(|x| x.get_u16() >= ProtocolVersion::TLSv1_3.get_u16()), "QUIC requires TLS version >= 1.3");
        let mut imp = ServerSessionImpl::new(config, vec![
                ServerExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::TransportParameters,
                    payload: Payload::new(params),
                }),
        ]);
        imp.common.quic.enabled = true;
        ServerSession { imp }
    }
}

impl ServerQuicExt for ServerSession {}
