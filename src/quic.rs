/// This module contains optional APIs for implementing QUIC TLS.
use client::{ClientConfig, ClientSession, ClientSessionImpl};
use msgs::base::Payload;
use msgs::enums::{ExtensionType, ContentType, ProtocolVersion};
use msgs::handshake::{ClientExtension, ServerExtension, UnknownExtension};
use msgs::message::{Message, MessagePayload};
use server::{ServerConfig, ServerSession, ServerSessionImpl};
use error::TLSError;

use std::sync::Arc;
use webpki;

/// Generic methods for QUIC sessions
pub trait QuicExt {
    /// Return the TLS-encoded transport parameters for the session's peer.
    fn get_quic_transport_parameters(&self) -> Option<&[u8]>;

    /// Consume unencrypted TLS handshake data
    fn read_hs(&mut self, plaintext: &[u8]) -> Result<(), TLSError>;

    /// Emit unencrypted TLS handshake data
    fn write_hs(&mut self, buf: &mut Vec<u8>);
}

impl QuicExt for ClientSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.quic_params.as_ref().map(|v| v.as_ref())
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
}

impl QuicExt for ServerSession {
    fn get_quic_transport_parameters(&self) -> Option<&[u8]> {
        self.imp.quic_params.as_ref().map(|v| v.as_ref())
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
}

/// Methods specific to QUIC client sessions
pub trait ClientQuicExt {
    /// Make a new QUIC ClientSession. This differs from `ClientSession::new()`
    /// in that it takes an extra argument, `params`, which contains the
    /// TLS-encoded transport parameters to send.
    fn new_quic(config: &Arc<ClientConfig>, hostname: webpki::DNSNameRef, params: Vec<u8>)
                -> ClientSession {
        let mut imp = ClientSessionImpl::new(config);
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
        ServerSession {
            imp: ServerSessionImpl::new(config, vec![
                ServerExtension::Unknown(UnknownExtension {
                    typ: ExtensionType::TransportParameters,
                    payload: Payload::new(params),
                }),
            ]),
        }
    }
}

impl ServerQuicExt for ServerSession {}
