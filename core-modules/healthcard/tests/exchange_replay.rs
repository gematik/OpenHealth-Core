use healthcard::command::apdu::{CardCommandApdu, CardResponseApdu};
use healthcard::exchange::channel::CardChannel;
use healthcard::exchange::{
    establish_secure_channel_with, get_random, read_vsd, retrieve_certificate, retrieve_certificate_from, verify_pin,
    CardAccessNumber, CardPin, CertificateFile, ExchangeError, HealthCardVerifyPinResult, SecureChannel,
};
use healthcard_apdu_base::{ReplaySession, Transcript};

struct ReplayChannel {
    session: ReplaySession,
}

impl ReplayChannel {
    fn from_transcript(transcript: Transcript) -> Self {
        Self { session: ReplaySession::from_transcript(transcript) }
    }
}

impl CardChannel for ReplayChannel {
    type Error = ExchangeError;

    fn supports_extended_length(&self) -> bool {
        self.session.supports_extended_length()
    }

    fn transmit(&mut self, command: &CardCommandApdu) -> Result<CardResponseApdu, Self::Error> {
        let tx = command.to_bytes();
        let rx = self.session.transmit_bytes(&tx).map_err(|err| ExchangeError::Transport {
            code: 0,
            message: err.to_string(),
        })?;
        CardResponseApdu::new(&rx).map_err(ExchangeError::from)
    }
}

fn establish_from_transcript(jsonl: &str) -> SecureChannel<ReplayChannel> {
    let transcript = Transcript::from_jsonl_str(jsonl).expect("load transcript");
    let can = transcript.can().expect("CAN in transcript");
    let card_access_number = CardAccessNumber::new(can).expect("CAN format");
    let mut generator = transcript
        .fixed_key_generator()
        .expect("keys parse")
        .expect("fixed key generator");
    let replay = ReplayChannel::from_transcript(transcript);
    establish_secure_channel_with(replay, &card_access_number, &mut generator).expect("replay establish secure channel")
}

#[test]
fn replay_establish_secure_channel() {
    let _channel = establish_from_transcript(JSONL_ESTABLISH_SECURE_CHANNEL);
}

#[test]
fn replay_verify_pin() {
    let mut channel = establish_from_transcript(JSONL_VERIFY_PIN);
    let pin = CardPin::new("123456").expect("valid PIN format");
    match verify_pin(&mut channel, &pin).expect("verify PIN") {
        HealthCardVerifyPinResult::Success(_) => {}
        HealthCardVerifyPinResult::WrongSecretWarning { retries_left, .. } => {
            panic!("PIN verification failed, retries left: {retries_left}");
        }
        HealthCardVerifyPinResult::CardBlocked(_) => panic!("PIN verification failed: card blocked"),
    }
}

#[test]
fn replay_get_random() {
    let mut channel = establish_from_transcript(JSONL_GET_RANDOM);
    let random = get_random(&mut channel, 32).expect("get random");
    assert_eq!(random.len(), 32);
}

#[test]
fn replay_read_vsd() {
    let mut channel = establish_from_transcript(JSONL_READ_VSD);
    let vsd = read_vsd(&mut channel).expect("read VSD");
    assert!(!vsd.is_empty());
}

#[test]
fn replay_retrieve_certificates() {
    let mut channel = establish_from_transcript(JSONL_READ_CERTS);
    let cert = retrieve_certificate(&mut channel).expect("retrieve default certificate");
    assert!(!cert.is_empty());

    let cv_cert = retrieve_certificate_from(&mut channel, CertificateFile::EgkAutCvcE256)
        .expect("retrieve CV certificate");
    assert!(!cv_cert.is_empty());
}

const JSONL_ESTABLISH_SECURE_CHANNEL: &str =
    include_str!("../../../test-vectors/apdu-replay/establish-secure-channel.jsonl");
const JSONL_VERIFY_PIN: &str = include_str!("../../../test-vectors/apdu-replay/verify-pin.jsonl");
const JSONL_GET_RANDOM: &str = include_str!("../../../test-vectors/apdu-replay/get-random.jsonl");
const JSONL_READ_VSD: &str = include_str!("../../../test-vectors/apdu-replay/read-vsd.jsonl");
const JSONL_READ_CERTS: &str = include_str!("../../../test-vectors/apdu-replay/read-certs.jsonl");
