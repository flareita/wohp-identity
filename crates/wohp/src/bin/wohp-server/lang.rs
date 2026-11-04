//! Page language: Italian when the browser prefers it to English, otherwise
//! English. Only the wallet pages are translated; the client API has no text.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Lang {
    En,
    It,
}

/// Reads `Accept-Language` (RFC 9110): the higher quality of `it` and `en`
/// wins, the earlier one on a tie; anything else, or no header, is English.
pub fn language(headers: &HeaderMap) -> Lang {
    let Some(value) = headers
        .get("accept-language")
        .and_then(|value| value.to_str().ok())
    else {
        return Lang::En;
    };
    let mut best: [Option<(u16, usize)>; 2] = [None, None];
    for (position, item) in value.split(',').take(32).enumerate() {
        let mut parts = item.split(';');
        let primary = parts
            .next()
            .unwrap_or("")
            .trim()
            .split('-')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let slot = match primary.as_str() {
            "en" => 0,
            "it" => 1,
            _ => continue,
        };
        let quality = match parts.find_map(|part| part.trim().strip_prefix("q=")) {
            None => 1000,
            Some(raw) => match raw.trim().parse::<f32>() {
                Ok(q) if (0.0..=1.0).contains(&q) => (q * 1000.0).round() as u16,
                _ => continue,
            },
        };
        if quality > 0 && best[slot].is_none_or(|(known, _)| quality > known) {
            best[slot] = Some((quality, position));
        }
    }
    match best {
        [Some((en, en_at)), Some((it, it_at))] if it > en || (it == en && it_at < en_at) => {
            Lang::It
        }
        [None, Some(_)] => Lang::It,
        _ => Lang::En,
    }
}

/// Every text of the wallet pages, in one language.
pub struct Texts {
    pub code: &'static str,
    pub title: &'static str,
    pub default_tagline: &'static str,
    pub default_notice: &'static str,
    pub index_eyebrow: &'static str,
    pub index_heading: &'static str,
    pub index_lead: &'static str,
    pub enroll_eyebrow: &'static str,
    pub enroll_lead: &'static str,
    pub enroll_ready: &'static str,
    pub recover_eyebrow: &'static str,
    pub recover_lead: &'static str,
    pub recover_ready: &'static str,
    pub scan_heading: &'static str,
    pub open_wallet: &'static str,
    pub waiting: &'static str,
    pub security_note: &'static str,
    pub expired_heading: &'static str,
    pub expired_lead: &'static str,
    pub back: &'static str,
}

const EN: Texts = Texts {
    code: "en",
    title: "EUDI Wallet",
    default_tagline: "EUDI wallet identity",
    default_notice: "demo sandbox · no verification of unique identity",
    index_eyebrow: "Sign in with a wallet",
    index_heading: "Start from the service you are using",
    index_lead: "This page opens from the wallet button of a service. \
                 Go back to that service and try again from there.",
    enroll_eyebrow: "EUDI Wallet",
    enroll_lead: "Open your EUDI wallet and scan the code. The request asks only for the \
                  PID data needed to recognise the same person and to compute an age threshold.",
    enroll_ready: "Wallet verified. Redirecting…",
    recover_eyebrow: "Account recovery",
    recover_lead: "Present the same PID to prove you are the same person. \
                   The service you came from then lets you restore access to the same account.",
    recover_ready: "Identity verified. Redirecting…",
    scan_heading: "Scan with your wallet",
    open_wallet: "Open the wallet on this phone",
    waiting: "Waiting for the wallet…",
    security_note: "On another device, scan the QR code. The result does not prove a unique \
                    identity. No wallet data is stored. The QR code is valid for 5 minutes.",
    expired_heading: "Request expired",
    expired_lead: "The QR code is valid for 5 minutes. Go back to the service to get a new one.",
    back: "Back to the service",
};

const IT: Texts = Texts {
    code: "it",
    title: "Wallet EUDI",
    default_tagline: "Identità con wallet EUDI",
    default_notice: "demo sandbox · nessuna verifica di identità unica",
    index_eyebrow: "Accesso con wallet",
    index_heading: "Inizia dal servizio che stai usando",
    index_lead: "Questa pagina si apre dal pulsante di accesso con il wallet del servizio. \
                 Torna al servizio e riprova da lì.",
    enroll_eyebrow: "Wallet EUDI",
    enroll_lead: "Apri il wallet EUDI e inquadra il codice. La richiesta contiene solo \
                  i dati del PID necessari a riconoscere la stessa identità e calcolare la soglia d'età.",
    enroll_ready: "Wallet verificato. Reindirizzamento…",
    recover_eyebrow: "Recupero account",
    recover_lead: "Presenta lo stesso PID per dimostrare che sei la stessa persona. \
                   Il servizio da cui arrivi ti farà poi riprendere lo stesso account.",
    recover_ready: "Identità verificata. Reindirizzamento…",
    scan_heading: "Scansiona con il wallet",
    open_wallet: "Apri il wallet su questo telefono",
    waiting: "In attesa del wallet…",
    security_note: "Su un altro dispositivo scansiona il QR. Il risultato non prova un'identità \
                    unica. Nessun dato del wallet viene conservato. Il QR vale 5 minuti.",
    expired_heading: "Richiesta scaduta",
    expired_lead: "Il QR vale 5 minuti. Torna al servizio per generarne uno nuovo.",
    back: "Torna al servizio",
};

impl Lang {
    pub fn texts(self) -> &'static Texts {
        match self {
            Self::En => &EN,
            Self::It => &IT,
        }
    }
}
