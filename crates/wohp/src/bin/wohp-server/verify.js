"use strict";
const field = document.getElementById("status");
const TEXTS = {
  en: {
    PENDING: "Waiting for the wallet…",
    VERIFYING: "Verifying…",
    back: "Back to the service",
    failed: "Verification unavailable ({error}): go back to the service and try again.",
    error: "error",
    reasons: {
      ambiguous: "The wallet did not provide enough data to recognise the person.",
      underage: "Minimum age not reached.",
      unavailable: "Verifier unavailable.",
      expired: "Request expired.",
      invalid: "Invalid presentation.",
    },
  },
  it: {
    PENDING: "In attesa del wallet…",
    VERIFYING: "Verifica in corso…",
    back: "Torna al servizio",
    failed: "Verifica non disponibile ({error}): torna al servizio e riprova.",
    error: "errore",
    reasons: {
      ambiguous: "Il wallet non ha fornito dati sufficienti per riconoscere la persona.",
      underage: "Età minima non raggiunta.",
      unavailable: "Verificatore non disponibile.",
      expired: "Richiesta scaduta.",
      invalid: "Presentazione non valida.",
    },
  },
};
// The server picked the page language from Accept-Language.
const text = TEXTS[document.documentElement.lang] || TEXTS.en;
const labels = {
  PENDING: text.PENDING,
  VERIFYING: text.VERIFYING,
  READY: field.dataset.ready,
};
const reasons = text.reasons;
let busy = false;
const timer = setInterval(async () => {
  if (busy) return;
  busy = true;
  try {
    const response = await fetch(field.dataset.poll, { cache: "no-store" });
    if (!response.ok) throw new Error("HTTP " + response.status);
    const data = await response.json();
    if (data.state === "REJECTED") {
      clearInterval(timer);
      field.textContent = reasons[data.reason] || reasons.invalid;
      if (data.restart) {
        const again = document.createElement("a");
        again.className = "button";
        again.href = data.restart;
        again.textContent = text.back;
        field.closest(".status-card").appendChild(again);
      }
      return;
    }
    if (data.redirect) {
      clearInterval(timer);
      location.assign(data.redirect);
    } else {
      field.textContent = labels[data.state] || data.state;
    }
  } catch (error) {
    clearInterval(timer);
    field.textContent = text.failed.replace("{error}", error.message || text.error);
  }
  busy = false;
}, 2000);
