//! Local browser controller and observer for the real-time arena.
//! The browser never decides game rules and never sees a secret: it draws the
//! provisional 60 Hz state the Rust simulation publishes, next to the last
//! independently certified state.
#![forbid(unsafe_code)]
use gv_edge::{ArenaState, Fighter};
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const PAGE: &str = include_str!("arena.html");
const MAX_REQUEST: usize = 8192;
const MAX_EVENTS: usize = 60;
const LEGAL_CONTROLS: u16 = 0b11_1111;
const MOVE_MASK: u16 = 0b1111;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HideView {
    /// Roster index of the player whose location is hidden.
    pub hider: usize,
    pub start: u64,
    pub end: u64,
}

/// Everything the page shows. Written by the simulation and pipeline tasks,
/// read by the HTTP handler; never holds a lock across I/O.
pub struct View {
    pub you: usize,
    pub phase: String,
    /// Provisional 60 Hz state (what you are playing right now).
    pub players: [Fighter; 2],
    /// Last state both players co-signed.
    pub verified: [Fighter; 2],
    pub tick: u64,
    pub verified_tick: u64,
    pub checkpoint: String,
    pub events: VecDeque<String>,
    pub stopped: bool,
    pub controls: u16,
    control_events: VecDeque<u16>,
    pub inject_cheat: bool,
    pub inject_illegal: bool,
    pub hide_request: bool,
    /// Epochs certified by two matching signatures.
    pub accepted: u64,
    /// Epochs closed by fraud evidence instead.
    pub disputed: u64,
    /// Proven cheats / invalid actions (each counted once).
    pub rejected: u64,
    pub verdict: &'static str,
    /// Ticks of play (oldest first) that are not yet certified; `None` = all final.
    pub pending_ticks: Option<u64>,
    pub finality_ms: Option<u64>,
    pub finality_avg_ms: Option<f64>,
    pub tick_hz: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub sim_us: Option<u64>,
    pub rollbacks: u64,
    pub max_rollback: u64,
    pub prediction: u64,
    pub stalled: bool,
    pub hide: Option<HideView>,
    pub hide_cooldown_ticks: u64,
    pub rtt_ms: Option<f64>,
    pub net_tx_kbps: Option<f64>,
    pub net_rx_kbps: Option<f64>,
    /// Session health: avg/max cost of one encrypted send (µs), longest inbox
    /// stall (µs), messages lost to fan-out lag.
    pub send_avg_us: Option<u64>,
    pub send_max_us: Option<u64>,
    pub inbox_stall_us: Option<u64>,
    pub lagged: u64,
    pub retransmits: u64,
    pub bad_frames: u64,
    pub send_errors: u64,
    pub suppressed: u64,
    pub hydra_send_max_us: u64,
    pub hydra_recv_max_us: u64,
    pub hydra_slow_calls: u64,
    pub audit: gv_edge::live::AuditStats,
}

fn audit_json(a: &gv_edge::live::AuditStats) -> String {
    format!(
        "{{\"pending\":{},\"provenEquivocation\":{},\"suspected\":{},\"cleared\":{},\"unavailable\":{},\"rejectedEvidence\":{},\"logLen\":{},\"logRetained\":{},\"authSent\":{},\"authSeen\":{},\"answered\":{},\"evidenceFiles\":{},\"evidenceBytes\":{},\"persistOk\":{}}}",
        a.pending, a.proven_equivocation, a.suspected, a.cleared, a.unavailable, a.rejected_evidence,
        a.log_len, a.log_retained, a.authenticators_sent, a.authenticators_seen, a.challenges_answered,
        a.evidence_files, a.evidence_bytes, a.persist_ok
    )
}

impl View {
    pub fn new(you: usize, initial: &ArenaState) -> Self {
        Self {
            you,
            phase: "Starting P2P and Hydra handshake".into(),
            players: initial.fighters,
            verified: initial.fighters,
            tick: 0,
            verified_tick: 0,
            checkpoint: "genesis or resumed checkpoint".into(),
            events: VecDeque::new(),
            stopped: false,
            controls: 0,
            control_events: VecDeque::new(),
            inject_cheat: false,
            inject_illegal: false,
            hide_request: false,
            accepted: 0,
            disputed: 0,
            rejected: 0,
            verdict: "pending",
            pending_ticks: None,
            finality_ms: None,
            finality_avg_ms: None,
            tick_hz: None,
            jitter_ms: None,
            sim_us: None,
            rollbacks: 0,
            max_rollback: 0,
            prediction: 0,
            stalled: false,
            hide: None,
            hide_cooldown_ticks: 0,
            rtt_ms: None,
            net_tx_kbps: None,
            net_rx_kbps: None,
            send_avg_us: None,
            send_max_us: None,
            inbox_stall_us: None,
            lagged: 0,
            retransmits: 0,
            bad_frames: 0,
            send_errors: 0,
            suppressed: 0,
            hydra_send_max_us: 0,
            hydra_recv_max_us: 0,
            hydra_slow_calls: 0,
            audit: gv_edge::live::AuditStats::default(),
        }
    }
    pub fn push_event(&mut self, event: String) {
        self.events.push_front(event);
        self.events.truncate(MAX_EVENTS);
    }
    fn json(&self) -> String {
        let hidden_index = self.hide.as_ref().and_then(|h| {
            // The opponent is fogged only on the observer's screen, and only while
            // the window is live; the hider always sees themselves.
            (h.hider != self.you && self.tick >= h.start && self.tick < h.end).then_some(h.hider)
        });
        let fighter = |i: usize, p: &Fighter| {
            format!(
                "{{\"x\":{},\"y\":{},\"hp\":{},\"cooldown\":{},\"guarding\":{},\"hidden\":{}}}",
                p.x,
                p.y,
                p.hp,
                p.cooldown,
                p.guarding,
                hidden_index == Some(i)
            )
        };
        let list = |players: &[Fighter; 2]| {
            players
                .iter()
                .enumerate()
                .map(|(i, p)| fighter(i, p))
                .collect::<Vec<_>>()
                .join(",")
        };
        let events = self
            .events
            .iter()
            .map(|s| format!("\"{}\"", escape(s)))
            .collect::<Vec<_>>()
            .join(",");
        let opt = |v: Option<f64>| v.map_or_else(|| "null".to_owned(), |x| format!("{x:.1}"));
        let optu = |v: Option<u64>| v.map_or_else(|| "null".to_owned(), |x| x.to_string());
        let hide = self.hide.as_ref().map_or_else(
            || "null".to_owned(),
            |h| {
                format!(
                    "{{\"hider\":{},\"start\":{},\"end\":{},\"active\":{}}}",
                    h.hider,
                    h.start,
                    h.end,
                    self.tick >= h.start && self.tick < h.end
                )
            },
        );
        format!(
            "{{\"you\":{},\"phase\":\"{}\",\"tick\":{},\"verifiedTick\":{},\"checkpoint\":\"{}\",\"fighters\":[{}],\"verified\":[{}],\"events\":[{}],\"stopped\":{},\"controls\":{},\"accepted\":{},\"disputed\":{},\"rejected\":{},\"verdict\":\"{}\",\"pendingTicks\":{},\"finalityMs\":{},\"finalityAvgMs\":{},\"tickHz\":{},\"jitterMs\":{},\"simUs\":{},\"rollbacks\":{},\"maxRollback\":{},\"prediction\":{},\"stalled\":{},\"hide\":{},\"hideCooldownTicks\":{},\"rttMs\":{},\"txKbps\":{},\"rxKbps\":{},\"sendAvgUs\":{},\"sendMaxUs\":{},\"inboxStallUs\":{},\"lagged\":{},\"retransmits\":{},\"badFrames\":{},\"sendErrors\":{},\"suppressed\":{},\"hydraSendMaxUs\":{},\"hydraRecvMaxUs\":{},\"hydraSlowCalls\":{},\"audit\":{}}}",
            self.you, escape(&self.phase), self.tick, self.verified_tick, escape(&self.checkpoint),
            list(&self.players), list(&self.verified), events, self.stopped, self.controls,
            self.accepted, self.disputed, self.rejected, self.verdict, optu(self.pending_ticks), optu(self.finality_ms),
            opt(self.finality_avg_ms), opt(self.tick_hz), opt(self.jitter_ms), optu(self.sim_us),
            self.rollbacks, self.max_rollback, self.prediction, self.stalled, hide,
            self.hide_cooldown_ticks, opt(self.rtt_ms), opt(self.net_tx_kbps), opt(self.net_rx_kbps),
            optu(self.send_avg_us), optu(self.send_max_us), optu(self.inbox_stall_us), self.lagged,
            self.retransmits, self.bad_frames, self.send_errors, self.suppressed,
            self.hydra_send_max_us, self.hydra_recv_max_us, self.hydra_slow_calls,
            audit_json(&self.audit)
        )
    }
}

fn escape(input: &str) -> String {
    let mut out = String::new();
    for c in input.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push(' '),
            _ => out.push(c),
        }
    }
    out
}

/// Turns browser key transitions into one control word per 60 Hz tick.
/// A press shorter than a tick still counts for one tick, a quick direction
/// change never yields a contradictory word, and attack/guard are held.
#[derive(Default)]
pub struct Sampler {
    prev: u16,
}
impl Sampler {
    pub fn sample(&mut self, events: &mut VecDeque<u16>) -> u16 {
        let held_move = self.prev & MOVE_MASK;
        let mut other = self.prev & !MOVE_MASK;
        let mut first_move = 0;
        let mut last = None;
        for m in events.drain(..) {
            if first_move == 0 && held_move == 0 && m & MOVE_MASK != 0 {
                first_move = m & MOVE_MASK;
            }
            other |= m & !MOVE_MASK;
            last = Some(m);
        }
        let movement = match last {
            None => held_move,
            Some(m) if m & MOVE_MASK != 0 => m & MOVE_MASK,
            Some(_) => first_move,
        };
        if let Some(m) = last {
            self.prev = m;
        }
        movement | other
    }
}

/// Cloneable handle for reporting a failure after the UI has been handed to
/// the game task, so a fault always reaches the browser.
#[derive(Clone)]
pub struct UiReporter(Arc<Mutex<View>>);
impl UiReporter {
    pub fn failure(&self, reason: &str) {
        if let Ok(mut v) = self.0.lock() {
            v.stopped = true;
            v.verdict = "error";
            v.phase = format!("Match interrupted: {reason}");
            v.push_event(format!("TRANSPORT/PROTOCOL ERROR (NOT FRAUD): {reason}"));
        }
    }
}

pub struct ArenaUi {
    view: Arc<Mutex<View>>,
    sampler: Sampler,
}

impl ArenaUi {
    pub async fn start(port: u16, you: usize, initial: &ArenaState) -> Result<Self, String> {
        if you > 1 {
            return Err("invalid player index".into());
        }
        let address = format!("127.0.0.1:{port}");
        let listener = TcpListener::bind(&address)
            .await
            .map_err(|e| format!("UI bind {address}: {e}"))?;
        let view = Arc::new(Mutex::new(View::new(you, initial)));
        let view_task = Arc::clone(&view);
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let view = Arc::clone(&view_task);
                tokio::spawn(async move {
                    let _ = serve(socket, port, view).await;
                });
            }
        });
        println!("Arena frontend: http://127.0.0.1:{port}/");
        Ok(Self {
            view,
            sampler: Sampler::default(),
        })
    }
    /// Mutate the shared view. Poisoning is ignored: the page keeps working.
    pub fn update(&self, f: impl FnOnce(&mut View)) {
        if let Ok(mut v) = self.view.lock() {
            f(&mut v);
        }
    }
    pub fn status(&self, status: &str) {
        self.update(|v| v.phase = status.into());
    }
    pub fn event(&self, text: impl Into<String>) {
        let text = text.into();
        self.update(|v| v.push_event(text));
    }
    pub fn stop(&self, reason: &str) {
        self.update(|v| {
            v.stopped = true;
            v.phase = reason.into();
            v.push_event(reason.into());
        });
    }
    pub fn reporter(&self) -> UiReporter {
        UiReporter(Arc::clone(&self.view))
    }
    /// Keep the diagnostic page alive after a P2P/protocol failure. An
    /// interrupted match is not a mathematically proven fraud.
    pub fn failure(&self, reason: &str) {
        self.reporter().failure(reason);
    }
    /// Control word for the next 60 Hz tick.
    pub fn sample_controls(&mut self) -> u16 {
        match self.view.lock() {
            Ok(mut v) => self.sampler.sample(&mut v.control_events),
            Err(_) => 0,
        }
    }
    /// One-shot requests from the page: (cheat, illegal input, hide).
    pub fn take_injections(&self) -> (bool, bool, bool) {
        self.view.lock().map_or((false, false, false), |mut v| {
            (
                std::mem::take(&mut v.inject_cheat),
                std::mem::take(&mut v.inject_illegal),
                std::mem::take(&mut v.hide_request),
            )
        })
    }
}

async fn serve(mut sock: TcpStream, port: u16, view: Arc<Mutex<View>>) -> std::io::Result<()> {
    // TCP is a byte stream: one read does not necessarily contain all HTTP
    // headers. r7 sporadically returned 403 if Host/Origin arrived separately.
    let mut data = Vec::with_capacity(1024);
    loop {
        let mut chunk = [0u8; 1024];
        let count = tokio::time::timeout(Duration::from_secs(4), sock.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request timeout"))??;
        if count == 0 {
            return Ok(());
        }
        data.extend_from_slice(&chunk[..count]);
        if data.windows(4).any(|window| window == b"\r\n\r\n") {
            break;
        }
        if data.len() >= MAX_REQUEST {
            return respond(
                &mut sock,
                "431 Request Header Fields Too Large",
                "text/plain",
                "Headers too large",
            )
            .await;
        }
    }
    let request = String::from_utf8_lossy(&data);
    let first = request.lines().next().unwrap_or("");
    let host_allowed = request.lines().any(|line| {
        let line = line.trim();
        line.eq_ignore_ascii_case(&format!("Host: 127.0.0.1:{port}"))
            || line.eq_ignore_ascii_case(&format!("Host: localhost:{port}"))
    });
    if !host_allowed {
        return respond(&mut sock, "403 Forbidden", "text/plain", "Invalid Host").await;
    }
    if first == "GET / HTTP/1.1" || first == "GET / HTTP/1.0" {
        return respond(&mut sock, "200 OK", "text/html; charset=utf-8", PAGE).await;
    }
    if first.starts_with("GET /state ") {
        let state = view
            .lock()
            .map(|s| s.json())
            .unwrap_or_else(|_| "{}".into());
        return respond(&mut sock, "200 OK", "application/json", &state).await;
    }
    if first.starts_with("POST /controls?")
        || first.starts_with("POST /inject?")
        || first.starts_with("POST /hide ")
    {
        let same_origin = request.lines().any(|line| {
            let line = line.trim();
            line.eq_ignore_ascii_case(&format!("Origin: http://127.0.0.1:{port}"))
                || line.eq_ignore_ascii_case(&format!("Origin: http://localhost:{port}"))
        });
        if !same_origin {
            return respond(&mut sock, "403 Forbidden", "text/plain", "Invalid Origin").await;
        }
        // The first HTTP token is the METHOD, not the request target.
        // r7 accidentally matched "POST" as the route and returned
        // "Unknown injection" for *every* movement/cheat request.
        let mut fields = first.split_ascii_whitespace();
        let route = match (fields.next(), fields.next(), fields.next(), fields.next()) {
            (Some("POST"), Some(path), Some("HTTP/1.1" | "HTTP/1.0"), None) => path,
            _ => {
                return respond(
                    &mut sock,
                    "400 Bad Request",
                    "text/plain",
                    "Malformed request",
                )
                .await
            }
        };
        // Do not keep a synchronous MutexGuard alive across socket I/O.
        // This also keeps the spawned HTTP handler Send-safe.
        let outcome = (|| -> Result<(), (&'static str, &'static str)> {
            let mut v = view
                .lock()
                .map_err(|_| ("503 Service Unavailable", "UI unavailable"))?;
            if v.stopped {
                return Err(("409 Conflict", "Match stopped"));
            }
            if route.starts_with("/controls?") {
                let control = route
                    .strip_prefix("/controls?controls=")
                    .and_then(|s| s.parse::<u16>().ok());
                let controls = control
                    .filter(|value| value & !LEGAL_CONTROLS == 0)
                    .ok_or(("400 Bad Request", "Invalid controls"))?;
                if controls != v.controls {
                    // Fail closed instead of silently dropping authenticated
                    // input changes when the remote peer is slow.
                    if v.control_events.len() >= 256 {
                        return Err(("429 Too Many Requests", "Input event queue full"));
                    }
                    v.control_events.push_back(controls);
                    v.controls = controls;
                }
            } else if route == "/hide" {
                v.hide_request = true;
            } else {
                let kind = route.strip_prefix("/inject?kind=").unwrap_or("");
                match kind {
                    "cheat" => v.inject_cheat = true,
                    "invalid" => v.inject_illegal = true,
                    _ => return Err(("400 Bad Request", "Unknown injection")),
                }
                v.push_event(format!("TEST: {kind} queued for the next signed input"));
            }
            Ok(())
        })();
        return match outcome {
            Ok(()) => respond(&mut sock, "200 OK", "application/json", "{\"queued\":true}").await,
            Err((status, detail)) => respond(&mut sock, status, "text/plain", detail).await,
        };
    }
    respond(&mut sock, "404 Not Found", "text/plain", "Not found").await
}

async fn respond(
    sock: &mut TcpStream,
    status: &str,
    mime: &str,
    text: &str,
) -> std::io::Result<()> {
    let reply = format!("HTTP/1.1 {status}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'\r\nConnection: close\r\n\r\n", text.len());
    sock.write_all(reply.as_bytes()).await?;
    sock.write_all(text.as_bytes()).await?;
    sock.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fighter(x: i32) -> Fighter {
        Fighter {
            x,
            y: 0,
            hp: 100,
            cooldown: 0,
            move_cooldown: 0,
            guarding: false,
        }
    }
    fn view() -> View {
        View::new(
            0,
            &ArenaState {
                fighters: [fighter(-4), fighter(4)],
            },
        )
    }
    fn sample(prev: u16, events: &[u16]) -> (u16, u16) {
        let mut s = Sampler { prev };
        let mut q: VecDeque<u16> = events.iter().copied().collect();
        let out = s.sample(&mut q);
        (out, s.prev)
    }

    #[test]
    fn frontend_assets_and_json_escaping() {
        assert!(PAGE.contains("<canvas"));
        assert!(PAGE.contains("Send cheat move"));
        assert!(PAGE.contains("/controls?controls="));
        assert!(PAGE.contains("/inject?kind="));
        assert!(PAGE.contains("/hide"));
        assert_eq!(escape("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }

    #[test]
    fn a_tap_shorter_than_one_tick_still_lasts_one_tick() {
        assert_eq!(sample(0, &[2, 0]), (2, 0), "press+release inside one tick");
        assert_eq!(sample(0, &[16, 0]), (16, 0), "attack tap");
        assert_eq!(sample(0, &[]), (0, 0), "idle stays idle");
    }
    #[test]
    fn held_keys_repeat_and_releases_stop() {
        assert_eq!(sample(2, &[]), (2, 2), "still held");
        assert_eq!(sample(2, &[0]), (0, 0), "released: no extra movement tick");
        assert_eq!(
            sample(2 | 16, &[2]),
            (2 | 16, 2),
            "attack bit stays for the tick it was released"
        );
    }
    #[test]
    fn a_quick_direction_change_is_never_contradictory() {
        let (out, _) = sample(1, &[2]);
        assert_eq!(out & MOVE_MASK, 2);
        let (out, _) = sample(0, &[1, 2]);
        assert_eq!(out & MOVE_MASK, 2, "latest direction wins: {out}");
        assert_eq!((out & MOVE_MASK).count_ones(), 1);
    }

    #[test]
    fn json_reports_provisional_and_verified_state_and_fogs_only_the_observers_view() {
        let mut v = view();
        v.tick = 200;
        v.verified_tick = 160;
        v.hide = Some(HideView {
            hider: 1,
            start: 140,
            end: 440,
        });
        let json = v.json();
        assert!(json.contains("\"tick\":200") && json.contains("\"verifiedTick\":160"));
        // I am player 0 observing player 1 inside the window: opponent fogged.
        assert!(json.contains("\"hidden\":true"));
        assert!(json.contains("\"active\":true"));
        // The hider never fogs their own fighter.
        v.you = 1;
        assert!(!v.json().contains("\"hidden\":true"));
        // Outside the window nobody is fogged.
        v.you = 0;
        v.tick = 500;
        assert!(!v.json().contains("\"hidden\":true"));
    }

    #[test]
    fn transport_failure_is_not_labeled_as_cheating() {
        let ui = ArenaUi {
            view: Arc::new(Mutex::new(view())),
            sampler: Sampler::default(),
        };
        ui.failure("receive timeout");
        let v = ui.view.lock().unwrap();
        assert!(v.stopped);
        assert_eq!(v.verdict, "error");
        assert_eq!(v.rejected, 0);
        assert!(v.json().contains("receive timeout"));
    }

    #[tokio::test]
    async fn real_http_post_updates_controls_hide_and_injections() {
        let view = Arc::new(Mutex::new(view()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let requests = [
            ("/controls?controls=18", "200 OK"),
            ("/controls?controls=0", "200 OK"),
            ("/inject?kind=cheat", "200 OK"),
            ("/inject?kind=invalid", "200 OK"),
            ("/hide", "200 OK"),
            ("/inject?kind=unknown", "400 Bad Request"),
            ("/controls?controls=128", "400 Bad Request"),
        ];
        for (route, expected_status) in requests {
            let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let (server, _) = listener.accept().await.unwrap();
            let cloned = Arc::clone(&view);
            let server_task = tokio::spawn(async move { serve(server, port, cloned).await });
            let request = format!("POST {route} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://127.0.0.1:{port}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            // Fragment the request: the server must not assume one read().
            let split = 12.min(request.len());
            client
                .write_all(&request.as_bytes()[..split])
                .await
                .unwrap();
            tokio::time::sleep(Duration::from_millis(5)).await;
            client
                .write_all(&request.as_bytes()[split..])
                .await
                .unwrap();
            let mut reply = Vec::new();
            client.read_to_end(&mut reply).await.unwrap();
            server_task.await.unwrap().unwrap();
            assert!(
                String::from_utf8_lossy(&reply).contains(expected_status),
                "{route}: {}",
                String::from_utf8_lossy(&reply)
            );
        }
        let v = view.lock().unwrap();
        assert_eq!(v.controls, 0);
        assert_eq!(v.control_events, VecDeque::from([18, 0]));
        assert!(v.inject_cheat && v.inject_illegal && v.hide_request);
    }

    #[tokio::test]
    async fn cross_origin_posts_are_refused() {
        let view = Arc::new(Mutex::new(view()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        let cloned = Arc::clone(&view);
        let task = tokio::spawn(async move { serve(server, port, cloned).await });
        let req = format!(
            "POST /hide HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: http://evil.example\r\n\r\n"
        );
        client.write_all(req.as_bytes()).await.unwrap();
        let mut reply = Vec::new();
        client.read_to_end(&mut reply).await.unwrap();
        task.await.unwrap().unwrap();
        assert!(String::from_utf8_lossy(&reply).contains("403"));
        assert!(!view.lock().unwrap().hide_request);
    }
}
