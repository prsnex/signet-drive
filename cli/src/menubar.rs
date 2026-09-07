// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 PRSN EX Inc.

//! The host-signer's menu-bar status item (macOS only; Launch-Punch-List §1-29).
//!
//! The always-on host-signer also presents an `LSUIElement` menu-bar `NSStatusItem`
//! — no Dock icon, no window, no app menu — so a human can confirm at a glance that
//! SignetHelper is active and its version is current. The item's *presence* is the
//! liveness signal: it lives in the host-signer process, so no icon ⇒ not running.
//! The dropdown is info-only: a header, a running line, and the version (with update
//! currency when known). No actions, no logs (those are v1.x).
//!
//! AppKit must own the main thread, so the caller runs the serve loop on a
//! background thread and calls [`run`] (which blocks in `NSApplication::run`) on the
//! main thread.

use std::cell::RefCell;

use objc2::rc::Retained;
use objc2::runtime::{AnyObject, NSObject, NSObjectProtocol, ProtocolObject};
use objc2::{
    AnyThread, DefinedClass, MainThreadMarker, MainThreadOnly, define_class, msg_send, sel,
};
use objc2_app_kit::{
    NSAlert, NSAlertFirstButtonReturn, NSAlertSecondButtonReturn, NSApplication,
    NSApplicationActivationPolicy, NSMenu, NSMenuDelegate, NSMenuItem, NSPasteboard,
    NSPasteboardTypeString, NSStatusBar, NSStatusItem, NSTextField, NSVariableStatusItemLength,
    NSView,
};
use objc2_foundation::{NSPoint, NSRect, NSSize, NSString, NSTimer};

/// The placeholder product name shown in the header. Tracks the strawman's
/// deliberately-ugly `SignetHelper` placeholder (rename before v1, Punch-List §4-05).
const MENU_TITLE: &str = "SignetHelper";

/// Best-effort latest published version for the currency line: one short-timeout
/// GET of `<server>/cli/latest-version` (row-29 fast-follow), never retried — an
/// offline or serverless Mac costs at most the timeout, once, at startup, and the
/// version line simply drops its currency suffix. The response must *look like* a
/// version (dotted numerics): anything else — an HTML error page, a proxy
/// interstitial — is discarded rather than fed to the up-to-date comparison
/// (junk would compare as `[0,0,…]` and silently claim "up to date").
pub fn latest_version_best_effort(server_base_url: &str) -> Option<String> {
    let url = format!("{server_base_url}/cli/latest-version");
    let body = crate::http::get_text_once(&url, std::time::Duration::from_secs(2)).ok()?;
    let version = body.trim().to_string();
    looks_like_version(&version).then_some(version)
}

/// `"0.2.10"`-shaped: non-empty dotted numeric segments only.
fn looks_like_version(v: &str) -> bool {
    !v.is_empty()
        && v.split('.')
            .all(|part| !part.is_empty() && part.parse::<u64>().is_ok())
}

/// The menu-bar glyph — the Signet "◉" mark as monochrome text for v1 (a template
/// image is a v1.x polish).
const MENU_GLYPH: &str = "◉";

/// Build + run the menu-bar status item. Blocks in the AppKit run loop until the
/// process is terminated (launchd SIGTERM). MUST be called on the main thread.
///
/// `latest_version`: the newest published version (from a best-effort
/// `/cli/latest-version` check), or `None` when unknown/offline — the version line
/// then drops the currency suffix.
pub fn run(latest_version: Option<String>) {
    let mtm = MainThreadMarker::new()
        .expect("the menu-bar status item must be set up on the main thread");

    let app = NSApplication::sharedApplication(mtm);
    // Accessory == LSUIElement at runtime: no Dock icon, no app menu — status item only.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let status_bar = NSStatusBar::systemStatusBar();
    let status_item = status_bar.statusItemWithLength(NSVariableStatusItemLength);

    if let Some(button) = status_item.button(mtm) {
        button.setTitle(&NSString::from_str(MENU_GLYPH));
    }

    let action_target = AddContainerPrsnAction::new();
    let menu = build_menu(mtm, latest_version.as_deref(), &action_target);
    status_item.setMenu(Some(&menu));

    // Keep the status item AND the action target alive for the process lifetime.
    // `NSMenuItem.target` is a *weak* reference, so the target must outlive the menu;
    // `run()` never returns (the LaunchAgent is killed by SIGTERM), so these stay live.
    let _keep_alive: (
        Retained<NSStatusItem>,
        Retained<NSStatusBar>,
        Retained<AddContainerPrsnAction>,
    ) = (status_item, status_bar, action_target);
    app.run();
}

/// Build + run the **broker's** menu-bar status item — the Garnet equivalent of [`run`],
/// but **liveness + version only**: no "Add a containerized PRSN…" action (that is the
/// mount model's affordance; the Garnet container-add flow is a separate future piece).
/// Blocks in the AppKit run loop until the process is terminated (launchd SIGTERM). MUST be
/// called on the main thread. `latest_version` behaves as in [`run`].
///
/// `state`: what the broker is actually doing. The always-on broker shows this menu from
/// install time (Bug030(1)); the running line reflects whether it is actively serving a PRSN
/// (`● Running`), idle-but-ready (`○ Ready — no PRSNs yet`), or **impaired** (bug087 fix 3 —
/// the credential's key failed its binding self-check, so serving is impossible and the
/// guardian must re-provision; the pre-fix broker showed "Running" over a state where every
/// handshake failed, which is the lie this state exists to end).
pub fn run_broker(
    server_base_url: Option<String>,
    latest_version: Option<String>,
    state: BrokerMenuState,
) {
    let mtm = MainThreadMarker::new()
        .expect("the menu-bar status item must be set up on the main thread");

    let app = NSApplication::sharedApplication(mtm);
    // Accessory == LSUIElement at runtime: no Dock icon, no app menu — status item only.
    app.setActivationPolicy(NSApplicationActivationPolicy::Accessory);

    let status_bar = NSStatusBar::systemStatusBar();
    let status_item = status_bar.statusItemWithLength(NSVariableStatusItemLength);

    // Glance-able update signal (bug039): a badged glyph in the menu bar when the installed
    // version is behind the newest published one — visible without opening the dropdown.
    let update_available = update_is_available(latest_version.as_deref());
    if let Some(button) = status_item.button(mtm) {
        button.setTitle(&NSString::from_str(menu_glyph(update_available)));
    }

    let quit_target = QuitBrokerAction::new();
    let update_target = UpdateAction::new();
    let menu = build_broker_menu(
        mtm,
        latest_version.as_deref(),
        state,
        update_available,
        &quit_target,
        &update_target,
    );

    // bug049: re-verify currency each time the dropdown opens (the startup
    // check above is otherwise the ONLY one an always-on daemon ever runs, so
    // a long-uptime Mac asserted "up to date" indefinitely against a newer
    // server). The delegate re-checks + rebuilds the items before display.
    let delegate = BrokerMenuRefresh::new(
        mtm,
        BrokerMenuRefreshIvars {
            server_base_url,
            state,
            latest: RefCell::new(latest_version),
            status_item: status_item.clone(),
            quit_target: quit_target.clone(),
            update_target: update_target.clone(),
        },
    );
    menu.setDelegate(Some(ProtocolObject::from_ref(&*delegate)));
    status_item.setMenu(Some(&menu));

    // bug073: a coarse, jittered repeating timer re-checks currency + refreshes the ↑
    // badge WITHOUT a menu-open (bug049 option (c) — a long-uptime always-on daemon
    // otherwise shows a stale badge until the user happens to open the menu). Scheduled
    // on the main run loop, so it fires on the main thread (the same thread as
    // `menuNeedsUpdate:`), keeping the RefCell + `setTitle` single-threaded. The interval
    // is a rate-free freshness poll — a client-side default + per-process jitter is
    // legitimate (the ROOTS no-wall-time rule governs bytes÷rate quantities, not a poll
    // cadence) — jittered so the fleet doesn't hit /cli/latest-version in lockstep.
    let delegate_obj: &AnyObject = &*delegate;
    let refresh_timer = unsafe {
        NSTimer::scheduledTimerWithTimeInterval_target_selector_userInfo_repeats(
            update_poll_interval_secs(),
            delegate_obj,
            sel!(refreshCurrencyTick:),
            None,
            true,
        )
    };

    // Keep the status item AND the menu-item action targets alive for the process lifetime.
    // `NSMenuItem.target` is a *weak* reference (as is `NSMenu.delegate`), so the targets +
    // delegate must outlive the menu; `run()` never returns (launchd / Quit / the Update
    // restart kill it), so these stay live. The refresh timer rides along (the run loop
    // also retains it; holding it here gives it the same explicit process lifetime).
    let _keep_alive: (
        Retained<NSStatusItem>,
        Retained<NSStatusBar>,
        Retained<QuitBrokerAction>,
        Retained<UpdateAction>,
        Retained<BrokerMenuRefresh>,
        Retained<NSTimer>,
    ) = (
        status_item,
        status_bar,
        quit_target,
        update_target,
        delegate,
        refresh_timer,
    );
    app.run();
}

// ── bug049: the menu re-checks currency when it opens ────────────────────────────
//
// The startup check runs once, so under the always-on daemon (`KeepAlive=true`,
// bug039/Bug030(1)) a long-uptime Mac showed "Version X — up to date" indefinitely
// against a newer published release — an affirmative false claim (the S121 "P1
// over-assertion" class, observed live at the S122 T-U debut). This delegate
// re-runs the same short-timeout best-effort check each time the dropdown is about
// to display, so every claim the menu makes was verified moments before it is
// read. Honesty on a failed re-check is asymmetric: "update available" is durable
// knowledge (that release exists) and is kept; "up to date" is perishable (true
// only at check time) and is dropped rather than re-asserted unverified.

/// What the broker daemon is actually doing — drives the menu's running line (bug087 fix 3
/// added `Impaired`; the previous bool collapsed "serving" and "failing every handshake").
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BrokerMenuState {
    /// A provisioned credential passed its K3 binding self-check; the serve loop is up.
    Serving,
    /// No credential yet (a fresh install) — idle but healthy.
    Ready,
    /// A credential exists but CANNOT serve (its key failed the binding self-check, or the
    /// serve loop could not start) — the guardian must re-provision.
    Impaired,
}

struct BrokerMenuRefreshIvars {
    server_base_url: Option<String>,
    state: BrokerMenuState,
    /// The last known published version (None ⇒ the line makes no currency claim).
    latest: RefCell<Option<String>>,
    status_item: Retained<NSStatusItem>,
    quit_target: Retained<QuitBrokerAction>,
    update_target: Retained<UpdateAction>,
}

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - `MainThreadOnly` + AppKit delivers `menuNeedsUpdate:` on the main
    //   thread, so the `RefCell` ivar is never touched concurrently.
    #[unsafe(super(NSObject))]
    #[thread_kind = MainThreadOnly]
    #[name = "SignetBrokerMenuRefresh"]
    #[ivars = BrokerMenuRefreshIvars]
    struct BrokerMenuRefresh;

    unsafe impl NSObjectProtocol for BrokerMenuRefresh {}

    unsafe impl NSMenuDelegate for BrokerMenuRefresh {
        /// AppKit invokes this just before the menu is displayed (main thread).
        /// The 2 s-bounded check briefly delays the dropdown in the worst
        /// (offline) case; the typical fetch is tens of milliseconds.
        #[unsafe(method(menuNeedsUpdate:))]
        fn menu_needs_update(&self, menu: &NSMenu) {
            let Some(mtm) = MainThreadMarker::new() else {
                return;
            };
            // Re-check currency + refresh the glyph via the shared helper (bug073 —
            // one home for the currency logic), then rebuild the dropdown's items.
            let update_available = self.refresh_currency(mtm);
            let ivars = self.ivars();
            let latest = ivars.latest.borrow().clone();
            menu.removeAllItems();
            add_broker_menu_items(
                menu,
                mtm,
                latest.as_deref(),
                ivars.state,
                update_available,
                &ivars.quit_target,
                &ivars.update_target,
            );
        }
    }

    impl BrokerMenuRefresh {
        /// bug073: the background timer tick — re-check currency + refresh the ↑ badge
        /// glyph SPONTANEOUSLY, without a menu-open (bug049 option (c)). The timer is
        /// scheduled on the main run loop, so AppKit fires this on the main thread — the
        /// same thread as `menuNeedsUpdate:` — keeping the `latest` RefCell + `setTitle`
        /// single-threaded. Only the badge is moved here; the dropdown's items are
        /// rebuilt lazily on the next open, which is all a closed-menu user needs.
        #[unsafe(method(refreshCurrencyTick:))]
        fn refresh_currency_tick(&self, _timer: Option<&AnyObject>) {
            if let Some(mtm) = MainThreadMarker::new() {
                self.refresh_currency(mtm);
            }
        }
    }
);

impl BrokerMenuRefresh {
    fn new(mtm: MainThreadMarker, ivars: BrokerMenuRefreshIvars) -> Retained<Self> {
        let this = Self::alloc(mtm).set_ivars(ivars);
        unsafe { msg_send![super(this), init] }
    }

    /// bug073: re-check update currency (updating the durable `latest` with the
    /// asymmetric-honesty rule — keep a durable "update available", drop a perishable
    /// "up to date" on a failed re-check rather than re-assert it) and refresh the
    /// menu-bar glyph. ONE home for the currency logic, shared by `menuNeedsUpdate:`
    /// (menu-open) and the background timer (spontaneous — so the ↑ badge appears
    /// without opening the menu). Main-thread only. Returns the current
    /// update-available state so the menu-open caller can rebuild its items to match.
    fn refresh_currency(&self, mtm: MainThreadMarker) -> bool {
        let ivars = self.ivars();
        if let Some(url) = ivars.server_base_url.as_deref() {
            match latest_version_best_effort(url) {
                Some(fresh) => *ivars.latest.borrow_mut() = Some(fresh),
                None => {
                    let mut latest = ivars.latest.borrow_mut();
                    if !update_is_available(latest.as_deref()) {
                        *latest = None;
                    }
                }
            }
        }
        let update_available = update_is_available(ivars.latest.borrow().as_deref());
        if let Some(button) = ivars.status_item.button(mtm) {
            button.setTitle(&NSString::from_str(menu_glyph(update_available)));
        }
        update_available
    }
}

/// The broker dropdown: header · the running line · `Version X.Y.Z[ — currency]` ·
/// (when an update is available) **Update Signet…** · a separator · **Quit Signet**.
fn build_broker_menu(
    mtm: MainThreadMarker,
    latest_version: Option<&str>,
    state: BrokerMenuState,
    update_available: bool,
    quit_target: &QuitBrokerAction,
    update_target: &UpdateAction,
) -> Retained<NSMenu> {
    let menu = NSMenu::new(mtm);
    add_broker_menu_items(
        &menu,
        mtm,
        latest_version,
        state,
        update_available,
        quit_target,
        update_target,
    );
    menu
}

/// The broker menu's item set, appended to an (empty) menu. Shared by the
/// startup build and the bug049 `menuNeedsUpdate:` rebuild-on-open.
fn add_broker_menu_items(
    menu: &NSMenu,
    mtm: MainThreadMarker,
    latest_version: Option<&str>,
    state: BrokerMenuState,
    update_available: bool,
    quit_target: &QuitBrokerAction,
    update_target: &UpdateAction,
) {
    add_label(menu, mtm, MENU_TITLE);
    add_label(menu, mtm, running_line(state));
    add_label(menu, mtm, &version_line(latest_version));
    // bug039: the assisted-update affordance appears only when there IS a newer version.
    if update_available {
        add_update_action(menu, mtm, update_target);
    }
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add_quit_action(menu, mtm, quit_target);
}

/// Whether the running version is behind `latest_version` (the startup currency check result).
/// Shared by the glyph badge, the "Update Signet…" item's presence, and the version line.
fn update_is_available(latest_version: Option<&str>) -> bool {
    match latest_version {
        Some(latest) => crate::commands::is_newer(latest, env!("CARGO_PKG_VERSION")),
        None => false,
    }
}

/// The menu-bar glyph: the Signet mark, plus a glance-able up-arrow badge when an update is
/// available — so the guardian sees "you're behind" without opening the dropdown (bug039).
fn menu_glyph(update_available: bool) -> &'static str {
    if update_available {
        "◉ ↑"
    } else {
        MENU_GLYPH
    }
}

/// bug073: the update-currency poll cadence for the background timer. Coarse (updates
/// aren't urgent) with a per-process jitter so the fleet doesn't hit `/cli/latest-version`
/// in lockstep. A client-side default is legitimate here — this is a rate-free freshness
/// poll, not a bytes÷rate bound (the ROOTS no-wall-time rule). ~2 h base + up to 30 min of
/// per-process jitter (picked once at startup from a cheap wall-clock source; no `rand`
/// dependency, and exactness does not matter for a glance signal). A `system_config`-served
/// knob is a possible future refinement (bug073 doc §4) but disproportionate for one value.
fn update_poll_interval_secs() -> f64 {
    const BASE_SECS: f64 = 2.0 * 3600.0;
    let jitter = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| (d.subsec_nanos() % (30 * 60)) as f64)
        .unwrap_or(0.0);
    BASE_SECS + jitter
}

/// The broker's running-state line. `● Running` while serving a provisioned PRSN,
/// `○ Ready — no PRSNs yet` for a credential-less always-on install (Bug030(1)), or
/// `✕ Not serving — re-provision needed` when the credential failed its K3 binding
/// self-check (bug087 fix 3: the pre-fix menu said "Running" over a broker failing every
/// handshake — a hard-blocked state must never present as healthy). The menu-bar ◉ itself
/// stays the liveness signal (present ⇒ the app is running).
fn running_line(state: BrokerMenuState) -> &'static str {
    match state {
        BrokerMenuState::Serving => "● Running",
        BrokerMenuState::Ready => "○ Ready: no PRSNs yet",
        BrokerMenuState::Impaired => "✕ Not serving: re-provision needed (see `signet status`)",
    }
}

/// The dropdown: header · `● Running` · `Version X.Y.Z[ — currency]` · the
/// "Add a containerized PRSN…" action (the Phase-3 no-CLI affordance).
fn build_menu(
    mtm: MainThreadMarker,
    latest_version: Option<&str>,
    action_target: &AddContainerPrsnAction,
) -> Retained<NSMenu> {
    let menu = NSMenu::new(mtm);
    add_label(&menu, mtm, MENU_TITLE);
    add_label(&menu, mtm, "● Running");
    add_label(&menu, mtm, &version_line(latest_version));
    menu.addItem(&NSMenuItem::separatorItem(mtm));
    add_action(&menu, mtm, "Add a containerized PRSN…", action_target);
    menu
}

/// `Version X.Y.Z`, plus ` — up to date` / ` — update available` when the latest
/// published version is known.
fn version_line(latest_version: Option<&str>) -> String {
    let current = env!("CARGO_PKG_VERSION");
    match latest_version {
        Some(latest) if crate::commands::is_newer(latest, current) => {
            format!("Version {current}: update available")
        }
        Some(_) => format!("Version {current}: up to date"),
        None => format!("Version {current}"),
    }
}

/// Append a disabled (non-interactive) label row.
fn add_label(menu: &NSMenu, mtm: MainThreadMarker, text: &str) {
    let item = NSMenuItem::new(mtm);
    item.setTitle(&NSString::from_str(text));
    item.setEnabled(false);
    menu.addItem(&item);
}

/// Append an *enabled* action row wired to `target`'s `addContainerPrsn:` selector
/// (unlike [`add_label`], which is a disabled, non-interactive line).
fn add_action(menu: &NSMenu, mtm: MainThreadMarker, text: &str, target: &AddContainerPrsnAction) {
    let item = NSMenuItem::new(mtm);
    item.setTitle(&NSString::from_str(text));
    // `setTarget`/`setAction` are unsafe: the selector must exist on the target — it
    // does (`addContainerPrsn:` is defined on `AddContainerPrsnAction` below).
    let target_obj: &AnyObject = target;
    unsafe {
        item.setTarget(Some(target_obj));
        item.setAction(Some(sel!(addContainerPrsn:)));
    }
    item.setEnabled(true);
    menu.addItem(&item);
}

/// Append the enabled "Quit Signet" row, wired to `target`'s `quitBroker:` selector.
fn add_quit_action(menu: &NSMenu, mtm: MainThreadMarker, target: &QuitBrokerAction) {
    let item = NSMenuItem::new(mtm);
    item.setTitle(&NSString::from_str("Quit Signet"));
    // `setTarget`/`setAction` are unsafe: the selector must exist on the target — it
    // does (`quitBroker:` is defined on `QuitBrokerAction` below).
    let target_obj: &AnyObject = target;
    unsafe {
        item.setTarget(Some(target_obj));
        item.setAction(Some(sel!(quitBroker:)));
    }
    item.setEnabled(true);
    menu.addItem(&item);
}

/// Append the enabled "Update Signet…" row, wired to `target`'s `updateSignet:` selector
/// (bug039). Added only when an update is available (see [`build_broker_menu`]).
fn add_update_action(menu: &NSMenu, mtm: MainThreadMarker, target: &UpdateAction) {
    let item = NSMenuItem::new(mtm);
    item.setTitle(&NSString::from_str("Update Signet…"));
    // `setTarget`/`setAction` are unsafe: the selector must exist on the target — it does
    // (`updateSignet:` is defined on `UpdateAction` below).
    let target_obj: &AnyObject = target;
    unsafe {
        item.setTarget(Some(target_obj));
        item.setAction(Some(sel!(updateSignet:)));
    }
    item.setEnabled(true);
    menu.addItem(&item);
}

// ── The "Add a containerized PRSN…" action (Phase-3 no-CLI affordance) ──────────
//
// The dropdown's first *interactive* item (the rows above are disabled labels): the
// guardian clicks it, names the PRSN, and the app provisions a host-delegation channel
// + shows the ready-to-run container command — no CLI, no Terminal. This is the
// codebase's first interactive AppKit element, so it defines an `NSObject` subclass to
// be the menu item's target (AppKit dispatches the action selector to it). The target
// carries no state — it reads the host-signer dir from `config` and does everything on
// the main thread, where the action fires.

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - This class implements no `Drop` and declares no ivars.
    #[unsafe(super(NSObject))]
    #[name = "SignetAddContainerPrsnAction"]
    struct AddContainerPrsnAction;

    impl AddContainerPrsnAction {
        /// The menu item's action. AppKit invokes this on the main thread.
        #[unsafe(method(addContainerPrsn:))]
        fn add_container_prsn(&self, _sender: Option<&AnyObject>) {
            if let Some(mtm) = MainThreadMarker::new() {
                handle_add_container_prsn(mtm);
            }
        }
    }

    unsafe impl NSObjectProtocol for AddContainerPrsnAction {}
);

impl AddContainerPrsnAction {
    fn new() -> Retained<Self> {
        // The class has unit ivars; a `DefinedClass` still requires `set_ivars` to go
        // from `Allocated` to a `PartialInit` before the superclass `init`.
        let this = Self::alloc().set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

// ── The "Quit Signet" action (broker menu) ──────────────────────────────────────
//
// The broker menu's one interactive item: the guardian clicks it to stop the always-on
// broker daemon. Mirrors `AddContainerPrsnAction` (an `NSObject` subclass as the menu
// item's target). Stateless — it reads nothing; the click confirms, then boots out the
// broker LaunchAgent (see [`handle_quit_broker`] for why a bare kill won't do).

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - This class implements no `Drop` and declares no ivars.
    #[unsafe(super(NSObject))]
    #[name = "SignetQuitBrokerAction"]
    struct QuitBrokerAction;

    impl QuitBrokerAction {
        /// The menu item's action. AppKit invokes this on the main thread.
        #[unsafe(method(quitBroker:))]
        fn quit_broker(&self, _sender: Option<&AnyObject>) {
            if let Some(mtm) = MainThreadMarker::new() {
                handle_quit_broker(mtm);
            }
        }
    }

    unsafe impl NSObjectProtocol for QuitBrokerAction {}
);

impl QuitBrokerAction {
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

// ── The "Update Signet…" action (broker menu, bug039) ────────────────────────────
//
// The broker menu's assisted-update item (present only when a newer notarized release is
// published). Mirrors `QuitBrokerAction` (an `NSObject` subclass as the menu item's target).
// Stateless — the click runs the full download → verify → Gatekeeper-check → install flow
// (`crate::update::perform_update`) and, on success, exits so launchd relaunches on the new
// binary.

define_class!(
    // SAFETY:
    // - The superclass `NSObject` has no subclassing requirements.
    // - This class implements no `Drop` and declares no ivars.
    #[unsafe(super(NSObject))]
    #[name = "SignetUpdateAction"]
    struct UpdateAction;

    impl UpdateAction {
        /// The menu item's action. AppKit invokes this on the main thread.
        #[unsafe(method(updateSignet:))]
        fn update_signet(&self, _sender: Option<&AnyObject>) {
            if let Some(mtm) = MainThreadMarker::new() {
                handle_update(mtm);
            }
        }
    }

    unsafe impl NSObjectProtocol for UpdateAction {}
);

impl UpdateAction {
    fn new() -> Retained<Self> {
        let this = Self::alloc().set_ivars(());
        unsafe { msg_send![super(this), init] }
    }
}

/// The "Quit Signet" flow (main thread): confirm, then stop the broker daemon
/// **reversibly** by booting out its LaunchAgent.
///
/// A bare process kill would be relaunched by launchd — the broker LaunchAgent's
/// `KeepAlive` is always-on (Bug030(1)/S120), so "quit" must `launchctl bootout` the agent
/// to actually stop it (this is exactly the
/// gap that made a stray helper un-stoppable from the menu). The bootout is **spawned
/// detached and not waited on**: `launchctl bootout` blocks until the target process
/// exits, and this action runs *inside* that very process, so waiting would deadlock.
/// launchd removes the service (its `KeepAlive` no longer applies) and then `SIGTERM`s
/// us, ending `NSApplication::run` and taking the menu-bar item with it. Reversible: the
/// plist stays on disk, so the broker returns at the next login (or on reinstall).
fn handle_quit_broker(mtm: MainThreadMarker) {
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("Quit Signet?"));
    alert.setInformativeText(&NSString::from_str(
        "This stops Signet. Your AI won't be able to use Signet Drive until Signet starts \
         again: at your next login, or after reinstalling. Your keys are not affected.",
    ));
    alert.addButtonWithTitle(&NSString::from_str("Quit Signet"));
    alert.addButtonWithTitle(&NSString::from_str("Cancel"));
    bring_to_front(mtm);
    if alert.runModal() != NSAlertFirstButtonReturn {
        return; // Cancel — leave the daemon running.
    }
    crate::host_channel::spawn_bootout_launchagent(crate::host_channel::BROKER_LAUNCHD_LABEL);
    // Do not exit here — launchd's bootout will SIGTERM us in the correct order (after it
    // drops the service's KeepAlive), so we don't get relaunched. We simply return to the
    // run loop and wait for that signal.
}

/// The "Update Signet…" flow (main thread): confirm → run the assisted update → on success,
/// exit so launchd (`KeepAlive=true`, the Increment-I always-on gate) relaunches the daemon on
/// the new binary; otherwise report the outcome. The download + install run on the main thread
/// (a user-initiated action — the menu is briefly unresponsive; a background-thread progress UI
/// is a later refinement).
fn handle_update(mtm: MainThreadMarker) {
    let confirm = NSAlert::new(mtm);
    confirm.setMessageText(&NSString::from_str("Update Signet?"));
    confirm.setInformativeText(&NSString::from_str(
        "Signet will download the latest verified version, install it, and restart. This takes \
         a few moments; your PRSNs and keys are not affected.",
    ));
    confirm.addButtonWithTitle(&NSString::from_str("Update"));
    confirm.addButtonWithTitle(&NSString::from_str("Later"));
    bring_to_front(mtm);
    if confirm.runModal() != NSAlertFirstButtonReturn {
        return; // Later
    }

    match crate::update::perform_update() {
        Ok(crate::update::UpdateOutcome::Installed { from, to }) => {
            let done = NSAlert::new(mtm);
            done.setMessageText(&NSString::from_str("Signet updated"));
            done.setInformativeText(&NSString::from_str(&format!(
                "Updated from {from} to {to}. Signet will restart now."
            )));
            done.addButtonWithTitle(&NSString::from_str("Restart"));
            bring_to_front(mtm);
            let _ = done.runModal();
            // Exit — the always-on LaunchAgent (KeepAlive=true) relaunches on the new binary.
            std::process::exit(0);
        }
        Ok(crate::update::UpdateOutcome::AlreadyCurrent { version }) => show_alert(
            mtm,
            "Signet is up to date",
            &format!("You're already on the latest version ({version})."),
        ),
        Err(e) => show_alert(
            mtm,
            "Update failed",
            &format!(
                "Signet couldn't complete the update:\n\n{e}\n\nYou can try again later, or \
                 re-run the installer for the latest release."
            ),
        ),
    }
}

/// The full "Add a containerized PRSN…" flow (main thread): prompt → validate →
/// provision → show the fragment → reload the host-signer so the new channel is served.
fn handle_add_container_prsn(mtm: MainThreadMarker) {
    let Some(handle) = prompt_for_handle(mtm) else {
        return; // cancelled or left empty
    };
    if !valid_prsn_handle(&handle) {
        show_alert(
            mtm,
            "Invalid PRSN handle",
            &format!(
                "'{handle}' isn't a valid PRSN handle. Use lowercase letters, digits and \
                 hyphens, ending in '-ai' (for example: ada-ai)."
            ),
        );
        return;
    }
    let dir = crate::config::host_signer_dir();
    match crate::host_channel::provision_core(&dir, None, Some(&handle)) {
        Ok(receipt) => {
            // Modal — blocks until the guardian has copied / dismissed the fragment.
            show_fragment(mtm, &receipt, &handle);
            // The serve loop reads the registry only at startup, so a freshly-provisioned
            // channel isn't served until the host-signer reloads. Reuse the CLI's proven
            // kickstart (-k) — but only AFTER the fragment alert (modal) returns, so the
            // restart never races the guardian's copy. (A hot-reload inside the serve
            // loop is a v1.x refinement; here the security-critical loop stays untouched.)
            crate::host_channel::kickstart_host_signer();
        }
        Err(e) => show_alert(
            mtm,
            "Couldn't add the PRSN",
            &format!("Provisioning the host-delegation channel failed:\n\n{e}"),
        ),
    }
}

/// Validate a PRSN handle via the canonical rule (`KeyLabel::from_handle`): the SigDrive
/// handle regex, ending in `-ai`. Purpose is irrelevant to handle validity.
fn valid_prsn_handle(handle: &str) -> bool {
    crate::keystore::KeyLabel::from_handle(handle, crate::keystore::Purpose::Signing).is_ok()
}

/// Prompt for the PRSN handle in a modal alert with a text field. Returns the trimmed
/// entry, or `None` on Cancel / an empty entry.
fn prompt_for_handle(mtm: MainThreadMarker) -> Option<String> {
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("Add a containerized PRSN"));
    alert.setInformativeText(&NSString::from_str(
        "Enter the PRSN's handle (for example: ada-ai). Signet will provision a \
         host-delegation channel and show the container command to run.",
    ));
    alert.addButtonWithTitle(&NSString::from_str("Provision"));
    alert.addButtonWithTitle(&NSString::from_str("Cancel"));

    let frame = NSRect {
        origin: NSPoint { x: 0.0, y: 0.0 },
        size: NSSize {
            width: 260.0,
            height: 24.0,
        },
    };
    let field = NSTextField::initWithFrame(NSTextField::alloc(mtm), frame);
    let field_view: &NSView = &field;
    alert.setAccessoryView(Some(field_view));

    bring_to_front(mtm);
    if alert.runModal() != NSAlertFirstButtonReturn {
        return None; // Cancel
    }
    let entered = field.stringValue().to_string();
    let entered = entered.trim().to_string();
    (!entered.is_empty()).then_some(entered)
}

/// Show the provisioned channel's container fragment, with copy buttons for the Docker
/// and Apple-`container` snippets. Modal — returns after the guardian dismisses it.
fn show_fragment(
    mtm: MainThreadMarker,
    receipt: &crate::host_channel::ProvisionReceipt,
    handle: &str,
) {
    let body = format!(
        "Channel '{id}' is provisioned for {handle}.\n\n\
         Create the container with the command below; it bind-mounts the channel, the \
         secret, and the signet binary, and sets SIGNET_HANDLE. On first boot the agent \
         runs `signet enroll`, which pins this channel to {handle}.\n\n\
         Docker:\n{docker}\n\n\
         (Use the buttons to copy the Docker or Apple `container` command.)",
        id = receipt.channel_id,
        docker = receipt.docker_snippet,
    );
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str("PRSN channel ready"));
    alert.setInformativeText(&NSString::from_str(&body));
    alert.addButtonWithTitle(&NSString::from_str("Copy Docker command"));
    alert.addButtonWithTitle(&NSString::from_str("Copy Apple container command"));
    alert.addButtonWithTitle(&NSString::from_str("Done"));
    bring_to_front(mtm);
    let resp = alert.runModal();
    if resp == NSAlertFirstButtonReturn {
        copy_to_clipboard(&receipt.docker_snippet);
    } else if resp == NSAlertSecondButtonReturn {
        copy_to_clipboard(&receipt.apple_snippet);
    }
}

/// A simple modal info / error alert with an OK button.
fn show_alert(mtm: MainThreadMarker, title: &str, body: &str) {
    let alert = NSAlert::new(mtm);
    alert.setMessageText(&NSString::from_str(title));
    alert.setInformativeText(&NSString::from_str(body));
    alert.addButtonWithTitle(&NSString::from_str("OK"));
    bring_to_front(mtm);
    let _ = alert.runModal();
}

/// Copy `text` to the general pasteboard (best-effort).
fn copy_to_clipboard(text: &str) {
    let pb = NSPasteboard::generalPasteboard();
    pb.clearContents();
    // `NSPasteboardTypeString` is an extern static — reading it is unsafe.
    let ty = unsafe { NSPasteboardTypeString };
    let _ = pb.setString_forType(&NSString::from_str(text), ty);
}

/// Bring this (accessory / `LSUIElement`) app forward so a modal alert appears in front
/// of the user's other windows rather than behind them.
fn bring_to_front(mtm: MainThreadMarker) {
    NSApplication::sharedApplication(mtm).activate();
}

#[cfg(test)]
mod tests {
    use super::version_line;

    #[test]
    fn version_line_without_latest_has_no_currency_suffix() {
        let line = version_line(None);
        assert!(line.starts_with("Version "));
        assert!(!line.contains("—"));
    }

    #[test]
    fn version_line_flags_an_update_when_latest_is_newer() {
        assert!(version_line(Some("999.0.0")).ends_with("update available"));
    }

    #[test]
    fn version_line_says_up_to_date_when_not_newer() {
        assert!(version_line(Some("0.0.1")).ends_with("up to date"));
    }

    #[test]
    fn running_line_reflects_credential_state() {
        use super::BrokerMenuState::{Impaired, Ready, Serving};
        // Serving vs. the credential-less always-on install (Bug030(1)) vs. IMPAIRED
        // (bug087 fix 3): three distinct states; the ready line names "no PRSNs yet"
        // honestly, and the impaired line says "re-provision" (never presents as healthy).
        assert_eq!(super::running_line(Serving), "● Running");
        assert!(super::running_line(Ready).contains("Ready"));
        assert!(super::running_line(Ready).contains("no PRSNs"));
        assert!(super::running_line(Impaired).contains("Not serving"));
        assert!(super::running_line(Impaired).contains("re-provision"));
        assert!(!super::running_line(Impaired).contains("Running"));
        assert_ne!(super::running_line(Serving), super::running_line(Ready));
        assert_ne!(super::running_line(Serving), super::running_line(Impaired));
    }

    #[test]
    fn menu_glyph_badges_only_when_an_update_is_available() {
        // bug039: no badge normally; a distinct (still-contains-the-mark) glyph when behind.
        assert_eq!(super::menu_glyph(false), super::MENU_GLYPH);
        assert_ne!(super::menu_glyph(true), super::MENU_GLYPH);
        assert!(super::menu_glyph(true).contains(super::MENU_GLYPH));
    }

    #[test]
    fn update_is_available_compares_against_the_running_version() {
        assert!(super::update_is_available(Some("999.0.0")));
        assert!(!super::update_is_available(Some("0.0.1")));
        assert!(!super::update_is_available(None)); // offline / unknown → no false alarm
    }

    #[test]
    fn valid_prsn_handle_accepts_ai_handles_only() {
        assert!(super::valid_prsn_handle("ada-ai"));
        assert!(super::valid_prsn_handle("h2-ai"));
        assert!(!super::valid_prsn_handle("ada")); // no -ai suffix
        assert!(!super::valid_prsn_handle("Ada-ai")); // uppercase rejected
        assert!(!super::valid_prsn_handle("")); // empty
        assert!(!super::valid_prsn_handle("-ai")); // must start alphanumeric
    }

    #[test]
    fn looks_like_version_accepts_dotted_numerics_only() {
        assert!(super::looks_like_version("0.1.0"));
        assert!(super::looks_like_version("12.0"));
        assert!(!super::looks_like_version(""));
        assert!(!super::looks_like_version("v0.1.0"));
        assert!(!super::looks_like_version("0..1"));
        assert!(!super::looks_like_version("<!doctype html>"));
        assert!(!super::looks_like_version("no CLI release is published"));
    }

    /// One-shot HTTP mock: serve `body` to the first connection, then exit.
    fn serve_once(status_line: &'static str, body: &'static str) -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                use std::io::{Read, Write};
                let mut buf = [0u8; 1024];
                let _ = stream.read(&mut buf); // drain the request
                let resp = format!(
                    "HTTP/1.1 {status_line}\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        });
        port
    }

    #[test]
    fn latest_version_best_effort_returns_a_served_version() {
        let port = serve_once("200 OK", "0.9.9\n");
        let got = super::latest_version_best_effort(&format!("http://127.0.0.1:{port}"));
        assert_eq!(got.as_deref(), Some("0.9.9"), "trimmed body version");
    }

    #[test]
    fn latest_version_best_effort_discards_non_version_bodies_and_errors() {
        let port = serve_once("200 OK", "<!doctype html><title>oops</title>");
        assert_eq!(
            super::latest_version_best_effort(&format!("http://127.0.0.1:{port}")),
            None,
            "an HTML body must not feed the currency comparison"
        );

        let port = serve_once("404 Not Found", "no CLI release is published");
        assert_eq!(
            super::latest_version_best_effort(&format!("http://127.0.0.1:{port}")),
            None,
            "a 404 (unpublished) is a skip, not a value"
        );
    }
}
