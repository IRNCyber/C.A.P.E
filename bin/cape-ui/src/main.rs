//! Native, air-gapped desktop interface for C.A.P.E. All operations are local file operations.
use attribution_record::{
    canonical_bytes, DecryptionRecord, MlDsaPublicKey, MlKemPublicKey, RecipientId,
    SignedDecryptionRecord, WatermarkPayload,
};
use crypt_engine::{decrypt, encrypt, EncryptedPackage};
use eframe::egui::{self, Color32, RichText, Stroke};
use ledger::Ledger;
use pqc_core::{open_private_key, sign};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const NAVY: Color32 = Color32::from_rgb(18, 30, 46);
const PANEL: Color32 = Color32::from_rgb(28, 44, 63);
const GREEN: Color32 = Color32::from_rgb(90, 203, 141);
const AMBER: Color32 = Color32::from_rgb(240, 185, 74);
const RED: Color32 = Color32::from_rgb(235, 104, 104);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Page {
    Home,
    Sender,
    Recipient,
    Auditor,
}

#[derive(Deserialize, Serialize)]
struct RecipientPublic {
    recipient_id: RecipientId,
    kem_public: MlKemPublicKey,
    signing_public: MlDsaPublicKey,
}

#[derive(Deserialize)]
struct RecipientIdentity {
    recipient_id: RecipientId,
    signing_public: MlDsaPublicKey,
}

struct CapeApp {
    page: Page,
    sender_document: String,
    sender_recipients: String,
    sender_package: String,
    recipient_package: String,
    recipient_identity: String,
    recipient_passphrase: String,
    recipient_ledger: String,
    recipient_output: String,
    audit_leak: String,
    audit_ledger: String,
    status: Option<(bool, String)>,
    report: Option<String>,
}

impl Default for CapeApp {
    fn default() -> Self {
        Self {
            page: Page::Home,
            sender_document: "demo/memo.txt".into(),
            sender_recipients: "demo/recipients.json".into(),
            sender_package: "demo/package.cape".into(),
            recipient_package: "demo/package.cape".into(),
            recipient_identity: "demo/r2".into(),
            recipient_passphrase: String::new(),
            recipient_ledger: "demo/ledger".into(),
            recipient_output: "demo/recipient-copy.txt".into(),
            audit_leak: "demo/recipient-copy.txt".into(),
            audit_ledger: "demo/ledger".into(),
            status: None,
            report: None,
        }
    }
}

impl CapeApp {
    fn status(&mut self, ok: bool, message: impl Into<String>) {
        self.status = Some((ok, message.into()));
    }
    fn nav_button(ui: &mut egui::Ui, selected: bool, label: &str) -> bool {
        ui.add_sized(
            [174.0, 38.0],
            egui::Button::new(RichText::new(label).size(15.0)).fill(if selected {
                Color32::from_rgb(42, 79, 100)
            } else {
                NAVY
            }),
        )
        .clicked()
    }
    fn field(ui: &mut egui::Ui, label: &str, value: &mut String, secret: bool) {
        ui.label(RichText::new(label).color(Color32::from_rgb(187, 202, 216)));
        let edit = egui::TextEdit::singleline(value)
            .desired_width(f32::INFINITY)
            .password(secret);
        ui.add(edit);
        ui.add_space(8.0);
    }
    fn action_button(ui: &mut egui::Ui, label: &str) -> bool {
        ui.add_sized(
            [210.0, 38.0],
            egui::Button::new(RichText::new(label).strong()).fill(Color32::from_rgb(42, 113, 93)),
        )
        .clicked()
    }
    fn panel(ui: &mut egui::Ui, add: impl FnOnce(&mut egui::Ui)) {
        egui::Frame::new()
            .fill(PANEL)
            .inner_margin(20.0)
            .corner_radius(10.0)
            .stroke(Stroke::new(1.0_f32, Color32::from_rgb(59, 81, 101)))
            .show(ui, add);
    }
    fn sender(&mut self, ui: &mut egui::Ui) {
        ui.heading("Create protected package");
        ui.label("Encrypt a UTF-8 text document once for multiple verified recipient identities.");
        ui.add_space(16.0);
        Self::panel(ui, |ui| {
            Self::field(
                ui,
                "Document path  •  UTF-8 text supported",
                &mut self.sender_document,
                false,
            );
            Self::field(
                ui,
                "Recipients JSON path",
                &mut self.sender_recipients,
                false,
            );
            Self::field(ui, "Output package path", &mut self.sender_package, false);
            ui.label(
                RichText::new("Protection: ML-KEM-768 + AES-256-GCM. No network activity.")
                    .color(GREEN),
            );
            ui.add_space(8.0);
            if Self::action_button(ui, "Create offline package") {
                match self.create_package() { Ok(()) => self.status(true, "Protected package created. Distribute the .cape file using approved offline media."), Err(e) => self.status(false, e.to_string()) }
            }
        });
    }
    fn recipient(&mut self, ui: &mut egui::Ui) {
        ui.heading("Open received package");
        ui.label(
            "Decryption writes only an attributed copy and commits a signed local evidence event.",
        );
        ui.add_space(16.0);
        Self::panel(ui, |ui| {
            Self::field(
                ui,
                "Protected package path",
                &mut self.recipient_package,
                false,
            );
            Self::field(ui, "Identity folder", &mut self.recipient_identity, false);
            Self::field(
                ui,
                "Identity passphrase",
                &mut self.recipient_passphrase,
                true,
            );
            Self::field(ui, "Local ledger folder", &mut self.recipient_ledger, false);
            Self::field(
                ui,
                "Attributed output path",
                &mut self.recipient_output,
                false,
            );
            ui.colored_label(AMBER, "Opening this package records a unique watermark and your ML-DSA-65 signed decryption event.");
            ui.add_space(8.0);
            if Self::action_button(ui, "Decrypt and record") {
                match self.decrypt_and_record() {
                    Ok(()) => {
                        self.audit_leak = self.recipient_output.clone();
                        self.audit_ledger = self.recipient_ledger.clone();
                        self.status(true, "Decryption complete. A uniquely attributed copy and a signed ledger event were created.");
                    }
                    Err(e) => self.status(false, e.to_string()),
                }
            }
        });
    }
    fn auditor(&mut self, ui: &mut egui::Ui) {
        ui.heading("Analyze suspected leak");
        ui.label(
            "Extract a supported watermark and independently verify the local chain and signature.",
        );
        ui.add_space(16.0);
        Self::panel(ui, |ui| {
            Self::field(ui, "Suspected leak path", &mut self.audit_leak, false);
            Self::field(ui, "Ledger folder", &mut self.audit_ledger, false);
            ui.horizontal(|ui| {
                if Self::action_button(ui, "Analyze and verify") {
                    match self.analyze() {
                        Ok(()) => self.status(true, "Evidence report verified."),
                        Err(e) => self.status(false, e.to_string()),
                    }
                }
                if ui.button("Verify ledger only").clicked() {
                    match self.verify_ledger() {
                        Ok(()) => self.status(true, "Ledger integrity verified."),
                        Err(e) => self.status(false, e.to_string()),
                    }
                }
            });
        });
        if let Some(report) = &self.report {
            ui.add_space(14.0);
            Self::panel(ui, |ui| {
                ui.label(
                    RichText::new("VERIFIED EVIDENCE REPORT")
                        .strong()
                        .color(GREEN),
                );
                ui.add_space(6.0);
                egui::ScrollArea::vertical()
                    .max_height(250.0)
                    .show(ui, |ui| {
                        ui.monospace(report);
                    });
            });
        }
    }
    fn home(&mut self, ui: &mut egui::Ui) {
        ui.add_space(18.0);
        ui.heading(RichText::new("Cryptographic Attribution & Provenance Evidence").size(28.0));
        ui.add_space(8.0);
        ui.label(
            RichText::new("A local, evidence-first workflow for controlled document distribution.")
                .size(17.0)
                .color(Color32::from_rgb(196, 211, 223)),
        );
        ui.add_space(24.0);
        ui.columns(3, |columns| {
            let cards = [
                (
                    "01",
                    "Sender",
                    "Create a protected package for verified recipients.",
                ),
                (
                    "02",
                    "Recipient",
                    "Decrypt an attributed copy and sign the event.",
                ),
                ("03", "Auditor", "Attribute a leak and verify its evidence."),
            ];
            for (column, (number, title, text)) in columns.iter_mut().zip(cards) {
                Self::panel(column, |ui| {
                    ui.label(RichText::new(number).size(22.0).color(GREEN));
                    ui.heading(title);
                    ui.label(text);
                });
            }
        });
        ui.add_space(24.0);
        Self::panel(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new("●  OFFLINE / AIR-GAPPED")
                        .strong()
                        .color(GREEN),
                );
                ui.separator();
                ui.label("No cloud services • No telemetry • Local evidence ledger");
            });
        });
    }
    fn create_package(&self) -> anyhow::Result<()> {
        let plaintext = fs::read(&self.sender_document)?;
        let recipients: Vec<RecipientPublic> =
            serde_json::from_slice(&fs::read(&self.sender_recipients)?)?;
        let keys = recipients
            .into_iter()
            .map(|item| (item.recipient_id, item.kem_public))
            .collect::<Vec<_>>();
        let package = encrypt(&plaintext, &keys)?;
        write_file(&self.sender_package, &bincode::serialize(&package)?)
    }
    fn decrypt_and_record(&self) -> anyhow::Result<()> {
        if Path::new(&self.recipient_output)
            .extension()
            .and_then(|v| v.to_str())
            != Some("txt")
        {
            anyhow::bail!("only UTF-8 text output (.txt) is currently supported");
        }
        let identity: RecipientIdentity = serde_json::from_slice(&fs::read(
            Path::new(&self.recipient_identity).join("recipient.json"),
        )?)?;
        let package: EncryptedPackage = bincode::deserialize(&fs::read(&self.recipient_package)?)?;
        let kem = open_private_key(
            &Path::new(&self.recipient_identity).join("kem.private"),
            self.recipient_passphrase.as_bytes(),
        )?;
        let plaintext = decrypt(&package, &identity.recipient_id, &kem)?;
        let mut session_nonce = [0u8; 16];
        OsRng.fill_bytes(&mut session_nonce);
        let document_id = *blake3::hash(&package.ciphertext).as_bytes();
        let mut seed = Vec::new();
        seed.extend_from_slice(&document_id);
        seed.extend_from_slice(identity.recipient_id.0.as_bytes());
        seed.extend_from_slice(&session_nonce);
        let watermark = WatermarkPayload(*blake3::hash(&seed).as_bytes());
        let marked = watermark::embed(&plaintext, watermark)?;
        let record = DecryptionRecord {
            document_id,
            recipient_id: identity.recipient_id,
            watermark,
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
            session_nonce,
        };
        let signing_key = open_private_key(
            &Path::new(&self.recipient_identity).join("sign.private"),
            self.recipient_passphrase.as_bytes(),
        )?;
        let entry = SignedDecryptionRecord {
            signature: sign(&signing_key, &canonical_bytes(&record)?)?,
            record,
            signer_pubkey: identity.signing_public,
        };
        Ledger::open(&self.recipient_ledger)?.append(entry)?;
        write_file(&self.recipient_output, &marked)
    }
    fn analyze(&mut self) -> anyhow::Result<()> {
        let ledger = Ledger::open(&self.audit_ledger)?;
        let report = forensics::analyze(&fs::read(&self.audit_leak)?, &ledger)?;
        self.report = Some(serde_json::to_string_pretty(&report)?);
        Ok(())
    }
    fn verify_ledger(&self) -> anyhow::Result<()> {
        Ledger::open(&self.audit_ledger)?.verify_chain()?;
        Ok(())
    }
}

fn write_file(path: &str, bytes: &[u8]) -> anyhow::Result<()> {
    if let Some(parent) = Path::new(path)
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, bytes)?;
    Ok(())
}

impl eframe::App for CapeApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        ctx.set_visuals(egui::Visuals::dark());
        egui::SidePanel::left("navigation")
            .exact_width(210.0)
            .frame(egui::Frame::new().fill(NAVY).inner_margin(18.0))
            .show(ctx, |ui| {
                ui.heading(RichText::new("C.A.P.E.").size(28.0).color(Color32::WHITE));
                ui.label(
                    RichText::new("Evidence workspace").color(Color32::from_rgb(160, 188, 207)),
                );
                ui.add_space(30.0);
                if Self::nav_button(ui, self.page == Page::Home, "Overview") {
                    self.page = Page::Home;
                }
                if Self::nav_button(ui, self.page == Page::Sender, "01  Sender") {
                    self.page = Page::Sender;
                }
                if Self::nav_button(ui, self.page == Page::Recipient, "02  Recipient") {
                    self.page = Page::Recipient;
                }
                if Self::nav_button(ui, self.page == Page::Auditor, "03  Auditor") {
                    self.page = Page::Auditor;
                }
                ui.with_layout(egui::Layout::bottom_up(egui::Align::LEFT), |ui| {
                    ui.label(RichText::new("● OFFLINE").strong().color(GREEN));
                    ui.label(
                        RichText::new("Air-gapped mode")
                            .size(12.0)
                            .color(Color32::GRAY),
                    );
                });
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(Color32::from_rgb(21, 35, 51))
                    .inner_margin(32.0),
            )
            .show(ctx, |ui| {
                if let Some((ok, message)) = &self.status {
                    let color = if *ok { GREEN } else { RED };
                    ui.colored_label(
                        color,
                        format!("{}  {}", if *ok { "✓" } else { "!" }, message),
                    );
                    ui.add_space(14.0);
                }
                match self.page {
                    Page::Home => self.home(ui),
                    Page::Sender => self.sender(ui),
                    Page::Recipient => self.recipient(ui),
                    Page::Auditor => self.auditor(ui),
                }
            });
    }
}

fn main() -> eframe::Result<()> {
    eframe::run_native(
        "C.A.P.E. Evidence Workspace",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1100.0, 720.0])
                .with_min_inner_size([900.0, 620.0]),
            ..Default::default()
        },
        Box::new(|_| Ok(Box::<CapeApp>::default())),
    )
}
