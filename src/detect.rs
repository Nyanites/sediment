//! Detections: rules that flag suspicious activity in the loaded `$MFT`, USN
//! journal and prefetch files, each mapped to MITRE ATT&CK with a severity,
//! an explanation, likely false positives and references.
//!
//! Rules are Sediment's own, written for what these artifacts can show: a
//! file's names, location, timestamps and streams; the journal's history of
//! changes; and prefetch's record of what ran and what it loaded. A rule
//! flags items worth a look, not proof of compromise.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::mft::{self, MftFile};
use crate::prefetch::{self, Prefetch};
use crate::usn::{self, UsnJournal};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "Info",
            Severity::Low => "Low",
            Severity::Medium => "Medium",
            Severity::High => "High",
            Severity::Critical => "Critical",
        }
    }
}

/// MITRE ATT&CK tactics, in kill-chain order (rules are grouped by them).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tactic {
    InitialAccess,
    Execution,
    Persistence,
    PrivilegeEscalation,
    DefenseEvasion,
    CredentialAccess,
    Discovery,
    LateralMovement,
    CommandAndControl,
    Exfiltration,
    Impact,
}

impl Tactic {
    pub fn label(self) -> &'static str {
        match self {
            Tactic::InitialAccess => "Initial Access",
            Tactic::Execution => "Execution",
            Tactic::Persistence => "Persistence",
            Tactic::PrivilegeEscalation => "Privilege Escalation",
            Tactic::DefenseEvasion => "Defense Evasion",
            Tactic::CredentialAccess => "Credential Access",
            Tactic::Discovery => "Discovery",
            Tactic::LateralMovement => "Lateral Movement",
            Tactic::CommandAndControl => "Command and Control",
            Tactic::Exfiltration => "Exfiltration",
            Tactic::Impact => "Impact",
        }
    }

    /// The tactic's ATT&CK ID.
    pub fn id(self) -> &'static str {
        match self {
            Tactic::InitialAccess => "TA0001",
            Tactic::Execution => "TA0002",
            Tactic::Persistence => "TA0003",
            Tactic::PrivilegeEscalation => "TA0004",
            Tactic::DefenseEvasion => "TA0005",
            Tactic::CredentialAccess => "TA0006",
            Tactic::Discovery => "TA0007",
            Tactic::LateralMovement => "TA0008",
            Tactic::CommandAndControl => "TA0011",
            Tactic::Exfiltration => "TA0010",
            Tactic::Impact => "TA0040",
        }
    }
}

/// Which artifact a rule looks at; its hits live in that view.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Artifact {
    Mft,
    Journal,
    Prefetch,
}

impl Artifact {
    pub fn label(self) -> &'static str {
        match self {
            Artifact::Mft => "$MFT",
            Artifact::Journal => "USN journal",
            Artifact::Prefetch => "Prefetch",
        }
    }
}

pub struct Rule {
    pub id: String,
    pub name: String,
    pub tactic: Tactic,
    /// ATT&CK technique ID(s), comma-separated, e.g. "T1003.001".
    pub mitre: &'static str,
    pub severity: Severity,
    pub artifact: Artifact,
    pub description: String,
    /// What exactly is checked, in plain words.
    pub logic: String,
    pub false_positives: &'static str,
    pub references: Vec<&'static str>,
    check: Check,
}

#[derive(Clone, Copy)]
enum Check {
    Mft(fn(&MftFile, &mut Vec<Hit>)),
    Journal(fn(&UsnJournal, &mut Vec<Hit>)),
    Prefetch(fn(&Prefetch) -> Option<String>),
    /// Prefetch whose executable is named `exe` (upper case).
    Tool(&'static str),
    /// Prefetch checked against the `$MFT`.
    /// Prefetch checked against the `$MFT`, given the prefetch file's name.
    PrefetchMft(fn(&Prefetch, &str, &MftIndex) -> Option<String>),
}

/// An item a rule flagged.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, PartialOrd, Ord)]
pub enum Target {
    /// `$MFT` record number.
    Mft(u32),
    /// Index into the journal's records.
    Journal(u32),
    /// Index into the loaded prefetch files.
    Prefetch(u32),
}

pub struct Hit {
    pub target: Target,
    /// Why this item matched, e.g. the URL a file was downloaded from.
    pub detail: String,
}

pub struct Detections {
    pub rules: Vec<Rule>,
    /// Hits per rule, same order as `rules`.
    pub hits: Vec<Vec<Hit>>,
    /// For each flagged item: (rule, index into that rule's hits), most severe first.
    pub by_target: HashMap<Target, Vec<(usize, usize)>>,
    pub elapsed: Duration,
}

impl Detections {
    pub fn matched_rules(&self) -> usize {
        self.hits.iter().filter(|h| !h.is_empty()).count()
    }

    pub fn top_severity(&self) -> Option<Severity> {
        (0..self.rules.len()).filter(|&i| !self.hits[i].is_empty()).map(|i| self.rules[i].severity).max()
    }

    /// The most severe rule that flagged `t`.
    pub fn top_for(&self, t: Target) -> Option<&Rule> {
        self.by_target.get(&t).and_then(|v| v.first()).map(|&(r, _)| &self.rules[r])
    }
}

/// Lower-case paths of the `$MFT`, for checking prefetch's file lists.
pub struct MftIndex<'a> {
    pub file: &'a MftFile,
    pub paths: &'a HashMap<String, u32>,
}

pub struct Input<'a> {
    pub mft: Option<&'a MftFile>,
    pub journal: Option<&'a UsnJournal>,
    /// Loaded prefetch files by index; `None` for ones that failed to parse.
    pub prefetch: Vec<Option<&'a Prefetch>>,
    /// File names of the loaded prefetch files, same order.
    pub prefetch_names: Vec<String>,
    pub mft_paths: Option<&'a HashMap<String, u32>>,
}

pub fn run(input: &Input) -> Detections {
    let start = Instant::now();
    let rules = rules();
    let mut hits: Vec<Vec<Hit>> = Vec::with_capacity(rules.len());
    for r in &rules {
        let mut h = Vec::new();
        match r.check {
            Check::Mft(f) => {
                if let Some(m) = input.mft {
                    f(m, &mut h);
                }
            }
            Check::Journal(f) => {
                if let Some(j) = input.journal {
                    f(j, &mut h);
                }
            }
            Check::Prefetch(f) => each_pf(input, &mut h, f),
            Check::Tool(exe) => {
                for (i, pf) in input.prefetch.iter().enumerate() {
                    if let Some(pf) = pf
                        && pf.executable.eq_ignore_ascii_case(exe)
                    {
                        h.push(Hit { target: Target::Prefetch(i as u32), detail: runs(pf) });
                    }
                }
            }
            Check::PrefetchMft(f) => {
                if let (Some(file), Some(paths)) = (input.mft, input.mft_paths) {
                    let idx = MftIndex { file, paths };
                    for (i, pf) in input.prefetch.iter().enumerate() {
                        let name = input.prefetch_names.get(i).map_or("", String::as_str);
                        if let Some(d) = pf.and_then(|pf| f(pf, name, &idx)) {
                            h.push(Hit { target: Target::Prefetch(i as u32), detail: d });
                        }
                    }
                }
            }
        }
        hits.push(h);
    }
    let mut by_target: HashMap<Target, Vec<(usize, usize)>> = HashMap::new();
    for (r, hs) in hits.iter().enumerate() {
        for (k, h) in hs.iter().enumerate() {
            by_target.entry(h.target).or_default().push((r, k));
        }
    }
    for v in by_target.values_mut() {
        v.sort_by_key(|&(r, _)| std::cmp::Reverse(rules[r].severity));
    }
    Detections { rules, hits, by_target, elapsed: start.elapsed() }
}

fn each_pf(input: &Input, h: &mut Vec<Hit>, f: fn(&Prefetch) -> Option<String>) {
    for (i, pf) in input.prefetch.iter().enumerate() {
        if let Some(d) = pf.and_then(f) {
            h.push(Hit { target: Target::Prefetch(i as u32), detail: d });
        }
    }
}

fn runs(pf: &Prefetch) -> String {
    let path = pf.executable_path().map(prefetch::strip_volume).unwrap_or(&pf.executable).to_string();
    match pf.last_run_times.first() {
        Some(t) => format!("{path} · run {} time(s), last {}", pf.run_count, t.format("%Y-%m-%d %H:%M:%S UTC")),
        None => format!("{path} · run {} time(s)", pf.run_count),
    }
}

// ---------------------------------------------------------------- helpers

const EXECUTABLE: &[&str] = &["exe", "dll", "scr", "com", "pif", "cpl", "msi", "ps1", "bat", "cmd", "vbs", "vbe", "js", "jse", "wsf", "hta"];

fn ext(name_lc: &str) -> &str {
    name_lc.rsplit_once('.').map_or("", |(_, e)| e)
}

fn is_executable(name_lc: &str) -> bool {
    EXECUTABLE.contains(&ext(name_lc))
}

/// Executables Windows itself drops in temp folders all the time.
fn routine_temp_file(name_lc: &str) -> bool {
    // PowerShell's execution-policy probe and Defender's definition updates.
    name_lc.starts_with("__psscriptpolicytest_")
        || (name_lc.starts_with("mpam-") || name_lc.starts_with("mpas-")) && name_lc.ends_with(".exe")
        || name_lc == "mpengine.dll"
        || name_lc == "mpsigstub.exe"
}

/// Folders where ordinary users can write and where dropped tools often land.
fn user_writable(path_lc: &str) -> Option<&'static str> {
    if package_store(path_lc) {
        return None;
    }
    const DIRS: &[(&str, &str)] = &[
        ("\\downloads\\", "a Downloads folder"),
        ("\\desktop\\", "a desktop"),
        ("\\appdata\\local\\temp\\", "a user temp folder"),
        ("\\windows\\temp\\", "the Windows temp folder"),
        ("\\users\\public\\", "the Public profile"),
        ("\\$recycle.bin\\", "the Recycle Bin"),
        ("\\perflogs\\", "PerfLogs"),
    ];
    if let Some((_, what)) = DIRS.iter().find(|(d, _)| path_lc.contains(d)) {
        return Some(what);
    }
    // Files directly in ProgramData (its subfolders belong to installed software).
    let rest = path_lc.strip_prefix("\\programdata\\")?;
    (!rest.contains('\\')).then_some("the root of ProgramData")
}

fn ft(t: u64) -> String {
    mft::format_filetime(t).chars().take(19).collect()
}

fn with_path(e: &mft::Entry) -> String {
    if e.path.is_empty() { e.name.clone() } else { e.path.clone() }
}

fn journal_path(r: &usn::UsnRecord) -> (&str, String) {
    let lc = if r.path_lc.is_empty() { &r.name_lc } else { &r.path_lc };
    let shown = if r.path.is_empty() { r.name.clone() } else { r.path.clone() };
    (lc, shown)
}

// ---------------------------------------------------------------- rules

#[allow(clippy::too_many_arguments)] // a row of the rule table
fn rule(
    id: &str,
    name: &str,
    artifact: Artifact,
    tactic: Tactic,
    mitre: &'static str,
    severity: Severity,
    description: &str,
    logic: &str,
    false_positives: &'static str,
    references: &[&'static str],
    check: Check,
) -> Rule {
    Rule {
        id: id.into(),
        name: name.into(),
        tactic,
        mitre,
        severity,
        artifact,
        description: description.into(),
        logic: logic.into(),
        false_positives,
        references: references.to_vec(),
        check,
    }
}

/// Well-known attacker and dual-use tools, by executable name.
struct Tool {
    exe: &'static str,
    name: &'static str,
    tactic: Tactic,
    mitre: &'static str,
    severity: Severity,
    what: &'static str,
    false_positives: &'static str,
    reference: &'static str,
}

const TOOLS: &[Tool] = &[
    Tool { exe: "MIMIKATZ.EXE", name: "Mimikatz", tactic: Tactic::CredentialAccess, mitre: "T1003.001, T1558", severity: Severity::Critical,
        what: "dumps credentials from LSASS memory and forges Kerberos tickets",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/gentilkiwi/mimikatz" },
    Tool { exe: "RUBEUS.EXE", name: "Rubeus", tactic: Tactic::CredentialAccess, mitre: "T1558.003, T1558.004", severity: Severity::High,
        what: "requests and abuses Kerberos tickets: Kerberoasting, AS-REP roasting, pass-the-ticket",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/GhostPack/Rubeus" },
    Tool { exe: "LAZAGNE.EXE", name: "LaZagne", tactic: Tactic::CredentialAccess, mitre: "T1555", severity: Severity::High,
        what: "recovers passwords saved by browsers, mail clients and other software",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/AlessandroZ/LaZagne" },
    Tool { exe: "CERTIFY.EXE", name: "Certify", tactic: Tactic::CredentialAccess, mitre: "T1649", severity: Severity::High,
        what: "finds and abuses misconfigured Active Directory Certificate Services templates",
        false_positives: "Authorised penetration tests and AD CS audits.", reference: "https://github.com/GhostPack/Certify" },
    Tool { exe: "PROCDUMP.EXE", name: "ProcDump", tactic: Tactic::CredentialAccess, mitre: "T1003.001", severity: Severity::Medium,
        what: "writes process memory dumps; attackers use it on LSASS to steal credentials",
        false_positives: "Developers and support staff capturing crash dumps.",
        reference: "https://learn.microsoft.com/en-us/sysinternals/downloads/procdump" },
    Tool { exe: "PROCDUMP64.EXE", name: "ProcDump (64-bit)", tactic: Tactic::CredentialAccess, mitre: "T1003.001", severity: Severity::Medium,
        what: "writes process memory dumps; attackers use it on LSASS to steal credentials",
        false_positives: "Developers and support staff capturing crash dumps.",
        reference: "https://learn.microsoft.com/en-us/sysinternals/downloads/procdump" },
    Tool { exe: "NTDSUTIL.EXE", name: "ntdsutil", tactic: Tactic::CredentialAccess, mitre: "T1003.003", severity: Severity::Medium,
        what: "can create a copy of the Active Directory database (NTDS.dit) with all password hashes",
        false_positives: "Domain controller maintenance and IFM media creation.",
        reference: "https://attack.mitre.org/techniques/T1003/003/" },
    Tool { exe: "SHARPHOUND.EXE", name: "SharpHound", tactic: Tactic::Discovery, mitre: "T1087.002, T1482", severity: Severity::High,
        what: "collects Active Directory users, groups, sessions and trusts for BloodHound attack-path analysis",
        false_positives: "Authorised AD security assessments.", reference: "https://github.com/SpecterOps/SharpHound" },
    Tool { exe: "ADFIND.EXE", name: "AdFind", tactic: Tactic::Discovery, mitre: "T1087.002, T1482", severity: Severity::High,
        what: "queries Active Directory; widely used by ransomware operators for reconnaissance",
        false_positives: "AD administrators.", reference: "https://www.joeware.net/freetools/tools/adfind/" },
    Tool { exe: "SEATBELT.EXE", name: "Seatbelt", tactic: Tactic::Discovery, mitre: "T1082", severity: Severity::High,
        what: "runs dozens of host reconnaissance checks for an attacker",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/GhostPack/Seatbelt" },
    Tool { exe: "SHARPUP.EXE", name: "SharpUp", tactic: Tactic::PrivilegeEscalation, mitre: "T1068, T1574", severity: Severity::High,
        what: "looks for local privilege escalation paths",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/GhostPack/SharpUp" },
    Tool { exe: "WINPEAS.EXE", name: "winPEAS", tactic: Tactic::PrivilegeEscalation, mitre: "T1082, T1068", severity: Severity::High,
        what: "enumerates local privilege escalation paths",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/peass-ng/PEASS-ng" },
    Tool { exe: "WINPEASX64.EXE", name: "winPEAS (64-bit)", tactic: Tactic::PrivilegeEscalation, mitre: "T1082, T1068", severity: Severity::High,
        what: "enumerates local privilege escalation paths",
        false_positives: "Authorised penetration tests.", reference: "https://github.com/peass-ng/PEASS-ng" },
    Tool { exe: "PSEXEC.EXE", name: "PsExec", tactic: Tactic::LateralMovement, mitre: "T1569.002, T1021.002", severity: Severity::Medium,
        what: "runs commands on other machines over SMB by installing a temporary service",
        false_positives: "Administrators managing remote machines.",
        reference: "https://learn.microsoft.com/en-us/sysinternals/downloads/psexec" },
    Tool { exe: "PSEXEC64.EXE", name: "PsExec (64-bit)", tactic: Tactic::LateralMovement, mitre: "T1569.002, T1021.002", severity: Severity::Medium,
        what: "runs commands on other machines over SMB by installing a temporary service",
        false_positives: "Administrators managing remote machines.",
        reference: "https://learn.microsoft.com/en-us/sysinternals/downloads/psexec" },
    Tool { exe: "PSEXESVC.EXE", name: "PsExec service (target side)", tactic: Tactic::LateralMovement, mitre: "T1569.002, T1021.002", severity: Severity::High,
        what: "is the service PsExec installs on the machine it connects to: this host was the target of a remote PsExec session",
        false_positives: "Administrators managing this machine remotely.",
        reference: "https://learn.microsoft.com/en-us/sysinternals/downloads/psexec" },
    Tool { exe: "CHISEL.EXE", name: "Chisel", tactic: Tactic::CommandAndControl, mitre: "T1572, T1090", severity: Severity::High,
        what: "tunnels traffic over HTTP to reach internal networks",
        false_positives: "Rare outside penetration tests.", reference: "https://github.com/jpillora/chisel" },
    Tool { exe: "PLINK.EXE", name: "Plink", tactic: Tactic::CommandAndControl, mitre: "T1572", severity: Severity::Medium,
        what: "opens SSH connections and tunnels from the command line; used to expose RDP to the internet",
        false_positives: "Administrators using PuTTY's command-line client.",
        reference: "https://attack.mitre.org/techniques/T1572/" },
    Tool { exe: "NC.EXE", name: "Netcat", tactic: Tactic::CommandAndControl, mitre: "T1095", severity: Severity::High,
        what: "opens raw network connections, often for reverse shells",
        false_positives: "Network troubleshooting.", reference: "https://attack.mitre.org/techniques/T1095/" },
    Tool { exe: "NC64.EXE", name: "Netcat (64-bit)", tactic: Tactic::CommandAndControl, mitre: "T1095", severity: Severity::High,
        what: "opens raw network connections, often for reverse shells",
        false_positives: "Network troubleshooting.", reference: "https://attack.mitre.org/techniques/T1095/" },
    Tool { exe: "RCLONE.EXE", name: "Rclone", tactic: Tactic::Exfiltration, mitre: "T1567.002", severity: Severity::High,
        what: "syncs files to cloud storage; a favourite of ransomware groups for stealing data before encryption",
        false_positives: "Backups and administrators syncing to cloud storage.", reference: "https://rclone.org/" },
    Tool { exe: "VSSADMIN.EXE", name: "vssadmin", tactic: Tactic::Impact, mitre: "T1490", severity: Severity::Medium,
        what: "manages shadow copies; ransomware deletes them so files can't be restored",
        false_positives: "Backup software and administrators listing or resizing shadow storage.",
        reference: "https://attack.mitre.org/techniques/T1490/" },
    // Living-off-the-land binaries: built into Windows, abused to run code or fetch files.
    Tool { exe: "MSHTA.EXE", name: "mshta", tactic: Tactic::DefenseEvasion, mitre: "T1218.005", severity: Severity::Medium,
        what: "runs HTML applications (.hta) with script, locally or from a URL",
        false_positives: "Some legacy installers and line-of-business tools.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Mshta/" },
    Tool { exe: "REGSVR32.EXE", name: "regsvr32", tactic: Tactic::DefenseEvasion, mitre: "T1218.010", severity: Severity::Info,
        what: "registers DLLs; can also run script from a URL (Squiblydoo)",
        false_positives: "Very common: installers and updates register DLLs.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/" },
    Tool { exe: "INSTALLUTIL.EXE", name: "InstallUtil", tactic: Tactic::DefenseEvasion, mitre: "T1218.004", severity: Severity::Medium,
        what: "runs installer classes in .NET assemblies, a way to run code past application allow-listing",
        false_positives: "Installing .NET Windows services.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Installutil/" },
    Tool { exe: "MSBUILD.EXE", name: "MSBuild", tactic: Tactic::DefenseEvasion, mitre: "T1127.001", severity: Severity::Low,
        what: "compiles and runs inline C# from project files, a way to run code past application allow-listing",
        false_positives: "Developer machines and build servers.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Msbuild/" },
    Tool { exe: "REGASM.EXE", name: "RegAsm", tactic: Tactic::DefenseEvasion, mitre: "T1218.009", severity: Severity::Low,
        what: "registers .NET assemblies and can run code in them",
        false_positives: "Installers registering COM-visible .NET components.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Regasm/" },
    Tool { exe: "CMSTP.EXE", name: "CMSTP", tactic: Tactic::DefenseEvasion, mitre: "T1218.003", severity: Severity::Medium,
        what: "installs connection-manager profiles and can be abused to run code and bypass UAC",
        false_positives: "VPN profile installation.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Cmstp/" },
    Tool { exe: "CERTUTIL.EXE", name: "certutil", tactic: Tactic::CommandAndControl, mitre: "T1105, T1140", severity: Severity::Low,
        what: "manages certificates; attackers use it to download files and decode Base64 payloads",
        false_positives: "Certificate management by administrators and software.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Certutil/" },
    Tool { exe: "BITSADMIN.EXE", name: "bitsadmin", tactic: Tactic::Persistence, mitre: "T1197", severity: Severity::Low,
        what: "creates background transfer jobs, usable to download payloads and to persist",
        false_positives: "Older update and deployment scripts.",
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/" },
    Tool { exe: "WEVTUTIL.EXE", name: "wevtutil", tactic: Tactic::DefenseEvasion, mitre: "T1070.001", severity: Severity::Low,
        what: "manages event logs and can clear them",
        false_positives: "Administrators and scripts exporting or configuring logs.",
        reference: "https://attack.mitre.org/techniques/T1070/001/" },
    Tool { exe: "NLTEST.EXE", name: "nltest", tactic: Tactic::Discovery, mitre: "T1482", severity: Severity::Low,
        what: "lists domain controllers and domain trusts, a common early step after a breach",
        false_positives: "Administrators troubleshooting domain connectivity.",
        reference: "https://attack.mitre.org/techniques/T1482/" },
    Tool { exe: "BCDEDIT.EXE", name: "bcdedit", tactic: Tactic::Impact, mitre: "T1490", severity: Severity::Low,
        what: "changes boot settings; ransomware uses it to disable Windows recovery",
        false_positives: "Administrators changing boot configuration.",
        reference: "https://attack.mitre.org/techniques/T1490/" },
];

fn rules() -> Vec<Rule> {
    use Artifact::*;
    use Severity::*;
    use Tactic::*;
    let mut r = Vec::new();
    for t in TOOLS {
        r.push(rule(
            &format!("tool_{}", t.exe.trim_end_matches(".EXE").to_lowercase()),
            &format!("{} executed", t.name),
            Prefetch,
            t.tactic,
            t.mitre,
            t.severity,
            &format!("A prefetch file shows {} ran on this machine. It {}.", t.exe, t.what),
            &format!("The prefetch file's executable name is {}.", t.exe),
            t.false_positives,
            &[t.reference],
            Check::Tool(t.exe),
        ));
    }

    // ------------------------------------------------------------ prefetch
    r.push(rule("pf_masquerading", "System program name run from the wrong folder", Prefetch, DefenseEvasion, "T1036.005", High,
        "A program named like a core Windows process (svchost.exe, lsass.exe, csrss.exe, …) ran from outside the \
         Windows folder. Malware borrows these names to blend in.",
        "Executable name is one of Windows' core processes and its path is not under \\Windows\\.",
        "Rare: some security tools and sandboxes copy system binaries.",
        &["https://attack.mitre.org/techniques/T1036/005/"], Check::Prefetch(pf_masquerading)));
    r.push(rule("pf_user_folder", "Program run from a user-writable folder", Prefetch, Execution, "T1204.002", Medium,
        "A program ran from a Downloads folder, a desktop, a temp folder, the Public profile, the Recycle Bin or the root \
         of ProgramData: where downloaded and dropped tools usually run from.",
        "The prefetch file's executable path is in one of those folders.",
        "Installers and portable tools run from Downloads; updaters unpack into temp folders.",
        &["https://attack.mitre.org/techniques/T1204/002/"], Check::Prefetch(pf_user_folder)));
    r.push(rule("pf_unmanaged_powershell", "PowerShell engine loaded by another program", Prefetch, Execution, "T1059.001", Medium,
        "The program loaded System.Management.Automation, the PowerShell engine, without being PowerShell. Offensive \
         frameworks run PowerShell this way to avoid powershell.exe and its logging.",
        "Loaded files include System.Management.Automation(.ni).dll and the executable isn't powershell.exe, pwsh.exe, \
         powershell_ise.exe or a known Windows PowerShell host.",
        "Management tools and installers that host PowerShell, e.g. Exchange, SCCM and some admin consoles.",
        &["https://attack.mitre.org/techniques/T1059/001/"], Check::Prefetch(pf_unmanaged_powershell)));
    r.push(rule("pf_kerberos_ldap_tool", "Kerberos and LDAP tooling run from a user folder", Prefetch, CredentialAccess, "T1558, T1087.002", High,
        "A .NET program run from a user-writable folder loaded the Kerberos and Active Directory/LDAP libraries together: \
         the footprint of tools like Rubeus and SharpHound even when renamed.",
        "Run from a user-writable folder, and loaded files include the .NET runtime, Kerberos and LDAP/AD libraries.",
        "In-house .NET admin tools run from Downloads or a desktop.",
        &["https://attack.mitre.org/techniques/T1558/", "https://attack.mitre.org/techniques/T1087/002/"],
        Check::Prefetch(pf_kerberos_ldap)));
    r.push(rule("pf_ran_then_deleted", "Program ran, then its executable was deleted", Prefetch, DefenseEvasion, "T1070.004", Medium,
        "Prefetch shows a program ran, but its executable is no longer in the $MFT (or only as a deleted record). \
         Attackers delete their tools after use.",
        "The executable's path, outside \\Windows\\ and \\Program Files, is missing from the loaded $MFT or only deleted. \
         Only for prefetch files from the same machine: the .pf is in that $MFT, or most of its file references match.",
        "Installers and updaters that remove themselves; files deleted by users. Needs the $MFT from the same machine.",
        &["https://attack.mitre.org/techniques/T1070/004/"], Check::PrefetchMft(pf_ran_then_deleted)));

    // ------------------------------------------------------------ $MFT
    r.push(rule("mft_timestomp_zeroed", "Timestomping: executable with $SI set to a whole second", Mft, DefenseEvasion, "T1070.006", Medium,
        "An executable or script's $STANDARD_INFORMATION creation time is earlier than its $FILE_NAME creation time and has no \
         sub-second part. Windows records times to 100 ns; tools that backdate files often write whole seconds.",
        "$SI created < $FN created, and $SI created is an exact second while $FN created is not; Windows' component \
         and package stores, Program Files (installer packages carry whole-second times) and files hard-linked          into WinSxS are left out.",
        "MSI packages that install straight into System32 keep their packages' whole-second times (e.g. the          Visual C++ runtime: concrt140.dll, msvcp140*.dll, mfc140*.dll); files copied from FAT or network shares or          unpacked from archives.",
        &["https://attack.mitre.org/techniques/T1070/006/"], Check::Mft(mft_timestomp_zeroed)));
    r.push(rule("mft_timestomp", "Timestomping: executable with $SI created before $FN created", Mft, DefenseEvasion, "T1070.006", Low,
        "An executable or script's $STANDARD_INFORMATION creation time, which programs can change, is earlier than its \
         $FILE_NAME creation time, which only the file system sets. Backdating a file usually leaves this mismatch.",
        "$SI created < $FN created on an executable or script, outside Program Files and Windows' component and \
         package stores (installers keep their packages' times).",
        "Common for legitimate reasons: archive extraction, installers and copy tools preserve original times.",
        &["https://attack.mitre.org/techniques/T1070/006/"], Check::Mft(mft_timestomp)));
    r.push(rule("mft_motw_executable", "Downloaded executable or script (Mark of the Web)", Mft, InitialAccess, "T1566, T1204.002", Low,
        "An executable or script carries a Zone.Identifier stream: it came from the internet or an email attachment. \
         The stream often records the URL it was downloaded from.",
        "Executable/script extension with a Zone.Identifier alternate data stream; ZoneId and URLs read from the stream.",
        "Any software downloaded with a browser.",
        &["https://attack.mitre.org/techniques/T1566/", "https://attack.mitre.org/techniques/T1204/002/"],
        Check::Mft(mft_motw)));
    r.push(rule("mft_executable_user_folder", "Executable or script in a user-writable folder", Mft, CommandAndControl, "T1105", Low,
        "An executable or script sits in a Downloads folder, on a desktop, in a temp folder, the Public profile, the \
         Recycle Bin, PerfLogs or the root of ProgramData: typical drop locations for attacker tools.",
        "Executable/script extension and one of those folders in the path.",
        "Installers, updaters and portable tools.",
        &["https://attack.mitre.org/techniques/T1105/"], Check::Mft(mft_exec_user_folder)));
    r.push(rule("mft_masquerading", "System program name outside the Windows folder", Mft, DefenseEvasion, "T1036.005", High,
        "A file named like a core Windows process (svchost.exe, lsass.exe, csrss.exe, …) exists outside the \
         Windows folder. Malware uses these names to look harmless.",
        "File name is one of Windows' core processes and its path is not under \\Windows\\.",
        "Backups of Windows, installation media and some security tools' quarantine folders.",
        &["https://attack.mitre.org/techniques/T1036/005/"], Check::Mft(mft_masquerading)));
    r.push(rule("mft_startup_folder", "File in a Startup folder", Mft, Persistence, "T1547.001", Medium,
        "A file sits in a Startup folder: it runs every time a user logs on.",
        "Path contains \\Start Menu\\Programs\\Startup\\ (any user or All Users), except desktop.ini.",
        "Legitimate software that starts with Windows (often a shortcut).",
        &["https://attack.mitre.org/techniques/T1547/001/"], Check::Mft(mft_startup)));
    r.push(rule("mft_executable_ads", "Executable hidden in an alternate data stream", Mft, DefenseEvasion, "T1564.004", Medium,
        "A file has an alternate data stream named like an executable or script. ADS content doesn't show in Explorer \
         or directory listings, a classic way to hide payloads.",
        "An ADS name ends in an executable or script extension.",
        "Very rare.",
        &["https://attack.mitre.org/techniques/T1564/004/"], Check::Mft(mft_exec_ads)));
    r.push(rule("mft_webshell", "Script page in a web server folder", Mft, Persistence, "T1505.003", Low,
        "A server-side script (ASPX, ASHX, ASP, JSP, PHP) sits under inetpub\\wwwroot. Web shells are dropped there to \
         keep remote access to a server.",
        "Path under \\inetpub\\wwwroot\\ with a server-side script extension.",
        "Any web application hosted on this server: check pages that don't belong to it.",
        &["https://attack.mitre.org/techniques/T1505/003/"], Check::Mft(mft_webshell)));
    r.push(rule("mft_lsass_dump", "LSASS memory dump on disk", Mft, CredentialAccess, "T1003.001", High,
        "A memory dump named after LSASS exists. LSASS holds credentials; dumping it is how tools like Mimikatz, \
         ProcDump and comsvcs.dll MiniDump steal passwords and hashes.",
        "A .dmp file whose name contains \"lsass\".",
        "Crash dumps collected by support staff.",
        &["https://attack.mitre.org/techniques/T1003/001/"], Check::Mft(mft_lsass_dump)));
    r.push(rule("mft_ntds_copy", "Copy of the Active Directory database", Mft, CredentialAccess, "T1003.003", High,
        "A file named ntds.dit exists outside \\Windows\\NTDS\\. A copy of the AD database holds every domain password hash.",
        "File named ntds.dit not under \\Windows\\NTDS\\ (or \\Windows\\WinSxS\\ / \\Windows\\System32\\).",
        "Install-from-media (IFM) sets and DC backups.",
        &["https://attack.mitre.org/techniques/T1003/003/"], Check::Mft(mft_ntds_copy)));
    r.push(rule("mft_hive_copy", "Copy of the SAM, SYSTEM or SECURITY registry hive", Mft, CredentialAccess, "T1003.002", High,
        "A file named like the SAM, SYSTEM or SECURITY hive exists outside the registry's own folders. Together they \
         give local account password hashes and cached domain credentials (reg save, shadow copy theft).",
        "File named sam, system, security (or .hiv/.save variants) outside \\Windows\\System32\\config\\ and RegBack.",
        "Backups, forensic collections and registry tools' working copies.",
        &["https://attack.mitre.org/techniques/T1003/002/"], Check::Mft(mft_hive_copy)));
    r.push(rule("mft_kirbi", "Kerberos ticket files on disk", Mft, CredentialAccess, "T1558, T1550.003", High,
        "Exported Kerberos tickets (.kirbi or .ccache) exist. Mimikatz and Rubeus write tickets in these formats for \
         pass-the-ticket.",
        "File extension .kirbi or .ccache.",
        "Very rare on Windows hosts.",
        &["https://attack.mitre.org/techniques/T1558/", "https://attack.mitre.org/techniques/T1550/003/"],
        Check::Mft(mft_kirbi)));

    // ------------------------------------------------------------ journal
    r.push(rule("usn_evtx_deleted", "Event log file deleted", Journal, DefenseEvasion, "T1070.001", High,
        "An event log (.evtx) in the Windows event log folder was deleted, which destroys the record of activity.",
        "FileDelete of a .evtx file under \\winevt\\Logs\\.",
        "Rare: archived logs removed by retention scripts.",
        &["https://attack.mitre.org/techniques/T1070/001/"], Check::Journal(usn_evtx_deleted)));
    r.push(rule("usn_prefetch_wiped", "Many prefetch files deleted at once", Journal, DefenseEvasion, "T1070.004", Medium,
        "Ten or more prefetch files were deleted within a minute. Wiping prefetch removes evidence of what ran.",
        "≥10 FileDelete of .pf files in \\Windows\\Prefetch\\ within 60 seconds.",
        "Windows trims old prefetch files itself, and cleanup tools clear the folder.",
        &["https://attack.mitre.org/techniques/T1070/004/"], Check::Journal(usn_prefetch_wiped)));
    r.push(rule("usn_mass_rename", "Mass rename to one extension (ransomware)", Journal, Impact, "T1486", High,
        "Fifty or more files were renamed to the same new extension within a minute: the pattern of ransomware \
         encrypting files and appending its own extension.",
        "≥50 renames within 60 seconds where the new name is the old name plus the same extra extension \
         (report.docx → report.docx.lockbit), excluding working extensions (tmp, bak, part, …).",
        "Bulk renames by sync or migration tools.",
        &["https://attack.mitre.org/techniques/T1486/"], Check::Journal(usn_mass_rename)));
    r.push(rule("usn_created_deleted", "Executable created and deleted within minutes", Journal, DefenseEvasion, "T1070.004", Medium,
        "An executable or script was created in a user-facing or drop location and deleted again within ten minutes: \
         tools run once and cleaned up.",
        "FileCreate then FileDelete of the same file reference within 10 minutes, executable/script extension, \
         in Downloads, a desktop, Documents, the Public profile, PerfLogs, the root of ProgramData or \\Windows\\.",
        "Installers and updaters that stage and remove helper programs.",
        &["https://attack.mitre.org/techniques/T1070/004/"], Check::Journal(usn_created_deleted)));
    r.push(rule("usn_remote_exec_service", "Remote execution service binary created", Journal, LateralMovement, "T1569.002, T1021.002", High,
        "A service binary used by remote execution tools (PsExec, PAExec, RemCom, CSExec) was written to this machine: \
         someone ran commands on it remotely.",
        "FileCreate of psexesvc.exe, paexec*.exe, remcomsvc.exe or csexecsvc.exe.",
        "Administrators using these tools.",
        &["https://attack.mitre.org/techniques/T1569/002/", "https://attack.mitre.org/techniques/T1021/002/"],
        Check::Journal(usn_remote_exec)));
    r.push(rule("usn_startup_created", "File created in a Startup folder", Journal, Persistence, "T1547.001", Medium,
        "A file was created in a Startup folder, so it runs at every logon.",
        "FileCreate under \\Start Menu\\Programs\\Startup\\, except desktop.ini.",
        "Software adding itself to startup.",
        &["https://attack.mitre.org/techniques/T1547/001/"], Check::Journal(usn_startup)));
    r.push(rule("usn_executable_dropped", "Executable or script created in a user-writable folder", Journal, CommandAndControl, "T1105", Low,
        "An executable or script was created in a Downloads folder, desktop, temp folder, the Public profile, the \
         Recycle Bin, PerfLogs or the root of ProgramData, including ones that were deleted since.",
        "FileCreate with an executable/script extension in one of those folders.",
        "Installers, updaters and browser downloads.",
        &["https://attack.mitre.org/techniques/T1105/"], Check::Journal(usn_exec_dropped)));
    r
}

// ---------------------------------------------------------------- prefetch checks

const CORE_PROCESSES: &[&str] = &[
    "svchost.exe", "lsass.exe", "csrss.exe", "services.exe", "smss.exe", "winlogon.exe", "wininit.exe", "lsm.exe",
    "spoolsv.exe", "taskhostw.exe", "dllhost.exe", "conhost.exe", "rundll32.exe", "explorer.exe", "taskmgr.exe",
];

fn pf_exe_path(pf: &Prefetch) -> Option<String> {
    pf.executable_path().map(|p| prefetch::strip_volume(p).to_lowercase())
}

fn pf_masquerading(pf: &Prefetch) -> Option<String> {
    let exe = pf.executable.to_lowercase();
    let path = pf_exe_path(pf)?;
    (CORE_PROCESSES.contains(&exe.as_str()) && !path.starts_with("\\windows\\")).then(|| runs(pf))
}

fn pf_user_folder(pf: &Prefetch) -> Option<String> {
    let path = pf_exe_path(pf)?;
    user_writable(&path).map(|w| format!("{} · in {w}", runs(pf)))
}

fn pf_unmanaged_powershell(pf: &Prefetch) -> Option<String> {
    const HOSTS: &[&str] = &[
        "POWERSHELL.EXE", "PWSH.EXE", "POWERSHELL_ISE.EXE", "WSMPROVHOST.EXE", "SDIAGNHOST.EXE", "MSDT.EXE",
        "SERVERMANAGER.EXE", "MMC.EXE", "WMIPRVSE.EXE", "COMPATTELRUNNER.EXE", "DSMUSERTASK.EXE",
    ];
    let loads = pf.files.iter().any(|f| {
        let n = f.filename.rsplit('\\').next().unwrap_or("").to_uppercase();
        n == "SYSTEM.MANAGEMENT.AUTOMATION.DLL" || n == "SYSTEM.MANAGEMENT.AUTOMATION.NI.DLL"
    });
    (loads && !HOSTS.contains(&pf.executable.to_uppercase().as_str())).then(|| runs(pf))
}

fn pf_kerberos_ldap(pf: &Prefetch) -> Option<String> {
    let path = pf_exe_path(pf)?;
    user_writable(&path)?;
    let caps: Vec<&str> = pf.capabilities().into_iter().map(|(c, _)| c).collect();
    let needed = [".NET runtime", "Kerberos / authentication", "Active Directory / LDAP"];
    needed.iter().all(|c| caps.contains(c)).then(|| format!("{} · loads .NET, Kerberos and LDAP libraries", runs(pf)))
}

/// Whether a prefetch file comes from the machine the `$MFT` does: the `.pf`
/// itself is in its Prefetch folder, or most of the file references it
/// recorded point at matching records.
fn same_system(pf: &Prefetch, name: &str, idx: &MftIndex) -> bool {
    if idx.paths.contains_key(&format!("\\windows\\prefetch\\{}", name.to_lowercase())) {
        return true;
    }
    let refs: Vec<_> = pf.files.iter().filter_map(|f| f.file_reference.filter(|r| !r.is_empty())).collect();
    let matching = refs
        .iter()
        .filter(|r| idx.file.entries.get(r.entry() as usize).is_some_and(|e| e.valid && e.sequence == r.sequence()))
        .count();
    !refs.is_empty() && matching * 2 >= refs.len()
}

fn pf_ran_then_deleted(pf: &Prefetch, name: &str, idx: &MftIndex) -> Option<String> {
    if !same_system(pf, name, idx) {
        return None;
    }
    let path = pf_exe_path(pf)?;
    if path.starts_with("\\windows\\") || path.starts_with("\\program files") {
        return None;
    }
    match idx.paths.get(&path) {
        Some(&r) if idx.file.entries[r as usize].in_use => None,
        Some(&r) => Some(format!("{} · only a deleted record left (#{r})", runs(pf))),
        None => Some(format!("{} · not in the $MFT", runs(pf))),
    }
}

// ---------------------------------------------------------------- $MFT checks

fn files(m: &MftFile) -> impl Iterator<Item = &mft::Entry> {
    m.entries.iter().filter(|e| e.valid && e.has_fn && !e.is_dir && e.base_record == 0)
}

fn mft_hit(e: &mft::Entry, detail: String) -> Hit {
    Hit { target: Target::Mft(e.record as u32), detail }
}

/// Windows' own component and package stores, whose files keep the times
/// they were built with.
fn package_store(path_lc: &str) -> bool {
    const STORES: &[&str] = &[
        "\\windows\\winsxs\\",
        "\\windows\\softwaredistribution\\",
        "\\windows\\servicing\\",
        "\\windows\\installer\\",
        "\\windows\\assembly\\",
        "\\windows\\microsoft.net\\",
        "\\windows\\systemapps\\",
        "\\windows\\immersivecontrolpanel\\",
        "\\program files\\windowsapps\\",
        "\\windows\\system32\\driverstore\\",
        "\\$windows.~bt\\",
        "\\$winreagent\\",
    ];
    STORES.iter().any(|s| path_lc.starts_with(s))
}

/// Installed programs keep the timestamps their installer packages carry
/// (whole seconds and older than the install), so timestomp rules skip them.
fn installed_software(path_lc: &str) -> bool {
    path_lc.starts_with("\\program files") || package_store(path_lc)
}

fn timestomp_candidate(e: &mft::Entry) -> bool {
    e.timestomp_suspect()
        && is_executable(&e.name_lc)
        && !e.path_lc.is_empty()
        && !installed_software(&e.path_lc)
        // Hard-linked into the component store: Windows servicing put it there.
        && !e.links.iter().any(|l| l.path.to_lowercase().starts_with("\\windows\\winsxs\\"))
}

fn mft_timestomp(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m).filter(|e| timestomp_candidate(e)) {
        h.push(mft_hit(e, format!("{} · $SI created {} < $FN created {}", with_path(e), ft(e.si.created), ft(e.fn_times.created))));
    }
}

fn mft_timestomp_zeroed(m: &MftFile, h: &mut Vec<Hit>) {
    const SECOND: u64 = 10_000_000;
    for e in files(m).filter(|e| {
        timestomp_candidate(e) && e.si.created % SECOND == 0 && e.fn_times.created % SECOND != 0
    }) {
        h.push(mft_hit(e, format!("{} · $SI created {} (exact second) < $FN created {}", with_path(e), ft(e.si.created), ft(e.fn_times.created))));
    }
}

/// The ZoneId and URLs recorded in a file's resident Zone.Identifier stream.
fn zone_identifier(m: &MftFile, record: usize) -> Option<String> {
    let recs = m.file_records(record);
    let data = recs.iter().find_map(|r| {
        r.attributes
            .iter()
            .find(|a| a.type_code == mft::ATTR_DATA && a.name.eq_ignore_ascii_case("Zone.Identifier"))
            .and_then(|a| a.resident_content(&r.data))
    })?;
    let text = String::from_utf8_lossy(&data[..data.len().min(4096)]);
    let fields: Vec<String> = text
        .lines()
        .filter_map(|l| {
            let (k, v) = l.split_once('=')?;
            matches!(k.trim(), "ZoneId" | "HostUrl" | "ReferrerUrl").then(|| format!("{}={}", k.trim(), v.trim()))
        })
        .collect();
    (!fields.is_empty()).then(|| fields.join(", "))
}

fn mft_motw(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if is_executable(&e.name_lc) && e.ads.iter().any(|a| a.eq_ignore_ascii_case("Zone.Identifier")) {
            let zone = zone_identifier(m, e.record as usize).unwrap_or_else(|| "Zone.Identifier present".into());
            h.push(mft_hit(e, format!("{} · {zone}", with_path(e))));
        }
    }
}

fn mft_exec_user_folder(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if is_executable(&e.name_lc)
            && !routine_temp_file(&e.name_lc)
            && let Some(w) = user_writable(&e.path_lc)
        {
            h.push(mft_hit(e, format!("{} · in {w}{}", with_path(e), if e.in_use { "" } else { " (deleted)" })));
        }
    }
}

fn mft_masquerading(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if CORE_PROCESSES.contains(&e.name_lc.as_str()) && !e.path_lc.starts_with("\\windows\\") && !e.path_lc.is_empty() {
            h.push(mft_hit(e, with_path(e)));
        }
    }
}

fn mft_startup(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if e.path_lc.contains("\\start menu\\programs\\startup\\") && e.name_lc != "desktop.ini" {
            h.push(mft_hit(e, format!("{}{}", with_path(e), if e.in_use { "" } else { " (deleted)" })));
        }
    }
}

fn mft_exec_ads(m: &MftFile, h: &mut Vec<Hit>) {
    for e in m.entries.iter().filter(|e| e.valid && e.base_record == 0) {
        for a in &e.ads {
            if is_executable(&a.to_lowercase()) {
                h.push(mft_hit(e, format!("{}:{a}", with_path(e))));
            }
        }
    }
}

fn mft_webshell(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if e.path_lc.contains("\\inetpub\\wwwroot\\") && matches!(ext(&e.name_lc), "aspx" | "ashx" | "asmx" | "asp" | "jsp" | "jspx" | "php") {
            h.push(mft_hit(e, with_path(e)));
        }
    }
}

fn mft_lsass_dump(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if e.name_lc.contains("lsass") && ext(&e.name_lc) == "dmp" {
            h.push(mft_hit(e, format!("{} · {} bytes", with_path(e), e.size)));
        }
    }
}

fn mft_ntds_copy(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        let p = &e.path_lc;
        if e.name_lc == "ntds.dit" && !p.starts_with("\\windows\\ntds\\") && !p.starts_with("\\windows\\winsxs\\") && !p.starts_with("\\windows\\system32\\") {
            h.push(mft_hit(e, format!("{} · {} bytes", with_path(e), e.size)));
        }
    }
}

fn mft_hive_copy(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        let stem = e.name_lc.trim_end_matches(".hiv").trim_end_matches(".save").trim_end_matches(".bak");
        let p = &e.path_lc;
        if matches!(stem, "sam" | "system" | "security")
            && e.size > 0
            && !p.starts_with("\\windows\\system32\\config\\")
            && !p.starts_with("\\windows\\winsxs\\")
            && !p.starts_with("\\windows\\servicing\\")
            && !p.contains("\\regback\\")
        {
            h.push(mft_hit(e, format!("{} · {} bytes", with_path(e), e.size)));
        }
    }
}

fn mft_kirbi(m: &MftFile, h: &mut Vec<Hit>) {
    for e in files(m) {
        if matches!(ext(&e.name_lc), "kirbi" | "ccache") {
            h.push(mft_hit(e, with_path(e)));
        }
    }
}

// ---------------------------------------------------------------- journal checks

const FT_SECOND: u64 = 10_000_000;

fn j_hit(i: usize, detail: String) -> Hit {
    Hit { target: Target::Journal(i as u32), detail }
}

fn usn_evtx_deleted(j: &UsnJournal, h: &mut Vec<Hit>) {
    for (i, r) in j.records.iter().enumerate() {
        let (lc, shown) = journal_path(r);
        if r.reason & usn::REASON_FILE_DELETE != 0 && ext(&r.name_lc) == "evtx" && (lc.contains("\\winevt\\logs\\") || !lc.contains('\\')) {
            h.push(j_hit(i, format!("{shown} · deleted {}", ft(r.timestamp))));
        }
    }
}

/// Flags every record in groups where at least `min` records with the same
/// key fall within `window` (FILETIME units) of the group's first one.
fn bursts(j: &UsnJournal, min: usize, window: u64, key: impl Fn(usize, &usn::UsnRecord) -> Option<String>, h: &mut Vec<Hit>, describe: impl Fn(&str, usize) -> String) {
    let mut groups: HashMap<String, Vec<usize>> = HashMap::new();
    for (i, r) in j.records.iter().enumerate() {
        if let Some(k) = key(i, r) {
            groups.entry(k).or_default().push(i);
        }
    }
    let mut keys: Vec<_> = groups.into_iter().collect();
    keys.sort();
    for (k, mut idx) in keys {
        idx.sort_by_key(|&i| j.records[i].timestamp);
        let mut start = 0;
        let mut flagged = vec![false; idx.len()];
        for end in 0..idx.len() {
            while j.records[idx[end]].timestamp.saturating_sub(j.records[idx[start]].timestamp) > window {
                start += 1;
            }
            if end - start + 1 >= min {
                flagged[start..=end].iter_mut().for_each(|f| *f = true);
            }
        }
        let n = flagged.iter().filter(|&&f| f).count();
        for (pos, &i) in idx.iter().enumerate() {
            if flagged[pos] {
                let (_, shown) = journal_path(&j.records[i]);
                h.push(j_hit(i, format!("{shown} · {}", describe(&k, n))));
            }
        }
    }
}

fn usn_prefetch_wiped(j: &UsnJournal, h: &mut Vec<Hit>) {
    bursts(
        j,
        10,
        60 * FT_SECOND,
        |_, r| {
            let (lc, _) = journal_path(r);
            (r.reason & usn::REASON_FILE_DELETE != 0 && ext(&r.name_lc) == "pf" && (lc.contains("\\prefetch\\") || !lc.contains('\\')))
                .then(|| "pf".to_string())
        },
        h,
        |_, n| format!("one of {n} prefetch deletions in bursts"),
    );
}

fn usn_mass_rename(j: &UsnJournal, h: &mut Vec<Hit>) {
    const COMMON: &[&str] = &["tmp", "temp", "log", "bak", "old", "etl", "dat", "partial", "crdownload", "part", "aux", "new", "lock"];
    // A rename is logged as the old name, then the new one, for the same file.
    let mut old_names: HashMap<(u64, u16), &str> = HashMap::new();
    let mut appended: HashMap<usize, String> = HashMap::new();
    for (i, r) in j.records.iter().enumerate() {
        let key = (r.file_record, r.file_seq);
        if r.reason & 0x1000 != 0 {
            old_names.insert(key, &r.name_lc);
        } else if r.reason & 0x2000 != 0
            && let Some(old) = old_names.get(&key)
            && let Some(added) = r.name_lc.strip_prefix(*old).and_then(|rest| rest.strip_prefix('.'))
            && !added.is_empty()
            && added.len() <= 24
            && !added.contains('.')
            && !COMMON.contains(&added)
        {
            appended.insert(i, added.to_string());
        }
    }
    bursts(j, 50, 60 * FT_SECOND, |i, _| appended.get(&i).cloned(), h, |k, n| {
        format!("{n} files renamed by appending .{k}")
    });
}

fn usn_created_deleted(j: &UsnJournal, h: &mut Vec<Hit>) {
    let drop_dir = |lc: &str| {
        ["\\downloads\\", "\\desktop\\", "\\documents\\", "\\users\\public\\", "\\perflogs\\"].iter().any(|d| lc.contains(d))
            || lc.strip_prefix("\\windows\\").is_some_and(|rest| !rest.contains('\\'))
            || lc.strip_prefix("\\programdata\\").is_some_and(|rest| !rest.contains('\\'))
    };
    let mut created: HashMap<(u64, u16), usize> = HashMap::new();
    for (i, r) in j.records.iter().enumerate() {
        let key = (r.file_record, r.file_seq);
        if r.reason & usn::REASON_FILE_CREATE != 0 && is_executable(&r.name_lc) {
            created.entry(key).or_insert(i);
        }
        if r.reason & usn::REASON_FILE_DELETE != 0
            && let Some(&c) = created.get(&key)
        {
            let cr = &j.records[c];
            let (lc, shown) = journal_path(r);
            if r.timestamp.saturating_sub(cr.timestamp) <= 600 * FT_SECOND && drop_dir(lc) {
                let secs = r.timestamp.saturating_sub(cr.timestamp) / FT_SECOND;
                h.push(j_hit(i, format!("{shown} · created {} and deleted {secs} s later", ft(cr.timestamp))));
            }
            created.remove(&key);
        }
    }
}

fn usn_remote_exec(j: &UsnJournal, h: &mut Vec<Hit>) {
    for (i, r) in j.records.iter().enumerate() {
        let n = r.name_lc.as_str();
        if r.reason & usn::REASON_FILE_CREATE != 0
            && (n == "psexesvc.exe" || n == "remcomsvc.exe" || n == "csexecsvc.exe" || (n.starts_with("paexec") && n.ends_with(".exe")))
        {
            let (_, shown) = journal_path(r);
            h.push(j_hit(i, format!("{shown} · created {}", ft(r.timestamp))));
        }
    }
}

fn usn_startup(j: &UsnJournal, h: &mut Vec<Hit>) {
    for (i, r) in j.records.iter().enumerate() {
        let (lc, shown) = journal_path(r);
        if r.reason & usn::REASON_FILE_CREATE != 0 && lc.contains("\\start menu\\programs\\startup\\") && r.name_lc != "desktop.ini" {
            h.push(j_hit(i, format!("{shown} · created {}", ft(r.timestamp))));
        }
    }
}

fn usn_exec_dropped(j: &UsnJournal, h: &mut Vec<Hit>) {
    for (i, r) in j.records.iter().enumerate() {
        let (lc, shown) = journal_path(r);
        if r.reason & usn::REASON_FILE_CREATE != 0
            && is_executable(&r.name_lc)
            && !routine_temp_file(&r.name_lc)
            && let Some(w) = user_writable(lc)
        {
            h.push(j_hit(i, format!("{shown} · created {} in {w}", ft(r.timestamp))));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_are_well_formed() {
        let rules = rules();
        let mut ids = std::collections::HashSet::new();
        for r in &rules {
            assert!(ids.insert(r.id.clone()), "duplicate rule id {}", r.id);
            assert!(!r.description.is_empty() && !r.logic.is_empty() && !r.false_positives.is_empty(), "{}", r.id);
            for t in r.mitre.split(',').map(str::trim) {
                let ok = t.starts_with('T')
                    && t[1..].split('.').enumerate().all(|(i, p)| p.len() == if i == 0 { 4 } else { 3 } && p.bytes().all(|b| b.is_ascii_digit()));
                assert!(ok, "{}: bad technique {t:?}", r.id);
            }
            assert!(!r.references.is_empty() && r.references.iter().all(|u| u.starts_with("https://")), "{}", r.id);
        }
    }

    #[test]
    fn user_writable_folders() {
        assert!(user_writable("\\users\\bob\\downloads\\x.exe").is_some());
        assert!(user_writable("\\programdata\\evil.exe").is_some());
        assert!(user_writable("\\programdata\\microsoft\\x.exe").is_none());
        assert!(user_writable("\\windows\\system32\\x.exe").is_none());
    }

    #[test]
    fn burst_detection() {
        let mut j = UsnJournal { raw: Vec::new(), records: Vec::new(), skipped_bytes: 0 };
        let mk = |name: &str, file: u64, t: u64, reason: u32| usn::UsnRecord {
            name: name.into(),
            name_lc: name.to_lowercase(),
            file_record: file,
            timestamp: t,
            reason,
            ..Default::default()
        };
        // Ransomware: 60 files get ".lockbit" appended within half a minute.
        for i in 0..60 {
            let t = 1_000 * FT_SECOND + i * FT_SECOND / 2;
            j.records.push(mk(&format!("doc{i}.docx"), i, t, 0x1000));
            j.records.push(mk(&format!("doc{i}.docx.lockbit"), i, t, 0x2000));
        }
        // The same, spread over ten minutes: not a burst.
        for i in 0..60 {
            let t = 1_000 * FT_SECOND + i * 10 * FT_SECOND;
            j.records.push(mk(&format!("note{i}.txt"), 100 + i, t, 0x1000));
            j.records.push(mk(&format!("note{i}.txt.slow"), 100 + i, t, 0x2000));
        }
        // Renamed to an unrelated name with a new extension: no extension appended.
        for i in 0..60 {
            let t = 2_000 * FT_SECOND + i * FT_SECOND / 2;
            j.records.push(mk(&format!("tmp{i}.dll"), 200 + i, t, 0x1000));
            j.records.push(mk(&format!("final{i}.weird"), 200 + i, t, 0x2000));
        }
        let mut h = Vec::new();
        usn_mass_rename(&j, &mut h);
        assert_eq!(h.len(), 60, "only the burst within a minute");
        assert!(h[0].detail.contains(".lockbit"));
    }
}
