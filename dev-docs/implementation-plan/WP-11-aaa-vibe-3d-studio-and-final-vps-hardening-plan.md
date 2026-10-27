# WP-11 (P0): AAA Film-Level VibeScript 3D Asset & UI/UX Studio + Final Internet-Facing VPS Protocol Hardening

**Work Package ID:** `WP-11`  
**Priority:** `P0` (Complete AAA VibeScript 3D/UX Studio + Final Production VPS Protocol Closure)  
**Depends On:** [`WP-01`](./WP-01-large-ontology-streaming-compiler.md)–[`WP-10`](./WP-10-full-vps-readiness-and-live-control-plane-plan.md)  
**Target Repositories:** `C:\github\webizen-host` & `C:\github\qualiaDB\crates\vibe`

---

## 1. Comprehensive To-Do List of Remaining VPS & AAA UI/UX / 3D Studio Deliverables

### Swarm A — VibeScript 3D Procedural Asset & Scene Production Engine (`crates/webizen-host-workbench/src/vibe_3d_studio.rs`)
- [x] **D11.1 — 3D Procedural Mesh & 10D Manifold Scene Generator (`Vibe3dAssetForge`)**:
  - Link directly to `vibe::animation` (`AnimationFamily`, `evaluate_preset`, `list_all_presets`, 3D Projective Geometric Algebra $\mathcal{G}_{3,0,1}$ `Motor`, `MotorBivector`, `SpringConfig`, `SpringState3D`, `Quat` SQUAD splines) and `vibe::physics` (`MaterialSignature`, `FieldDeclaration`, `ContinuantState`, `evaluate_field_interactions`, `WorldLineTrajectory`).
  - Generate procedural 3D meshes (`GeodesicManifoldDome`, `TorusKnotQuantumCore`, `CrystalLatticeSpire`, `OrbitalStewardshipRing`) with 3D vertices, normals, faces, and edges transformed by real PGA `Motor` ScLERP poses and `SpringState3D` dynamics.
- [x] **D11.2 — AAA Film-Level Volumetric SVG Viewport Renderer & `QBDL` `.hmc` 3D Asset Packager**:
  - Render any `Vibe3dSceneSpec` into a high-contrast, depth-sorted, rim-lit volumetric SVG viewport (`render_aaa_3d_viewport_svg`) featuring `<feSpecularLighting>`, `<feGaussianBlur>` bloom, chromatic aberration auras, PBR material shaders (`ObsidianGlass`, `BioluminescentPlasma`, `BrushedTitanium`, `CrystallineQuartz`), 3D camera frustum telemetry HUD, and CSS keyframe animation tracks derived from `vibe::animation::evaluate_preset`.
  - Package the 3D mesh geometry, PBR `MaterialSignature` records, `vibe` animation track samples, and rendered SVG viewport into a 64-byte page-aligned `QBDL` `.hmc` bundle (`<data_dir>/studio/<scene_id>.hmc`) + W3C CBOR-LD receipt (`<data_dir>/studio/<scene_id>.cbor-ld`), and automatically publish it to IPFS (`/ipfs/<cid>`) and WebTorrent WebSeed (`/torrent/webseed/<scene_id>.hmc`).

### Swarm B — Complete VibeScript UI/UX Design Toolkit & Multi-Modal Presentation Sheaf Studio (`crates/webizen-host-workbench/src/vibe_ux_toolkit.rs`)
- [x] **D11.3 — VibeScript Composite UI Controls, 2D Flex Layout Solver & Projectional AST Editor Bridge (`VibeUiUxToolkit`)**:
  - Invoke `vibe::web_runtime::call_web_or_ui` to drive the full suite of VibeScript v0.02 UI/UX controls on the server:
    - Composite uplift widgets: `ui.range_interval`, `ui.tag_input`, `ui.combobox`, `ui.tree_select`, `ui.transfer_list`, `ui.projectional_editor` (with binary CBOR AST Tag `0xD90502`), and `ui.dag_canvas`.
    - Form & validation engine: `form.to_cbor_ld`, `form.sign_submission`, 11-flag `ValidityState`, and Belnap/$E_\tau$ paraconsistent conflict isolation.
- [x] **D11.4 — Multi-Modal Presentation Sheaf Compiler (`Visual` + `Haptic` + `Auditory` + `Braille`)**:
  - Use `vibe::presentation::{Presentation, PresentationKind, PresentationModality, PresentationSheaf}` to compile UI components into globally consistent 4-modality sheaves:
    1. `Visual`: AAA glassmorphic CSS/SVG tokens + `vibe::animation::AnimationFamily::HudGlassUi` (`glass_reveal`, `chroma_pulse`, `aura_glow`).
    2. `Haptic`: Tactile force/vibration envelope (`OutboundHaptics`).
    3. `Auditory`: Spatial earcon & speech synthesis cues (`AcousticSpectral`).
    4. `Braille`: Refreshable Unicode Braille cell array (`U+2800..U+28FF`) guaranteeing international human-rights accessibility compliance.
  - Persist compiled UI/UX sheaves to `<data_dir>/ux/<component_id>.cbor-ld` (`0xD9 0x05 0x01`).

### Swarm C — AAA Film-Level Epic Holographic Control Panel & 12-Module Studio UI (`assets/index.html`, `persona_ui.rs`, `webizen_host_adaptive_ui.html`)
- [x] **D11.5 — Expand Control Panel to 12 Modules with AAA Film-Level Holographic Design System**:
  - Add Module 11 (`#page-studio-3d` — **3D Asset & Scene Forge (`Vibe 3D + QBDL .hmc`)**) and Module 12 (`#page-vibe-ux` — **VibeScript UI/UX & Multi-Modal Sheaf Studio**) to `ControlPanelPage` in `persona_ui.rs` and `assets/index.html`.
  - Upgrade `assets/index.html` and `webizen_host_adaptive_ui.html` (maintaining 100% Zero-JavaScript `script-src 'none'`, zero `<script>` JS tags, zero `on*=` attributes) with:
    - **AAA Film-Level Volumetric 3D Viewport** (embedded depth-sorted geodesic manifold & orbital torus-knot SVG with `<feGaussianBlur>` bloom, `<feSpecularLighting>`, CSS3D perspective camera rig, and interactive pure-CSS `:checked` camera angle / PBR shader / animation family switchers).
    - **Interactive Multi-Track Animation Timeline & Keyframe Scrubber** (10 VibeScript Animation Families: `SpatialKinematics`, `PhysicalDynamics`, `MeshTopology`, `ThermodynamicPhase`, `OpticsWaves`, `AcousticSpectral`, `MultiTrackTimelines`, `HudGlassUi`, `OutboundHaptics`, `GenerativeFields`).
    - **Interactive VibeScript UI/UX Widget & Presentation Sheaf Workbench** (Projectional AST Editor, Node-Wire DAG Canvas, Interval Slider, Fuzzy Combobox, Belnap Paraconsistent Validator, and live 4-Modality `Visual / Haptic / Auditory / Braille` Sheaf Inspector).
    - Native HTML `<form method="post" action="/cpanel/studio/forge-3d">` and `<form method="post" action="/cpanel/ux/compile-sheaf">` controls.

### Swarm D — Final Internet-Facing VPS Protocol Hardening (`http_daemon.rs`, `lib.rs`, `webizen-hostd.rs`)
- [x] **D11.6 — Live RFC 8484 DNS-over-HTTPS (`GET/POST /dns-query`) & Live RFC 8555 ACME `HTTP-01` (`GET /.well-known/acme-challenge/<token>`)**:
  - Serve binary RFC 1035 DNS packets over HTTPS (`Content-Type: application/dns-message`) at `/dns-query` backed by the live `NQuinDnsZoneRing` and `QPolicy` split-horizon firewall.
  - Serve live ACME `HTTP-01` key-authorization tokens (`text/plain`) at `/.well-known/acme-challenge/<token>` using `AcmeChallengeManager`.
- [x] **D11.7 — Live Mode-B Desktop Pairing & Sanctuary Keep Encrypted Backup/Restore (`POST /peer/pair`, `POST /sanctuary/backup`, `POST /sanctuary/recover`)**:
  - Enable `:8080` ↔ `:4242` pairing and client-encrypted ChaCha20-Poly1305 `.q42j` Sanctuary Keep backup storage + $M$-of-$N$ $\text{GF}(2^8)$ Shamir share verification over HTTP without exposing plaintext keys to the VPS.
- [x] **D11.8 — Live Commercial `HTTP 402` Toll Gate & Settlement (`POST /commons/settle`), Steward Auth Login (`POST /cpanel/auth/login`), Live 3D/UX Studio Routes (`GET /studio/viewport.svg`, `POST /cpanel/studio/forge-3d`, `POST /cpanel/ux/compile-sheaf`), Telemetry (`GET /healthz`, `GET /metrics`), & 16-Point `--verify-vps-readiness`**:
  - Wire `IpRateLimiterRing` (`HTTP 429` on burst), `StewardSessionGuard` (`POST /cpanel/auth/login` issuing `Set-Cookie: DNI_SESSION=...`), `GET /healthz`, `GET /metrics`, `POST /commons/settle`, `GET /studio/viewport.svg`, `POST /cpanel/studio/forge-3d`, and `POST /cpanel/ux/compile-sheaf` into `http_daemon.rs`.
  - Upgrade `WebizenHostDaemon::verify_full_vps_readiness` to verify all **16 end-to-end production checks** (including DoH `/dns-query`, ACME `HTTP-01`, Sanctuary Keep backup/restore, `GET /studio/viewport.svg` 3D rendering, `POST /cpanel/studio/forge-3d` `.hmc` packaging, and `POST /cpanel/ux/compile-sheaf` 4-modality sheaf compilation).
