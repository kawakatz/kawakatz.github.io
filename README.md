# kawakatz.io

Source for kawakatz.io. Jekyll owns the Markdown content and static URLs. Three.js renders the homepage desk and cutaway room, with static lighting baked offline in Blender/Cycles.

## Usage

Requires Node.js 22 or newer, Ruby 3.3 or newer, Bundler, Poppler, and ImageMagick. On macOS, install the preview tools with `brew install poppler imagemagick`; on Ubuntu, use `sudo apt-get install poppler-utils imagemagick fonts-noto-cjk`. The static preview command uses Python 3; the optional scene authoring tools have separate requirements below.

```sh
npm ci
bundle install
npm run dev
```

Open http://127.0.0.1:4173/. Jekyll watches content and CSS. After editing browser JavaScript, run `npm run assets` in a second terminal and reload the page. Geometry and lighting changes also need the scene rebuild described below.

On macOS, if the system Ruby is selected, prepend an installed Homebrew Ruby before running the commands:

```sh
export PATH="$(brew --prefix ruby@3.4)/bin:$PATH"
```

Source modules and scene-authoring inputs stay in the repository for maintenance; the published site excludes them. The public Three.js license notice is retained.

To check and preview a production build:

```sh
npm test
npm run preview
```

## Writing notes

Add `_posts/YYYY-MM-DD-slug.md`. Existing articles and image/PDF assets were copied without changing their contents. Article URLs remain `/notes/slug/`.

```yaml
---
layout: post
title: My new note
description: A short description of the note
date: 2026-09-09 18:00:00 +0900
image:
  path: /assets/img/my-new-note/cover.png
---
```

Write ordinary Markdown below the front matter, with `##` and `###` headings. The article list, full-text search index, reading time, and RSS update at build time. The on-page outline is generated from the article headings. Use `last_modified_at` in front matter when an explicit update date is needed; otherwise the existing post-update hook reads Git history when a repository exists. Imported update dates are retained in `_data/post_updated.json` as a fallback when Git history has no date for a post.

Images and PDFs stay in `assets/img` and `assets/pdf`. Add optional `image.alt` text for list thumbnails. Update `_tabs/others.md` for the existing `/others/` page. `_drafts` and Jekyll's `--drafts` flag are available for unpublished writing.

Others links in `.work-entry` paragraphs automatically get hover previews during any Jekyll build. `_plugins/others-previews.rb` renders the first page of PDFs or retrieves a link's Open Graph/Twitter image, then creates a small local WebP. No image paths need to be maintained in Markdown. The ignored `.jekyll-cache/others-previews` folder caches results; PDFs refresh when their contents change, and web links refresh after one day. Remove that cache to force a refresh. GitHub Actions also restores this cache. If retrieval fails, the last cached image remains available, or the preview shows text only; the next build retries the download. Only the generated images under `_site/assets/img/previews` are published; visitors load them on demand without contacting the linked sites.

## Design and interaction

- Natural oak and white COFO desk, curved Dell monitor, diagonally placed Mouse Computer laptop, central MacBook aligned with the ultrawide monitor, right iPad, black mesh chair, and a zero-sugar Monster Ultra Fantasy Ruby Red can beside the MacBook, with a translucent, hollow 250 × 6 mm flexible straw carrying pink longitudinal stripes and leaning toward the chair
- The chair faces the desk on the same centerline, with its seat and lowered armrests tucked below the desktop without intersecting it; height controls sit on the left; SSDs are omitted
- The default Screen view frames the displays from world `[-0.25245, 0.98, 1.4]` m with a 17.797° lens aimed horizontally at `[-0.25245, 0.98, -0.25]`. This starts at the previous one-step zoom with a slightly higher aim; narrow screens retain the MacBook width fit. A 1.15 m near plane excludes the foreground chair; Mouse, iPad, and Notes inspection use a 0.1 m near plane; Dell uses a frontal view with its near plane 20 mm ahead of the closest curved screen edge to exclude foreground laptops. Both camera and clipping distance interpolate during transitions. The seated screen view is the only overview
- Drag to turn the camera direction from a fixed seated position. Use the wheel or the − / ＋ controls for lens zoom. Screen view, Mouse, and iPad support 0.8–4×; the Dell close-up initially fits its height between the controls and footer, and limits zoom to 5120 CSS pixels across the complete, partly cropped display. Dell close-up dragging pans parallel to its screen, preserving the frontal angle; other close-ups turn the viewing direction inside the display.
- Select the MacBook display or the centered “Explore notes ↗” cue to open Notes through the screen transition. Hovering anywhere in the display’s click area enlarges the cue and reveals a light ring; keyboard focus gives the same feedback
- Select a display or use the keyboard-accessible Inspect screens menu: Dell U4919DW, MouseComputer MB-K690, or iPad Air MUUQ2J/A. Back to desk or Escape restores the previous view
- Select an article in the MacBook menu to read its ordinary HTML page; Back to desk or Escape reverses the camera movement
- The MacBook menu follows published posts at build time, just like the notebook
- The homepage has no separate Recent notes list; the site footer contains only the copyright line
- Direct article links, Notes, and Search bypass the camera transition
- On the homepage, touch-capable screens with a short side of 600 CSS pixels or less go directly to Notes before the desk bundle loads. The screen-based check works in either orientation; ordinary desktop window resizing does not trigger it
- Reduced-motion preferences disable the entrance/navigation animations and pause screen motion; there is no public Pause screens control
- Local screen animation stops when paused, outside the viewport, in a hidden tab, or after WebGL context loss. The iPad YouTube player runs independently and is not paused by site visibility changes. An otherwise settled scene renders only when an update is needed; the desk clock updates once a second
- WebGL failure leaves the article links and the complete notebook available

Equipment geometry lives in `assets/js/workstation.js`; the cutaway room, bed, and fabric shapes live in `assets/js/room.js`. `tools/export-scene.mjs` exports the geometry for `tools/bake-scene.py`. The [MacBook Pro 14](https://support.apple.com/en-us/117736), [Mouse K690](https://www.mouse-jp.co.jp/contents/other/company/news/2018/pdf/company_news_2018_news_20180525_01.pdf), and [iPad Air 3](https://support.apple.com/en-us/111939) use their published dimensions, distinct chassis profiles, lids, glass, bezels, and display proportions. The MacBook opening and hinge clearance are modelled in its shell. Its lid is opened to 120 degrees for a clearer seated view, following the owner’s later preference for appearance over measured height. The forward left USB-C port holds a [YubiKey 5C Nano](https://docs.yubico.com/hardware/yubikey/datasheet/_static/YubiKey_technical_data_sheet.pdf), with its small black head and gold strip exposed. The rear port connects to the TS4 through a smooth CalDigit cable that passes left of the dock, hangs with slack behind the desk, then enters its rear [Computer port](https://downloads.caldigit.com/TS4/CalDigit_TS4_Manual.pdf). The cable wordmark’s baseline faces the desk back, matching the owner’s plug orientation; plug and cable proportions follow the supplied photos. Mouse has a dark pentagonal power button with a white illuminated symbol, two yellow-green front-left status lights, a tapered front edge, hinge gap, trackpad buttons, and a smooth lower bezel wordmark. The iPad has a curved aluminum back with a separate glass edge and rests in the low, six-slot [Yamazaki tower 5274](https://www.yamajitsu.co.jp/products/241913) rack. The clock is displayed at 90% scale above the CalDigit dock and turns 13° right, close to facing the default camera; both sit at the rear of the desk, clear of the Mouse PC and Dell base. Its 9 mm front carrier retains the side controls on shallow rear wings; a single 33 mm-deep central housing narrows toward the battery cap with curved top shoulders. The snooze button follows the front top edge. The LCD and front lettering retain their original geometry. Its dark rear shell follows the owner’s side and rear photographs: a tapered housing, raised center, stepped battery door and latch, four screw mounts, left adjustment/alarm controls, right SET/WAVE/MONITOR/RESET controls, and grouped side/rear vents. The white reference supplies shape only; the front face and black finish are retained. The COFO height-control panel is mounted under the left front edge, with a dark display, COFO wordmark, three paired button columns (up/down, 1/2, 3/m), and a rounded right end following the owner’s close-up reference. Keyboard geometry and white rendered legends share `assets/js/keyboard.js`: a 78-key US ANSI Mac layout with function symbols and Touch ID, and a 105-key Japanese Mouse layout with blue Fn markings. These remain approximations; the Mouse specification lists 107 keys. Hardware, the bed, and the decorative can wrap are authored approximations, not manufacturer CAD models. The can follows the supplied English Ruby Red package references, including the dark lid, pink pull tab, and side characters. The silver claw follows the official flat Ruby Red mark.

The surrounding room retains its cutaway walls, floor-height window, curtains, wooden floor, and a bed behind the chair with space between them. The solid rear section of the left wall holds a white TESSAN outlet expansion with three empty USB ports and one connected Mouse charger. Its right-angle DC plug points toward the rear of the Mouse laptop; the lead drops over the desk edge through a ferrite bead, leaves a loose floor loop, and reaches an adapter beside the left foot; the AC cord returns to the wall tap. The lower wall socket directly supplies a white extension cord with a low tied bundle and loose U before it enters the rear under-desk cable case. A thicker black cord runs from the height controls through a hanging bundle into the left side of the same case. Both form unequal folded figure-eight bundles with straight, densely gathered strands under close-fitting black INOVA-style hook-and-loop straps; the control bundle hangs midway between the controller and rear case, while the white bundle lies flat on the floor near the wall. The white lead has a rounded 6.8 × 3.4 mm flat profile, with eight closely stacked folds resting on the floor and a swivel wall plug with a recessed finger grip. A shallow bow in the drop from the case and broad floor bends suggest the stiffness of the thicker cord. The desk has round three-stage columns and white capsule feet with a 30 mm column seat, gently narrowing and lowering toward their rounded tips, broad upper shoulders, and a small lower edge, directly on the floor without black pads, matching the supplied photographs. The window and curtain start beyond this outlet section; the curtain hangs continuously without a local pullback around the cable route. These charging parts follow the supplied photographs, without reproducing unverified electrical ratings. A second, raised window sits over the bed. Gray bedding and a low gray Brain Sleep-inspired pillow sit against the wall without a headboard or lamp. The bed is an authored approximation using SIMMONS mattress dimensions as a reference.

The owner confirmed the iPad part number as MUUQ2J/A: iPad Air (3rd generation), 10.5-inch, Wi-Fi, 256 GB, Space Gray. Its landscape body remains 250.6 × 174.1 × 6.1 mm. It turns 21.2° inward and leans 13° back from vertical, resting in a wider rear slot of the stand. The original height measurements put the MacBook top at 145 mm, the iPad top at 147 mm, and the Dell lower bezel at 157 mm above the tabletop. The later visual adjustment keeps the Dell lower edge fixed while raising the MacBook and iPad tops to about 204 and 174 mm by opening their screens more upright.

[Dell’s specification](https://dl.dell.com/manuals/all-products/esuprt_electronics_accessories/esuprt_electronics_accessories_monitors/dell-u4919dw-monitor_user%27s-guide_en-us.pdf) sets the monitor body to 1215.1 × 371 × 109.3 mm, the active display to 1198.08 × 336.96 mm, and the base to 380.3 × 252.6 mm. For the requested visual emphasis, the body and active display are enlarged 10% horizontally and vertically about the lower edge: the body is 1336.61 × 408.1 mm, with its bottom still 157 mm above the tabletop. The screen retains 32:9 and shares the MacBook centerline. The new silver, fan-shaped base retains the published footprint; the wider column has a real cable aperture, and the lower bezel carries the tilted-E Dell logo and controls. The MacBook base is centered at world Z = −0.14 m; its display center is at Z = −0.29477 m. The keyboard deck retains 33 mm of front-to-back separation from the Dell base; the open lid extends above the base with more than 40 mm of vertical clearance. The MacBook and chair share the monitor centerline; the desk leaves a 50 mm gap to the rear wall. The horizontal [CalDigit TS4](https://www.caldigit.com/ts4-support/) uses a 141 × 42 × 113 mm reference housing, visually compressed to 37.8 mm in height, with fine continuous grooves and the documented six front ports. Its rear has the recessed panel, four screw heads, security slot, Ethernet, USB-A, audio, USB-C, Thunderbolt, power, and DisplayPort openings shown in the supplied reference. It and the clock are centered at X = −0.523 m, leaving approximately 10 mm beside the Dell base. The clock’s top and side bezel widths are increased while its live LCD aspect ratio is preserved.

`assets/js/mouse-video.js` plays the owner's Windows desktop recording from `assets/scene/mouse-desktop.mp4` as a `VideoTexture`: 1918×1078, 30 fps, 30 seconds, without audio. A small overlay updates the taskbar time and date in Japan time, and a black edge mask hides a pointer present in the final two frames. `assets/js/computer-screens.js` draws the Dell ultrawide with layered Windows App RDP, light-theme Ghidra, Codex, Caido, and Edge interfaces, using the owner's screenshots for fixed window chrome, toolbars, sidebar controls, dialogs, and app icons. Canvas overlays only the changing text and interaction state. A fictional messaging-app story runs through a Codex prompt, illustrated Ghidra/Edge activity, Caido history and Replay, an RDP notification and Calculator image, then a Codex result. The on-screen host is messages.kawakatz.com. Codex centers its welcome view and one-line composer, then slides them left as the right panel appears on submission. It uses task-specific image icons on status rows, moving highlights, and screenshot badges for subagent updates. The model selector sits beside the microphone. Its final cleanup prompt types `Please clean up @Computer`, selects a single Computer suggestion, and starts the illustrated pointer: close Calculator and the notification, bring Ghidra and Caido forward, delete the single Replay session and HTTP History through their menus, select and restore the browser before the final reply, then open a new chat. The approximately 155-second loop keeps the initial typing speed and schedules each output after its predecessor finishes. White replies stream at 17 characters per second, followed by a 0.35-second pause; gray investigations retain their longer reading time. App actions advance on a shared operation clock only while a gray status row shimmers; white replies hold the app state, with each investigation ending after its dialogs and typing complete. After the final cleanup reply, a small black manual pointer opens a new chat silently. Ghidra visits five functions with a screenshot-based References window and a call tree. Edge opens searches and message threads while Caido accumulates 17 authored requests beginning with the first Edge search, without selecting a row or filling its Request/Response panes. IDs start at 1 and stay left-aligned. A red circular Replay badge appears before a small black pointer with a white outline selects Caido and opens its one completed session, then brings RDP forward. This manual pointer is smaller than the blue Computer Use pointer; the messaging app identifies the current user as kawakatz. Edge starts in front and returns there during cleanup, retaining that order through the final reply and new chat. The RDP notification enters briskly; Calculator opens immediately after it settles. Compact subagent updates share one row, with working/done totals derived from the active agents. The loop returns through these actions instead of a full-screen crossfade. The request is inert demo data: the animation makes no MCP calls, sends no requests, and executes no programs. All Dell stages share the same timeline; illustrated pointers appear during browser activity and cleanup, within gray status intervals, followed by the silent new-chat navigation. Animated interfaces update at up to 30 fps. `assets/js/mac-desktop.js` uses the supplied MacBook desktop image with dynamic Japan-time dates, an empty calendar, weather-day labels without a location name, sample usage readouts, and an animated Codex sprite. The Dock appears only on Dell; `assets/js/mac-dock.js` draws the requested native app icons, two white separators, three minimized windows, a wall-date Calendar, and an authored CPU graph synchronized to the Dell story. It has no animated pointer and repaints only when the Notes transition or requested pixel density changes.

The iPad uses a perspective-aligned YouTube iframe, separate from the locally drawn desktop textures. Its screen focus and navigation remain available.

My Room in 3D uses 512 × 256, 30 fps local H.264 clips as `VideoTexture` surfaces. The normal screen view renders at up to three device pixels per CSS pixel, including embedded previews that report DPR 1, with a 12-megapixel budget for extra sampling. Small viewports and the Inspector views retain two device pixels per CSS pixel. This project rasterizes Canvas UI text at its final pixel size: 8192×2304 for Dell before the first desktop-sized render (5120×1440 on small viewports), and 3072×1996 for MacBook. The blank iPad uses a fixed 4×3 texture. The Mouse recording retains its original 1918×1078 resolution. Ghidra no longer shrinks a previously rendered text cache. Once zoom settles, visible Canvas screens are redrawn at the projected device-pixel density; old GPU allocations are released and the animation phase is retained. Full-surface canvases are limited to the GPU texture limit, 12,288 px per side and 64 megapixels per surface. Larger demands would require tiled rendering. The Dell story repeats approximately every 155 seconds; Mouse plays its recorded desktop on an independent 30-second cycle. None of these screens connects to a live application session or broadcast. No reference-site videos or models are copied. The iPad loads an official YouTube iframe from youtube-nocookie.com, with standard controls, muted autoplay, and a 0–31 second loop. Its 16:9 video retains black bars inside the 4:3 display. Captions are disabled once when the player exposes its undocumented track option; later manual choices are preserved.

`assets/js/screens.js` coordinates the screen textures and uses the Dell texture directly, without an additional full-screen Canvas copy. [The screen clarity analysis](docs/screen-clarity-analysis.md) records the original comparison and subsequent fixes. The MacBook's desktop UI fades into its coastal wallpaper as the camera approaches, with the live HTML article menu opening inside that screen. The Dell research workspace remains visible. `assets/js/clock.js` draws the segmented clock display on a 1280 × 650 Canvas texture; `assets/js/desk.js` controls its one-second updates, camera motion, rendering, and playback lifecycle. The clock's time/date use the device wall clock in Japan time, including while animations are paused; the Dock Calendar also refreshes its date; the clock temperature and humidity and the authored Dock CPU graph use sample values.

The reference sites informed composition, movement, and baked lighting; their geometry and textures were not copied. The pre-Screen-view source and assets are retained locally as `before-screen-view-20260910.tar.gz`, and the illustrated alternative is also stored locally outside this repository. Ordinary article pages and Markdown publishing are unchanged by these visual updates.

The page layout and styles are `_layouts/studio.html`, `_layouts/desk.html`, `_layouts/notes.html`, `_layouts/reading.html`, and `assets/css/studio.css`. Browser code uses `assets/js/site.js`; shared small functions are in `assets/js/navigation.js`.

## Rebuilding the 3D scene

Article writing only needs the normal Jekyll build. Rebuild the baked assets when changing equipment geometry, placement, or lighting:

The room bake also requires Homebrew WebP tools (`cwebp`) in the default Apple Silicon installation location for lossless atlas encoding.

```sh
uv venv --python 3.13 .asset-tools
uv pip install --python .asset-tools/bin/python bpy==5.2.1
npm run scene
npm run build
```

To inspect wide and narrow room compositions before baking, run `node tools/export-scene.mjs` followed by `.asset-tools/bin/python tools/bake-scene.py --preview`. Add `--desk` to the export command to frame the desk instead; both export modes include the room geometry. The renders are `.scene-build/composition-0.png` and `composition-1.png`. The exporter records both view bounds in `assets/scene/layout.json`; desk camera settings are shared with the browser through `overview` in `workstation.js`.

The desk and room use separate UV atlases so the large walls, floor, and bedding do not reduce the texture space available to the equipment:

| Geometry | Daylight atlas | Contact occlusion atlas |
| --- | --- | --- |
| Desk and equipment | `desk-daylight.jpg`, 4096 × 4096 | `desk-occlusion.jpg`, 2048 × 2048 |
| Room and furnishings | `room-daylight.webp`, 4096 × 4096, lossless RGBM32 | `room-occlusion.jpg`, 2048 × 2048 |

Each daylight atlas uses 8-pixel padding; its half-size AO atlas uses 4 pixels. Outlet, plug, and flat white cord islands receive eight times the room UV scale; black under-desk cords and straps receive three times the scale, preserving small socket slots and contact shadows between cable folds. `.asset-tools/bin/python tools/bake-scene.py --layout-check` checks the UV packing without running the lighting bake. The GLB retains separate desk and room groups with `userData.atlas` to select the appropriate textures. Floor contact shadows are baked into the room surfaces; the room export does not generate a separate contact-shadow image.

Cycles integrates direct light, indirect bounce, and diffuse material color into floating-point daylight atlases at 256 samples. Native OIDN denoises the room atlas and, through a material mask, only the `desk-powder-coat` paint in the desk atlas, using albedo and object-normal guides baked into the same UV layout. Other desk pixels retain their original baked radiance. The desk atlas preserves radiance up to 4 as an sRGB JPEG at −2 EV, restored by `emissiveIntensity: 4`. The room also includes baked window emission and preserves radiance up to 32 using RGBM: RGB stores `radiance / (32 × M)` with sRGB encoding, and alpha stores the linear multiplier `M`. The browser restores linear RGB with `emissiveIntensity: 32` and the sampled alpha; alpha represents brightness, not transparency. `tools/bake-scene.py` writes an intermediate RGBA PNG in `.scene-build`, then automatically runs `cwebp -lossless -q 100 -m 6 -exact` to produce `room-daylight.webp` without changing its encoded pixels.

The browser adds view-dependent physical reflections and applies AgX once. Separate roughness and metalness remain in the GLB materials; AO attenuates reflected light at contacts. The chair combines baked fabric lighting with a small repeating cutout mask in a separate UV channel, with filtered thread coverage at a distance. The native Three.js studio environment supplies filtered reflections without a separate environment download.

Wood uses `tools/materials/oak-albedo-refined.png`, created with imagegen and projected with world-XY `FLAT` mapping so the grain follows the desk's 180 cm axis. Bedding and curtains use the Poly Haven linen maps credited below. The scene source hash includes `workstation.js`, `keyboard.js`, and `room.js`, so geometry changes require refreshed baked assets.

The bake script currently targets Metal on Apple Silicon macOS. It creates an editable Blender scene and temporary geometry in ignored `.scene-build`, then writes the GLB and textures to `assets/scene`. Commit the generated scene assets alongside geometry changes so ordinary builds and deployment do not require Blender.

Changing drawn desktop UI or screen timing only needs `npm run assets`; it does not require Blender. Local screen animations share an elapsed clock and resume without catching up after a pause. The iPad iframe has its own playback clock.

## Validation and publishing

`npm test` builds the production site, checks model separation, chassis profiles, the diagonal Mouse laptop and aligned MacBook, camera framing, baked UV coordinates, screen timing and playback cleanup, search matching, camera easing, article routes and metadata, then runs HTML-Proofer on local links and assets. Before publishing, check the seated view, its look-around and zoom controls, opening and closing the MacBook Notes menu and the Dell/Mouse/iPad close-ups, Escape, article navigation, reduced-motion preferences, and automatic playback suspension/resumption in a browser. Camera fitting is also checked numerically at narrow and wide aspect ratios. Real-device performance still needs review.

The GitHub Pages workflow builds the JavaScript bundles before Jekyll and runs the checks before deployment. The replacement `sw.min.js` retires existing Chirpy service workers and removes only their named caches. The current layout does not register a new service worker.

## References

- [My Room in 3D source — baked lighting approach](https://github.com/brunosimon/my-room-in-3d/blob/main/src/Experience/Baked.js)
- [My Room in 3D source — local video screens](https://github.com/brunosimon/my-room-in-3d/blob/main/src/Experience/Screen.js)
- [Albino Tonnina — visual choreography reference](https://albinotonnina.com/)
- [Apple HIG: Motion](https://developer.apple.com/design/human-interface-guidelines/motion)
- [Apple HIG: Typography](https://developer.apple.com/design/human-interface-guidelines/typography)
- [Apple HIG: Accessibility](https://developer.apple.com/design/human-interface-guidelines/accessibility)
- [Jekyll documentation](https://jekyllrb.com/docs/)
- [Three.js documentation](https://threejs.org/docs/)

## License

Retain the existing project LICENSE. Three.js is MIT licensed; its notice is included in `assets/licenses/three.txt`. Fabric uses [Rough Linen by Rico Cilliers and colormass / Poly Haven](https://polyhaven.com/a/rough_linen), released under [CC0](https://polyhaven.com/license). The retained wood albedo was created with imagegen. X, GitHub, HackerOne, and Udacity icons come from [Simple Icons](https://simpleicons.org/) under CC0; the LinkedIn icon comes from [LinkedIn's brand assets](https://brand.linkedin.com/downloads). Certification badges come from the linked OffSec credentials on Accredible and Zero-Point Security badge classes on Badgr, and retain their issuers' ownership. Monster artwork and marks belong to [Monster Energy](https://www.monsterenergy.com/); Codex character artwork and marks belong to OpenAI. Application icons retain their respective product ownership. Product names identify the owner's equipment; this site is not affiliated with the manufacturers.
