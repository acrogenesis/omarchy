# 32:9 theme backgrounds

Each built-in still background has a same-stem `@32x9.svg` variant for a 5120×1440 display. The aspect-ratio resolver selects it automatically on a 32:9 screen; the background picker and current-background link continue to identify the canonical image.

## Original artwork

The SVG references the original raster directly, centers its complete composition, and scales it proportionally to the canvas height. Its source file is unchanged. Normal display resampling applies, but no generated pixels, color adjustments, crops, or compression are applied to the original artwork.

The surrounding scenery lives in separate WebP side panels under each theme's `backgrounds/ultrawide/` directory. Generated scenery uses quality 95; source-derived fields and panels requiring dot-grid or chromatic-grain fidelity use lossless encoding. The original is drawn last over a one-pixel underlap that keeps fractional raster boundaries opaque. The visible panels fill the space outside it. Keep these relative resources together when copying a theme. These SVGs compose raster artwork; they do not convert it to vector paths.

## Extensions

Scenery, photography, textures, and complex illustrations use generative outpainting through Codex's built-in image generator. Each side was generated with the adjacent original as context. Only pixels in the new outer area were retained; the generator's rendition of the original was discarded. Palette and boundary corrections affect the generated panels only.

Uniform backgrounds behind wordmarks and isolated motifs use the original field color. Designs with horizontal color bands continue their source edge colors by row. This preserves the existing typography, symbols, and line work without regenerating them.

The dotted forearm extensions use a grid registered to the original dot positions and sizes. The original hands, fingertip spacing, and credit remain in the unchanged center raster. These source-derived panels use lossless WebP.

Painted scenery matches the original interior palette separately from its darker scan edges. Corrections at the joins affect the side panels only.

[The provenance manifest](assets/ultrawide/provenance.json) records the source hashes, extension methods, and generation prompts. [The gallery](assets/ultrawide/gallery.md) shows all complete 32:9 compositions for review. Boot intro videos retain their existing framing.

## Generation recipe

Prepare a 5120×1440 composition with the original centered at its full proportional height. Split the new space into left and right jobs, each with adjacent source context on a transparent 2560×1440 canvas. Request continuation of the existing scene, lighting, perspective, contours, texture, and exposure, with no duplicate focal subjects, text, mirroring, tiling, cropping, or reframing. Extract only the newly filled outer area from the result, match its colors to the source boundary, and encode it as WebP at quality 95. Reference the untouched original above both panels in the SVG.

Review the assembled composition, rather than the raw generator output: the original source is restored during assembly, so a convincing raw result can still expose a mismatch at the join.
