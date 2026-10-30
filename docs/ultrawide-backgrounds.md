# 32:9 theme backgrounds

Each built-in still background has a same-stem `@32x9.svg` variant for a 5120×1440 display. The aspect-ratio resolver selects it automatically on a 32:9 screen; the background picker and current-background link continue to identify the canonical image.

## Original artwork

The SVG references the original raster directly, centers its complete composition, and scales it proportionally to the canvas height. All 98 original source files are byte unchanged. Normal display resampling applies.

The surrounding scenery lives in separate WebP side panels under each theme's `backgrounds/ultrawide/` directory. Generated scenery generally uses quality 95; revised Gruvbox panels use quality 98, and revised Last Horizon and Ristretto panels use lossless encoding. Keep these relative resources together when copying a theme. The dotted forearms use native SVG circles instead of raster side panels.

Six photo compositions blend the original's edge strips with registered generated context to remove visible scan edges and rectangular joins: Gruvbox 1 and 2, Last Horizon 2 and 3, and Ristretto 2 on both sides; Last Horizon 4 on the right only. Each blend is limited to 64 display pixels inside the original rectangle at 5120×1440, with a smooth opacity ramp. Panels extend underneath the complete fade, with integer placement and additional coverage at fractional boundaries. The protected interior is opaque and pixel-exact against a source-only render. Last Horizon 4's left panel and left half are unchanged by this correction. The remaining 92 compositions preserve the complete original rectangle.

## Extensions

Scenery, photography, textures, and complex illustrations use generative outpainting through Codex's built-in image generator. Each side was generated with the adjacent original as context. Generated source context is discarded except in the six documented edge blends. The corrected panels are aligned to source features and calibrated against matching source regions before assembly.

Uniform backgrounds behind wordmarks and isolated motifs use the original field color. Designs with horizontal color bands continue their source edge colors by row. This preserves the existing typography, symbols, and line work without regenerating them.

The dotted forearm extensions use a grid registered to the original dot positions and sizes. Circles are drawn directly at final canvas coordinates, avoiding bitmap rescaling and blurred dots. Dot size stays consistent through the arm body, with falloff confined to its silhouette. The original hands, fingertip spacing, and credit remain in the unchanged center raster.

Matte Black and Vantablack share the same canonical hand drawing and the same source-registered forearm extensions.

Painted scenery matches the original interior palette separately from its darker scan edges. Coffee foliage follows the original depth of field. Missing fine grain in the coffee extensions and the right sky transition of Last Horizon 4 is matched to the source's channel covariance with reproducible noise.

[The provenance manifest](assets/ultrawide/provenance.json) records the source hashes, extension methods, and generation prompts. [The gallery](assets/ultrawide/gallery.md) shows all complete 32:9 compositions for review. Boot intro videos retain their existing framing.

## Generation recipe

Prepare a 5120×1440 composition with the original centered at its full proportional height. Split the new space into left and right jobs, each with adjacent source context on a 2560×1440 canvas. Request continuation of the existing scene, lighting, perspective, contours, texture, exposure, and depth of field, with no duplicate focal subjects, text, mirroring, tiling, cropping, or reframing. Register the generated context to the source and match its palette. Extract the outer scenery, retaining only the required underlap for the documented blends, and encode the panels. Reference the original above both panels in the SVG; use a mask only for the explicitly documented edge strips.

Review the assembled composition at native display resolution and in the running Background plugin: restoring the source during assembly can expose a mismatch that was absent in the generator output. Verify protected interiors against a source-only render with the edge mask removed. The gallery includes native-resolution seam and dot details as well as complete compositions.
