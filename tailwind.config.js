/**
 * Tailwind CSS v4 Configuration
 *
 * LEARNING: Tailwind v4 moved to CSS-first configuration.
 * Most config now lives in static/css/input.css using @plugin, @source, @theme.
 *
 * This file is kept for reference / tooling compatibility (e.g., IDE plugins),
 * but the Tailwind v4 CLI reads configuration from the CSS file directly.
 *
 * Key config in static/css/input.css:
 *   @source "../../chat/templates/**/*.html"  → which files to scan for classes
 *   @plugin "daisyui" { themes: night --default; }  → DaisyUI with night theme
 */

/** @type {import('tailwindcss').Config} */
module.exports = {
  // In v4, content scanning is done via @source in CSS — this is a no-op
  content: [],
  plugins: [],
};
