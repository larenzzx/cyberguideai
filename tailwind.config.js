/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./chat/templates/**/*.html",
    "./templates/**/*.html",
    "./**/templates/**/*.html",
  ],
  plugins: [require("daisyui")],
  daisyui: {
    themes: ["night"],
    defaultTheme: "night",
    darkTheme: "night",
  },
};
