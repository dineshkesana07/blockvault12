/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        primary: "#080D1A",
        secondary: "#101827",
        accentPurple: "#7C5CFF",
        accentBlue: "#22D3EE",
        black: "#000000",
        white: "#FFFFFF",
        red: "#FF0000",
        green: "#00FF00",
      },
      boxShadow: {
        glass: "0 4px 30px rgba(0,0,0,0.12)"
      }
    },
  },
  plugins: [],
};
