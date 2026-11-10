/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx,ts,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        bone: '#F5F2EB',
        charcoal: '#1C1C1E',
        ash: '#2C2C2E',
        stone: '#8E8E93',
        chalk: '#E5E5EA',
        paper: '#FFFFFF',
        accent: '#C23D2E',
        'accent-hover': '#A83226',
      },
      fontFamily: {
        sans: ['-apple-system', "'Helvetica Neue'", 'Helvetica', 'sans-serif'],
        serif: ["'Playfair Display'", 'Georgia', 'serif'],
        mono: ["'SF Mono'", "'Fira Code'", "'Cascadia Code'", 'Menlo', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '4px',
        sm: '2px',
        none: '0px',
      },
      transitionDuration: {
        DEFAULT: '100ms',
      },
      maxWidth: {
        prose: '65ch',
      },
    },
  },
  plugins: [],
};
