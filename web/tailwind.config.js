export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: { display: ['"IBM Plex Sans"', 'sans-serif'], sans: ['"IBM Plex Sans"', 'sans-serif'], mono: ['"IBM Plex Mono"', 'ui-monospace', 'monospace'] },
      colors: {
        ink: { 950: '#020304', 900: '#07090c', 800: '#0c0f13', 700: '#13171d', 600: '#1b2028' },
        accent: { DEFAULT: '#6cb6ff', soft: '#9ccfff', dim: '#2f5f8f' },
        signal: { DEFAULT: '#4ade80', dim: '#1f6b43' },
      },
      borderRadius: { none: '0', sm: '4px', DEFAULT: '8px', md: '8px', lg: '10px', xl: '12px', '2xl': '16px', '3xl': '16px', full: '9999px' },
          },
  },
};
