/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  // Dark mode is ALWAYS on — we lock the dark palette for CTS Security
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: [
          '"Inter"',
          '"SF Pro Display"',
          '"SF Pro Text"',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Helvetica Neue"',
          'Arial',
          'sans-serif',
        ],
      },
      colors: {
        // Apple-inspired Blue as primary
        primary: {
          DEFAULT: '#007AFF',
          dark: '#0A84FF',
        },
        secondary: {
          DEFAULT: '#5856D6',
          dark: '#5E5CE6',
        },
        accent: {
          DEFAULT: '#FF2D55',
          dark: '#FF375F',
        },
        success: {
          DEFAULT: '#30D158',
          dark: '#32D74B',
        },
        warning: {
          DEFAULT: '#FF9F0A',
          dark: '#FFB340',
        },
        error: {
          DEFAULT: '#FF453A',
          dark: '#FF6961',
        },
        // Dark backgrounds — always forced dark
        background: {
          DEFAULT: '#0A0A0F',
          dark: '#0A0A0F',
        },
        surface: {
          DEFAULT: '#141418',
          dark: '#141418',
        },
        elevated: {
          DEFAULT: '#1C1C22',
          dark: '#1C1C22',
        },
        border: {
          DEFAULT: 'rgba(255,255,255,0.08)',
          dark: 'rgba(255,255,255,0.08)',
        },
        // Text colors — always white / near-white for readability
        textPrimary: {
          DEFAULT: '#FFFFFF',
          dark: '#FFFFFF',
        },
        textSecondary: {
          DEFAULT: 'rgba(255,255,255,0.55)',
          dark: 'rgba(255,255,255,0.55)',
        },
        muted: {
          DEFAULT: 'rgba(255,255,255,0.30)',
          dark: 'rgba(255,255,255,0.30)',
        },
      },
      boxShadow: {
        'apple': '0 8px 30px rgba(0,0,0,0.5)',
        'apple-dark': '0 8px 30px rgba(0,0,0,0.7)',
        'glow': '0 0 30px rgba(0,122,255,0.25)',
      },
      borderRadius: {
        'xl': '12px',
        '2xl': '16px',
        '3xl': '24px',
      },
      animation: {
        'in': 'animateIn 0.4s ease-out both',
        'fade-in': 'fadeIn 0.3s ease-out both',
        'slide-up': 'slideUp 0.4s ease-out both',
      },
      keyframes: {
        animateIn: {
          from: { opacity: '0', transform: 'translateY(12px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
        fadeIn: {
          from: { opacity: '0' },
          to: { opacity: '1' },
        },
        slideUp: {
          from: { opacity: '0', transform: 'translateY(20px)' },
          to: { opacity: '1', transform: 'translateY(0)' },
        },
      },
    },
  },
  plugins: [],
}
