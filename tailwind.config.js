module.exports = {
  content: [
    './templates/**/*.{html,js}',
    './static/js/**/*.{js,jsx}',
  ],
  safelist: [
    'bg-[#150d28]',
    'bg-[#2f142e]',
    'peer-checked:translate-x-5',
    'transform'
  ],
  theme: {
    extend: {
      colors: {
        primary: '#150d28',
        bgcard: rgba(22, 125, 255, .3),
      }
    },
    
  },
  corePlugins: {
    // Ensure this is not disabled:
    transform: true,
  },
  plugins: [],
}