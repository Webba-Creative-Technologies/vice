// vice.config.example.js
// Example configuration file for VICE
// Copy this file to vice.config.js and modify as needed

export default {
  // URL to scan in remote mode
  url: 'https://your-site.com',

  // Ignore specific findings
  ignore: [
    'Supabase Anon Key',
    'Firebase API Key',
  ],

  // CI configuration
  ci: {
    minScore: 70,           // Minimum score required to pass
    failOnCritical: true,   // Fail if critical findings are found
  },

  // Path to Supabase migrations for RLS checks
  supabaseMigrations: './supabase/migrations',

  // Custom headers for remote scans
  headers: {
    'User-Agent': 'VICE Security Scanner',
  },

  // Timeout for remote scans in milliseconds
  timeout: 30000,

  // Maximum depth for crawling
  maxDepth: 5,

  // Exclude specific URLs from crawling
  excludeUrls: [
    '/admin',
    '/api',
  ],
};
