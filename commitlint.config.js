module.exports = {
  extends: ['@commitlint/config-conventional'],
  
  rules: {
    // Type must be one of the allowed types
    'type-enum': [
      2,
      'always',
      [
        'feat',      // A new feature
        'fix',       // A bug fix
        'docs',      // Documentation only
        'style',     // Changes that don't affect code meaning
        'refactor',  // Code change that neither fixes bug nor adds feature
        'perf',      // Code change that improves performance
        'test',      // Adding missing tests or correcting existing tests
        'chore',     // Changes to build process, dependencies, etc
        'ci',        // Changes to CI/CD configuration
      ]
    ],

    // Scope should be lowercase
    'scope-case': [2, 'always', 'lowercase'],

    // Scope should be one of these (optional, but validated if present)
    'scope-enum': [
      2,
      'always',
      [
        'firewall',       // NGFW firewall module
        'packet-capture', // Packet capture & sniffing
        'docker',         // Docker & containerization
        'ci-cd',          // GitHub Actions & pipelines
        'core',           // Core application
        'config',         // Configuration files
        'deps',           // Dependencies
      ]
    ],

    // Type must be lowercase
    'type-case': [2, 'always', 'lowercase'],

    // Subject must not end with a period
    'subject-full-stop': [2, 'never', '.'],

    // Subject must use imperative (add, fix, not added, fixed)
    'subject-case': [2, 'never', ['start-case', 'pascal-case', 'upper-case']],

    // Subject line max length
    'subject-empty': [2, 'never'],
    'subject-max-length': [2, 'always', 50],

    // Body line max length
    'body-leading-blank': [2, 'always'],
    'body-max-line-length': [2, 'always', 72],

    // Footer line max length
    'footer-leading-blank': [2, 'always'],
    'footer-max-line-length': [2, 'always', 72],

    // Require a body for non-chore commits (optional, set to 0 to disable)
    // 'body-empty': [0, 'never'],
  },

  // Ignored patterns (commits that don't require validation)
  ignores: [
    (commit) => commit.includes('WIP'),
    (commit) => commit.startsWith('Merge pull request'),
    (commit) => commit.startsWith('Merge branch'),
    (commit) => commit.startsWith('Revert'),
  ],

  // Prompt configuration (if using commitizen)
  prompt: {
    settings: {},
    messages: {
      skip: ':skip',
      max: 'upper %s chars',
      min: '%s chars at least',
      emptyNotAllowed: 'empty not allowed',
      upperLimitWarning: 'over limit',
      commitIsNotInScope: 'commit message is not in the scope of this project',
      userAbort: 'User action was cancelled.',
    },
    questions: {
      type: {
        description:
          "Select the type of change that you're committing:\n" +
          '  feat:     A new feature\n' +
          '  fix:      A bug fix\n' +
          '  docs:     Documentation only\n' +
          '  style:    Code formatting (no logic change)\n' +
          '  refactor: Code refactoring\n' +
          '  perf:     Performance improvement\n' +
          '  test:     Adding or updating tests\n' +
          '  chore:    Build, deps, config\n' +
          '  ci:       CI/CD changes\n',
        enum: {
          feat: {
            description: 'A new feature',
            title: 'Features',
            emoji: '✨',
          },
          fix: {
            description: 'A bug fix',
            title: 'Bug Fixes',
            emoji: '🐛',
          },
          docs: {
            description: 'Documentation only changes',
            title: 'Documentation',
            emoji: '📝',
          },
          style: {
            description: 'Changes that do not affect code meaning (formatting)',
            title: 'Styles',
            emoji: '💎',
          },
          refactor: {
            description: 'A code change that neither fixes a bug nor adds a feature',
            title: 'Code Refactoring',
            emoji: '♻️',
          },
          perf: {
            description: 'A code change that improves performance',
            title: 'Performance Improvements',
            emoji: '⚡',
          },
          test: {
            description: 'Adding missing tests or correcting existing tests',
            title: 'Tests',
            emoji: '🧪',
          },
          chore: {
            description: 'Other changes that don\'t modify src or test files',
            title: 'Chores',
            emoji: '🔧',
          },
          ci: {
            description: 'Changes to CI/CD configuration and scripts',
            title: 'CI/CD',
            emoji: '👷',
          },
        },
      },
      scope: {
        description: 'What is the scope of this change? (e.g. firewall, packet-capture)',
        enum: {
          firewall: {
            description: 'NGFW firewall rules',
            title: 'Firewall',
          },
          'packet-capture': {
            description: 'Packet capture module',
            title: 'Packet Capture',
          },
          docker: {
            description: 'Docker configuration',
            title: 'Docker',
          },
          'ci-cd': {
            description: 'GitHub Actions',
            title: 'CI/CD',
          },
          core: {
            description: 'Core application',
            title: 'Core',
          },
          config: {
            description: 'Configuration files',
            title: 'Config',
          },
          deps: {
            description: 'Dependencies',
            title: 'Dependencies',
          },
        },
      },
      subject: {
        description: 'Write a short, imperative tense description of the change:\n',
      },
      body: {
        description: 'Provide a longer description of the change:\n',
      },
      isBreaking: {
        description: 'Are there any breaking changes?',
      },
      breakingBody: {
        description: 'Describe the breaking changes:\n',
      },
      footer: {
        description:
          'List any closed issues (e.g. #31, #34):\n',
      },
      confirmCommit: {
        description: 'Are you sure you want to proceed with the commit above?',
      },
    },
  },
};