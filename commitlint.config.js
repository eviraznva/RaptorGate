module.exports = {
  extends: ['@commitlint/config-conventional'],

  rules: {
    // Typ musi być jednym z dozwolonych
    'type-enum': [
      2,
      'always',
      [
        'feat',      // Nowa funkcjonalność
        'fix',       // Naprawa błędu
        'docs',      // Wyłącznie dokumentacja
        'style',     // Zmiany nie wpływające na logikę kodu
        'refactor',  // Zmiana kodu bez naprawy błędu ani nowej funkcji
        'perf',      // Poprawa wydajności
        'test',      // Dodawanie lub poprawianie testów
        'chore',     // Zmiany w procesie budowania, zależności itp.
        'ci',        // Zmiany w konfiguracji CI/CD
      ]
    ],

    // Zakres musi być małymi literami
    'scope-case': [2, 'always', 'lowercase'],

    // Zakres musi być jednym z poniższych (opcjonalny, ale walidowany jeśli podany)
    'scope-enum': [
      2,
      'always',
      [
        'firewall',       // Pipeline Rust — pcap, parser, conntrack, NAT, policy engine, inspekcja, ML
        'packet-capture', // Przechwytywanie pakietów
        'docker',         // Docker i konteneryzacja
        'ci-cd',          // GitHub Actions i potoki CI/CD
        'core',           // Rdzeń aplikacji
        'config',         // Pliki konfiguracyjne
        'deps',           // Zależności
      ]
    ],

    // Typ musi być małymi literami
    'type-case': [2, 'always', 'lowercase'],

    // Temat nie może kończyć się kropką
    'subject-full-stop': [2, 'never', '.'],

    // Temat musi być w trybie rozkazującym (add, fix, nie added, fixed)
    'subject-case': [2, 'never', ['start-case', 'pascal-case', 'upper-case']],

    'subject-empty': [2, 'never'],
    'subject-max-length': [2, 'always', 250],

    // Treść commita
    'body-leading-blank': [2, 'always'],
    'body-max-line-length': [2, 'always', 250],

    // Stopka commita
    'footer-leading-blank': [2, 'always'],
    'footer-max-line-length': [2, 'always', 100],
  },

  // Wzorce ignorowane (commity niewymagające walidacji)
  ignores: [
    (commit) => commit.includes('WIP'),
    (commit) => commit.startsWith('Merge pull request'),
    (commit) => commit.startsWith('Merge branch'),
    (commit) => commit.startsWith('Revert'),
  ],

  // Konfiguracja promptu (jeśli używasz commitizen)
  prompt: {
    settings: {},
    messages: {
      skip: ':pomiń',
      max: 'maks. %s znaków',
      min: 'min. %s znaków',
      emptyNotAllowed: 'pole nie może być puste',
      upperLimitWarning: 'przekroczono limit',
      userAbort: 'Anulowano.',
    },
    questions: {
      type: {
        description:
          'Wybierz typ zmiany:\n' +
          '  feat:     Nowa funkcjonalność\n' +
          '  fix:      Naprawa błędu\n' +
          '  docs:     Wyłącznie dokumentacja\n' +
          '  style:    Formatowanie (bez zmian logiki)\n' +
          '  refactor: Refaktoryzacja kodu\n' +
          '  perf:     Poprawa wydajności\n' +
          '  test:     Dodawanie lub aktualizacja testów\n' +
          '  chore:    Zależności, narzędzia, konfiguracja\n' +
          '  ci:       Zmiany CI/CD\n',
        enum: {
          feat: {
            description: 'Nowa funkcjonalność',
            title: 'Funkcjonalności',
          },
          fix: {
            description: 'Naprawa błędu',
            title: 'Naprawy błędów',
          },
          docs: {
            description: 'Wyłącznie zmiany dokumentacji',
            title: 'Dokumentacja',
          },
          style: {
            description: 'Zmiany niemodyfikujące logiki (formatowanie)',
            title: 'Styl',
          },
          refactor: {
            description: 'Zmiana kodu bez naprawy błędu ani nowej funkcji',
            title: 'Refaktoryzacja',
          },
          perf: {
            description: 'Zmiana kodu poprawiająca wydajność',
            title: 'Wydajność',
          },
          test: {
            description: 'Dodawanie lub poprawianie testów',
            title: 'Testy',
          },
          chore: {
            description: 'Inne zmiany niemodyfikujące kodu źródłowego ani testów',
            title: 'Utrzymanie',
          },
          ci: {
            description: 'Zmiany konfiguracji i skryptów CI/CD',
            title: 'CI/CD',
          },
        },
      },
      scope: {
        description: 'Jaki jest zakres tej zmiany? (np. firewall, packet-capture)',
        enum: {
          firewall: {
            description: 'Pipeline Rust — reguły, policy engine, inspekcja',
            title: 'Firewall',
          },
          'packet-capture': {
            description: 'Moduł przechwytywania pakietów',
            title: 'Packet Capture',
          },
          docker: {
            description: 'Konfiguracja Docker',
            title: 'Docker',
          },
          'ci-cd': {
            description: 'GitHub Actions',
            title: 'CI/CD',
          },
          core: {
            description: 'Rdzeń aplikacji',
            title: 'Core',
          },
          config: {
            description: 'Pliki konfiguracyjne',
            title: 'Konfiguracja',
          },
          deps: {
            description: 'Zależności',
            title: 'Zależności',
          },
        },
      },
      subject: {
        description: 'Napisz krótki opis zmiany w trybie rozkazującym:\n',
      },
      body: {
        description: 'Podaj dłuższy opis zmiany (wyjaśnij DLACZEGO):\n',
      },
      isBreaking: {
        description: 'Czy są przełomowe zmiany (breaking changes)?',
      },
      breakingBody: {
        description: 'Opisz przełomowe zmiany:\n',
      },
      footer: {
        description:
          'Podaj zamknięte zgłoszenia (np. Closes FW-42, Fixes BE-12):\n',
      },
      confirmCommit: {
        description: 'Czy na pewno chcesz zatwierdzić powyższy commit?',
      },
    },
  },
};
