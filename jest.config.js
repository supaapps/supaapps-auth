module.exports = {
    testEnvironment: 'jsdom',  // Use jsdom environment to run tests
    roots: ['<rootDir>/tests'],
    testMatch: ['**/*.test.ts'],  // Matches test files in the tests directory
    transform: {
      '^.+\\.tsx?$': 'ts-jest',  // Transform TypeScript files using ts-jest
    },
    setupFilesAfterEnv: ['jest-localstorage-mock'],  // Setup local storage mock for all tests
    testEnvironment: 'node',  // Use node environment to run tests,
    collectCoverage: true,
    coverageReporters: [
        "text",
        "cobertura"
    ]
  };
  