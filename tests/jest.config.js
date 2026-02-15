module.exports = {
    testEnvironment: 'jsdom',
    setupFilesAfterEnv: ['<rootDir>/setup.js'],
    moduleFileExtensions: ['js', 'json'],
    testMatch: ['<rootDir>/**/*.test.js'],
    collectCoverageFrom: [
        '../mailsafepro-widget.js',
        '!**/node_modules/**'
    ],
    coverageDirectory: 'coverage',
    verbose: true
};
