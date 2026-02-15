# MailSafePro Widget Tests

This directory contains comprehensive tests for the MailSafePro Widget.

## Structure

```
tests/
├── package.json           # Node.js test dependencies
├── jest.config.js        # Jest configuration
├── setup.js              # Test setup and mocks
├── widget.test.js        # JavaScript widget tests
├── requirements.txt      # Python test dependencies
├── test_backend.py       # Python backend tests
└── README.md            # This file
```

## Running JavaScript Tests (Widget)

### Prerequisites
```bash
cd tests
npm install
```

### Run Tests
```bash
npm test
```

### Run with Coverage
```bash
npm run test:coverage
```

### Run in Watch Mode
```bash
npm run test:watch
```

## Running Python Tests (Backend)

### Prerequisites
```bash
cd tests
pip install -r requirements.txt
```

### Run Tests
```bash
pytest
```

### Run with Coverage
```bash
pytest --cov=../main.py
```

## Test Coverage

### JavaScript Tests
- Constructor initialization
- Email syntax validation (valid/invalid formats)
- API integration (endpoints, headers, payloads)
- Demo mode behavior
- UI state updates (valid, invalid, risky, loading)
- Suggestion handling
- Event handling (input, blur)
- Result processing
- Reset functionality
- Widget destruction
- Accessibility attributes
- Configuration options
- Edge cases (errors, non-ok responses)

### Python Tests
- Health check endpoint
- Widget static file endpoint
- CORS configuration
- Validation endpoint
- Rate limiting
- Security headers
- OpenAPI schema
- API documentation
- ReDoc endpoint
