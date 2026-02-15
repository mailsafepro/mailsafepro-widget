global.fetch = jest.fn();
global.Response = jest.fn().mockImplementation((body, init) => ({
    ok: init?.status >= 200 && init?.status < 300,
    status: init?.status || 200,
    json: jest.fn().mockResolvedValue(JSON.parse(body)),
    text: jest.fn().mockResolvedValue(body)
}));

global.window = {
    MailSafeProWidget: undefined
};

global.document = {
    head: {
        appendChild: jest.fn()
    },
    getElementById: jest.fn(),
    querySelector: jest.fn(),
    createElement: jest.fn().mockImplementation((tag) => ({
        tagName: tag.toUpperCase(),
        id: '',
        className: '',
        textContent: '',
        innerHTML: '',
        style: {},
        setAttribute: jest.fn(),
        getAttribute: jest.fn(),
        appendChild: jest.fn(),
        removeChild: jest.fn(),
        addEventListener: jest.fn(),
        removeEventListener: jest.fn(),
        parentNode: {
            insertBefore: jest.fn(),
            removeChild: jest.fn()
        }
    })),
    currentScript: null,
    readyState: 'complete'
};

global.navigator = {
    userAgent: ''
};

jest.useFakeTimers();
