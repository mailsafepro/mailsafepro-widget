export interface MailSafeProOptions {
    /**
     * Your MailSafePro API Key.
     */
    apiKey: string;

    /**
     * Enable deep SMTP verification (slower but more accurate).
     * @default false
     */
    checkSmtp?: boolean;

    /**
     * Debounce time in milliseconds.
     * @default 600
     */
    debounceTime?: number;

    /**
     * Custom API URL (for proxies).
     */
    apiUrl?: string;

    /**
     * Show floating status icons inside the input.
     * @default true
     */
    showIcons?: boolean;

    /**
     * Custom messages for localization.
     */
    messages?: {
        valid?: string;
        invalid?: string;
        risky?: string;
        disposable?: string;
        loading?: string;
        suggestion?: string;
        error?: string;
    };
}

export class MailSafeProWidget {
    /**
     * Initialize the MailSafePro Widget on a specific input element.
     * @param inputElement The HTMLInputElement to attach to.
     * @param options Configuration options.
     */
    constructor(inputElement: HTMLInputElement, options: MailSafeProOptions);
}

declare global {
    interface Window {
        MailSafeProWidget: typeof MailSafeProWidget;
    }
}
