# Contributing to EcomSecure Scanner

Thank you for your interest in contributing to EcomSecure Scanner! This project is a security tool designed to help developers and security researchers identify vulnerabilities in e-commerce platforms.

## Development Setup

1.  **Fork and Clone**:
    ```bash
    git clone https://github.com/bhasinagam/Ecom-Secure.git
    cd Ecom-Secure
    ```

2.  **Install Dependencies**:
    ```bash
    npm install
    ```

3.  **Environment Configuration**:
    Copy the example environment file and configure your API keys:
    ```bash
    cp .env.example .env
    ```

4.  **Run Development Build**:
    ```bash
    npm run dev
    ```

## Code Standards

-   **TypeScript**: We use strict TypeScript configuration. Ensure no `any` types are used unless absolutely necessary.
-   **Linting**: Run `npm run lint` before committing to ensure code style consistency.
-   **Testing**: Add unit tests for new detectors or features. Run `npm test` to verify changes.

## Pull Request Process

1.  Create a feature branch from `main`: `git checkout -b feature/my-new-feature`.
2.  Commit your changes with clear, descriptive messages following [Conventional Commits](https://www.conventionalcommits.org/).
3.  Push your branch and open a Pull Request.
4.  Ensure all CI checks pass.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
