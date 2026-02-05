# Contributing to IWSN Security

Thank you for considering contributing to the IWSN Security project! We welcome contributions of all kinds.

## How to Contribute

### Reporting Bugs

If you find a bug, please create an issue with:
- A clear, descriptive title
- Steps to reproduce the problem
- Expected behavior vs actual behavior
- Your environment (OS, gcc version, library versions)
- Any relevant logs or error messages

### Suggesting Enhancements

We welcome feature requests! Please create an issue describing:
- The enhancement you'd like to see
- Why it would be useful
- Any implementation ideas you have

### Pull Requests

1. **Fork the Repository**
   ```bash
   git clone https://github.com/YOUR_USERNAME/iwsn_security.git
   cd iwsn_security
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Write clear, commented code
   - Follow the existing code style
   - Test your changes thoroughly

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Add: Brief description of your changes"
   ```
   
   Use conventional commit messages:
   - `Add:` for new features
   - `Fix:` for bug fixes
   - `Update:` for updates to existing features
   - `Docs:` for documentation changes
   - `Refactor:` for code refactoring

5. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Open a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Include test results if applicable

## Code Style Guidelines

- Use consistent indentation (4 spaces)
- Add comments for complex logic
- Keep functions focused and modular
- Use meaningful variable names
- Follow C best practices and conventions

## Testing

Before submitting a pull request:
- Ensure your code compiles without warnings
- Test with provided sample PCAP files
- Test with attack sample files
- Verify no memory leaks (use valgrind if possible)

## Documentation

If your contribution changes functionality:
- Update relevant documentation in the `docs/` directory
- Update the README.md if needed
- Add comments to new functions and complex code

## Questions?

Feel free to open an issue for any questions about contributing!

Thank you for helping improve IWSN Security! 🚀
