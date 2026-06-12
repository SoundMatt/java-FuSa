# Contributing to java-FuSa

Thank you for contributing to java-FuSa!

## Prerequisites

- Java 21 (Eclipse Temurin recommended)
- Maven 3.9+
- Docker (optional, for container builds)

## Development Setup

```bash
git clone https://github.com/soundmatt/java-FuSa.git
cd java-FuSa
mvn package
java -jar target/jfusa.jar version
```

## Workflow

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/my-rule`
3. Write your code and tests
4. Run the full check suite: `make vet test`
5. Run qualification: `make qualify`
6. Submit a pull request

## Adding a New Rule

1. Choose the appropriate package (`lint/`, `cyber/`, `analyze/`, etc.)
2. Implement `Rule` interface:
   ```java
   public String id()          { return "LINT011"; }
   public String description() { return "..."; }
   public List<Finding> run(Path root, Config cfg) throws IOException { ... }
   ```
3. Register in the package's `static {}` block:
   ```java
   static { Engine.DEFAULT.mustRegister(new RuleMyRule()); }
   ```
4. Add an `activate()` no-op and call it from `Main.java`'s static initializer
5. Write a test in `src/test/java/.../<Package>RulesTest.java`
6. Document in `README.md` under the relevant section

## Rule ID Conventions

| Prefix  | Package        | Standards        |
|---------|----------------|------------------|
| FUSA    | engine         | x-FuSa §4       |
| LINT    | lint           | Java coding      |
| ANA     | analyze        | Static analysis  |
| CYBER   | cyber          | CWE/OWASP       |
| TRACE   | trace          | ISO 26262        |
| VERIFY  | verify         | x-FuSa §7       |
| RELEASE | release        | SLSA             |
| QUALIFY | qualify        | DO-178C §12      |
| SLSA    | slsa           | SLSA L2/L3       |
| MISRA   | misra          | MISRA Java 2023  |
| COMP    | comp           | DO-178C §6.3.4   |
| COV     | coverage       | DO-178C §6.4.4   |
| VULN    | vuln           | ISO 21434        |
| IEC62443| iec62443       | IEC 62443        |

## Code Standards

- Zero runtime dependencies (stdlib only)
- Java 21 features encouraged (records, pattern matching, text blocks)
- No `System.out.println` in rule implementations — only CLI handlers
- All public APIs must have a corresponding test
- Run `jfusa lint` on your changes before opening a PR

## Commit Messages

Follow Conventional Commits:

```
feat(lint): add LINT011 rule for unchecked cast without annotation
fix(cyber): CYBER005 false positive on final constants
docs: update README with LINT011 documentation
```

## Testing

```bash
mvn test                  # Unit tests
make qualify              # Tool qualification suite
make vet                  # Run jfusa on itself
```

All tests must pass. The qualification suite (`qualify-report.json`) must
report `PASS` for all 10 test cases.

## Pull Request Checklist

- [ ] Tests added/updated
- [ ] `make vet` passes
- [ ] `make qualify` reports PASS
- [ ] README updated if new command added
- [ ] CHANGELOG.md entry added
- [ ] Rule ID is unique and follows convention
