BINARY    := jfusa
VERSION   := $(shell grep -m1 '<version>' pom.xml | sed 's/.*<version>\(.*\)<\/version>/\1/' | tr -d ' ')
JAR       := target/$(BINARY).jar
MAIN      := com.soundmatt.jfusa.cmd.Main
JAVA_HOME ?= $(shell /usr/libexec/java_home -v 21 2>/dev/null || echo "")

.PHONY: all build test vet check trace verify release qualify evidence \
        audit-pack badge diff sign hooks clean docker docker-push \
        safety-case fmea tara hara boundary coupling do178 iso26262 \
        iso21434 iec61508 iec62443 unece slsa sas sci coverage comp \
        misra metrics capabilities version help

# ── Build ─────────────────────────────────────────────────────────────────────

all: build

build:
	@echo "==> Building $(BINARY) $(VERSION)"
	mvn -q package -DskipTests
	@echo "==> Built: $(JAR)"

test:
	@echo "==> Running tests"
	mvn -q test

vet: build
	@echo "==> Running built-in rules on java-FuSa itself"
	java -jar $(JAR) check --format=text

check: build
	@echo "==> Full gate check"
	java -jar $(JAR) check

lint: build
	java -jar $(JAR) lint

analyze: build
	java -jar $(JAR) analyze

cyber: build
	java -jar $(JAR) cyber

# ── Evidence Pipeline ─────────────────────────────────────────────────────────

trace: build
	java -jar $(JAR) trace

verify: build
	java -jar $(JAR) verify

release: build
	java -jar $(JAR) release

qualify: build
	java -jar $(JAR) qualify

evidence: verify release qualify safety-case fmea tara hara audit-pack
	@echo "==> All evidence artifacts generated"

audit-pack: build
	java -jar $(JAR) audit-pack

badge: build
	java -jar $(JAR) badge

# ── Compliance ────────────────────────────────────────────────────────────────

safety-case: build
	java -jar $(JAR) safety-case

fmea: build
	java -jar $(JAR) fmea

tara: build
	java -jar $(JAR) tara

hara: build
	java -jar $(JAR) hara

boundary: build
	java -jar $(JAR) boundary

coupling: build
	java -jar $(JAR) coupling

do178: build
	java -jar $(JAR) do178

iso26262: build
	java -jar $(JAR) iso26262

iso21434: build
	java -jar $(JAR) iso21434

iec61508: build
	java -jar $(JAR) iec61508

iec62443: build
	java -jar $(JAR) iec62443

unece: build
	java -jar $(JAR) unece

slsa: build
	java -jar $(JAR) slsa

sas: build
	java -jar $(JAR) sas

sci: build
	java -jar $(JAR) sci

coverage: test
	java -jar $(JAR) coverage

comp: build
	java -jar $(JAR) comp

misra: build
	java -jar $(JAR) misra

metrics: build
	java -jar $(JAR) metrics

# ── Signing ───────────────────────────────────────────────────────────────────

sign: build
	java -jar $(JAR) sign sign $(JAR)

hooks: build
	java -jar $(JAR) hooks install

# ── Docker ────────────────────────────────────────────────────────────────────

docker:
	docker build --build-arg VERSION=$(VERSION) -t soundmatt/$(BINARY):$(VERSION) .
	docker tag soundmatt/$(BINARY):$(VERSION) soundmatt/$(BINARY):latest

docker-push: docker
	docker push soundmatt/$(BINARY):$(VERSION)
	docker push soundmatt/$(BINARY):latest

# ── Info ──────────────────────────────────────────────────────────────────────

capabilities: build
	java -jar $(JAR) capabilities

version: build
	java -jar $(JAR) version

# ── Housekeeping ──────────────────────────────────────────────────────────────

clean:
	mvn -q clean
	rm -f badge.svg audit-pack.zip qualify-report.json sbom.json provenance.json \
	      .fusa-evidence.json tara.json fmea.json safety-case.json safety-case.md \
	      safety-case.mermaid .fusa-hara.json boundary.mermaid boundary.dot \
	      fusa-report.json fusa-report.html fusa-report.sarif fusa-report.json \
	      vuln.json coupling-report.json comp-report.json misra-report.json \
	      do178-gap-report.json iso26262-gap-report.json iso21434-gap-report.json \
	      iec61508-gap-report.json unece-gap-report.json sci.json sci.md sas.md \
	      impact-report.json .fusa-signing.key .fusa-signing.sig

help:
	@echo "jfusa Makefile targets:"
	@echo "  build       Compile and package fat-JAR"
	@echo "  test        Run JUnit 5 test suite"
	@echo "  vet         Run jfusa on itself"
	@echo "  check       Full gate check"
	@echo "  evidence    Generate all evidence artifacts"
	@echo "  qualify     Tool qualification suite"
	@echo "  docker      Build Docker image"
	@echo "  clean       Remove build artifacts and evidence files"
	@echo ""
	@echo "Compliance: do178 iso26262 iso21434 iec61508 iec62443 unece slsa"
	@echo "Analysis:   lint analyze cyber trace boundary coupling comp misra"
	@echo "Safety:     safety-case fmea tara hara sas sci"
