#!/bin/sh
# Maven wrapper script — downloads Maven 3.9.9 if not already present.
# Generated for java-FuSa.

set -e

# Resolve the Maven home directory from the wrapper properties
MAVEN_WRAPPER_PROPERTIES=".mvn/wrapper/maven-wrapper.properties"
WRAPPER_JAR=".mvn/wrapper/maven-wrapper.jar"
WRAPPER_LAUNCHER=org.apache.maven.wrapper.MavenWrapperMain

# Find JAVA_HOME
if [ -n "$JAVA_HOME" ]; then
    JAVA_CMD="$JAVA_HOME/bin/java"
elif command -v java >/dev/null 2>&1; then
    JAVA_CMD="java"
else
    echo "ERROR: JAVA_HOME is not set and 'java' is not in PATH." >&2
    exit 1
fi

# Parse distributionUrl from properties
DISTRIBUTION_URL=$(grep "^distributionUrl=" "$MAVEN_WRAPPER_PROPERTIES" | cut -d= -f2-)
WRAPPER_URL=$(grep "^wrapperUrl=" "$MAVEN_WRAPPER_PROPERTIES" | cut -d= -f2-)

# Compute distribution directory
DIST_NAME=$(basename "$DISTRIBUTION_URL" .zip)
M2_HOME="${M2_HOME:-$HOME/.m2}"
MAVEN_HOME="$M2_HOME/wrapper/dists/$DIST_NAME"

if [ ! -d "$MAVEN_HOME" ]; then
    echo "Downloading Maven $DIST_NAME ..."
    mkdir -p "$MAVEN_HOME"
    if command -v curl >/dev/null 2>&1; then
        curl -fL -o "$MAVEN_HOME/dist.zip" "$DISTRIBUTION_URL"
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$MAVEN_HOME/dist.zip" "$DISTRIBUTION_URL"
    else
        echo "ERROR: Neither curl nor wget found." >&2
        exit 1
    fi
    # Unzip
    unzip -q "$MAVEN_HOME/dist.zip" -d "$MAVEN_HOME"
    rm "$MAVEN_HOME/dist.zip"
    echo "Maven installed to $MAVEN_HOME"
fi

# Find the mvn binary
MVN_BIN=$(find "$MAVEN_HOME" -name "mvn" -type f | head -1)
if [ -z "$MVN_BIN" ]; then
    echo "ERROR: Could not find mvn binary in $MAVEN_HOME" >&2
    exit 1
fi

exec "$MVN_BIN" "$@"
