# Build and testing notes


## Building

Produce deliverables with:

    # Default OMERO profile
    ./gradlew clean dist

    # Alternate OMERO profile
    ./gradlew clean dist -Pprofile=omero508-ice34


## Testing

### Structure and tooling overview

#### Prerequisites

- One PostgreSQL database per profile mainline

#### Tooling

- Flyway: database schema migration + database fixtures loading
- Gradle/TestNG: test configuration generation & tests execution/reporting
- Gradle/JUnit/ContiPerf: benchmark tests execution/reporting

#### Resources generation

Integration testing relies Gradle resource generation and resource filtering to produce
profile-specific test configurations at build time.

Generated resources are located in `<buildDir>/generated-resources/<sourceSetName>`:

- `integration-tests.sh`: basic command shorthand for integration environment initialization

Filtered resources are located in

- `omero-local.properties`: testing OMERO.server configuration (database connection settings,
   ManagedRepository location, in-memory LDAP connection parameters, authentication extension configuration)

### Gradle testing

Example "quick testing" steps for `5.0.8` profile:

    ./gradlew clean generateTestResources -Pprofile=omero508-ice34
    chmod u+x ./build/generated-resources/test/integration-tests.sh
    ./build/generated-resources/test/integration-tests.sh

### Eclipse testing

Prerequisites:

  - Integration database server started (both schema and fixtures are initialized at testing time)
  - Test resources filters applied (eg. via `./gradlew processTestResources -Pprofile=omero508-ice34`)

Run via TestNG plugin with either of:

  - JVM argument: `-Domero.config.location=${project_loc:omero-auth-ppms}/build/resources/test/omero-local.properties`
  - environment variable: `OMERO_CONFIG=omero-local.properties`

Note: this step is unnecessary in a Gradle environment, as the `test` build target sets the `omero.config.location`
system property to the relevant file location within the build directory.

### Test coverage reporting

    # Create database
    ./src/test/resources/db/setup-db.sh ome508 ome508 ome508

    # Prepare server configuration (apply test resource filters)
    ./gradlew processTestResources

    # Generate coverage report
    ./gradlew test jacocoTestReport

    # Delete database
    ./src/test/resources/db/teardown-db.sh ome508 ome508

### Benchmarks reporting

Prerequisites:

  - Integration database started
  - Integration PPMS server started and LDAP-enabled, with test PUMAPI endpoint

    # Create database
    ./src/test/resources/db/setup-db.sh ome508 ome508 ome508

    # Initialize db schema
    ./gradlew integrationTestDbMigrate

    # Prepare bench configuration
    ./gradlew processBenchResources
    cp -pvi ./build/resources/bench/omero-local.bench.properties ~/omero-local.bench.properties
    cp -pvi ./build/resources/bench/db/ldap_user.template.sql    ~/omero_ldap_user.bench.sql

    # Edit ~/omero-local.bench.properties (environment-specific LDAP and PPMS settings)
    vim ~/omero-local.bench.properties

    # Edit LDAP user OMERO SQL fixture (environment-specific LDAP and user settings)
    vim ~/omero_ldap_user.bench.sql

    # Load db fixture
    psql -h localhost -U ome508 ome508 < ~/omero_ldap_user.bench.sql

    # Generate bench report
    BENCH_CONFIG=~/omero-local.bench.properties ./gradlew benchTest

    # Cleanup bench resources
    rm ~/omero-local.bench.properties
    rm ~/omero_ldap_user.bench.sql

    # Delete database
    ./src/test/resources/db/teardown-db.sh ome508 ome508


## Publishing

Upload and publish released deliverables with:

    # Default OMERO profile, all artifacts
    ORG_GRADLE_PROJECT_bintray_user=user_name ORG_GRADLE_PROJECT_bintray_key=api_key \
    ./gradlew -Pbintray_org=imagopole -Pbintray_dryRun=false -Pbintray_publish=true \
    clean dist bintrayUpload --info
