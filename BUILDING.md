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

Run via TestNG plugin with either of:

  - JVM argument: `-Domero.config.location=${project_loc:omero-auth-ppms}/bin/omero-local.properties`
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

